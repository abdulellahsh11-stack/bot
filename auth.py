"""
auth.py — نظام مصادقة وصلاحيات متعدد الأدوار (RBAC) لمشروع Whiteout Bot.
FastAPI + SQLite. بلا تبعيات ثقيلة: PyJWT فقط (التجزئة عبر hashlib/PBKDF2 المتوافق مع Render).
الدمج في server.py:
    from auth import router as auth_router, init_db
    init_db()
    app.include_router(auth_router)
"""
import os, sqlite3, secrets, hashlib, hmac, time
from typing import Optional, List
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field

# ───────── الإعدادات (من متغيّرات البيئة) ─────────
DB_PATH     = os.getenv("DB_PATH", "whiteout.db")
JWT_SECRET  = os.getenv("JWT_SECRET", "dev-only-change-me")
DEBUG       = os.getenv("DEBUG", "0") == "1"
SUPER_EMAIL = os.getenv("SUPER_EMAIL", "owner@whiteout.local")
SUPER_PW    = os.getenv("SUPER_PW", "ChangeMe!2026")
ACCESS_TTL, REFRESH_TTL = 15 * 60, 7 * 24 * 3600
VERIFY_TTL, RESET_TTL   = 24 * 3600, 30 * 60
MAX_FAILS, LOCK_TTL, ITER = 5, 15 * 60, 200_000

bearer = HTTPBearer(auto_error=False)
router = APIRouter()

def db():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); return c

def now(): return int(time.time())

# ───────── المخطط والبذور ─────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT,
  password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', verified INTEGER NOT NULL DEFAULT 0,
  trial_expires INTEGER, trial_used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER, updated_at INTEGER, deleted_at INTEGER);
CREATE TABLE IF NOT EXISTS roles(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, is_system INTEGER NOT NULL DEFAULT 0, description TEXT);
CREATE TABLE IF NOT EXISTS permissions(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, module TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS role_permissions(
  role_id INTEGER, permission_id INTEGER, PRIMARY KEY(role_id,permission_id),
  FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS user_roles(
  user_id INTEGER, role_id INTEGER, PRIMARY KEY(user_id,role_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS refresh_tokens(
  id INTEGER PRIMARY KEY, user_id INTEGER, token_hash TEXT UNIQUE, expires INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS password_reset_tokens(
  id INTEGER PRIMARY KEY, user_id INTEGER, token_hash TEXT, expires INTEGER,
  used INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS email_verification_tokens(
  id INTEGER PRIMARY KEY, user_id INTEGER, token_hash TEXT, expires INTEGER,
  used INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS login_attempts(
  id INTEGER PRIMARY KEY, email TEXT, ip TEXT, ok INTEGER, at INTEGER);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, detail TEXT, ip TEXT, at INTEGER);
CREATE INDEX IF NOT EXISTS ix_attempts ON login_attempts(email,at);
CREATE INDEX IF NOT EXISTS ix_audit ON audit_logs(at);
"""
PERMS = [("users.create","users"),("users.read","users"),("users.update","users"),("users.delete","users"),
         ("roles.create","roles"),("roles.read","roles"),("roles.update","roles"),("roles.delete","roles"),
         ("permissions.assign","permissions"),("dashboard.view","dashboard"),
         ("reports.view","reports"),("reports.export","reports"),("settings.update","settings"),
         ("profile.view","profile"),("profile.update","profile"),("audit_logs.view","audit")]
ROLE_PERMS = {
  "super_admin": [p[0] for p in PERMS],
  "manager":     ["users.read","users.update","dashboard.view","reports.view","reports.export","profile.view","profile.update"],
  "user":        ["dashboard.view","profile.view","profile.update"],
  "test":        ["dashboard.view","profile.view","profile.update"],
  "guest":       ["dashboard.view"],
}

def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return f"{ITER}${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITER).hex()}"

def verify_pw(pw: str, stored: str) -> bool:
    try:
        it, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex()
        return hmac.compare_digest(calc, h)
    except Exception:
        return False

def sha(t: str) -> str: return hashlib.sha256(t.encode()).hexdigest()
def access_token(uid: int) -> str:
    return jwt.encode({"sub": uid, "typ": "a", "exp": now() + ACCESS_TTL}, JWT_SECRET, algorithm="HS256")
def new_refresh(c, uid: int) -> str:
    t = secrets.token_urlsafe(32)
    c.execute("INSERT INTO refresh_tokens(user_id,token_hash,expires) VALUES(?,?,?)", (uid, sha(t), now()+REFRESH_TTL))
    return t
def audit(c, uid, action, detail="", ip=""):
    c.execute("INSERT INTO audit_logs(user_id,action,detail,ip,at) VALUES(?,?,?,?,?)", (uid, action, detail, ip, now()))
def send_email(to, subject, body):  # اربط SMTP فعليًا هنا؛ حاليًا يُسجَّل فقط.
    print(f"[EMAIL] {to} :: {subject} :: {body}")

def init_db():
    c = db(); c.executescript(SCHEMA)
    for code, mod in PERMS:
        c.execute("INSERT OR IGNORE INTO permissions(code,module) VALUES(?,?)", (code, mod))
    for r, codes in ROLE_PERMS.items():
        c.execute("INSERT OR IGNORE INTO roles(name,is_system,description) VALUES(?,1,?)", (r, r))
        rid = c.execute("SELECT id FROM roles WHERE name=?", (r,)).fetchone()["id"]
        for code in codes:
            pid = c.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()["id"]
            c.execute("INSERT OR IGNORE INTO role_permissions VALUES(?,?)", (rid, pid))
    if not c.execute("SELECT 1 FROM users WHERE email=?", (SUPER_EMAIL,)).fetchone():
        c.execute("INSERT INTO users(name,email,password,status,verified,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  ("Owner", SUPER_EMAIL, hash_pw(SUPER_PW), "active", now(), now()))
        uid = c.execute("SELECT id FROM users WHERE email=?", (SUPER_EMAIL,)).fetchone()["id"]
        rid = c.execute("SELECT id FROM roles WHERE name='super_admin'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO user_roles VALUES(?,?)", (uid, rid))
    c.commit(); c.close()

# ───────── الصلاحيات والحماية ─────────
def load_perms(c, uid) -> set:
    rows = c.execute("""SELECT DISTINCT p.code FROM permissions p
      JOIN role_permissions rp ON rp.permission_id=p.id
      JOIN user_roles ur ON ur.role_id=rp.role_id WHERE ur.user_id=?""", (uid,)).fetchall()
    return {r["code"] for r in rows}
def load_roles(c, uid) -> list:
    return [r["name"] for r in c.execute(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?", (uid,)).fetchall()]

async def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if not cred: raise HTTPException(401, "غير مصرح")
    try:
        data = jwt.decode(cred.credentials, JWT_SECRET, algorithms=["HS256"]); assert data.get("typ") == "a"
    except Exception:
        raise HTTPException(401, "جلسة غير صالحة")
    c = db(); u = c.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (data["sub"],)).fetchone()
    if not u: c.close(); raise HTTPException(401, "غير مصرح")
    if u["status"] != "active": c.close(); raise HTTPException(403, "الحساب معطّل")
    if not u["verified"]: c.close(); raise HTTPException(403, "يلزم تفعيل البريد")
    if u["trial_expires"] and now() > u["trial_expires"]: c.close(); raise HTTPException(403, "انتهت الفترة التجريبية")
    user = dict(u); user["perms"] = load_perms(c, u["id"]); user["roles"] = load_roles(c, u["id"]); c.close()
    return user

def require(*need):
    async def dep(user=Depends(current_user)):
        if not set(need).issubset(user["perms"]): raise HTTPException(403, "لا تملك صلاحية هذا الإجراء")
        return user
    return dep

def is_super(user): return "super_admin" in user["roles"]
def guard_target(c, actor, target_id):
    if "super_admin" in load_roles(c, target_id) and not is_super(actor):
        raise HTTPException(403, "لا يمكن تعديل مالك النظام")
def guard_roles(actor, names):
    if "super_admin" in (names or []) and not is_super(actor):
        raise HTTPException(403, "لا يمكن منح صلاحية المالك")

# ───────── نماذج المدخلات ─────────
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=60); email: EmailStr
    phone: Optional[str] = None; password: str = Field(min_length=8, max_length=128)
class LoginIn(BaseModel):  email: EmailStr; password: str
class ForgotIn(BaseModel): email: EmailStr
class ResetIn(BaseModel):  token: str; password: str = Field(min_length=8, max_length=128)
class TokenIn(BaseModel):  token: str
class RefreshIn(BaseModel):refresh: str
class UserIn(BaseModel):
    name: str; email: EmailStr; password: str = Field(min_length=8); roles: List[str] = ["user"]
class UserPatch(BaseModel):
    name: Optional[str] = None; status: Optional[str] = None; roles: Optional[List[str]] = None
class RoleIn(BaseModel):
    name: str; description: Optional[str] = None; permissions: Optional[List[str]] = None
class AssignIn(BaseModel):  permissions: List[str]
class ExtendIn(BaseModel):  hours: int = 36

def _set_user_roles(c, uid, names):
    c.execute("DELETE FROM user_roles WHERE user_id=?", (uid,))
    for n in names or []:
        r = c.execute("SELECT id FROM roles WHERE name=?", (n,)).fetchone()
        if r: c.execute("INSERT OR IGNORE INTO user_roles VALUES(?,?)", (uid, r["id"]))
def _set_role_perms(c, rid, codes):
    if codes is None: return
    c.execute("DELETE FROM role_permissions WHERE role_id=?", (rid,))
    for code in codes:
        p = c.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()
        if p: c.execute("INSERT OR IGNORE INTO role_permissions VALUES(?,?)", (rid, p["id"]))
def _user_dict(c, u):
    return {"id": u["id"], "name": u["name"], "email": u["email"], "phone": u["phone"],
            "status": u["status"], "verified": bool(u["verified"]), "roles": load_roles(c, u["id"]),
            "trial_expires": u["trial_expires"], "trial_used": bool(u["trial_used"])}

# ───────── المصادقة ─────────
@router.post("/auth/register")
def register(b: RegisterIn, req: Request):
    c = db()
    if c.execute("SELECT 1 FROM users WHERE email=?", (b.email,)).fetchone():
        c.close(); raise HTTPException(409, "تعذّر إنشاء الحساب")
    c.execute("INSERT INTO users(name,email,phone,password,status,verified,created_at,updated_at) VALUES(?,?,?,?,?,0,?,?)",
              (b.name, b.email, b.phone, hash_pw(b.password), "active", now(), now()))
    uid = c.execute("SELECT id FROM users WHERE email=?", (b.email,)).fetchone()["id"]
    _set_user_roles(c, uid, ["user"])
    tok = secrets.token_urlsafe(24)
    c.execute("INSERT INTO email_verification_tokens(user_id,token_hash,expires) VALUES(?,?,?)", (uid, sha(tok), now()+VERIFY_TTL))
    audit(c, uid, "register", b.email, req.client.host if req.client else "")
    c.commit(); c.close(); send_email(b.email, "تفعيل الحساب", f"رمز التفعيل: {tok}")
    out = {"message": "تم التسجيل، تحقّق من بريدك للتفعيل"}
    if DEBUG: out["verify_token"] = tok
    return out

@router.post("/auth/login")
def login(b: LoginIn, req: Request):
    ip = req.client.host if req.client else ""; c = db()
    fails = c.execute("SELECT COUNT(*) n FROM login_attempts WHERE email=? AND ok=0 AND at>?",
                      (b.email, now()-LOCK_TTL)).fetchone()["n"]
    if fails >= MAX_FAILS: c.close(); raise HTTPException(429, "الحساب مقفول مؤقتًا، حاول لاحقًا")
    u = c.execute("SELECT * FROM users WHERE email=? AND deleted_at IS NULL", (b.email,)).fetchone()
    ok = bool(u) and verify_pw(b.password, u["password"])
    c.execute("INSERT INTO login_attempts(email,ip,ok,at) VALUES(?,?,?,?)", (b.email, ip, 1 if ok else 0, now()))
    if not ok:
        audit(c, u["id"] if u else None, "login_fail", b.email, ip); c.commit(); c.close()
        raise HTTPException(401, "بيانات الدخول غير صحيحة")
    if u["status"] != "active": c.commit(); c.close(); raise HTTPException(403, "الحساب معطّل")
    if not u["verified"]:      c.commit(); c.close(); raise HTTPException(403, "يلزم تفعيل البريد أولًا")
    refresh = new_refresh(c, u["id"]); audit(c, u["id"], "login", "", ip); c.commit(); c.close()
    return {"access": access_token(u["id"]), "refresh": refresh, "token_type": "bearer"}

@router.post("/auth/refresh")
def refresh(b: RefreshIn):
    c = db(); r = c.execute("SELECT * FROM refresh_tokens WHERE token_hash=? AND revoked=0", (sha(b.refresh),)).fetchone()
    if not r or r["expires"] < now(): c.close(); raise HTTPException(401, "جلسة منتهية")
    c.execute("UPDATE refresh_tokens SET revoked=1 WHERE id=?", (r["id"],))
    new = new_refresh(c, r["user_id"]); c.commit(); c.close()
    return {"access": access_token(r["user_id"]), "refresh": new, "token_type": "bearer"}

@router.post("/auth/logout")
def logout(b: RefreshIn, user=Depends(current_user)):
    c = db(); c.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (sha(b.refresh),))
    audit(c, user["id"], "logout"); c.commit(); c.close(); return {"message": "تم تسجيل الخروج"}

@router.post("/auth/verify-email")
def verify_email(b: TokenIn):
    c = db(); t = c.execute("SELECT * FROM email_verification_tokens WHERE token_hash=? AND used=0", (sha(b.token),)).fetchone()
    if not t or t["expires"] < now(): c.close(); raise HTTPException(400, "رمز غير صالح")
    c.execute("UPDATE users SET verified=1, updated_at=? WHERE id=?", (now(), t["user_id"]))
    c.execute("UPDATE email_verification_tokens SET used=1 WHERE id=?", (t["id"],))
    audit(c, t["user_id"], "verify_email"); c.commit(); c.close(); return {"message": "تم تفعيل الحساب"}

@router.post("/auth/forgot-password")
def forgot(b: ForgotIn):
    c = db(); u = c.execute("SELECT id FROM users WHERE email=? AND deleted_at IS NULL", (b.email,)).fetchone()
    if u:
        tok = secrets.token_urlsafe(24)
        c.execute("INSERT INTO password_reset_tokens(user_id,token_hash,expires) VALUES(?,?,?)", (u["id"], sha(tok), now()+RESET_TTL))
        c.commit(); send_email(b.email, "إعادة تعيين كلمة المرور", f"الرمز: {tok}")
    c.close(); return {"message": "إن وُجد الحساب فستصلك رسالة"}

@router.post("/auth/reset-password")
def reset(b: ResetIn):
    c = db(); t = c.execute("SELECT * FROM password_reset_tokens WHERE token_hash=? AND used=0", (sha(b.token),)).fetchone()
    if not t or t["expires"] < now(): c.close(); raise HTTPException(400, "رمز غير صالح أو منتهٍ")
    c.execute("UPDATE users SET password=?, updated_at=? WHERE id=?", (hash_pw(b.password), now(), t["user_id"]))
    c.execute("UPDATE password_reset_tokens SET used=1 WHERE id=?", (t["id"],))
    c.execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", (t["user_id"],))
    audit(c, t["user_id"], "reset_password"); c.commit(); c.close(); return {"message": "تم تغيير كلمة المرور"}

@router.get("/auth/me")
def me(user=Depends(current_user)):
    return {"id": user["id"], "name": user["name"], "email": user["email"], "roles": user["roles"],
            "permissions": sorted(user["perms"]), "verified": bool(user["verified"]), "status": user["status"]}

# ───────── المستخدمون ─────────
@router.get("/users")
def list_users(q: str = "", user=Depends(require("users.read"))):
    c = db(); rows = c.execute(
        "SELECT * FROM users WHERE deleted_at IS NULL AND (email LIKE ? OR name LIKE ?) ORDER BY id DESC",
        (f"%{q}%", f"%{q}%")).fetchall()
    out = [_user_dict(c, r) for r in rows]; c.close(); return out

@router.get("/users/{uid}")
def get_user(uid: int, user=Depends(require("users.read"))):
    c = db(); u = c.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
    if not u: c.close(); raise HTTPException(404, "غير موجود")
    out = _user_dict(c, u); c.close(); return out

@router.post("/users")
def create_user(b: UserIn, user=Depends(require("users.create"))):
    guard_roles(user, b.roles); c = db()
    if c.execute("SELECT 1 FROM users WHERE email=?", (b.email,)).fetchone():
        c.close(); raise HTTPException(409, "البريد مستخدم")
    c.execute("INSERT INTO users(name,email,password,status,verified,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
              (b.name, b.email, hash_pw(b.password), "active", now(), now()))
    uid = c.execute("SELECT id FROM users WHERE email=?", (b.email,)).fetchone()["id"]
    _set_user_roles(c, uid, b.roles); audit(c, user["id"], "user_create", b.email)
    out = _user_dict(c, c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()); c.commit(); c.close(); return out

@router.patch("/users/{uid}")
def patch_user(uid: int, b: UserPatch, user=Depends(require("users.update"))):
    c = db(); u = c.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
    if not u: c.close(); raise HTTPException(404, "غير موجود")
    guard_target(c, user, uid)
    if b.roles is not None and uid == user["id"]: c.close(); raise HTTPException(403, "لا يمكنك تعديل دورك بنفسك")
    if b.name is not None: c.execute("UPDATE users SET name=? WHERE id=?", (b.name, uid))
    if b.status is not None:
        if b.status not in ("active", "inactive", "disabled"): c.close(); raise HTTPException(400, "حالة غير صالحة")
        c.execute("UPDATE users SET status=? WHERE id=?", (b.status, uid))
    if b.roles is not None: guard_roles(user, b.roles); _set_user_roles(c, uid, b.roles)
    c.execute("UPDATE users SET updated_at=? WHERE id=?", (now(), uid)); audit(c, user["id"], "user_update", str(uid))
    out = _user_dict(c, c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()); c.commit(); c.close(); return out

@router.delete("/users/{uid}")
def delete_user(uid: int, user=Depends(require("users.delete"))):
    c = db(); u = c.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
    if not u: c.close(); raise HTTPException(404, "غير موجود")
    guard_target(c, user, uid)
    if uid == user["id"]: c.close(); raise HTTPException(400, "لا يمكن حذف نفسك")
    c.execute("UPDATE users SET deleted_at=?, status='disabled' WHERE id=?", (now(), uid))
    c.execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", (uid,))
    audit(c, user["id"], "user_delete", str(uid)); c.commit(); c.close(); return {"message": "تم الحذف الناعم"}

@router.patch("/users/{uid}/activate")
def activate(uid: int, user=Depends(require("users.update"))):
    c = db(); guard_target(c, user, uid)
    c.execute("UPDATE users SET status='active', updated_at=? WHERE id=? AND deleted_at IS NULL", (now(), uid))
    audit(c, user["id"], "user_activate", str(uid)); c.commit(); c.close(); return {"message": "مُفعّل"}

@router.patch("/users/{uid}/deactivate")
def deactivate(uid: int, user=Depends(require("users.update"))):
    c = db()
    if uid == user["id"]: c.close(); raise HTTPException(400, "لا يمكن تعطيل نفسك")
    guard_target(c, user, uid)
    c.execute("UPDATE users SET status='disabled', updated_at=? WHERE id=? AND deleted_at IS NULL", (now(), uid))
    c.execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", (uid,))
    audit(c, user["id"], "user_deactivate", str(uid)); c.commit(); c.close(); return {"message": "مُعطّل"}

@router.post("/users/{uid}/trial")  # منح تجربة Test: 36 ساعة مرة واحدة فقط
def grant_trial(uid: int, user=Depends(require("users.update"))):
    c = db(); u = c.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
    if not u: c.close(); raise HTTPException(404, "غير موجود")
    if u["trial_used"]: c.close(); raise HTTPException(400, "استُخدمت التجربة مسبقًا")
    _set_user_roles(c, uid, ["test"])
    c.execute("UPDATE users SET trial_expires=?, trial_used=1, updated_at=? WHERE id=?", (now()+36*3600, now(), uid))
    audit(c, user["id"], "trial_grant", str(uid)); c.commit(); c.close(); return {"message": "تم منح تجربة 36 ساعة"}

@router.patch("/users/{uid}/extend-trial")  # تمديد التجربة من لوحة المالك
def extend_trial(uid: int, b: ExtendIn, user=Depends(require("users.update"))):
    c = db(); u = c.execute("SELECT trial_expires FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
    if not u: c.close(); raise HTTPException(404, "غير موجود")
    base = max(now(), u["trial_expires"] or now())
    c.execute("UPDATE users SET trial_expires=?, updated_at=? WHERE id=?", (base+b.hours*3600, now(), uid))
    audit(c, user["id"], "trial_extend", f"{uid}:+{b.hours}h"); c.commit(); c.close()
    return {"message": f"مُدّدت التجربة {b.hours} ساعة"}

# ───────── الأدوار والصلاحيات ─────────
@router.get("/roles")
def list_roles(user=Depends(require("roles.read"))):
    c = db(); out = []
    for r in c.execute("SELECT * FROM roles ORDER BY id").fetchall():
        perms = [x["code"] for x in c.execute(
            "SELECT p.code FROM permissions p JOIN role_permissions rp ON rp.permission_id=p.id WHERE rp.role_id=?",
            (r["id"],)).fetchall()]
        out.append({"id": r["id"], "name": r["name"], "is_system": bool(r["is_system"]),
                    "description": r["description"], "permissions": perms})
    c.close(); return out

@router.post("/roles")
def create_role(b: RoleIn, user=Depends(require("roles.create"))):
    c = db()
    if c.execute("SELECT 1 FROM roles WHERE name=?", (b.name,)).fetchone(): c.close(); raise HTTPException(409, "الاسم مستخدم")
    c.execute("INSERT INTO roles(name,is_system,description) VALUES(?,0,?)", (b.name, b.description))
    rid = c.execute("SELECT id FROM roles WHERE name=?", (b.name,)).fetchone()["id"]
    _set_role_perms(c, rid, b.permissions or []); audit(c, user["id"], "role_create", b.name)
    c.commit(); c.close(); return {"id": rid, "message": "تم"}

@router.patch("/roles/{rid}")
def update_role(rid: int, b: RoleIn, user=Depends(require("roles.update"))):
    c = db(); r = c.execute("SELECT * FROM roles WHERE id=?", (rid,)).fetchone()
    if not r: c.close(); raise HTTPException(404, "غير موجود")
    if r["is_system"] and not is_super(user): c.close(); raise HTTPException(403, "دور نظام محمي")
    if b.description is not None: c.execute("UPDATE roles SET description=? WHERE id=?", (b.description, rid))
    _set_role_perms(c, rid, b.permissions); audit(c, user["id"], "role_update", r["name"])
    c.commit(); c.close(); return {"message": "تم"}

@router.delete("/roles/{rid}")
def delete_role(rid: int, user=Depends(require("roles.delete"))):
    c = db(); r = c.execute("SELECT * FROM roles WHERE id=?", (rid,)).fetchone()
    if not r: c.close(); raise HTTPException(404, "غير موجود")
    if r["is_system"]: c.close(); raise HTTPException(403, "لا يمكن حذف دور نظام")
    c.execute("DELETE FROM roles WHERE id=?", (rid,)); audit(c, user["id"], "role_delete", r["name"])
    c.commit(); c.close(); return {"message": "تم"}

@router.get("/permissions")
def list_permissions(user=Depends(require("roles.read"))):
    c = db(); rows = c.execute("SELECT code,module,description FROM permissions ORDER BY module,code").fetchall()
    c.close(); return [dict(r) for r in rows]

@router.post("/roles/{rid}/permissions")
def assign_perms(rid: int, b: AssignIn, user=Depends(require("permissions.assign"))):
    c = db(); r = c.execute("SELECT * FROM roles WHERE id=?", (rid,)).fetchone()
    if not r: c.close(); raise HTTPException(404, "غير موجود")
    for code in b.permissions:
        p = c.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()
        if p: c.execute("INSERT OR IGNORE INTO role_permissions VALUES(?,?)", (rid, p["id"]))
    audit(c, user["id"], "perm_assign", f"{r['name']}:{','.join(b.permissions)}"); c.commit(); c.close(); return {"message": "تم"}

@router.delete("/roles/{rid}/permissions/{code}")
def revoke_perm(rid: int, code: str, user=Depends(require("permissions.assign"))):
    c = db()
    c.execute("DELETE FROM role_permissions WHERE role_id=? AND permission_id=(SELECT id FROM permissions WHERE code=?)", (rid, code))
    audit(c, user["id"], "perm_revoke", f"{rid}:{code}"); c.commit(); c.close(); return {"message": "تم"}

@router.get("/audit-logs")
def audit_logs(limit: int = 100, user=Depends(require("audit_logs.view"))):
    c = db(); rows = c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (min(limit, 500),)).fetchall()
    c.close(); return [dict(r) for r in rows]
