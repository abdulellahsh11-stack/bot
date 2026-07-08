"""
reports.py — حفظ بيانات كل مشترك (نشاط المزارع) وإرسالها للمالك.
يعمل فوق auth.py. الدمج في server.py:
    from reports import router as reports_router, init_reports
    init_reports()
    app.include_router(reports_router)
المُشرف (supervisor) يرفع تقاريره عبر POST /reports مع ترويسة X-Service-Token = قيمة SERVICE_TOKEN.
"""
import os, io, csv
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from auth import db, now, current_user, is_super, load_roles, send_email, SUPER_EMAIL

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
router = APIRouter()

SCHEMA = """
CREATE TABLE IF NOT EXISTS farm_reports(
  id INTEGER PRIMARY KEY, user_id INTEGER, farm TEXT, duration INTEGER,
  tasks TEXT, ok INTEGER NOT NULL DEFAULT 1, at INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS ix_reports ON farm_reports(user_id, at);
"""
def init_reports():
    c = db(); c.executescript(SCHEMA); c.commit(); c.close()

def owner_only(user=Depends(current_user)):
    if not is_super(user): raise HTTPException(403, "للمالك فقط")
    return user

def _service(x_service_token: str = Header(None)):
    if not SERVICE_TOKEN or x_service_token != SERVICE_TOKEN:
        raise HTTPException(401, "خدمة غير مصرّحة")

class ReportIn(BaseModel):
    user_id: int; farm: str
    duration: int = 0          # ثوانٍ استغرقتها زيارة المزرعة
    tasks: str = ""            # ملخّص المهام المنجزة
    ok: bool = True

# ── المُشرف يرفع تقرير زيارة مزرعة ──
@router.post("/reports")
def add_report(b: ReportIn, _=Depends(_service)):
    c = db()
    c.execute("INSERT INTO farm_reports(user_id,farm,duration,tasks,ok,at) VALUES(?,?,?,?,?,?)",
              (b.user_id, b.farm, b.duration, b.tasks, 1 if b.ok else 0, now()))
    c.commit(); c.close(); return {"message": "تم الحفظ"}

# ── المالك: كل المشتركين مع خلاصة نشاطهم ──
@router.get("/owner/subscribers")
def all_subscribers(user=Depends(owner_only)):
    c = db(); out = []
    for u in c.execute("SELECT * FROM users WHERE deleted_at IS NULL ORDER BY id").fetchall():
        s = c.execute("SELECT COUNT(*) n, COALESCE(SUM(duration),0) tot, MAX(at) last FROM farm_reports WHERE user_id=?",
                      (u["id"],)).fetchone()
        out.append({"id": u["id"], "name": u["name"], "email": u["email"], "status": u["status"],
                    "verified": bool(u["verified"]), "roles": load_roles(c, u["id"]),
                    "trial_expires": u["trial_expires"], "runs": s["n"],
                    "total_seconds": s["tot"], "last_run": s["last"]})
    c.close(); return out

# ── المالك: تقارير المزارع (الكل أو مشترك محدّد) ──
@router.get("/owner/reports")
def owner_reports(user_id: Optional[int] = None, limit: int = 500, user=Depends(owner_only)):
    c = db(); limit = min(limit, 2000)
    if user_id:
        rows = c.execute("SELECT * FROM farm_reports WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit)).fetchall()
    else:
        rows = c.execute("SELECT * FROM farm_reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close(); return [dict(r) for r in rows]

# ── المالك: تصدير الجميع CSV ──
@router.get("/owner/export.csv")
def export_csv(user=Depends(owner_only)):
    c = db()
    rows = c.execute("""SELECT u.id,u.name,u.email,u.status,
        (SELECT GROUP_CONCAT(r.name) FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=u.id) roles,
        COUNT(f.id) runs, COALESCE(SUM(f.duration),0) total_seconds, MAX(f.at) last_run
        FROM users u LEFT JOIN farm_reports f ON f.user_id=u.id
        WHERE u.deleted_at IS NULL GROUP BY u.id ORDER BY u.id""").fetchall()
    c.close()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["id", "name", "email", "status", "roles", "runs", "total_seconds", "last_run"])
    for r in rows:
        w.writerow([r["id"], r["name"], r["email"], r["status"], r["roles"] or "",
                    r["runs"], r["total_seconds"], r["last_run"] or ""])
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=subscribers.csv"})

# ── يُستدعى دوريًا من المُشرف: يرسل خلاصة آخر 24 ساعة لبريد المالك ──
def email_owner_summary():
    c = db()
    rows = c.execute("""SELECT u.email, COUNT(f.id) runs, COALESCE(SUM(f.duration),0) tot
        FROM users u LEFT JOIN farm_reports f ON f.user_id=u.id AND f.at > ?
        WHERE u.deleted_at IS NULL GROUP BY u.id""", (now()-86400,)).fetchall()
    c.close()
    body = "\n".join(f"{r['email']}: {r['runs']} زيارة، {r['tot']} ثانية" for r in rows) or "لا نشاط"
    send_email(SUPER_EMAIL, "تقرير المشتركين اليومي", body)
