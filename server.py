"""
server.py — سيرفر Whiteout Bot (تسعير لكل مزرعة)
المشترك يحدّد عدد المزارع عند الاشتراك → السعر = العدد × سعر المزرعة.
يخدم لوحة المالك + لوحة المشترك + JSON API، تخزين SQLite.
تشغيل: uvicorn server:app --host 0.0.0.0 --port 8000
"""
import os, json, sqlite3, datetime, uuid
from contextlib import closing
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

OWNER_ID  = os.environ.get("OWNER_ID", "99999999")
OWNER_PW  = os.environ.get("OWNER_PW", "0500111329")
DB_PATH   = os.environ.get("DB_PATH", "whiteout.db")
HERE      = os.path.dirname(os.path.abspath(__file__))
BASE_URL  = os.environ.get("BASE_URL", "")
MOYASAR_SECRET = os.environ.get("MOYASAR_SECRET", "")
ZAPIER_HOOK    = os.environ.get("ZAPIER_HOOK", "")
CURRENCY  = os.environ.get("CURRENCY", "SAR")

# الباقات الثابتة (عدد المزارع) وأسعارها الافتراضية — يعدّلها المالك من اللوحة
TIERS = [10, 20, 30, 50, 70]
DEF_PRICES = {"10": "450", "20": "800", "30": "1100", "50": "1700", "70": "2200"}
DEF_PERIOD_DAYS = os.environ.get("PERIOD_DAYS", "30")
TRIAL_DAYS  = int(os.environ.get("TRIAL_DAYS", "2"))    # مدة التجربة المجانية
TRIAL_FARMS = int(os.environ.get("TRIAL_FARMS", "2"))   # مزارع التجربة

app = FastAPI(title="Whiteout Bot Server")

def db():
    con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row; return con

def init_db():
    with closing(db()) as con:
        con.execute("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, pw TEXT, blob TEXT)")
        con.execute("""CREATE TABLE IF NOT EXISTS payments(
            id TEXT PRIMARY KEY, user_id TEXT, farms INTEGER, amount REAL, currency TEXT,
            status TEXT, provider TEXT, ref TEXT, created_at TEXT)""")
        con.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)")
        con.commit()
        defaults = [("period_days", DEF_PERIOD_DAYS), ("currency", CURRENCY), ("providers", "manual")]
        defaults += [(f"price_{n}", DEF_PRICES[str(n)]) for n in TIERS]
        for k, v in defaults:
            if con.execute("SELECT 1 FROM settings WHERE k=?", (k,)).fetchone() is None:
                con.execute("INSERT INTO settings(k,v) VALUES(?,?)", (k, v))
        con.commit()
init_db()

def today(): return datetime.date.today().isoformat()
def get_user(uid):
    with closing(db()) as con:
        r = con.execute("SELECT blob FROM users WHERE id=?", (uid,)).fetchone()
        return json.loads(r["blob"]) if r else None
def put_user(b):
    with closing(db()) as con:
        con.execute("INSERT OR REPLACE INTO users(id,pw,blob) VALUES(?,?,?)",
                    (b["id"], b.get("pw",""), json.dumps(b, ensure_ascii=False))); con.commit()
def all_users():
    with closing(db()) as con:
        return [json.loads(r["blob"]) for r in con.execute("SELECT blob FROM users ORDER BY id")]
def del_user(uid):
    with closing(db()) as con:
        con.execute("DELETE FROM users WHERE id=?", (uid,)); con.commit()

def add_payment(p):
    with closing(db()) as con:
        con.execute("INSERT OR REPLACE INTO payments VALUES(?,?,?,?,?,?,?,?,?)",
            (p["id"],p["user_id"],p["farms"],p["amount"],p["currency"],p["status"],
             p["provider"],p.get("ref",""),p.get("created_at",today()))); con.commit()
def get_payment(pid):
    with closing(db()) as con:
        r = con.execute("SELECT * FROM payments WHERE id=?", (pid,)).fetchone()
        return dict(r) if r else None
def set_payment_status(pid, status, ref=""):
    with closing(db()) as con:
        con.execute("UPDATE payments SET status=?, ref=? WHERE id=?", (status, ref, pid)); con.commit()
def all_payments():
    with closing(db()) as con:
        return [dict(r) for r in con.execute("SELECT * FROM payments ORDER BY created_at DESC LIMIT 200")]

def setting(k, default=""):
    with closing(db()) as con:
        r = con.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default
def set_setting(k, v):
    with closing(db()) as con:
        con.execute("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, v)); con.commit()

def tier_price(n):    return float(setting(f"price_{int(n)}", DEF_PRICES.get(str(int(n)), "0")))
def period_days():    return int(setting("period_days", DEF_PERIOD_DAYS))
def max_farms():      return max(TIERS)

def notify_zapier(event, data):
    hook = ZAPIER_HOOK or setting("zapier_hook", "")
    if not hook: return
    try:
        import requests; requests.post(hook, json={"event": event, "data": data}, timeout=6)
    except Exception: pass

def activate(user_id, farms):
    u = get_user(user_id)
    if not u: return
    exp = (datetime.date.today() + datetime.timedelta(days=period_days())).isoformat()
    u["maxFarms"]  = int(farms)
    u["planName"]  = f"{farms} مزرعة"
    u["subStatus"] = "active"
    u["subExpiry"] = exp
    u["botOn"]     = True
    put_user(u)
    notify_zapier("subscription_activated", {"user_id": user_id, "farms": farms, "expiry": exp})

# ───── نماذج ─────
class Register(BaseModel): id: str; pw: str; maxFarms: int = 1
class Login(BaseModel): id: str; pw: str
class Save(BaseModel): id: str; pw: str; blob: dict
class OwnerAuth(BaseModel): pw: str
class OwnerUpsert(BaseModel): pw: str; blob: dict
class OwnerDelete(BaseModel): pw: str; id: str
class OwnerActivate(BaseModel): pw: str; id: str; farms: int = 10
class OwnerDeactivate(BaseModel): pw: str; id: str
class SettingsIn(BaseModel): pw: str; settings: dict
class PayCreate(BaseModel): userId: str; pw: str; farms: int = 1; provider: str = "manual"

# ───── المشترك ─────
@app.post("/api/register")
def register(r: Register):
    if len(r.id)!=8 or not r.id.isdigit(): raise HTTPException(400,"ID يجب أن يكون 8 أرقام")
    if len(r.pw)<6: raise HTTPException(400,"كلمة المرور قصيرة")
    if get_user(r.id): raise HTTPException(409,"هذا الـ ID مسجّل مسبقاً")
    exp=(datetime.date.today()+datetime.timedelta(days=TRIAL_DAYS)).isoformat()
    b={"id":r.id,"pw":r.pw,"maxFarms":TRIAL_FARMS,"botOn":True,
       "createdAt":today(),"farms":[],"subStatus":"trial","subExpiry":exp,
       "planName":f"تجربة مجانية ({TRIAL_DAYS} يوم)"}
    put_user(b)
    notify_zapier("user_registered",{"user_id":r.id})
    notify_zapier("trial_started",{"user_id":r.id,"farms":TRIAL_FARMS,"expiry":exp})
    return b

def check_expiry(u):
    """يغلق التجربة/الاشتراك تلقائياً بعد انتهاء المدة."""
    if u.get("subStatus") in ("trial","active") and u.get("subExpiry"):
        if u["subExpiry"] < today():
            u["subStatus"]="expired"; u["botOn"]=False
            put_user(u)
            notify_zapier("subscription_expired",{"user_id":u["id"]})
    return u

@app.post("/api/login")
def login(r: Login):
    u=get_user(r.id)
    if not u: raise HTTPException(404,"لا يوجد حساب بهذا الـ ID")
    if u.get("pw")!=r.pw: raise HTTPException(401,"كلمة المرور خاطئة")
    return check_expiry(u)

@app.post("/api/save")
def save(r: Save):
    u=get_user(r.id)
    if not u or u.get("pw")!=r.pw: raise HTTPException(401,"غير مصرّح")
    b=r.blob; b["id"]=r.id
    for f in ("subStatus","subExpiry","planName","maxFarms"):
        if f in u: b[f]=u[f]
    # لا يتجاوز عدد المزارع المسموح
    if isinstance(b.get("farms"), list) and len(b["farms"])>int(u.get("maxFarms",1)):
        b["farms"]=b["farms"][:int(u.get("maxFarms",1))]
    put_user(b); return {"ok":True}

@app.get("/api/pricing")
def pricing():
    return {"tiers":[{"farms":n,"price":tier_price(n)} for n in TIERS],
            "period_days":period_days(),"max_farms":max_farms(),
            "currency":setting("currency",CURRENCY)}

# ───── الدفع (لكل مزرعة) ─────
@app.post("/api/pay/create")
def pay_create(r: PayCreate):
    u=get_user(r.userId)
    if not u or u.get("pw")!=r.pw: raise HTTPException(401,"غير مصرّح")
    if int(r.farms) not in TIERS:
        raise HTTPException(400, "باقة غير صالحة — اختر 10 أو 20 أو 30 مزرعة")
    farms=int(r.farms)
    amount=round(tier_price(farms),2)
    cur=setting("currency",CURRENCY); pid=uuid.uuid4().hex
    add_payment({"id":pid,"user_id":r.userId,"farms":farms,"amount":amount,"currency":cur,
                 "status":"pending","provider":r.provider,"ref":"","created_at":today()})
    base=(BASE_URL or "").rstrip("/")
    if r.provider=="moyasar" and MOYASAR_SECRET:
        try:
            import requests
            res=requests.post("https://api.moyasar.com/v1/invoices", auth=(MOYASAR_SECRET,""),
                json={"amount":int(round(amount*100)),"currency":cur,
                      "description":f"{farms} مزرعة - {r.userId}",
                      "callback_url":f"{base}/api/pay/webhook","metadata":{"payment_id":pid}}, timeout=15)
            d=res.json(); set_payment_status(pid,"pending",d.get("id",""))
            return {"payUrl":d.get("url"),"paymentId":pid,"amount":amount,"farms":farms}
        except Exception as e:
            raise HTTPException(502,f"تعذّر إنشاء فاتورة Moyasar: {e}")
    if r.provider=="paypal":
        return {"payUrl":f"{base}/pay/confirm?pid={pid}","paymentId":pid,"amount":amount,"farms":farms,
                "note":"PayPal يحتاج مفاتيحك — وضع تأكيد يدوي حالياً"}
    return {"payUrl":f"{base}/pay/confirm?pid={pid}","paymentId":pid,"amount":amount,"farms":farms}

@app.post("/api/pay/webhook")
async def pay_webhook(request: Request):
    try: body=await request.json()
    except Exception: body={}
    pid=(body.get("metadata") or {}).get("payment_id") or body.get("payment_id")
    status=body.get("status","paid")
    if not pid: raise HTTPException(400,"payment_id مفقود")
    pay=get_payment(pid)
    if not pay: raise HTTPException(404,"دفعة غير معروفة")
    if status in ("paid","succeeded","completed","active"):
        set_payment_status(pid,"paid",body.get("id",""))
        activate(pay["user_id"], pay["farms"])
        notify_zapier("payment_paid",{"user_id":pay["user_id"],"amount":pay["amount"],
                                      "farms":pay["farms"],"payment_id":pid})
        return {"ok":True,"activated":True}
    set_payment_status(pid,status); return {"ok":True,"activated":False}

@app.get("/pay/confirm", response_class=HTMLResponse)
def pay_confirm_page(pid: str):
    p=get_payment(pid); amt=p["amount"] if p else ""; cur=p["currency"] if p else ""
    return HTMLResponse(f"""<!doctype html><html lang=ar dir=rtl><meta charset=utf-8>
<body style="font-family:sans-serif;background:#0d0d20;color:#fff;text-align:center;padding:40px">
<h2>تأكيد الدفع</h2><p>المبلغ: <b>{amt} {cur}</b></p><p style="color:#94a3b8">رقم العملية: {pid}</p>
<button onclick="pay()" style="padding:12px 24px;font-size:16px;border:0;border-radius:10px;
 background:linear-gradient(135deg,#16a34a,#22c55e);color:#fff;cursor:pointer">✅ تأكيد الدفع وتفعيل الاشتراك</button>
<p id=m></p><script>async function pay(){{const r=await fetch('/api/pay/webhook',{{method:'POST',
headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{payment_id:'{pid}',status:'paid'}})}});
const d=await r.json();document.getElementById('m').textContent=d.activated?'✅ تم تفعيل الاشتراك — عُد للوحة':'حالة: '+JSON.stringify(d);}}</script>
</body></html>""")

# ───── المالك ─────
def chk(pw):
    if pw!=OWNER_PW: raise HTTPException(401,"كلمة مرور المالك خاطئة")
@app.post("/api/owner/login")
def owner_login(r: Login):
    if r.id not in (OWNER_ID,"admin") or r.pw!=OWNER_PW: raise HTTPException(401,"بيانات المالك خاطئة")
    return {"ok":True}
@app.post("/api/owner/users")
def owner_users(r: OwnerAuth): chk(r.pw); return {"users": all_users()}
@app.post("/api/owner/upsert")
def owner_upsert(r: OwnerUpsert): chk(r.pw); put_user(r.blob); return {"ok":True}
@app.post("/api/owner/delete")
def owner_delete(r: OwnerDelete): chk(r.pw); del_user(r.id); return {"ok":True}
@app.post("/api/owner/activate")
def owner_activate(r: OwnerActivate):
    chk(r.pw)
    if not get_user(r.id): raise HTTPException(404,"مشترك غير موجود")
    activate(r.id, int(r.farms))   # تفعيل يدوي بعدد المزارع المختار
    notify_zapier("manual_activation",{"user_id":r.id,"farms":int(r.farms)})
    return {"ok":True}
@app.post("/api/owner/deactivate")
def owner_deactivate(r: OwnerDeactivate):
    chk(r.pw)
    u=get_user(r.id)
    if not u: raise HTTPException(404,"مشترك غير موجود")
    u["subStatus"]="expired"; u["botOn"]=False; put_user(u)
    return {"ok":True}
@app.post("/api/owner/payments")
def owner_payments(r: OwnerAuth): chk(r.pw); return {"payments": all_payments()}
@app.post("/api/owner/settings/get")
def owner_settings_get(r: OwnerAuth):
    chk(r.pw)
    s = {"period_days": period_days(), "currency": setting("currency",CURRENCY),
         "providers": setting("providers","manual"), "zapier_hook": setting("zapier_hook",""),
         "payout_note": setting("payout_note",""), "moyasar_ready": bool(MOYASAR_SECRET)}
    for n in TIERS: s[f"price_{n}"] = tier_price(n)
    return {"settings": s}
@app.post("/api/owner/settings/save")
def owner_settings_save(r: SettingsIn):
    chk(r.pw)
    keys = ["period_days","currency","providers","zapier_hook","payout_note"] + [f"price_{n}" for n in TIERS]
    for k in keys:
        if k in r.settings: set_setting(k, str(r.settings[k]))
    return {"ok":True}

# ───── الصفحات ─────
def _page(name):
    p=os.path.join(HERE,name)
    if not os.path.exists(p): return HTMLResponse(f"<h3>{name} غير موجود</h3>",404)
    return HTMLResponse(open(p,encoding="utf-8").read())
@app.get("/", response_class=HTMLResponse)
def home(): return _page("user_panel.html")
@app.get("/owner", response_class=HTMLResponse)
def owner_page(): return _page("owner_panel.html")
