import os, tempfile
os.environ.update(DB_PATH=tempfile.mktemp(suffix=".db"), DEBUG="1", JWT_SECRET="test",
                  SUPER_EMAIL="owner@example.com", SUPER_PW="Owner!2026", SERVICE_TOKEN="svc")
from fastapi import FastAPI
from fastapi.testclient import TestClient
import auth, reports
auth.init_db(); reports.init_reports()
app = FastAPI(); app.include_router(auth.router); app.include_router(reports.router)
client = TestClient(app)
H = lambda t: {"Authorization": f"Bearer {t}"}

def owner():
    return client.post("/auth/login", json={"email": "owner@example.com", "password": "Owner!2026"}).json()["access"]

def make_sub(o, email):
    client.post("/users", headers=H(o), json={"name": "Sub", "email": email, "password": "Passw0rd!", "roles": ["user"]})
    return [u for u in client.get("/users", headers=H(o)).json() if u["email"] == email][0]["id"]

def test_report_requires_service_token():
    assert client.post("/reports", json={"user_id": 1, "farm": "f", "duration": 10}).status_code == 401

def test_report_saved_and_summarized():
    o = owner(); sid = make_sub(o, "s1@example.com")
    assert client.post("/reports", headers={"X-Service-Token": "svc"},
                       json={"user_id": sid, "farm": "m1", "duration": 300, "tasks": "بناء"}).status_code == 200
    client.post("/reports", headers={"X-Service-Token": "svc"}, json={"user_id": sid, "farm": "m2", "duration": 420})
    me = [s for s in client.get("/owner/subscribers", headers=H(o)).json() if s["email"] == "s1@example.com"][0]
    assert me["runs"] == 2 and me["total_seconds"] == 720

def test_owner_only_full_view():
    o = owner()
    client.post("/users", headers=H(o), json={"name": "Mgr", "email": "mgr@example.com", "password": "Passw0rd!", "roles": ["manager"]})
    m = client.post("/auth/login", json={"email": "mgr@example.com", "password": "Passw0rd!"}).json()["access"]
    assert client.get("/owner/subscribers", headers=H(m)).status_code == 403
    assert client.get("/owner/subscribers", headers=H(o)).status_code == 200

def test_csv_export():
    r = client.get("/owner/export.csv", headers=H(owner()))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("id,name,email")
