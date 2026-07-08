import os, tempfile
os.environ.update(DB_PATH=tempfile.mktemp(suffix=".db"), DEBUG="1", JWT_SECRET="test",
                  SUPER_EMAIL="owner@example.com", SUPER_PW="Owner!2026")
from fastapi import FastAPI
from fastapi.testclient import TestClient
import auth
auth.init_db()
app = FastAPI(); app.include_router(auth.router); client = TestClient(app)
H = lambda t: {"Authorization": f"Bearer {t}"}

def reg_login(email, pw="Passw0rd!"):
    tok = client.post("/auth/register", json={"name": "Us", "email": email, "password": pw}).json()["verify_token"]
    client.post("/auth/verify-email", json={"token": tok})
    r = client.post("/auth/login", json={"email": email, "password": pw}).json()
    return r["access"], r["refresh"]

def owner():
    return client.post("/auth/login", json={"email": "owner@example.com", "password": "Owner!2026"}).json()["access"]

def test_register_verify_login():
    a, _ = reg_login("a@example.com")
    assert "user" in client.get("/auth/me", headers=H(a)).json()["roles"]

def test_wrong_password():
    client.post("/auth/register", json={"name": "Bb", "email": "b@example.com", "password": "Passw0rd!"})
    assert client.post("/auth/login", json={"email": "b@example.com", "password": "nope"}).status_code == 401

def test_unverified_blocked():
    client.post("/auth/register", json={"name": "Cc", "email": "c@example.com", "password": "Passw0rd!"})
    assert client.post("/auth/login", json={"email": "c@example.com", "password": "Passw0rd!"}).status_code == 403

def test_lockout_after_5():
    e = "lock@example.com"
    client.post("/auth/register", json={"name": "Ll", "email": e, "password": "Passw0rd!"})
    for _ in range(5): client.post("/auth/login", json={"email": e, "password": "bad"})
    assert client.post("/auth/login", json={"email": e, "password": "bad"}).status_code == 429

def test_user_cannot_list_users():
    a, _ = reg_login("u@example.com")
    assert client.get("/users", headers=H(a)).status_code == 403

def test_manager_no_create_and_no_escalation():
    o = owner()
    client.post("/users", headers=H(o), json={"name": "Mgr", "email": "mgr@example.com", "password": "Passw0rd!", "roles": ["manager"]})
    m = client.post("/auth/login", json={"email": "mgr@example.com", "password": "Passw0rd!"}).json()["access"]
    assert client.post("/users", headers=H(m), json={"name": "x", "email": "x@example.com", "password": "Passw0rd!"}).status_code == 403
    client.post("/users", headers=H(o), json={"name": "Tt", "email": "t@example.com", "password": "Passw0rd!", "roles": ["user"]})
    tid = [u for u in client.get("/users", headers=H(o)).json() if u["email"] == "t@example.com"][0]["id"]
    assert client.patch(f"/users/{tid}", headers=H(m), json={"roles": ["super_admin"]}).status_code == 403

def test_refresh_rotation():
    _, rf = reg_login("r@example.com")
    assert "access" in client.post("/auth/refresh", json={"refresh": rf}).json()

def test_trial_once():
    o = owner()
    client.post("/users", headers=H(o), json={"name": "Tr", "email": "tr@example.com", "password": "Passw0rd!", "roles": ["user"]})
    tid = [u for u in client.get("/users", headers=H(o)).json() if u["email"] == "tr@example.com"][0]["id"]
    assert client.post(f"/users/{tid}/trial", headers=H(o)).status_code == 200
    assert client.post(f"/users/{tid}/trial", headers=H(o)).status_code == 400
