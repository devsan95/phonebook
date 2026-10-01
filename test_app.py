"""Integration tests. Needs a running Postgres reachable via DATABASE_URL (e.g. `docker compose up -d db`)."""
import os
import uuid

os.environ.setdefault("SECRET_KEY", "test-secret")

from app import app  # noqa: E402


def register(c, email=None, password="password123"):
    email = email or f"user-{uuid.uuid4().hex[:8]}@example.com"
    r = c.post("/api/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.json
    return email, {"Authorization": f"Bearer {r.json['token']}"}


def test_auth():
    c = app.test_client()
    assert c.get("/health").json == {"status": "ok"}

    email, auth = register(c)
    assert c.post("/api/auth/register", json={"email": email, "password": "password123"}).status_code == 409
    assert c.post("/api/auth/register", json={"email": "bad", "password": "short"}).status_code == 400
    assert c.post("/api/auth/login", json={"email": email, "password": "wrong-password"}).status_code == 401
    r = c.post("/api/auth/login", json={"email": email.upper(), "password": "password123"})
    assert r.status_code == 200 and r.json["token"]
    assert c.get("/api/auth/me", headers=auth).json["email"] == email

    assert c.get("/api/contacts").status_code == 401
    assert c.get("/api/contacts", headers={"Authorization": "Bearer forged"}).status_code == 401


def test_crud_and_isolation():
    c = app.test_client()
    _, alice = register(c)
    _, bob = register(c)

    r = c.post("/api/contacts", headers=alice, json={"name": "Carol", "phone": "+1 555-1234", "email": "c@x.com"})
    assert r.status_code == 201
    cid = r.json["id"]

    assert c.post("/api/contacts", headers=alice, json={"name": "", "phone": "abc"}).status_code == 400
    assert c.get("/api/contacts?q=car", headers=alice).json[0]["name"] == "Carol"
    upd = c.put(f"/api/contacts/{cid}", headers=alice, json={"phone": "+44 20 7946 0000"})
    assert upd.json["phone"] == "+44 20 7946 0000"

    # Bob cannot see or modify Alice's contacts
    assert c.get("/api/contacts", headers=bob).json == []
    assert c.get(f"/api/contacts/{cid}", headers=bob).status_code == 404
    assert c.put(f"/api/contacts/{cid}", headers=bob, json={"name": "X"}).status_code == 404
    assert c.delete(f"/api/contacts/{cid}", headers=bob).status_code == 404

    assert c.delete(f"/api/contacts/{cid}", headers=alice).status_code == 204
    assert c.get(f"/api/contacts/{cid}", headers=alice).status_code == 404
    assert c.get("/").status_code == 200


if __name__ == "__main__":
    test_auth()
    test_crud_and_isolation()
    print("all tests passed")
