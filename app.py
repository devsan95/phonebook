"""Phone Book application: REST API + minimal web UI, backed by PostgreSQL, with user accounts."""
import os
import re
from functools import wraps

from flask import Flask, g, jsonify, request, render_template_string
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://phonebook:phonebook@localhost:5432/phonebook")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
TOKEN_MAX_AGE = int(os.environ.get("TOKEN_MAX_AGE", 7 * 24 * 3600))

PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__)
signer = URLSafeTimedSerializer(SECRET_KEY, salt="auth-token")
pool = ConnectionPool(
    DATABASE_URL,
    min_size=1,
    max_size=int(os.environ.get("DB_POOL_SIZE", 10)),
    kwargs={"row_factory": dict_row},
    open=True,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS contacts (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    phone      TEXT NOT NULL,
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_contacts_user_name ON contacts(user_id, name);
"""


def init_db():
    # Every gunicorn worker runs this; the advisory lock stops them racing on CREATE TABLE.
    with pool.connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(727274)")
        conn.execute(SCHEMA)


# ---------- helpers ----------
def db():
    if "conn" not in g:
        g._conn_ctx = pool.connection()
        g.conn = g._conn_ctx.__enter__()
    return g.conn


@app.teardown_appcontext
def release_db(exc):
    ctx = g.pop("_conn_ctx", None)
    if ctx is not None:
        g.pop("conn", None)
        ctx.__exit__(type(exc) if exc else None, exc, None)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return {"error": "authentication required"}, 401
        try:
            payload = signer.loads(header[7:], max_age=TOKEN_MAX_AGE)
        except SignatureExpired:
            return {"error": "token expired"}, 401
        except BadSignature:
            return {"error": "invalid token"}, 401
        g.user_id = payload["uid"]
        return view(*args, **kwargs)

    return wrapper


def validate_contact(data, partial=False):
    errors = {}
    if not partial or "name" in data:
        if not (data.get("name") or "").strip():
            errors["name"] = "required"
    if not partial or "phone" in data:
        if not PHONE_RE.match((data.get("phone") or "").strip()):
            errors["phone"] = "invalid phone number"
    email = (data.get("email") or "").strip()
    if email and not EMAIL_RE.match(email):
        errors["email"] = "invalid email"
    return errors


def public_contact(row):
    return {"id": row["id"], "name": row["name"], "phone": row["phone"], "email": row["email"]}


# ---------- health ----------
@app.get("/health")
def health():
    db().execute("SELECT 1")
    return {"status": "ok"}


# ---------- auth ----------
def read_credentials():
    data = request.get_json(silent=True) or {}
    return (data.get("email") or "").strip().lower(), data.get("password") or ""


@app.post("/api/auth/register")
def register():
    email, password = read_credentials()
    errors = {}
    if not EMAIL_RE.match(email):
        errors["email"] = "invalid email"
    if len(password) < 8:
        errors["password"] = "must be at least 8 characters"
    if errors:
        return {"errors": errors}, 400
    try:
        row = db().execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id, email",
            (email, generate_password_hash(password)),
        ).fetchone()
    except UniqueViolation:
        db().rollback()
        return {"errors": {"email": "already registered"}}, 409
    return {"id": row["id"], "email": row["email"], "token": signer.dumps({"uid": row["id"]})}, 201


@app.post("/api/auth/login")
def login():
    email, password = read_credentials()
    row = db().execute("SELECT id, email, password_hash FROM users WHERE email = %s", (email,)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return {"error": "invalid email or password"}, 401
    return {"id": row["id"], "email": row["email"], "token": signer.dumps({"uid": row["id"]})}


@app.get("/api/auth/me")
@login_required
def me():
    row = db().execute("SELECT id, email FROM users WHERE id = %s", (g.user_id,)).fetchone()
    if row is None:
        return {"error": "user not found"}, 401
    return row


# ---------- contacts (always scoped to the logged-in user) ----------
def fetch_contact(cid):
    return db().execute(
        "SELECT * FROM contacts WHERE id = %s AND user_id = %s", (cid, g.user_id)
    ).fetchone()


@app.get("/api/contacts")
@login_required
def list_contacts():
    q = request.args.get("q", "").strip()
    if q:
        rows = db().execute(
            "SELECT * FROM contacts WHERE user_id = %s AND (name ILIKE %s OR phone ILIKE %s) ORDER BY name",
            (g.user_id, f"%{q}%", f"%{q}%"),
        ).fetchall()
    else:
        rows = db().execute("SELECT * FROM contacts WHERE user_id = %s ORDER BY name", (g.user_id,)).fetchall()
    return jsonify([public_contact(r) for r in rows])


@app.get("/api/contacts/<int:cid>")
@login_required
def get_contact(cid):
    row = fetch_contact(cid)
    if row is None:
        return {"error": "not found"}, 404
    return public_contact(row)


@app.post("/api/contacts")
@login_required
def create_contact():
    data = request.get_json(silent=True) or {}
    errors = validate_contact(data)
    if errors:
        return {"errors": errors}, 400
    row = db().execute(
        "INSERT INTO contacts (user_id, name, phone, email) VALUES (%s, %s, %s, %s) RETURNING *",
        (g.user_id, data["name"].strip(), data["phone"].strip(), (data.get("email") or "").strip() or None),
    ).fetchone()
    return public_contact(row), 201


@app.put("/api/contacts/<int:cid>")
@login_required
def update_contact(cid):
    data = request.get_json(silent=True) or {}
    errors = validate_contact(data, partial=True)
    if errors:
        return {"errors": errors}, 400
    row = fetch_contact(cid)
    if row is None:
        return {"error": "not found"}, 404
    merged = {**row, **{k: v for k, v in data.items() if k in ("name", "phone", "email")}}
    row = db().execute(
        "UPDATE contacts SET name = %s, phone = %s, email = %s WHERE id = %s AND user_id = %s RETURNING *",
        (merged["name"].strip(), merged["phone"].strip(), (merged["email"] or "").strip() or None, cid, g.user_id),
    ).fetchone()
    return public_contact(row)


@app.delete("/api/contacts/<int:cid>")
@login_required
def delete_contact(cid):
    cur = db().execute("DELETE FROM contacts WHERE id = %s AND user_id = %s", (cid, g.user_id))
    if cur.rowcount == 0:
        return {"error": "not found"}, 404
    return "", 204


# ---------- Web UI ----------
PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phone Book</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#222}
 h1{margin-bottom:.5rem} form{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}
 input{padding:.5rem;border:1px solid #bbb;border-radius:6px;flex:1;min-width:140px}
 button{padding:.5rem 1rem;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}
 button.alt{background:#64748b} button.del{background:#dc2626;padding:.3rem .7rem}
 table{width:100%;border-collapse:collapse} td,th{padding:.5rem;border-bottom:1px solid #eee;text-align:left}
 .err{color:#dc2626} .bar{display:flex;justify-content:space-between;align-items:center}
 .hidden{display:none}
</style></head><body>
<h1>📒 Phone Book</h1>

<section id="auth">
  <form onsubmit="auth(event)">
    <input id="aemail" type="email" placeholder="Email" required autocomplete="username">
    <input id="apass" type="password" placeholder="Password (min 8 chars)" required minlength="8" autocomplete="current-password">
    <button data-mode="login">Log in</button>
    <button data-mode="register" class="alt">Register</button>
  </form>
</section>

<section id="book" class="hidden">
  <div class="bar"><span id="who"></span><button class="alt" onclick="logout()">Log out</button></div>
  <input id="q" placeholder="Search by name or number…" oninput="load()" style="width:100%;margin-top:1rem">
  <form onsubmit="add(event)">
    <input id="name" placeholder="Name" required>
    <input id="phone" placeholder="Phone" required>
    <input id="email" placeholder="Email (optional)">
    <button>Add</button>
  </form>
  <table><thead><tr><th>Name</th><th>Phone</th><th>Email</th><th></th></tr></thead><tbody id="rows"></tbody></table>
</section>
<p id="err" class="err"></p>

<script>
const $=id=>document.getElementById(id);
const esc=s=>(s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let token=null; try{token=localStorage.getItem('pb_token')}catch(e){}
function setToken(t){token=t;try{t?localStorage.setItem('pb_token',t):localStorage.removeItem('pb_token')}catch(e){}}
async function api(path,opts={}){
  const r=await fetch(path,{...opts,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})}});
  if(r.status===401&&token){logout();throw new Error('Session expired, please log in again');}
  const body=r.status===204?null:await r.json();
  if(!r.ok) throw new Error(body.error||Object.entries(body.errors||{}).map(([k,v])=>k+': '+v).join(', '));
  return body;
}
function show(err){$('err').textContent=err?err.message||err:'';}
async function auth(e){
  e.preventDefault();
  const mode=e.submitter.dataset.mode;
  try{
    const res=await api('/api/auth/'+mode,{method:'POST',body:JSON.stringify({email:$('aemail').value,password:$('apass').value})});
    setToken(res.token); show(); start();
  }catch(err){show(err)}
}
async function start(){
  if(!token){$('auth').classList.remove('hidden');$('book').classList.add('hidden');return;}
  try{ const me=await api('/api/auth/me'); $('who').textContent='Signed in as '+me.email;
       $('auth').classList.add('hidden');$('book').classList.remove('hidden'); load(); }catch(err){show(err)}
}
function logout(){setToken(null);$('rows').innerHTML='';start();}
async function load(){
  try{
    const data=await api('/api/contacts?q='+encodeURIComponent($('q').value));
    $('rows').innerHTML=data.map(c=>`<tr><td>${esc(c.name)}</td><td>${esc(c.phone)}</td><td>${esc(c.email)}</td>
      <td><button class="del" onclick="del(${c.id})">Delete</button></td></tr>`).join('');
  }catch(err){show(err)}
}
async function add(e){
  e.preventDefault();
  try{ await api('/api/contacts',{method:'POST',body:JSON.stringify({name:$('name').value,phone:$('phone').value,email:$('email').value})});
       show(); e.target.reset(); load(); }catch(err){show(err)}
}
async function del(id){try{await api('/api/contacts/'+id,{method:'DELETE'});load();}catch(err){show(err)}}
start();
</script></body></html>"""


@app.get("/")
def index():
    return render_template_string(PAGE)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
