import hashlib
import os
import secrets
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Form, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Warmi Bypass Tools Auth")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
DB_PATH = Path(os.getenv("DATABASE_PATH", "users.db"))
ADMIN_TOKENS: set[str] = set()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)")
    return conn

def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def admin_ok(token: str | None) -> bool:
    return bool(token and token in ADMIN_TOKENS)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/user/auth/")
def authenticate(username: str = Form(default=""), password: str = Form(default=""), mac_adress: str = Form(default="")):
    admin_user, admin_password = os.getenv("APP_USERNAME", ""), os.getenv("APP_PASSWORD", "")
    valid = bool(admin_user and admin_password and username == admin_user and secrets.compare_digest(password, admin_password))
    with db() as conn:
        row = conn.execute("SELECT active, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    valid = valid or bool(row and row["active"] and secrets.compare_digest(digest(password), row["password_hash"]))
    return {"active": valid, "auth": valid}

@app.post("/admin/login")
def admin_login(username: str = Form(default=""), password: str = Form(default="")):
    expected = os.getenv("APP_PASSWORD", "")
    if username != os.getenv("APP_USERNAME", "") or not expected or not secrets.compare_digest(password, expected):
        raise HTTPException(401, "Credenciales inválidas")
    token = secrets.token_urlsafe(32)
    ADMIN_TOKENS.add(token)
    return {"token": token}

@app.get("/admin/users")
def list_users(x_admin_token: str | None = Header(default=None)):
    if not admin_ok(x_admin_token): raise HTTPException(401, "No autorizado")
    with db() as conn: return [dict(row) for row in conn.execute("SELECT username, active FROM users ORDER BY username")]

@app.post("/admin/users")
def create_user(username: str = Form(default=""), password: str = Form(default=""), x_admin_token: str | None = Header(default=None)):
    if not admin_ok(x_admin_token): raise HTTPException(401, "No autorizado")
    if not username.strip() or not password: raise HTTPException(400, "Usuario y contraseña son obligatorios")
    try:
        with db() as conn: conn.execute("INSERT INTO users(username, password_hash, active) VALUES (?, ?, 1)", (username.strip(), digest(password)))
    except sqlite3.IntegrityError: raise HTTPException(409, "Ese usuario ya existe")
    return {"ok": True}

@app.patch("/admin/users/{username}")
def toggle_user(username: str, x_admin_token: str | None = Header(default=None)):
    if not admin_ok(x_admin_token): raise HTTPException(401, "No autorizado")
    with db() as conn:
        row = conn.execute("SELECT active FROM users WHERE username = ?", (username,)).fetchone()
        if not row: raise HTTPException(404, "Usuario no encontrado")
        conn.execute("UPDATE users SET active = ? WHERE username = ?", (0 if row["active"] else 1, username))
    return {"ok": True}

@app.delete("/admin/users/{username}")
def delete_user(username: str, x_admin_token: str | None = Header(default=None)):
    if not admin_ok(x_admin_token): raise HTTPException(401, "No autorizado")
    with db() as conn: conn.execute("DELETE FROM users WHERE username = ?", (username,))
    return {"ok": True}
