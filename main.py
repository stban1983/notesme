import os
import re
import uuid
import html as html_module
import hashlib
import secrets
import sqlite3
import base64
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from typing import Optional, List
import jwt
from cryptography.fernet import Fernet

# ─── Argon2 password hashing ───
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _ph = PasswordHasher()
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# ─── Config ───
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "notes.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "") or secrets.token_hex(32)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
DEFAULT_USERNAME = os.environ.get("USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("PASSWORD", "admin")
TOKEN_EXPIRY_HOURS = int(os.environ.get("TOKEN_EXPIRY_HOURS", "72"))
TRASH_RETENTION_DAYS = int(os.environ.get("TRASH_RETENTION_DAYS", "30"))
VERSION_INTERVAL_MIN = int(os.environ.get("VERSION_INTERVAL_MIN", "5"))
MAX_VERSIONS_PER_NOTE = int(os.environ.get("MAX_VERSIONS_PER_NOTE", "50"))
MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE", str(10 * 1024 * 1024)))  # 10 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── Rate Limiting ───
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SEC = int(os.environ.get("LOGIN_WINDOW_SEC", "900"))
_login_attempts: dict[str, list[float]] = defaultdict(list)

def check_rate_limit(ip: str):
    now = time.time()
    cutoff = now - LOGIN_WINDOW_SEC
    _login_attempts[ip] = [t for t in _login_attempts[ip] if t > cutoff]
    if len(_login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS:
        wait = int(_login_attempts[ip][0] + LOGIN_WINDOW_SEC - now) + 1
        raise HTTPException(429, f"Trop de tentatives. Réessayez dans {wait}s")

def record_failed_login(ip: str):
    _login_attempts[ip].append(time.time())

def clear_login_attempts(ip: str):
    _login_attempts.pop(ip, None)

# ─── Encryption ───
_fernet = None

def get_fernet():
    global _fernet
    if _fernet:
        return _fernet
    if ENCRYPTION_KEY:
        key = ENCRYPTION_KEY.encode()
        if len(key) != 44:
            key = base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY.encode()).digest())
        _fernet = Fernet(key)
    return _fernet

def encrypt_content(text: str) -> str:
    f = get_fernet()
    if not f or not text:
        return text
    return "ENC:" + f.encrypt(text.encode()).decode()

def decrypt_content(text: str) -> str:
    f = get_fernet()
    if not f or not text or not text.startswith("ENC:"):
        return text
    try:
        return f.decrypt(text[4:].encode()).decode()
    except Exception:
        return text

def strip_html(html_text: str) -> str:
    if not html_text:
        return ""
    text = re.sub(r'<br\s*/?>|</p>|</div>|</li>|</h[1-6]>', '\n', html_text)
    text = re.sub(r'<[^>]+>', '', text)
    for ent, ch in [('&nbsp;',' '),('&amp;','&'),('&lt;','<'),('&gt;','>'),('&quot;','"'),('&#39;',"'")]:
        text = text.replace(ent, ch)
    return re.sub(r'\n{3,}', '\n\n', text).strip()

# ─── Database ───
app = FastAPI(title="Notes", docs_url=None, redoc_url=None)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id TEXT,
            user_id INTEGER NOT NULL,
            position INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT 'Sans titre',
            content TEXT DEFAULT '',
            folder_id TEXT,
            user_id INTEGER NOT NULL,
            position INTEGER DEFAULT 0,
            pinned INTEGER DEFAULT 0,
            deleted_at TEXT DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS images (
            id TEXT PRIMARY KEY,
            note_id TEXT,
            filename TEXT NOT NULL,
            original_name TEXT,
            mime_type TEXT,
            size INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS note_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_id TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
        );
    """)
    for migration in [
        "ALTER TABLE notes ADD COLUMN deleted_at TEXT DEFAULT NULL",
        "ALTER TABLE folders ADD COLUMN user_id INTEGER DEFAULT 1",
        "ALTER TABLE notes ADD COLUMN user_id INTEGER DEFAULT 1",
    ]:
        try:
            db.execute(migration)
        except Exception:
            pass
    # Drop legacy FTS table if it exists (content now searched in-memory after decryption)
    try:
        db.execute("DROP TABLE IF EXISTS notes_fts")
    except Exception:
        pass
    existing = db.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_USERNAME,)).fetchone()
    if not existing:
        pw_hash = hash_pw(DEFAULT_PASSWORD)
        # salt column kept for legacy compat, empty for Argon2 (salt is embedded in hash)
        db.execute("INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, 1)",
                   (DEFAULT_USERNAME, pw_hash, ""))
    db.commit()
    purge_trash(db)
    db.close()

def purge_trash(db):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=TRASH_RETENTION_DAYS)).isoformat()
    old = db.execute("SELECT id FROM notes WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,)).fetchall()
    for row in old:
        imgs = db.execute("SELECT filename FROM images WHERE note_id = ?", (row["id"],)).fetchall()
        for img in imgs:
            fp = os.path.join(UPLOAD_DIR, img["filename"])
            if os.path.exists(fp):
                os.remove(fp)
    db.execute("DELETE FROM notes WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,))
    db.commit()

def maybe_save_version(db, note_id: str, old_title: str, old_content_encrypted: str):
    last = db.execute(
        "SELECT created_at FROM note_versions WHERE note_id = ? ORDER BY created_at DESC LIMIT 1",
        (note_id,)
    ).fetchone()
    if last:
        try:
            raw = last["created_at"]
            last_time = datetime.fromisoformat(raw.replace("Z", "+00:00") if "Z" in raw else raw)
            if last_time.tzinfo is None:
                last_time = last_time.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - last_time).total_seconds() < VERSION_INTERVAL_MIN * 60:
                return
        except Exception:
            pass
    now_str = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO note_versions (note_id, title, content, created_at) VALUES (?, ?, ?, ?)",
        (note_id, old_title, old_content_encrypted, now_str)
    )
    db.execute("""
        DELETE FROM note_versions WHERE note_id = ? AND id NOT IN (
            SELECT id FROM note_versions WHERE note_id = ? ORDER BY created_at DESC LIMIT ?
        )
    """, (note_id, note_id, MAX_VERSIONS_PER_NOTE))
    db.commit()

# ─── Password Hashing (Argon2 with SHA-256 legacy fallback) ───
def hash_pw(password: str, salt: str = None) -> str:
    """Hash password with Argon2. salt param is ignored (Argon2 manages its own salt)."""
    if ARGON2_AVAILABLE:
        return _ph.hash(password)
    # Fallback to SHA-256 if argon2 not installed (should not happen in prod)
    if salt is None:
        salt = secrets.token_hex(16)
    return hashlib.sha256((password + salt).encode()).hexdigest()

def verify_pw(password: str, stored_hash: str, salt: str = "") -> bool:
    """Verify password against stored hash. Supports both Argon2 and legacy SHA-256."""
    if stored_hash.startswith("$argon2"):
        if not ARGON2_AVAILABLE:
            return False
        try:
            return _ph.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    else:
        # Legacy SHA-256 format
        return hashlib.sha256((password + salt).encode()).hexdigest() == stored_hash

def needs_rehash(stored_hash: str) -> bool:
    """Check if a legacy SHA-256 hash should be upgraded to Argon2."""
    if not ARGON2_AVAILABLE:
        return False
    return not stored_hash.startswith("$argon2")

# ─── In-memory search (replaces FTS — no plaintext stored on disk) ───
def search_notes_in_memory(db, user_id: int, query: str) -> list:
    """Search notes by decrypting content in memory. Secure: no plaintext touches the DB."""
    rows = db.execute(
        "SELECT id, title, content, folder_id, pinned, created_at, updated_at, deleted_at "
        "FROM notes WHERE user_id = ? AND deleted_at IS NULL",
        (user_id,)
    ).fetchall()
    query_lower = query.lower()
    results = []
    for r in rows:
        title = r["title"] or ""
        plain_content = decrypt_content(r["content"] or "")
        plain_text = strip_html(plain_content)
        if query_lower in title.lower() or query_lower in plain_text.lower():
            d = dict(r)
            d["preview"] = plain_text[:200]
            del d["content"]
            results.append(d)
    # Sort: pinned first, then by updated_at descending
    results.sort(key=lambda x: (-int(x.get("pinned", 0)), x.get("updated_at", "")), reverse=False)
    results.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    results.sort(key=lambda x: -int(x.get("pinned", 0)))
    return results

init_db()

# ─── Auth ───
class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False

def create_token(user_id: int, username: str, is_admin: bool) -> str:
    return jwt.encode({
        "user_id": user_id, "username": username, "is_admin": is_admin,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
    }, SECRET_KEY, algorithm="HS256")

def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # Fallback: token in query param (for export/download links)
        t = request.query_params.get("token", "")
        if t:
            auth = "Bearer " + t
        else:
            raise HTTPException(401, "Non authentifié")
    try:
        return jwt.decode(auth[7:], SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Token invalide")

def require_admin(user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(403, "Droits administrateur requis")
    return user

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
    if not user or not verify_pw(req.password, user["password_hash"], user["salt"]):
        db.close()
        record_failed_login(ip)
        raise HTTPException(401, "Identifiants invalides")
    # Transparent rehash: upgrade SHA-256 → Argon2 on successful login
    if needs_rehash(user["password_hash"]):
        new_hash = hash_pw(req.password)
        db.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                   (new_hash, "", user["id"]))
        db.commit()
    db.close()
    clear_login_attempts(ip)
    return {
        "token": create_token(user["id"], user["username"], bool(user["is_admin"])),
        "username": user["username"],
        "is_admin": bool(user["is_admin"])
    }

@app.post("/api/auth/change-password")
def change_password(req: ChangePasswordRequest, user=Depends(get_current_user)):
    db = get_db()
    db_user = db.execute("SELECT * FROM users WHERE id = ?", (user["user_id"],)).fetchone()
    if not verify_pw(req.current_password, db_user["password_hash"], db_user["salt"]):
        db.close()
        raise HTTPException(400, "Mot de passe actuel incorrect")
    new_hash = hash_pw(req.new_password)
    db.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
               (new_hash, "", user["user_id"]))
    db.commit()
    db.close()
    return {"message": "Mot de passe modifié"}

@app.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    return {"username": user["username"], "is_admin": user.get("is_admin", False), "user_id": user["user_id"]}

# ─── User Management (admin) ───
@app.get("/api/users")
def list_users(user=Depends(require_admin)):
    db = get_db()
    users = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY id").fetchall()
    db.close()
    return [dict(u) for u in users]

@app.post("/api/users")
def create_user(req: CreateUserRequest, user=Depends(require_admin)):
    db = get_db()
    if db.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone():
        db.close()
        raise HTTPException(400, "Utilisateur déjà existant")
    pw_hash = hash_pw(req.password)
    db.execute("INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)",
               (req.username, pw_hash, "", int(req.is_admin)))
    db.commit()
    db.close()
    return {"message": "Utilisateur créé"}

@app.delete("/api/users/{uid}")
def delete_user(uid: int, user=Depends(require_admin)):
    if uid == user["user_id"]:
        raise HTTPException(400, "Impossible de supprimer votre propre compte")
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    db.close()
    return {"deleted": True}

# ─── Folders ───
class FolderCreate(BaseModel):
    name: str
    parent_id: Optional[str] = None

class FolderUpdate(BaseModel):
    name: Optional[str] = None
    parent_id: Optional[str] = "__unchanged__"

@app.get("/api/folders")
def list_folders(user=Depends(get_current_user)):
    db = get_db()
    folders = db.execute("SELECT * FROM folders WHERE user_id = ? ORDER BY position, name",
                         (user["user_id"],)).fetchall()
    db.close()
    return [dict(f) for f in folders]

@app.post("/api/folders")
def create_folder(req: FolderCreate, user=Depends(get_current_user)):
    db = get_db()
    fid = str(uuid.uuid4())
    if req.parent_id:
        parent = db.execute("SELECT id FROM folders WHERE id = ? AND user_id = ?",
                            (req.parent_id, user["user_id"])).fetchone()
        if not parent:
            db.close()
            raise HTTPException(404, "Dossier parent introuvable")
    db.execute("INSERT INTO folders (id, name, parent_id, user_id) VALUES (?, ?, ?, ?)",
               (fid, req.name, req.parent_id, user["user_id"]))
    db.commit()
    folder = db.execute("SELECT * FROM folders WHERE id = ?", (fid,)).fetchone()
    db.close()
    return dict(folder)

@app.put("/api/folders/{folder_id}")
def update_folder(folder_id: str, req: FolderUpdate, user=Depends(get_current_user)):
    db = get_db()
    folder = db.execute("SELECT * FROM folders WHERE id = ? AND user_id = ?",
                        (folder_id, user["user_id"])).fetchone()
    if not folder:
        db.close()
        raise HTTPException(404, "Dossier introuvable")
    if req.name is not None:
        db.execute("UPDATE folders SET name = ? WHERE id = ?", (req.name, folder_id))
    if req.parent_id != "__unchanged__":
        db.execute("UPDATE folders SET parent_id = ? WHERE id = ?", (req.parent_id, folder_id))
    db.commit()
    folder = db.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()
    db.close()
    return dict(folder)

@app.delete("/api/folders/{folder_id}")
def delete_folder(folder_id: str, user=Depends(get_current_user)):
    db = get_db()
    db.execute("DELETE FROM folders WHERE id = ? AND user_id = ?", (folder_id, user["user_id"]))
    db.commit()
    db.close()
    return {"deleted": True}

# ─── Notes ───
class NoteCreate(BaseModel):
    title: Optional[str] = "Sans titre"
    content: Optional[str] = ""
    folder_id: Optional[str] = None

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    folder_id: Optional[str] = "__unchanged__"
    pinned: Optional[bool] = None

@app.get("/api/notes")
def list_notes(folder_id: Optional[str] = None, search: Optional[str] = None,
               trash: bool = False, user=Depends(get_current_user)):
    db = get_db()
    uid = user["user_id"]
    # ─── Search: decrypt in memory, never store plaintext on disk ───
    if search:
        results = search_notes_in_memory(db, uid, search)
        db.close()
        return results

    # FIX: fetch full content so we can decrypt BEFORE truncating for preview
    if trash:
        rows = db.execute(
            "SELECT id, title, folder_id, pinned, created_at, updated_at, deleted_at, content FROM notes WHERE user_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC",
            (uid,)).fetchall()
    elif folder_id == "__none__":
        rows = db.execute(
            "SELECT id, title, folder_id, pinned, created_at, updated_at, deleted_at, content FROM notes WHERE folder_id IS NULL AND user_id = ? AND deleted_at IS NULL ORDER BY pinned DESC, updated_at DESC",
            (uid,)).fetchall()
    elif folder_id:
        rows = db.execute(
            "SELECT id, title, folder_id, pinned, created_at, updated_at, deleted_at, content FROM notes WHERE folder_id = ? AND user_id = ? AND deleted_at IS NULL ORDER BY pinned DESC, updated_at DESC",
            (folder_id, uid)).fetchall()
    else:
        rows = db.execute(
            "SELECT id, title, folder_id, pinned, created_at, updated_at, deleted_at, content FROM notes WHERE user_id = ? AND deleted_at IS NULL ORDER BY pinned DESC, updated_at DESC",
            (uid,)).fetchall()
    db.close()
    results = []
    for r in rows:
        d = dict(r)
        # Decrypt FULL content first, THEN strip HTML and truncate
        full = decrypt_content(d.get("content") or "")
        d["preview"] = strip_html(full)[:200]
        del d["content"]
        results.append(d)
    return results

@app.post("/api/notes")
def create_note(req: NoteCreate, user=Depends(get_current_user)):
    db = get_db()
    nid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    enc_content = encrypt_content(req.content or "")
    db.execute("INSERT INTO notes (id, title, content, folder_id, user_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
               (nid, req.title, enc_content, req.folder_id, user["user_id"], now, now))
    db.commit()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (nid,)).fetchone()
    db.close()
    d = dict(note)
    d["content"] = decrypt_content(d["content"])
    return d

@app.get("/api/notes/{note_id}")
def get_note(note_id: str, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    db.close()
    if not note:
        raise HTTPException(404, "Note introuvable")
    d = dict(note)
    d["content"] = decrypt_content(d["content"])
    return d

@app.put("/api/notes/{note_id}")
def update_note(note_id: str, req: NoteUpdate, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable")
    # Save version before modifying content
    if req.content is not None:
        maybe_save_version(db, note_id, note["title"], note["content"])
    now = datetime.now(timezone.utc).isoformat()
    if req.title is not None:
        db.execute("UPDATE notes SET title=?, updated_at=? WHERE id=?", (req.title, now, note_id))
    if req.content is not None:
        enc = encrypt_content(req.content)
        db.execute("UPDATE notes SET content=?, updated_at=? WHERE id=?", (enc, now, note_id))
    if req.folder_id != "__unchanged__":
        db.execute("UPDATE notes SET folder_id=?, updated_at=? WHERE id=?", (req.folder_id, now, note_id))
    if req.pinned is not None:
        db.execute("UPDATE notes SET pinned=?, updated_at=? WHERE id=?", (int(req.pinned), now, note_id))
    db.commit()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    db.close()
    d = dict(note)
    d["content"] = decrypt_content(d["content"])
    return d

@app.delete("/api/notes/{note_id}")
def delete_note(note_id: str, permanent: bool = False, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable")
    if permanent or note["deleted_at"]:
        imgs = db.execute("SELECT filename FROM images WHERE note_id = ?", (note_id,)).fetchall()
        for img in imgs:
            fp = os.path.join(UPLOAD_DIR, img["filename"])
            if os.path.exists(fp):
                os.remove(fp)
        db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    else:
        now = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE notes SET deleted_at=?, folder_id=NULL WHERE id=?", (now, note_id))
    db.commit()
    db.close()
    return {"deleted": True}

@app.post("/api/notes/{note_id}/restore")
def restore_note(note_id: str, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable dans la corbeille")
    db.execute("UPDATE notes SET deleted_at = NULL WHERE id = ?", (note_id,))
    db.commit()
    db.close()
    return {"restored": True}

@app.delete("/api/trash")
def empty_trash(user=Depends(get_current_user)):
    db = get_db()
    trashed = db.execute("SELECT id FROM notes WHERE user_id = ? AND deleted_at IS NOT NULL",
                         (user["user_id"],)).fetchall()
    for row in trashed:
        imgs = db.execute("SELECT filename FROM images WHERE note_id = ?", (row["id"],)).fetchall()
        for img in imgs:
            fp = os.path.join(UPLOAD_DIR, img["filename"])
            if os.path.exists(fp):
                os.remove(fp)
    db.execute("DELETE FROM notes WHERE user_id = ? AND deleted_at IS NOT NULL", (user["user_id"],))
    db.commit()
    db.close()
    return {"emptied": True}

# ─── Export ───
@app.get("/api/notes/{note_id}/export")
def export_note(note_id: str, format: str = "txt", user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    db.close()
    if not note:
        raise HTTPException(404, "Note introuvable")
    title = note["title"] or "Sans titre"
    content = decrypt_content(note["content"])
    safe_title = re.sub(r'[^\w\s-]', '', title).strip().replace(' ', '_')[:50] or "note"
    if format == "html":
        # Escape title to prevent XSS in exported HTML
        escaped_title = html_module.escape(title)
        body = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>{escaped_title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:800px;margin:40px auto;padding:0 20px;line-height:1.7;color:#222}}
h1{{border-bottom:2px solid #6c5ce7;padding-bottom:8px}}img{{max-width:100%;border-radius:8px}}</style>
</head><body><h1>{escaped_title}</h1>{content}</body></html>"""
        return Response(content=body, media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{safe_title}.html"'})
    else:
        plain = f"{title}\n{'='*len(title)}\n\n{strip_html(content)}"
        return Response(content=plain, media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{safe_title}.txt"'})

# ─── Versions ───
@app.get("/api/notes/{note_id}/versions")
def list_versions(note_id: str, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT id FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable")
    rows = db.execute(
        "SELECT id, title, created_at FROM note_versions WHERE note_id = ? ORDER BY created_at DESC",
        (note_id,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.get("/api/notes/{note_id}/versions/{version_id}")
def get_version(note_id: str, version_id: int, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT id FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable")
    version = db.execute("SELECT * FROM note_versions WHERE id = ? AND note_id = ?",
                         (version_id, note_id)).fetchone()
    db.close()
    if not version:
        raise HTTPException(404, "Version introuvable")
    d = dict(version)
    d["content"] = decrypt_content(d["content"])
    return d

@app.post("/api/notes/{note_id}/versions/{version_id}/restore")
def restore_version(note_id: str, version_id: int, user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable")
    version = db.execute("SELECT * FROM note_versions WHERE id = ? AND note_id = ?",
                         (version_id, note_id)).fetchone()
    if not version:
        db.close()
        raise HTTPException(404, "Version introuvable")
    # Save current state before restoring
    maybe_save_version(db, note_id, note["title"], note["content"])
    now = datetime.now(timezone.utc).isoformat()
    db.execute("UPDATE notes SET title=?, content=?, updated_at=? WHERE id=?",
               (version["title"], version["content"], now, note_id))
    db.commit()
    restored = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    db.close()
    d = dict(restored)
    d["content"] = decrypt_content(d["content"])
    return d

# ─── Images ───
# Allowed MIME types → forced file extensions (no SVG — XSS vector)
ALLOWED_IMAGE_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
}

@app.post("/api/notes/{note_id}/images")
async def upload_image(note_id: str, file: UploadFile = File(...), user=Depends(get_current_user)):
    db = get_db()
    note = db.execute("SELECT id FROM notes WHERE id = ? AND user_id = ?",
                      (note_id, user["user_id"])).fetchone()
    if not note:
        db.close()
        raise HTTPException(404, "Note introuvable")
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        db.close()
        raise HTTPException(400, "Type non autorisé (JPEG, PNG, GIF, WebP uniquement)")
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        db.close()
        raise HTTPException(413, f"Fichier trop volumineux (max {MAX_UPLOAD_SIZE // (1024*1024)} MB)")
    # Force extension from MIME type (ignore client-provided extension)
    ext = ALLOWED_IMAGE_TYPES[file.content_type]
    image_id = str(uuid.uuid4())
    filename = f"{image_id}.{ext}"
    with open(os.path.join(UPLOAD_DIR, filename), "wb") as f:
        f.write(content)
    db.execute("INSERT INTO images (id, note_id, filename, original_name, mime_type, size) VALUES (?,?,?,?,?,?)",
               (image_id, note_id, filename, file.filename, file.content_type, len(content)))
    db.commit()
    db.close()
    return {"id": image_id, "filename": filename, "url": f"/api/images/{filename}"}

@app.get("/api/images/{filename}")
def get_image(filename: str):
    # Prevent path traversal: only use the basename, then verify resolved path
    safe_name = os.path.basename(filename)
    fp = os.path.join(UPLOAD_DIR, safe_name)
    real_path = os.path.realpath(fp)
    if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
        raise HTTPException(403, "Accès interdit")
    if not os.path.exists(real_path):
        raise HTTPException(404)
    return FileResponse(real_path)

# ─── Stats ───
@app.get("/api/stats")
def get_stats(user=Depends(get_current_user)):
    db = get_db()
    uid = user["user_id"]
    nc = db.execute("SELECT COUNT(*) as c FROM notes WHERE user_id=? AND deleted_at IS NULL", (uid,)).fetchone()["c"]
    fc = db.execute("SELECT COUNT(*) as c FROM folders WHERE user_id=?", (uid,)).fetchone()["c"]
    tc = db.execute("SELECT COUNT(*) as c FROM notes WHERE user_id=? AND deleted_at IS NOT NULL", (uid,)).fetchone()["c"]
    uc = db.execute("SELECT COUNT(*) as c FROM notes WHERE user_id=? AND deleted_at IS NULL AND folder_id IS NULL", (uid,)).fetchone()["c"]
    rows = db.execute(
        "SELECT folder_id, COUNT(*) as c FROM notes WHERE user_id=? AND deleted_at IS NULL AND folder_id IS NOT NULL GROUP BY folder_id",
        (uid,)
    ).fetchall()
    db.close()
    folder_counts = {r["folder_id"]: r["c"] for r in rows}
    return {"notes": nc, "folders": fc, "trash": tc, "unclassified": uc, "folder_counts": folder_counts}

# ─── Serve Frontend ───
app.mount("/static", StaticFiles(directory="/app/static"), name="static")

@app.get("/manifest.json")
def manifest():
    return FileResponse("/app/static/manifest.json")

@app.get("/sw.js")
def service_worker():
    return FileResponse("/app/static/sw.js", media_type="application/javascript")

@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    return FileResponse("/app/static/index.html")
