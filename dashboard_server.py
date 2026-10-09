# -*- coding: utf-8 -*-
"""
FreeFire Level Up Bot - Professional Web Dashboard & Real-Time EXP Tracker
Embedded Async Web Server (aiohttp)
"""

import asyncio
import json
import os
import time
import sqlite3
import hashlib
import secrets
import hmac
from pathlib import Path
from typing import Dict, List, Any, Optional
from aiohttp import web

# Lightweight account auth store. Set USER_DB_PATH to a mounted Render disk path
# if user accounts must survive redeploys (for example /var/data/levelup_users.sqlite3).
AUTH_DB_PATH = os.environ.get("USER_DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "levelup_users.sqlite3"))
SESSION_COOKIE = "levelup_session"
SESSION_TTL = 60 * 60 * 24 * 14

def _db():
    Path(AUTH_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE COLLATE NOCASE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', slots INTEGER NOT NULL DEFAULT 1, plan TEXT NOT NULL DEFAULT 'Standard', expires_at INTEGER, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
      CREATE TABLE IF NOT EXISTS account_owners (account_key TEXT PRIMARY KEY, user_id INTEGER NOT NULL, uid TEXT, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
    """)
    conn.commit()
    return conn

def _password_hash(password: str, salt: bytes = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240000)
    return salt.hex() + ":" + digest.hex()

def _password_ok(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 240000).hex(), digest_hex)
    except Exception:
        return False

def _bootstrap_admin(conn):
    username = os.environ.get("ADMIN_USERNAME", "").strip()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not username or not password:
        return
    row = conn.execute("SELECT id, role FROM users WHERE username=?", (username,)).fetchone()
    if row:
        # Reconcile credentials from Render on every bootstrap. Previously an
        # existing admin kept an old password forever, so the correct Render
        # password could still be rejected after an environment change.
        full = conn.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
        password_changed = not _password_ok(password, full["password_hash"])
        if row["role"] != "admin" or password_changed:
            conn.execute(
                "UPDATE users SET password_hash=?, role='admin', slots=-1, plan='Lifetime', expires_at=NULL WHERE id=?",
                (_password_hash(password) if password_changed or row["role"] != "admin" else full["password_hash"], row["id"])
            )
        else:
            conn.execute("UPDATE users SET slots=-1, plan='Lifetime', expires_at=NULL WHERE id=?", (row["id"],))
    else:
        conn.execute("INSERT INTO users(username,password_hash,role,slots,plan,expires_at,created_at) VALUES(?,?, 'admin', -1, 'Lifetime', NULL, ?)", (username, _password_hash(password), int(time.time())))
    conn.commit()

def _public_user(row):
    now = int(time.time())
    admin = row["role"] == "admin"
    expired = bool(row["expires_at"] and row["expires_at"] < now)
    return {"id": row["id"], "username": row["username"], "role": row["role"], "slots": -1 if admin else row["slots"], "plan": "Lifetime" if admin else row["plan"], "expires_at": None if admin else row["expires_at"], "subscription_active": admin or not expired}

def _user_from_request(request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    conn = _db()
    try:
        _bootstrap_admin(conn)
        row = conn.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at> ?", (digest, int(time.time()))).fetchone()
        return _public_user(row) if row else None
    finally:
        conn.close()

def _auth_error():
    return web.json_response({"status":"error", "error":"Please sign in to continue.", "auth_required":True}, status=401)

def _account_key(data):
    if data.get("uid"):
        return "uid:" + str(data["uid"]).strip()
    if data.get("token"):
        return "token:" + hashlib.sha256(str(data["token"]).strip().encode()).hexdigest()
    return ""

# Global bot state shared between Main.py and Web Dashboard
class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "uid": uid
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str, level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": exp,
                "current_exp": exp,
                "gained_exp": 0,
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S")
            }
        else:
            acc = self.accounts[uid_str]
            if nickname:
                acc["nickname"] = nickname
            if region:
                acc["region"] = region
            if level:
                acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! Total Gained: +{acc['gained_exp']}", "success", uid_str)
            self.recalc_totals()

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = time.strftime("%H:%M:%S")
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")
            self.log(f"Account {self.accounts[uid_str]['nickname']} finished Match #{self.accounts[uid_str]['matches_played']}", "info", uid_str)

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()


# ==================== HTTP HANDLERS ====================

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")

async def handle_index(request: web.Request) -> web.Response:
    if os.path.exists(TEMPLATE_PATH):
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "<h1>templates/index.html not found!</h1>"
    return web.Response(text=content, content_type="text/html", charset="utf-8")


async def handle_verify_page(request: web.Request) -> web.Response:
    """Serve the VPLink pre-verification warning page from the same Render app."""
    page_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "steps.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            content = f.read()
        return web.Response(text=content, content_type="text/html", charset="utf-8")
    except OSError:
        return web.Response(text="Verification page is unavailable.", status=500, content_type="text/plain")


async def handle_get_stats(request: web.Request) -> web.Response:
    user = _user_from_request(request)
    if not user:
        return _auth_error()
    all_accounts = list(bot_state.accounts.values())
    if user["role"] != "admin":
        conn = _db()
        try:
            owner_rows = conn.execute(
                "SELECT account_key,user_id,uid FROM account_owners WHERE user_id=?",
                (user["id"],)
            ).fetchall()
            # Token-based accounts are initially stored under a hashed token
            # key. Once login reveals their in-game UID, the owner row's uid
            # field is the canonical link used by the monitor.
            owned_uids = {str(r["uid"]) for r in owner_rows if r["uid"]}
            owned_keys = {r["account_key"] for r in owner_rows}
        finally:
            conn.close()
        accounts_data = [
            a for a in all_accounts
            if (str(a.get("uid")) in owned_uids or "uid:" + str(a.get("uid")) in owned_keys)
        ]
    else:
        accounts_data = all_accounts

    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    # Return only fields used by the account cards. This keeps the response small
    # and avoids exposing unrelated internal state in the dashboard API.
    visible_fields = (
        "uid", "nickname", "region", "level", "initial_exp", "current_exp",
        "gained_exp", "status", "active_matches", "matches_played",
        "last_match_time"
    )
    public_accounts = [
        {key: account.get(key) for key in visible_fields}
        for account in accounts_data
    ]
    response = web.json_response({
        "total_accounts": len(public_accounts),
        "total_matches": sum(int(a.get("matches_played", 0) or 0) for a in public_accounts),
        "total_gained_exp": sum(int(a.get("gained_exp", 0) or 0) for a in public_accounts),
        "accounts": public_accounts,
        "uptime": int(time.time() - bot_state.start_time),
        "user": user
    })
    response.headers["Cache-Control"] = "no-store"
    return response

async def handle_register(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not 3 <= len(username) <= 32 or not all(c.isalnum() or c in "_.-" for c in username):
            return web.json_response({"status":"error", "error":"Username must be 3–32 characters (letters, numbers, ., _ or -)."}, status=400)
        if len(password) < 8 or len(password) > 128:
            return web.json_response({"status":"error", "error":"Password must be at least 8 characters."}, status=400)
        conn = _db()
        try:
            _bootstrap_admin(conn)
            conn.execute("INSERT INTO users(username,password_hash,role,slots,plan,expires_at,created_at) VALUES(?,?, 'user', 1, 'Standard', NULL, ?)", (username, _password_hash(password), int(time.time())))
            conn.commit()
            user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        except sqlite3.IntegrityError:
            return web.json_response({"status":"error", "error":"That username is already taken."}, status=409)
        finally:
            conn.close()
        return await _create_session(user_id, username, request)
    except Exception as exc:
        return web.json_response({"status":"error", "error":"Could not create account."}, status=500)

async def handle_login(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        conn = _db()
        try:
            _bootstrap_admin(conn)
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row or not _password_ok(password, row["password_hash"]):
                return web.json_response({"status":"error", "error":"Incorrect username or password."}, status=401)
            user_id = row["id"]
        finally:
            conn.close()
        return await _create_session(user_id, username, request)
    except Exception:
        return web.json_response({"status":"error", "error":"Sign-in failed."}, status=500)

async def _create_session(user_id, username, request):
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    conn = _db()
    try:
        conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (digest, user_id, int(time.time()) + SESSION_TTL))
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        public = _public_user(row)
    finally:
        conn.close()
    response = web.json_response({"status":"ok", "user":public})
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, secure=(request.secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https"), samesite="Lax", path="/")
    return response

async def handle_me(request: web.Request):
    user = _user_from_request(request)
    if not user: return _auth_error()
    return web.json_response({"status":"ok", "user":user})

async def handle_logout(request: web.Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        conn = _db()
        try:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
            conn.commit()
        finally: conn.close()
    response = web.json_response({"status":"ok"})
    response.del_cookie(SESSION_COOKIE, path="/")
    return response

async def handle_admin_users(request: web.Request):
    user = _user_from_request(request)
    if not user: return _auth_error()
    if user["role"] != "admin": return web.json_response({"status":"error", "error":"Admin access required."}, status=403)
    conn = _db()
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        users = [_public_user(r) | {"created_at":r["created_at"], "account_count":conn.execute("SELECT COUNT(*) FROM account_owners WHERE user_id=?", (r["id"],)).fetchone()[0]} for r in rows]
    finally: conn.close()
    return web.json_response({"status":"ok", "users":users})

async def handle_admin_update_user(request: web.Request):
    user = _user_from_request(request)
    if not user: return _auth_error()
    if user["role"] != "admin": return web.json_response({"status":"error", "error":"Admin access required."}, status=403)
    try:
        data = await request.json(); target_id = int(data.get("id")); slots = int(data.get("slots", 1)); plan = str(data.get("plan", "Standard"))[:40]
        expires_at = data.get("expires_at")
        expires_at = int(expires_at) if expires_at not in (None, "") else None
        if slots < 1: return web.json_response({"status":"error", "error":"Slots must be at least 1."}, status=400)
        conn = _db()
        try:
            target = conn.execute("SELECT role FROM users WHERE id=?", (target_id,)).fetchone()
            if not target: return web.json_response({"status":"error", "error":"User not found."}, status=404)
            if target["role"] == "admin": return web.json_response({"status":"error", "error":"Admin account settings are fixed."}, status=400)
            conn.execute("UPDATE users SET slots=?,plan=?,expires_at=? WHERE id=?", (slots, plan, expires_at, target_id)); conn.commit()
        finally: conn.close()
        return web.json_response({"status":"ok"})
    except Exception:
        return web.json_response({"status":"error", "error":"Invalid user settings."}, status=400)


def bind_account_identity(source: str, uid: str) -> None:
    """Attach a token/password record to its resolved in-game UID without
    creating a second slot reservation."""
    source = str(source or "").strip()
    uid = str(uid or "").strip()
    if not source or not uid:
        return
    if source.startswith("token:"):
        key = source
    elif source.startswith("uid:"):
        key = source
    else:
        key = "token:" + hashlib.sha256(source.encode()).hexdigest()
    conn = _db()
    try:
        conn.execute("UPDATE account_owners SET uid=? WHERE account_key=?", (uid, key))
        conn.commit()
    finally:
        conn.close()


async def handle_add_account(request: web.Request) -> web.Response:
    try:
        user = _user_from_request(request)
        if not user: return _auth_error()
        if not user["subscription_active"]: return web.json_response({"status":"error", "error":"Subscription expired. Contact the administrator."}, status=403)
        data = await request.json()
        key = _account_key(data)
        if not key: return web.json_response({"status":"error", "error":"UID/password or token is required."}, status=400)
        conn = _db()
        try:
            owner = conn.execute("SELECT user_id FROM account_owners WHERE account_key=?", (key,)).fetchone()
            if owner and owner["user_id"] != user["id"] and user["role"] != "admin":
                return web.json_response({"status":"error", "error":"This account is already assigned to another user."}, status=409)
            current_count = conn.execute("SELECT COUNT(*) FROM account_owners WHERE user_id=?", (user["id"],)).fetchone()[0]
            if not owner and user["role"] != "admin" and current_count >= user["slots"]:
                return web.json_response({"status":"error", "error":f"Your plan allows {user['slots']} UID slot(s). Remove an account or contact the administrator to add slots."}, status=403)
        finally: conn.close()
        accounts_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")
        existing = []
        if os.path.exists(accounts_file):
            try:
                with open(accounts_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return web.json_response({"status": "error", "error": "UID and Password are required"})
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            existing.append({"uid": uid, "password": pwd})
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return web.json_response({"status": "error", "error": "Token is required"})
            existing = [acc for acc in existing if acc.get("token") != token]
            existing.append({"token": token})
        else:
            return web.json_response({"status": "error", "error": "Invalid payload"})

        with open(accounts_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        conn = _db()
        try:
            uid_value = str(data.get("uid", "")).strip() or None
            conn.execute("INSERT INTO account_owners(account_key,user_id,uid,created_at) VALUES(?,?,?,?) ON CONFLICT(account_key) DO UPDATE SET user_id=excluded.user_id,uid=excluded.uid", (key, user["id"], uid_value, int(time.time())))
            conn.commit()
        finally: conn.close()

        bot_state.log(f"New account added: {data.get('uid') or 'Token'}", "success")
        
        # Trigger dynamic worker launch
        if "on_account_added" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_account_added"](data))

        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_delete_account(request: web.Request) -> web.Response:
    try:
        user = _user_from_request(request)
        if not user: return _auth_error()
        data = await request.json()
        uid = str(data.get("uid")).strip()
        conn = _db()
        try:
            owners = conn.execute(
                "SELECT account_key,user_id FROM account_owners WHERE uid=? OR account_key=?",
                (uid, "uid:" + uid)
            ).fetchall()
            if user["role"] != "admin" and not any(r["user_id"] == user["id"] for r in owners):
                return web.json_response({"status":"error", "error":"You do not own this account."}, status=403)
            keys = [r["account_key"] for r in owners]
            if keys:
                conn.executemany("DELETE FROM account_owners WHERE account_key=?", [(k,) for k in keys])
            conn.commit()
        finally: conn.close()
        accounts_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")
        if os.path.exists(accounts_file):
            with open(accounts_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
            owned_keys_set = set(keys)
            kept = []
            for acc in existing:
                acc_uid = str(acc.get("uid", "")).strip()
                acc_token = str(acc.get("token", "")).strip()
                token_key = "token:" + hashlib.sha256(acc_token.encode()).hexdigest() if acc_token else ""
                # Remove the selected UID and any access-token record mapped
                # to it, otherwise a deleted token account would restart.
                if acc_uid == uid or (token_key and token_key in owned_keys_set):
                    continue
                kept.append(acc)
            with open(accounts_file, "w", encoding="utf-8") as f:
                json.dump(kept, f, indent=2)

        if uid in bot_state.accounts:
            del bot_state.accounts[uid]

        if uid in bot_state.account_workers:
            bot_state.account_workers[uid].cancel()
            del bot_state.account_workers[uid]

        bot_state.log(f"Account {uid} removed from rotation.", "warning", uid)
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_refresh_account(request: web.Request) -> web.Response:
    try:
        user = _user_from_request(request)
        if not user: return _auth_error()
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if user["role"] != "admin":
            conn = _db()
            try:
                owner = conn.execute("SELECT user_id FROM account_owners WHERE uid=? OR account_key=?", (uid, "uid:" + uid)).fetchall()
            finally: conn.close()
            if not any(r["user_id"] == user["id"] for r in owner):
                return web.json_response({"status":"error", "error":"You do not own this account."}, status=403)
        if "on_refresh_account" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_refresh_account"](uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def start_web_dashboard(host: str = "0.0.0.0", port: Optional[int] = None):
    if port is None:
        try:
            port = int(os.environ.get("PORT", "5000"))
        except (TypeError, ValueError):
            port = 5000
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/verify", handle_verify_page)
    app.router.add_static("/assets/", os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets"), show_index=False)
    app.router.add_post("/api/auth/register", handle_register)
    app.router.add_post("/api/auth/login", handle_login)
    app.router.add_get("/api/auth/me", handle_me)
    app.router.add_post("/api/auth/logout", handle_logout)
    app.router.add_get("/api/admin/users", handle_admin_users)
    app.router.add_post("/api/admin/users/update", handle_admin_update_user)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"\033[92m[+] Web Dashboard running on {host}:{port}\033[0m")
