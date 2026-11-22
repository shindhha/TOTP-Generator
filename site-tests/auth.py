"""Comptes locaux, enrôlement et sessions du site de démonstration."""

import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.cookies import CookieError, SimpleCookie
import os
import re
import secrets
import sqlite3
from threading import BoundedSemaphore
from urllib.parse import quote, urlencode

ISSUER = "Atelier TOTP"
USERNAME = re.compile(r"[a-z0-9_.-]{3,32}")
HASH_SLOTS = BoundedSemaphore(2)
SESSION_TTL = {"guest": 900, "setup": 900, "challenge": 300, "full": 8 * 3600}


def password_hash(password, salt):
    with HASH_SLOTS:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1,
                              maxmem=160 * 1024 * 1024)


def fingerprint(token):
    return hashlib.sha256(token.encode("ascii")).digest()


def enrollment_uri(username, secret):
    label = quote(ISSUER, safe="") + ":" + quote(username, safe="")
    query = urlencode({
        "secret": base64.b32encode(secret).decode("ascii"),
        "issuer": ISSUER, "algorithm": "SHA1", "digits": 6, "period": 30,
    })
    return f"otpauth://totp/{label}?{query}"


class AuthStore:
    def __init__(self, path):
        self.path = path
        self.dummy_salt = secrets.token_bytes(16)
        self.dummy_hash = password_hash(secrets.token_hex(32), self.dummy_salt)
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with self.database() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    salt BLOB NOT NULL,
                    password BLOB NOT NULL,
                    secret BLOB UNIQUE NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0,
                    last_step INTEGER NOT NULL DEFAULT -1
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token BLOB PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    phase TEXT NOT NULL,
                    csrf TEXT NOT NULL,
                    expires INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires);
                CREATE TABLE IF NOT EXISTS attempts (
                    scope TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    expires INTEGER NOT NULL,
                    count INTEGER NOT NULL,
                    PRIMARY KEY (scope, subject)
                );
                CREATE INDEX IF NOT EXISTS attempts_expires ON attempts(expires);
            """)

    @contextmanager
    def database(self, *, write=False):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys = ON")
            if write:
                db.execute("BEGIN IMMEDIATE")
            with db:
                yield db
        finally:
            db.close()

    def allow_attempt(self, scope, subject, limit, seconds, now):
        with self.database(write=True) as db:
            db.execute("DELETE FROM attempts WHERE expires <= ?", (now,))
            row = db.execute("""
                INSERT INTO attempts VALUES (?, ?, ?, 1)
                ON CONFLICT (scope, subject) DO UPDATE SET count = count + 1
                RETURNING count
            """, (scope, subject, now + seconds)).fetchone()
            return row["count"] <= limit

    def session(self, request_cookie, now):
        jar = SimpleCookie()
        try:
            jar.load(request_cookie)
        except CookieError:
            return None
        cookie = jar.get("totp_session")
        if not cookie or not re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie.value):
            return None
        with self.database() as db:
            return db.execute("""
                SELECT sessions.*, users.username,
                       CASE WHEN phase IN ('setup', 'challenge') THEN users.secret END AS secret
                FROM sessions
                LEFT JOIN users ON users.id = sessions.user_id
                WHERE token = ? AND expires > ?
            """, (fingerprint(cookie.value), now)).fetchone()

    def new_session(self, db, phase, now, user_id=None):
        token = secrets.token_urlsafe(32)
        db.execute("DELETE FROM sessions WHERE expires <= ?", (now,))
        db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                   (fingerprint(token), user_id, phase, secrets.token_urlsafe(32),
                    now + SESSION_TTL[phase]))
        return token

    def guest(self, now):
        with self.database(write=True) as db:
            return self.new_session(db, "guest", now)

    def revoke(self, db, session, now):
        return db.execute("DELETE FROM sessions WHERE token = ? AND expires > ?",
                          (session["token"], now)).rowcount == 1

    def logout(self, session, now):
        with self.database(write=True) as db:
            self.revoke(db, session, now)

    def register(self, session, username, password, now):
        salt = secrets.token_bytes(16)
        digest = password_hash(password, salt)
        secret = secrets.token_bytes(20)
        with self.database(write=True) as db:
            user = db.execute("""
                INSERT INTO users (username, salt, password, secret) VALUES (?, ?, ?, ?)
                ON CONFLICT (username) DO NOTHING RETURNING id
            """, (username, salt, digest, secret)).fetchone()
            if user is None:
                return None
            if not self.revoke(db, session, now):
                db.execute("DELETE FROM users WHERE id = ?", (user["id"],))
                return None
            return self.new_session(db, "setup", now, user["id"])

    def login(self, session, username, password, now):
        with self.database() as db:
            user = db.execute("SELECT id, salt, password FROM users WHERE username = ?",
                              (username,)).fetchone()
        digest = password_hash(password, user["salt"] if user else self.dummy_salt)
        if not hmac.compare_digest(digest, user["password"] if user else self.dummy_hash) or not user:
            return None
        with self.database(write=True) as db:
            if not self.revoke(db, session, now):
                return None
            active = db.execute("SELECT active FROM users WHERE id = ?", (user["id"],)).fetchone()["active"]
            phase = "challenge" if active else "setup"
            return self.new_session(db, phase, now, user["id"]), phase

    def complete(self, session, step, now):
        """Consomme une période et remplace la session partielle dans la même transaction."""
        with self.database(write=True) as db:
            if not db.execute("SELECT 1 FROM sessions WHERE token = ? AND expires > ?",
                              (session["token"], now)).fetchone():
                return None
            if session["phase"] == "setup":
                changed = db.execute("""
                    UPDATE users SET active = 1, last_step = ? WHERE id = ? AND active = 0
                """, (step, session["user_id"])).rowcount
                if changed:
                    db.execute("DELETE FROM sessions WHERE user_id = ? AND phase = 'setup'",
                               (session["user_id"],))
            else:
                changed = db.execute("""
                    UPDATE users SET last_step = ? WHERE id = ? AND active = 1 AND last_step < ?
                """, (step, session["user_id"], step)).rowcount
                if changed:
                    self.revoke(db, session, now)
            if changed:
                return self.new_session(db, "full", now, session["user_id"])
        return None
