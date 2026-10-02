"""CSRF protection, security headers and login rate limiting."""
import hmac
import secrets
import time

from flask import abort, request, session

from .db import get_db

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def check_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token.")


def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def is_locked_out(username, ip):
    cutoff = int(time.time()) - LOCKOUT_SECONDS
    row = get_db().execute(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE username = ? AND ip = ? AND ts > ?",
        (username, ip, cutoff),
    ).fetchone()
    return row["n"] >= MAX_FAILED_LOGINS


def record_failed_login(username, ip):
    db = get_db()
    now = int(time.time())
    db.execute("INSERT INTO login_attempts (username, ip, ts) VALUES (?, ?, ?)", (username, ip, now))
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (now - LOCKOUT_SECONDS,))
    db.commit()


def clear_failed_logins(username, ip):
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE username = ? AND ip = ?", (username, ip))
    db.commit()
