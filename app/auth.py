import functools
import re
import sqlite3

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .security import clear_failed_logins, is_locked_out, record_failed_login

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MIN_PASSWORD, MAX_PASSWORD = 10, 128
# Used to equalise timing when the username does not exist.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


@bp.before_app_request
def load_user():
    uid = session.get("user_id")
    g.user = None
    if uid is not None:
        g.user = get_db().execute("SELECT id, username FROM users WHERE id = ?", (uid,)).fetchone()
        if g.user is None:
            session.clear()


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-30 characters: letters, numbers, underscore."
        elif not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
            error = f"Password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters."
        elif password != confirm:
            error = "Passwords do not match."
        if error is None:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is taken."
            else:
                flash("Account created. Please log in.", "ok")
                return redirect(url_for("auth.login"))
        flash(error, "error")
    return render_template("register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:MAX_PASSWORD]
        ip = request.remote_addr or "unknown"
        if is_locked_out(username, ip):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user is None or not valid:
            record_failed_login(username, ip)
            flash("Incorrect username or password.", "error")
            return render_template("login.html"), 401
        clear_failed_logins(username, ip)
        session.clear()  # prevents session fixation
        session.permanent = True
        session["user_id"] = user["id"]
        return redirect(url_for("tasks.index"))
    return render_template("login.html")


@bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
