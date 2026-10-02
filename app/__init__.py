import os
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template

from . import auth, db, security, tasks


def _load_secret_key(instance_path):
    """Use SECRET_KEY from the environment, else a persistent random key file."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    key_file = Path(instance_path) / "secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        key_file.chmod(0o600)
    return key_file.read_text().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    production = os.environ.get("APP_ENV") == "production"
    app.config.update(
        DATABASE=os.path.join(app.instance_path, "app.sqlite"),
        SECRET_KEY=_load_secret_key(app.instance_path),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production,  # requires HTTPS in production
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(tasks.bp)
    app.before_request(security.check_csrf)
    app.after_request(security.add_security_headers)
    app.jinja_env.globals["csrf_token"] = security.csrf_token

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def client_error(err):
        return render_template("error.html", err=err), err.code

    @app.errorhandler(500)
    def server_error(_err):
        return render_template("error.html", err=_err), 500

    return app
