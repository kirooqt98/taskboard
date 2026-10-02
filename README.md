# TaskBoard

A small but complete web app: user accounts, a SQLite database and a personal task manager.
Built with Flask, with no JavaScript, so a strict Content-Security-Policy can be used.

## Run it

```bash
pip install -r requirements.txt
python run.py          # http://127.0.0.1:5000
python -m unittest discover -s tests -v   # run the tests
```

The database (`instance/app.sqlite`) and a random signing key (`instance/secret_key`) are created on first run.
Back up the `instance/` folder and never commit it.

## Security features

| Concern | What is done |
|---|---|
| Passwords | Salted scrypt hashes (Werkzeug), 10-128 chars, never stored in plain text |
| Sessions | Signed cookie, `HttpOnly`, `SameSite=Lax`, `Secure` in production, 7-day expiry, session reset on login |
| CSRF | Per-session token required on every POST, checked with a constant-time compare |
| Brute force | 5 failed logins per username+IP locks login for 15 minutes; dummy hash equalises timing for unknown users |
| SQL injection | Parameterised queries only |
| XSS | Jinja2 auto-escaping and a CSP of `default-src 'self'` (no inline scripts or styles) |
| Access control | Every task query is scoped to the logged-in user (other users' IDs return 404) |
| Headers | CSP, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy, Permissions-Policy, `no-store` |
| Abuse | 64 KB request cap, length limits on all fields |

## Deploying

```bash
export APP_ENV=production            # turns on Secure cookies, so serve over HTTPS
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
gunicorn -w 3 -b 127.0.0.1:8000 'app:create_app()'
```

Put nginx or Caddy in front for HTTPS (Caddy gets certificates automatically).
If you run behind a proxy, wrap the app with `werkzeug.middleware.proxy_fix.ProxyFix`
so the login lockout sees real client IPs.

## Known limits / next steps

- No email verification or password reset (needs an email service).
- SQLite suits a single server. Move to Postgres if you need several app servers.
- Lockout state lives in the database, which is fine for one node.

## Layout

```
app/__init__.py   app factory and config
app/auth.py       register / login / logout
app/tasks.py      task CRUD
app/security.py   CSRF, headers, rate limiting
app/db.py         SQLite helpers
schema.sql        tables
```
