import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402

PW = "correct-horse-battery"


class AppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"DATABASE": os.path.join(self.tmp.name, "t.sqlite"), "TESTING": True})
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def token(self, client=None, path="/login"):
        html = (client or self.c).get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, path, data=None, client=None, token_path="/login"):
        client = client or self.c
        data = dict(data or {}, csrf_token=self.token(client, token_path))
        return client.post(path, data=data)

    def register(self, name="alice", pw=PW, client=None):
        return self.post("/register", {"username": name, "password": pw, "confirm": pw},
                         client, "/register")

    def login(self, name="alice", pw=PW, client=None):
        return self.post("/login", {"username": name, "password": pw}, client)

    # --- auth ---
    def test_requires_login(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_register_and_login(self):
        self.assertEqual(self.register().status_code, 302)
        r = self.login()
        self.assertEqual(r.status_code, 302)
        self.assertIn("alice", self.c.get("/").get_data(as_text=True))

    def test_weak_and_duplicate_registration_rejected(self):
        r = self.register(pw="short")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Password must be", r.get_data(as_text=True))
        self.register()
        r = self.register()
        self.assertIn("taken", r.get_data(as_text=True))

    def test_password_is_hashed(self):
        self.register()
        with self.app.app_context():
            from app.db import get_db
            h = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn(PW, h)
        self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))

    def test_bad_login_and_lockout(self):
        self.register()
        for _ in range(5):
            self.assertEqual(self.login(pw="wrong-password-1").status_code, 401)
        self.assertEqual(self.login().status_code, 429)  # even the right password is locked out

    def test_logout(self):
        self.register()
        self.login()
        self.post("/logout", token_path="/")
        self.assertEqual(self.c.get("/").status_code, 302)

    # --- csrf & headers ---
    def test_csrf_required(self):
        self.assertEqual(self.c.post("/login", data={"username": "a", "password": "b"}).status_code, 400)
        self.assertEqual(self.c.post("/login", data={"csrf_token": "forged"}).status_code, 400)

    def test_security_headers_and_cookie_flags(self):
        r = self.c.get("/login")
        for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
            self.assertIn(h, r.headers)
        self.assertIn("HttpOnly", r.headers.get("Set-Cookie", ""))
        self.assertIn("SameSite=Lax", r.headers.get("Set-Cookie", ""))

    # --- tasks ---
    def test_task_crud(self):
        self.register()
        self.login()
        self.post("/tasks", {"title": "Write tests", "notes": "n"}, token_path="/")
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("Write tests", page)
        tid = int(re.search(r"/tasks/(\d+)/edit", page).group(1))
        self.post(f"/tasks/{tid}/edit", {"title": "Renamed", "notes": ""}, token_path=f"/tasks/{tid}/edit")
        self.assertIn("Renamed", self.c.get("/").get_data(as_text=True))
        self.post(f"/tasks/{tid}/toggle", token_path="/")
        self.assertIn("Reopen", self.c.get("/?show=done").get_data(as_text=True))
        self.post(f"/tasks/{tid}/delete", token_path="/")
        self.assertNotIn("Renamed", self.c.get("/").get_data(as_text=True))

    def test_users_cannot_touch_each_others_tasks(self):
        self.register("alice")
        self.login("alice")
        self.post("/tasks", {"title": "alice secret"}, token_path="/")
        tid = int(re.search(r"/tasks/(\d+)/edit", self.c.get("/").get_data(as_text=True)).group(1))

        bob = self.app.test_client()
        self.register("bob", client=bob)
        self.login("bob", client=bob)
        self.assertNotIn("alice secret", bob.get("/").get_data(as_text=True))
        self.assertEqual(bob.get(f"/tasks/{tid}/edit").status_code, 404)
        self.assertEqual(self.post(f"/tasks/{tid}/delete", client=bob, token_path="/").status_code, 404)
        self.assertIn("alice secret", self.c.get("/").get_data(as_text=True))

    def test_xss_is_escaped(self):
        self.register()
        self.login()
        self.post("/tasks", {"title": "<script>alert(1)</script>"}, token_path="/")
        page = self.c.get("/").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_sql_injection_attempt_is_harmless(self):
        self.register()
        r = self.login(name="' OR '1'='1", pw="x' OR '1'='1")
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
