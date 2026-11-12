import os
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import app as app_module  # noqa: E402
import db as db_module  # noqa: E402


class SecurityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test.sqlite3")
        db_module.init_db(self.db_path)
        app_module.app.config["TESTING"] = True
        app_module.app.config["DB_PATH"] = self.db_path
        app_module._failed_login_attempts.clear()
        self.client = app_module.app.test_client()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _extract_csrf_token(self, html: str) -> str:
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(match, "CSRF token input missing in form")
        return match.group(1)

    def test_passwords_are_hashed_in_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT username, password FROM users").fetchall()
        conn.close()
        self.assertGreater(len(rows), 0)
        for username, stored_pw in rows:
            self.assertNotIn(stored_pw, ("alice123", "bob12345"), f"Plaintext password for {username}")
            self.assertTrue(stored_pw.startswith("pbkdf2:sha256:"), f"Unexpected hash format for {username}")

    def test_sqli_is_blocked_in_search(self) -> None:
        payload = "test' UNION SELECT id, username, password FROM users--"
        resp = self.client.get("/search", query_string={"q": payload})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertNotIn("alice", body)
        self.assertNotIn("pbkdf2:sha256", body)
        self.assertNotIn("SELECT id, title, body FROM posts", body)

    def test_reflected_xss_is_escaped_in_echo(self) -> None:
        payload = "<script>alert('xss')</script>"
        resp = self.client.get("/echo", query_string={"msg": payload})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertNotIn(payload, body)
        self.assertIn("&lt;script&gt;", body)

    def test_security_headers_and_cookie_flags(self) -> None:
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Server"), "SecureApp")

        set_cookie = resp.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Lax", set_cookie)

    def test_profile_requires_authentication(self) -> None:
        resp = self.client.get("/profile", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

    def test_csrf_required_on_login(self) -> None:
        resp = self.client.post("/login", data={"username": "alice", "password": "alice123"})
        self.assertEqual(resp.status_code, 403)

    def test_valid_login_and_logout_with_csrf(self) -> None:
        login_page = self.client.get("/login").get_data(as_text=True)
        token = self._extract_csrf_token(login_page)

        resp = self.client.post(
            "/login",
            data={"username": "alice", "password": "alice123", "csrf_token": token},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        profile_html = resp.get_data(as_text=True)
        self.assertIn("User: alice", profile_html)

        logout_token = self._extract_csrf_token(profile_html)
        logout_resp = self.client.post(
            "/logout",
            data={"csrf_token": logout_token},
            follow_redirects=False,
        )
        self.assertEqual(logout_resp.status_code, 302)

    def test_login_rate_limiting(self) -> None:
        login_page = self.client.get("/login").get_data(as_text=True)
        token = self._extract_csrf_token(login_page)

        for _ in range(app_module.LOGIN_MAX_ATTEMPTS):
            resp = self.client.post(
                "/login",
                data={"username": "alice", "password": "wrong", "csrf_token": token},
            )
            self.assertEqual(resp.status_code, 401)

        blocked = self.client.post(
            "/login",
            data={"username": "alice", "password": "wrong", "csrf_token": token},
        )
        self.assertEqual(blocked.status_code, 429)


if __name__ == "__main__":
    unittest.main()
