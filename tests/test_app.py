import io
import json
import tempfile
import unittest
from pathlib import Path

from custom_auth.app import Request, create_app
from custom_auth.db import SQLiteRepository


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(Path(self.tmp.name) / "test.sqlite3")

    def tearDown(self):
        self.app.repo.close()
        self.tmp.cleanup()

    def request(self, method, path, payload=None, token=None):
        raw = json.dumps(payload or {}).encode()
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        if token:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        status, body = self.app.route(Request(environ))
        return status.value, body

    def login(self, email="user@example.com", password="UserPass123!"):
        status, body = self.request("POST", "/api/auth/login/", {"email": email, "password": password})
        self.assertEqual(status, 200)
        return body["token"]

    def test_login_identifies_user_and_logout_revokes_token(self):
        token = self.login()
        status, body = self.request("GET", "/api/users/me/", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(body["user"]["email"], "user@example.com")

        status, _ = self.request("POST", "/api/auth/logout/", token=token)
        self.assertEqual(status, 200)
        status, _ = self.request("GET", "/api/users/me/", token=token)
        self.assertEqual(status, 401)

    def test_soft_delete_blocks_future_login(self):
        token = self.login()
        status, _ = self.request("DELETE", "/api/users/me/delete/", token=token)
        self.assertEqual(status, 200)
        row = self.app.repo.fetchone("SELECT is_active FROM users WHERE email = ?", ("user@example.com",))
        self.assertEqual(row["is_active"], 0)

        status, _ = self.request("POST", "/api/auth/login/", {"email": "user@example.com", "password": "UserPass123!"})
        self.assertEqual(status, 401)

    def test_permission_responses_are_401_and_403(self):
        status, _ = self.request("GET", "/api/business/documents/")
        self.assertEqual(status, 401)

        token = self.login()
        status, _ = self.request("GET", "/api/business/reports/", token=token)
        self.assertEqual(status, 403)

        status, body = self.request("GET", "/api/business/documents/", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(body["documents"][0]["title"], "Public contract draft")

    def test_admin_can_manage_access_rules(self):
        admin_token = self.login("admin@example.com", "AdminPass123!")
        status, body = self.request("GET", "/api/access/rules/", token=admin_token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(body["rules"]), 1)

        status, _ = self.request(
            "POST",
            "/api/access/rules/",
            {"role": "user", "resource": "reports", "action": "read", "is_allowed": True},
            admin_token,
        )
        self.assertEqual(status, 201)

        user_token = self.login()
        status, _ = self.request("GET", "/api/business/reports/", token=user_token)
        self.assertEqual(status, 200)

    def test_repository_schema_contains_access_tables(self):
        repo = SQLiteRepository(":memory:")
        repo.initialize()
        tables = {row["name"] for row in repo.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"roles", "resources", "actions", "access_rules", "auth_sessions"}.issubset(tables))
        repo.close()


if __name__ == "__main__":
    unittest.main()
