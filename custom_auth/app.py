from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs

from custom_auth import services
from custom_auth.backend import CustomAuthBackend

AUTH_HEADER_PREFIX = "Bearer "


def bearer_token(environ: dict[str, Any]) -> str | None:
    header = environ.get("HTTP_AUTHORIZATION", "")
    if header.startswith(AUTH_HEADER_PREFIX):
        return header[len(AUTH_HEADER_PREFIX) :].strip()
    return None


class Application:
    """Small WSGI adapter around the framework-agnostic auth backend.

    The project intentionally keeps HTTP concerns here and business/auth rules
    in `CustomAuthBackend`, so the same backend can be used from FastAPI via
    `custom_auth.integrations.fastapi.CustomAuthMiddleware`.
    """

    def __init__(self, backend: CustomAuthBackend):
        self.backend = backend

    def __call__(self, environ, start_response):
        request = Request(environ)
        status, body = self.route(request)
        payload = json.dumps(body).encode()
        start_response(
            f"{status.value} {status.phrase}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))],
        )
        return [payload]

    def route(self, request: "Request") -> tuple[HTTPStatus, dict[str, Any]]:
        route_key = (request.method, request.path)
        routes = {
            ("POST", "/api/auth/register/"): self.register,
            ("POST", "/api/auth/login/"): self.login,
            ("POST", "/api/auth/logout/"): self.logout,
            ("GET", "/api/users/me/"): self.profile,
            ("PATCH", "/api/users/me/"): self.profile,
            ("DELETE", "/api/users/me/delete/"): self.delete_account,
            ("GET", "/api/access/rules/"): self.access_rules,
            ("POST", "/api/access/rules/"): self.access_rules,
            ("GET", "/api/business/documents/"): lambda req: self.mock_resource(
                req, "documents", "documents", [{"id": 1, "title": "Public contract draft"}]
            ),
            ("GET", "/api/business/reports/"): lambda req: self.mock_resource(
                req, "reports", "reports", [{"id": 1, "title": "Quarterly revenue report"}]
            ),
            ("GET", "/api/business/admin-dashboard/"): lambda req: self.mock_resource(
                req, "admin-dashboard", "metrics", {"active_users": 2}
            ),
        }
        handler = routes.get(route_key)
        if handler is None:
            return HTTPStatus.NOT_FOUND, {"error": "Not found"}
        return handler(request)

    def register(self, request: "Request") -> tuple[HTTPStatus, dict[str, Any]]:
        try:
            user = self.backend.register(request.json)
        except services.ValidationError as exc:
            return HTTPStatus.BAD_REQUEST, {"error": str(exc)}
        except services.ConflictError as exc:
            return HTTPStatus.CONFLICT, {"error": str(exc)}
        return HTTPStatus.CREATED, {"user": user.as_dict()}

    def login(self, request: "Request") -> tuple[HTTPStatus, dict[str, Any]]:
        try:
            result = self.backend.login(request.json.get("email", ""), request.json.get("password", ""))
        except services.AuthenticationError:
            return HTTPStatus.UNAUTHORIZED, {"error": "Invalid email or password"}
        return HTTPStatus.OK, {"token": result.token, "user": result.user.as_dict()}

    def logout(self, request: "Request") -> tuple[HTTPStatus, dict[str, str]]:
        self.backend.logout(request.token)
        return HTTPStatus.OK, {"status": "logged_out"}

    def profile(self, request: "Request") -> tuple[HTTPStatus, dict[str, Any]]:
        user = self.backend.identify_token(request.token)
        if user is None:
            return unauthorized()
        if request.method == "PATCH":
            user = self.backend.update_profile(user.id, request.json)
        return HTTPStatus.OK, {"user": user.as_dict()}

    def delete_account(self, request: "Request") -> tuple[HTTPStatus, dict[str, str]]:
        user = self.backend.identify_token(request.token)
        if user is None:
            return unauthorized()
        self.backend.soft_delete_user(user.id)
        return HTTPStatus.OK, {"status": "deleted"}

    def access_rules(self, request: "Request") -> tuple[HTTPStatus, dict[str, Any]]:
        user = self.backend.identify_token(request.token)
        if user is None:
            return unauthorized()
        if not self.backend.is_admin(user.id):
            return forbidden()
        if request.method == "GET":
            return HTTPStatus.OK, {"rules": self.backend.list_rules()}
        try:
            return HTTPStatus.CREATED, {"rules": self.backend.save_rule(request.json)}
        except services.AccessRuleError as exc:
            return HTTPStatus.BAD_REQUEST, {"error": str(exc)}

    def mock_resource(
        self,
        request: "Request",
        resource: str,
        response_key: str,
        response_value: Any,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        user = self.backend.identify_token(request.token)
        if user is None:
            return unauthorized()
        if not self.backend.has_permission(user.id, resource, "read"):
            return forbidden()
        return HTTPStatus.OK, {response_key: response_value}


class Request:
    def __init__(self, environ: dict[str, Any]):
        self.method = environ["REQUEST_METHOD"]
        self.path = environ.get("PATH_INFO", "/")
        self.query = parse_qs(environ.get("QUERY_STRING", ""))
        self.token = bearer_token(environ)
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw = environ["wsgi.input"].read(length) if length else b"{}"
        self.json = json.loads(raw.decode() or "{}")


def unauthorized() -> tuple[HTTPStatus, dict[str, str]]:
    return HTTPStatus.UNAUTHORIZED, {"error": "Authentication credentials were not provided or are invalid"}


def forbidden() -> tuple[HTTPStatus, dict[str, str]]:
    return HTTPStatus.FORBIDDEN, {"error": "Forbidden"}


def create_app(database="custom_auth.sqlite3", seed=True):
    return Application(CustomAuthBackend.with_sqlite(database, seed=seed))


if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    app = create_app()
    with make_server("127.0.0.1", 8000, app) as server:
        print("Serving on http://127.0.0.1:8000")
        server.serve_forever()
