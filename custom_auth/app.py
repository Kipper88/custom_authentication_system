import json
from http import HTTPStatus
from urllib.parse import parse_qs

from custom_auth.db import SQLiteRepository
from custom_auth.services import (
    AuthenticationError,
    ConflictError,
    authenticate,
    current_user,
    has_permission,
    is_admin,
    list_rules,
    register,
    revoke,
    soft_delete,
    update_profile,
    upsert_rule,
    user_to_dict,
)


def bearer_token(environ):
    header = environ.get("HTTP_AUTHORIZATION", "")
    prefix = "Bearer "
    return header[len(prefix):].strip() if header.startswith(prefix) else None


class Application:
    def __init__(self, repo: SQLiteRepository):
        self.repo = repo

    def __call__(self, environ, start_response):
        request = Request(environ)
        status, body = self.route(request)
        payload = json.dumps(body).encode()
        start_response(
            f"{status.value} {status.phrase}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))],
        )
        return [payload]

    def route(self, request):
        if request.path == "/api/auth/register/" and request.method == "POST":
            return self.register(request)
        if request.path == "/api/auth/login/" and request.method == "POST":
            return self.login(request)
        if request.path == "/api/auth/logout/" and request.method == "POST":
            revoke(self.repo, request.token)
            return HTTPStatus.OK, {"status": "logged_out"}
        if request.path == "/api/users/me/" and request.method in {"GET", "PATCH"}:
            return self.profile(request)
        if request.path == "/api/users/me/delete/" and request.method == "DELETE":
            return self.delete_account(request)
        if request.path == "/api/access/rules/" and request.method in {"GET", "POST"}:
            return self.access_rules(request)
        if request.path == "/api/business/documents/" and request.method == "GET":
            return self.mock_resource(request, "documents", "documents", [{"id": 1, "title": "Public contract draft"}])
        if request.path == "/api/business/reports/" and request.method == "GET":
            return self.mock_resource(request, "reports", "reports", [{"id": 1, "title": "Quarterly revenue report"}])
        if request.path == "/api/business/admin-dashboard/" and request.method == "GET":
            return self.mock_resource(request, "admin-dashboard", "metrics", {"active_users": 2})
        return HTTPStatus.NOT_FOUND, {"error": "Not found"}

    def register(self, request):
        try:
            return HTTPStatus.CREATED, {"user": register(self.repo, request.json)}
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, {"error": str(exc)}
        except ConflictError as exc:
            return HTTPStatus.CONFLICT, {"error": str(exc)}

    def login(self, request):
        try:
            token, user = authenticate(self.repo, request.json.get("email", ""), request.json.get("password", ""))
        except AuthenticationError:
            return HTTPStatus.UNAUTHORIZED, {"error": "Invalid email or password"}
        return HTTPStatus.OK, {"token": token, "user": user}

    def profile(self, request):
        user = current_user(self.repo, request.token)
        if user is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "Authentication credentials were not provided or are invalid"}
        if request.method == "PATCH":
            return HTTPStatus.OK, {"user": update_profile(self.repo, user["id"], request.json)}
        return HTTPStatus.OK, {"user": user_to_dict(self.repo, user)}

    def delete_account(self, request):
        user = current_user(self.repo, request.token)
        if user is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "Authentication credentials were not provided or are invalid"}
        soft_delete(self.repo, user["id"])
        return HTTPStatus.OK, {"status": "deleted"}

    def access_rules(self, request):
        user = current_user(self.repo, request.token)
        if user is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "Authentication credentials were not provided or are invalid"}
        if not is_admin(self.repo, user["id"]):
            return HTTPStatus.FORBIDDEN, {"error": "Forbidden"}
        if request.method == "GET":
            return HTTPStatus.OK, {"rules": list_rules(self.repo)}
        return HTTPStatus.CREATED, {"rules": upsert_rule(self.repo, request.json)}

    def mock_resource(self, request, resource, key, value):
        user = current_user(self.repo, request.token)
        if user is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "Authentication credentials were not provided or are invalid"}
        if not has_permission(self.repo, user["id"], resource, "read"):
            return HTTPStatus.FORBIDDEN, {"error": "Forbidden"}
        return HTTPStatus.OK, {key: value}


class Request:
    def __init__(self, environ):
        self.method = environ["REQUEST_METHOD"]
        self.path = environ.get("PATH_INFO", "/")
        self.query = parse_qs(environ.get("QUERY_STRING", ""))
        self.token = bearer_token(environ)
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw = environ["wsgi.input"].read(length) if length else b"{}"
        self.json = json.loads(raw.decode() or "{}")


def create_app(database="custom_auth.sqlite3", seed=True):
    repo = SQLiteRepository(database)
    repo.initialize(seed=seed)
    return Application(repo)


if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    app = create_app()
    with make_server("127.0.0.1", 8000, app) as server:
        print("Serving on http://127.0.0.1:8000")
        server.serve_forever()
