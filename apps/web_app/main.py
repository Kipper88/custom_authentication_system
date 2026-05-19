from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from custom_auth.backend import CustomAuthBackend
from custom_auth.integrations.fastapi import CustomAuthMiddleware, extract_bearer_token
from custom_auth.mock_views import get_mock_resource, list_mock_resources
from custom_auth.services import AuthenticationError, ConflictError, ValidationError

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

backend = CustomAuthBackend.from_url("sqlite:///web_app.sqlite3")
app = FastAPI(title="Custom Auth Web App")
app.add_middleware(CustomAuthMiddleware, backend=backend)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        user = backend.register(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"user": user.as_dict()}


@app.post("/api/login")
def login(payload: dict[str, str]) -> dict[str, Any]:
    try:
        result = backend.login(payload.get("email", ""), payload.get("password", ""))
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password") from exc
    return {"token": result.token, "user": result.user.as_dict()}


@app.get("/api/me")
def me(request: Request) -> dict[str, Any]:
    user = request.state.user
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return {"user": user.as_dict()}


@app.post("/api/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request) -> Response:
    backend.logout(extract_bearer_token(request.headers.get("Authorization")))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.delete("/api/account", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_account(request: Request) -> Response:
    user = request.state.user
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    backend.soft_delete_user(user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/mock/resources")
def mock_resources() -> dict[str, Any]:
    return {"resources": list_mock_resources()}


@app.get("/api/mock/{resource_code}")
def mock_view(resource_code: str, request: Request) -> dict[str, Any]:
    resource = get_mock_resource(resource_code)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown mock resource")

    user = request.state.user
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not backend.has_permission(user.id, resource.code, resource.action):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    return {
        "resource": resource.code,
        "action": resource.action,
        "user": user.as_dict(),
        resource.payload_key: resource.payload,
    }
