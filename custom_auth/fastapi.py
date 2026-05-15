from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware

from custom_auth.backend import AuthenticatedUser, CustomAuthBackend

AUTH_HEADER_PREFIX = "Bearer "


def extract_bearer_token(authorization_header: str | None) -> str | None:
    if authorization_header and authorization_header.startswith(AUTH_HEADER_PREFIX):
        return authorization_header[len(AUTH_HEADER_PREFIX) :].strip()
    return None


class CustomAuthMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that attaches the current user to request.state.

    Usage:
        backend = CustomAuthBackend.with_sqlite("auth.sqlite3")
        app.add_middleware(CustomAuthMiddleware, backend=backend)

    After that, route dependencies can read request.state.user or use the
    helpers below (`current_user_dependency`, `permission_dependency`).
    """

    def __init__(self, app, backend: CustomAuthBackend, state_attribute: str = "user"):
        super().__init__(app)
        self.backend = backend
        self.state_attribute = state_attribute

    async def dispatch(self, request: Request, call_next):
        token = extract_bearer_token(request.headers.get("Authorization"))
        setattr(request.state, self.state_attribute, self.backend.identify_token(token))
        request.state.auth_backend = self.backend
        return await call_next(request)


def current_user_dependency(request: Request) -> AuthenticatedUser:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided or are invalid",
        )
    return user


CurrentUser = Annotated[AuthenticatedUser, Depends(current_user_dependency)]


def permission_dependency(resource: str, action: str = "read") -> Callable[[Request], AuthenticatedUser]:
    def dependency(request: Request) -> AuthenticatedUser:
        user = current_user_dependency(request)
        backend = request.state.auth_backend
        if not backend.has_permission(user.id, resource, action):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user

    return dependency


def admin_dependency(request: Request) -> AuthenticatedUser:
    user = current_user_dependency(request)
    backend = request.state.auth_backend
    if not backend.is_admin(user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user
