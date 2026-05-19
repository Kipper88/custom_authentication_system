from __future__ import annotations

from typing import Any

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.permissions import BasePermission

from custom_auth.backend import CustomAuthBackend
from custom_auth.services import AuthenticatedUser

AUTH_HEADER_PREFIX = b"bearer"


class DRFBearerAuthentication(BaseAuthentication):
    """DRF authentication class backed by `CustomAuthBackend`.

    Configure it with `as_authentication_class(backend)` and put the returned
    class into `DEFAULT_AUTHENTICATION_CLASSES` or directly on a view.
    """

    backend: CustomAuthBackend | None = None

    def authenticate(self, request) -> tuple[AuthenticatedUser, None] | None:
        parts = get_authorization_header(request).split()
        if not parts:
            return None
        if parts[0].lower() != AUTH_HEADER_PREFIX or len(parts) != 2:
            raise AuthenticationFailed("Invalid bearer token header")
        if self.backend is None:
            raise AuthenticationFailed("Custom auth backend is not configured")
        user = self.backend.identify_token(parts[1].decode())
        if user is None:
            raise AuthenticationFailed("Authentication credentials were not provided or are invalid")
        request.custom_auth_user = user
        return user, None


def as_authentication_class(backend: CustomAuthBackend) -> type[DRFBearerAuthentication]:
    class ConfiguredDRFBearerAuthentication(DRFBearerAuthentication):
        pass

    ConfiguredDRFBearerAuthentication.backend = backend
    return ConfiguredDRFBearerAuthentication


def require_permission(resource: str, action: str = "read") -> type[BasePermission]:
    class CustomAccessPermission(BasePermission):
        def has_permission(self, request, view) -> bool:
            backend: CustomAuthBackend | None = getattr(view, "auth_backend", None)
            user: AuthenticatedUser | None = getattr(request, "custom_auth_user", None)
            if user is None:
                return False
            if backend is None:
                raise PermissionDenied("Custom auth backend is not configured")
            return backend.has_permission(user.id, resource, action)

    return CustomAccessPermission


def require_admin() -> type[BasePermission]:
    class CustomAdminPermission(BasePermission):
        def has_permission(self, request, view) -> bool:
            backend: CustomAuthBackend | None = getattr(view, "auth_backend", None)
            user: AuthenticatedUser | None = getattr(request, "custom_auth_user", None)
            if user is None:
                return False
            if backend is None:
                raise PermissionDenied("Custom auth backend is not configured")
            return backend.is_admin(user.id)

    return CustomAdminPermission


def user_response(user: AuthenticatedUser) -> dict[str, Any]:
    return user.as_dict()
