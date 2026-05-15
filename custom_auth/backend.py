from __future__ import annotations

from dataclasses import dataclass
from sqlite3 import Row
from typing import Any

from custom_auth.db import SQLiteRepository
from custom_auth import services


@dataclass(frozen=True)
class AuthenticatedUser:
    """Small immutable user object exposed to framework integrations."""

    id: int
    email: str
    first_name: str
    last_name: str
    middle_name: str
    is_active: bool
    roles: tuple[str, ...]

    @classmethod
    def from_row(cls, repo: SQLiteRepository, row: Row) -> "AuthenticatedUser":
        payload = services.user_to_dict(repo, row)
        return cls(
            id=payload["id"],
            email=payload["email"],
            first_name=payload["first_name"],
            last_name=payload["last_name"],
            middle_name=payload["middle_name"],
            is_active=payload["is_active"],
            roles=tuple(payload["roles"]),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "middle_name": self.middle_name,
            "is_active": self.is_active,
            "roles": list(self.roles),
        }


@dataclass(frozen=True)
class LoginResult:
    token: str
    user: AuthenticatedUser


class CustomAuthBackend:
    """Application-facing API for custom auth.

    The backend keeps framework code thin: HTTP adapters only extract bearer
    tokens, then delegate registration, login, session lookup and permission
    checks here. That makes it straightforward to plug into FastAPI middleware
    or another web framework without rewriting auth rules.
    """

    def __init__(self, repo: SQLiteRepository):
        self.repo = repo

    @classmethod
    def with_sqlite(cls, database: str = "custom_auth.sqlite3", seed: bool = True) -> "CustomAuthBackend":
        repo = SQLiteRepository(database)
        repo.initialize(seed=seed)
        return cls(repo)

    def register(self, payload: dict[str, Any]) -> AuthenticatedUser:
        user = services.register(self.repo, payload)
        row = self.repo.fetchone("SELECT * FROM users WHERE id = ?", (user["id"],))
        return AuthenticatedUser.from_row(self.repo, row)

    def login(self, email: str, password: str) -> LoginResult:
        token, user = services.authenticate(self.repo, email, password)
        row = self.repo.fetchone("SELECT * FROM users WHERE id = ?", (user["id"],))
        return LoginResult(token=token, user=AuthenticatedUser.from_row(self.repo, row))

    def identify_token(self, token: str | None) -> AuthenticatedUser | None:
        row = services.current_user(self.repo, token)
        if row is None:
            return None
        return AuthenticatedUser.from_row(self.repo, row)

    def logout(self, token: str | None) -> None:
        services.revoke(self.repo, token)

    def update_profile(self, user_id: int, payload: dict[str, Any]) -> AuthenticatedUser:
        user = services.update_profile(self.repo, user_id, payload)
        row = self.repo.fetchone("SELECT * FROM users WHERE id = ?", (user["id"],))
        return AuthenticatedUser.from_row(self.repo, row)

    def soft_delete_user(self, user_id: int) -> None:
        services.soft_delete(self.repo, user_id)

    def has_permission(self, user_id: int, resource: str, action: str = "read") -> bool:
        return services.has_permission(self.repo, user_id, resource, action)

    def is_admin(self, user_id: int) -> bool:
        return services.is_admin(self.repo, user_id)

    def list_rules(self) -> list[dict[str, Any]]:
        return services.list_rules(self.repo)

    def save_rule(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        return services.upsert_rule(self.repo, payload)
