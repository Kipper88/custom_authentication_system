from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from custom_auth.models import AccessRule, User
from custom_auth.repositories import DuplicateUserError, SqlAlchemyAuthRepository, UnknownAccessRulePartError
from custom_auth.security import hash_password, hash_token, new_token, verify_password

TOKEN_TTL = timedelta(hours=12)


class AuthenticationError(Exception):
    pass


class ConflictError(Exception):
    pass


class ValidationError(Exception):
    pass


class AccessRuleError(Exception):
    pass


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    email: str
    first_name: str
    last_name: str
    middle_name: str
    is_active: bool
    roles: tuple[str, ...]

    @classmethod
    def from_model(cls, user: User) -> "AuthenticatedUser":
        return cls(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            middle_name=user.middle_name,
            is_active=user.is_active,
            roles=tuple(link.role.code for link in user.roles),
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


class AuthService:
    """Business rules for authentication and authorization."""

    def __init__(self, repo: SqlAlchemyAuthRepository):
        self.repo = repo

    def register(self, payload: dict[str, Any]) -> AuthenticatedUser:
        password = payload.get("password", "")
        if password != payload.get("password_repeat", ""):
            raise ValidationError("Passwords do not match")
        for field in ["email", "first_name", "last_name", "password"]:
            if not payload.get(field):
                raise ValidationError("email, first_name, last_name and password are required")
        role = self.repo.get_role("user")
        if role is None:
            raise ValidationError("Default user role is not configured")
        try:
            user = self.repo.create_user(
                email=payload["email"].strip().lower(),
                first_name=payload["first_name"].strip(),
                last_name=payload["last_name"].strip(),
                middle_name=payload.get("middle_name", "").strip(),
                password_hash=hash_password(password),
                role=role,
            )
        except DuplicateUserError as exc:
            raise ConflictError(str(exc)) from exc
        return AuthenticatedUser.from_model(user)

    def login(self, email: str, password: str) -> LoginResult:
        user = self.repo.get_active_user_by_email(email.strip().lower())
        if user is None or not verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid email or password")
        token = new_token()
        self.repo.create_session(user, hash_token(token), self._expires_at())
        return LoginResult(token=token, user=AuthenticatedUser.from_model(user))

    def identify_token(self, token: str | None) -> AuthenticatedUser | None:
        if not token:
            return None
        user = self.repo.get_active_user_by_token_hash(hash_token(token), self._now())
        if user is None:
            return None
        return AuthenticatedUser.from_model(user)

    def logout(self, token: str | None) -> None:
        if token:
            self.repo.revoke_token(hash_token(token), self._now())

    def update_profile(self, user_id: int, payload: dict[str, Any]) -> AuthenticatedUser:
        user = self.repo.get_user(user_id)
        if user is None or not user.is_active:
            raise AuthenticationError("User is not active")
        for field in ["first_name", "last_name", "middle_name"]:
            if field in payload:
                setattr(user, field, payload[field].strip())
        return AuthenticatedUser.from_model(user)

    def soft_delete_user(self, user_id: int) -> None:
        user = self.repo.get_user(user_id)
        if user is None:
            return
        now = self._now()
        user.is_active = False
        user.deleted_at = now
        self.repo.revoke_user_sessions(user_id, now)

    def has_permission(self, user_id: int, resource: str, action: str = "read") -> bool:
        return self.repo.user_has_permission(user_id, resource, action)

    def is_admin(self, user_id: int) -> bool:
        return self.repo.user_is_admin(user_id)

    def list_rules(self) -> list[dict[str, Any]]:
        return [self._rule_to_dict(rule) for rule in self.repo.list_rules()]

    def save_rule(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            self.repo.upsert_rule(
                role_code=payload["role"],
                resource_code=payload["resource"],
                action_code=payload["action"],
                is_allowed=bool(payload.get("is_allowed", True)),
            )
        except KeyError as exc:
            raise AccessRuleError("role, resource and action are required") from exc
        except UnknownAccessRulePartError as exc:
            raise AccessRuleError(str(exc)) from exc
        return self.list_rules()

    def _rule_to_dict(self, rule: AccessRule) -> dict[str, Any]:
        return {
            "id": rule.id,
            "role": rule.role.code,
            "resource": rule.resource.code,
            "action": rule.action.code,
            "is_allowed": rule.is_allowed,
        }

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _expires_at(self) -> datetime:
        return self._now() + TOKEN_TTL
