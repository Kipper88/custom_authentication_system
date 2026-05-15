from __future__ import annotations

from datetime import datetime

from sqlalchemy import Select, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from custom_auth.models import AccessRule, Action, AuthSession, Resource, Role, User, UserRole, utcnow


class DuplicateUserError(Exception):
    pass


class UnknownAccessRulePartError(Exception):
    pass


class SqlAlchemyAuthRepository:
    """Persistence boundary for the auth service.

    Service code talks to this repository instead of constructing SQL queries
    itself. Swapping SQLite for PostgreSQL is a database URL change, not a
    rewrite of authentication rules.
    """

    def __init__(self, session: Session):
        self.session = session

    def create_user(
        self,
        *,
        email: str,
        first_name: str,
        last_name: str,
        middle_name: str,
        password_hash: str,
        role: Role,
    ) -> User:
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            password_hash=password_hash,
        )
        user.roles.append(UserRole(role=role))
        self.session.add(user)
        try:
            self.session.flush()
        except IntegrityError as exc:
            raise DuplicateUserError("User with this email already exists") from exc
        return user

    def create_access_rule(self, role: Role, resource: Resource, action: Action, is_allowed: bool) -> AccessRule:
        rule = AccessRule(role=role, resource=resource, action=action, is_allowed=is_allowed)
        self.session.add(rule)
        self.session.flush()
        return rule

    def get_role(self, code: str) -> Role | None:
        return self.session.scalar(select(Role).where(Role.code == code))

    def get_resource(self, code: str) -> Resource | None:
        return self.session.scalar(select(Resource).where(Resource.code == code))

    def get_action(self, code: str) -> Action | None:
        return self.session.scalar(select(Action).where(Action.code == code))

    def get_active_user_by_email(self, email: str) -> User | None:
        return self.session.scalar(self._user_query().where(User.email == email, User.is_active.is_(True)))

    def get_active_user_by_token_hash(self, token_hash: str, now: datetime) -> User | None:
        session = self.session.scalar(
            select(AuthSession)
            .options(joinedload(AuthSession.user).joinedload(User.roles).joinedload(UserRole.role))
            .where(
                AuthSession.token_hash == token_hash,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
            )
        )
        if session is None or not session.user.is_active:
            return None
        session.last_seen_at = now
        return session.user

    def get_user(self, user_id: int) -> User | None:
        return self.session.scalar(self._user_query().where(User.id == user_id))

    def create_session(self, user: User, token_hash: str, expires_at: datetime) -> AuthSession:
        session = AuthSession(user=user, token_hash=token_hash, expires_at=expires_at)
        self.session.add(session)
        self.session.flush()
        return session

    def revoke_token(self, token_hash: str, revoked_at: datetime) -> None:
        self.session.execute(
            update(AuthSession)
            .where(AuthSession.token_hash == token_hash, AuthSession.revoked_at.is_(None))
            .values(revoked_at=revoked_at)
        )

    def revoke_user_sessions(self, user_id: int, revoked_at: datetime) -> None:
        self.session.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=revoked_at)
        )

    def user_has_permission(self, user_id: int, resource_code: str, action_code: str) -> bool:
        return self.session.scalar(
            select(AccessRule.id)
            .join(UserRole, UserRole.role_id == AccessRule.role_id)
            .join(Resource, Resource.id == AccessRule.resource_id)
            .join(Action, Action.id == AccessRule.action_id)
            .where(
                UserRole.user_id == user_id,
                Resource.code == resource_code,
                Action.code == action_code,
                AccessRule.is_allowed.is_(True),
            )
            .limit(1)
        ) is not None

    def user_is_admin(self, user_id: int) -> bool:
        return self.session.scalar(
            select(Role.id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id, Role.code == "admin")
            .limit(1)
        ) is not None

    def list_rules(self) -> list[AccessRule]:
        return list(
            self.session.scalars(
                select(AccessRule)
                .options(joinedload(AccessRule.role), joinedload(AccessRule.resource), joinedload(AccessRule.action))
                .order_by(AccessRule.id)
            )
        )

    def upsert_rule(self, role_code: str, resource_code: str, action_code: str, is_allowed: bool) -> AccessRule:
        role = self.get_role(role_code)
        resource = self.get_resource(resource_code)
        action = self.get_action(action_code)
        if role is None or resource is None or action is None:
            raise UnknownAccessRulePartError("Unknown role, resource or action")

        rule = self.session.scalar(
            select(AccessRule).where(
                AccessRule.role_id == role.id,
                AccessRule.resource_id == resource.id,
                AccessRule.action_id == action.id,
            )
        )
        if rule is None:
            rule = AccessRule(role=role, resource=resource, action=action)
            self.session.add(rule)
        rule.is_allowed = is_allowed
        rule.updated_at = utcnow()
        self.session.flush()
        return rule

    def _user_query(self) -> Select[tuple[User]]:
        return select(User).options(joinedload(User.roles).joinedload(UserRole.role))
