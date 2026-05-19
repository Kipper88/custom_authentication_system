from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from custom_auth.database import build_engine, build_session_factory, initialize_database, session_scope
from custom_auth.repositories import SqlAlchemyAuthRepository
from custom_auth.services import AuthService, AuthenticatedUser, LoginResult

T = TypeVar("T")


class CustomAuthBackend:
    """Application-facing facade for custom auth.

    The facade owns SQLAlchemy session boundaries. Web adapters call this class,
    while `AuthService` contains business rules and `SqlAlchemyAuthRepository`
    contains database access.
    """

    def __init__(self, session_factory: sessionmaker[Session]):
        self.session_factory = session_factory

    @classmethod
    def from_engine(cls, engine: Engine, seed: bool = True) -> "CustomAuthBackend":
        initialize_database(engine, seed=seed)
        return cls(build_session_factory(engine))

    @classmethod
    def from_url(cls, database_url: str = "sqlite:///custom_auth.sqlite3", seed: bool = True) -> "CustomAuthBackend":
        return cls.from_engine(build_engine(database_url), seed=seed)

    @classmethod
    def with_sqlite(cls, database: str = "custom_auth.sqlite3", seed: bool = True) -> "CustomAuthBackend":
        return cls.from_url(f"sqlite:///{database}", seed=seed)

    def register(self, payload: dict[str, Any]) -> AuthenticatedUser:
        return self._write(lambda service: service.register(payload))

    def login(self, email: str, password: str) -> LoginResult:
        return self._write(lambda service: service.login(email, password))

    def identify_token(self, token: str | None) -> AuthenticatedUser | None:
        return self._write(lambda service: service.identify_token(token))

    def logout(self, token: str | None) -> None:
        self._write(lambda service: service.logout(token))

    def update_profile(self, user_id: int, payload: dict[str, Any]) -> AuthenticatedUser:
        return self._write(lambda service: service.update_profile(user_id, payload))

    def soft_delete_user(self, user_id: int) -> None:
        self._write(lambda service: service.soft_delete_user(user_id))

    def has_permission(self, user_id: int, resource: str, action: str = "read") -> bool:
        return self._read(lambda service: service.has_permission(user_id, resource, action))

    def is_admin(self, user_id: int) -> bool:
        return self._read(lambda service: service.is_admin(user_id))

    def list_rules(self) -> list[dict[str, Any]]:
        return self._read(lambda service: service.list_rules())

    def save_rule(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        return self._write(lambda service: service.save_rule(payload))

    def _read(self, callback: Callable[[AuthService], T]) -> T:
        with self.session_factory() as session:
            return callback(self._service(session))

    def _write(self, callback: Callable[[AuthService], T]) -> T:
        with session_scope(self.session_factory) as session:
            return callback(self._service(session))

    def _service(self, session: Session) -> AuthService:
        return AuthService(SqlAlchemyAuthRepository(session))
