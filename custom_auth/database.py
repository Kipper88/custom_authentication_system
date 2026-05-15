from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from custom_auth.models import Action, Base, Resource, Role

DEFAULT_DATABASE_URL = "sqlite:///custom_auth.sqlite3"


def build_engine(database_url: str = DEFAULT_DATABASE_URL) -> Engine:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args, future=True)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def initialize_database(engine: Engine, seed: bool = True) -> None:
    Base.metadata.create_all(engine)
    if seed:
        session_factory = build_session_factory(engine)
        with session_scope(session_factory) as session:
            seed_demo_data(session)


def seed_demo_data(session: Session) -> None:
    if session.scalar(select(Role.id).where(Role.code == "admin")) is not None:
        return

    roles = {
        "admin": Role(code="admin", title="Administrator", description="Can manage access rules and read all resources"),
        "user": Role(code="user", title="Regular user", description="Can read regular documents"),
        "analyst": Role(code="analyst", title="Analyst", description="Can read documents and reports"),
    }
    resources = {
        "documents": Resource(code="documents", title="Documents", description="Business documents"),
        "reports": Resource(code="reports", title="Reports", description="Analytical reports"),
        "admin-dashboard": Resource(code="admin-dashboard", title="Admin dashboard", description="Administration metrics"),
    }
    actions = {"read": Action(code="read", title="Read")}
    session.add_all([*roles.values(), *resources.values(), *actions.values()])
    session.flush()

    from custom_auth.repositories import SqlAlchemyAuthRepository
    from custom_auth.security import hash_password

    repo = SqlAlchemyAuthRepository(session)
    repo.create_access_rule(roles["admin"], resources["documents"], actions["read"], True)
    repo.create_access_rule(roles["admin"], resources["reports"], actions["read"], True)
    repo.create_access_rule(roles["admin"], resources["admin-dashboard"], actions["read"], True)
    repo.create_access_rule(roles["user"], resources["documents"], actions["read"], True)
    repo.create_access_rule(roles["analyst"], resources["documents"], actions["read"], True)
    repo.create_access_rule(roles["analyst"], resources["reports"], actions["read"], True)
    repo.create_user(
        email="admin@example.com",
        first_name="System",
        last_name="Administrator",
        middle_name="",
        password_hash=hash_password("AdminPass123!"),
        role=roles["admin"],
    )
    repo.create_user(
        email="user@example.com",
        first_name="Demo",
        last_name="User",
        middle_name="",
        password_hash=hash_password("UserPass123!"),
        role=roles["user"],
    )
