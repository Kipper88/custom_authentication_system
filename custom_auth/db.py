"""Compatibility exports for database setup.

New code should import from `custom_auth.database`, `custom_auth.models` and
`custom_auth.repositories` directly. This module remains as a small bridge for
older examples that imported `custom_auth.db`.
"""

from custom_auth.database import DEFAULT_DATABASE_URL, build_engine, build_session_factory, initialize_database
from custom_auth.repositories import SqlAlchemyAuthRepository

__all__ = [
    "DEFAULT_DATABASE_URL",
    "SqlAlchemyAuthRepository",
    "build_engine",
    "build_session_factory",
    "initialize_database",
]
