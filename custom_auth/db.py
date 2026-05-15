import sqlite3
from pathlib import Path
from typing import Any

from custom_auth.security import hash_password


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    middle_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    action_id INTEGER NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    is_allowed INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (role_id, resource_id, action_id)
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
"""


class SQLiteRepository:
    def __init__(self, database: str | Path = "custom_auth.sqlite3"):
        self.database = str(database)
        self.connection = sqlite3.connect(self.database)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")

    def initialize(self, seed: bool = True) -> None:
        self.connection.executescript(SCHEMA)
        if seed:
            self.seed_demo_data()
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        cursor = self.connection.execute(query, params)
        self.connection.commit()
        return cursor

    def fetchone(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        return self.connection.execute(query, params).fetchone()

    def fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(self.connection.execute(query, params).fetchall())

    def seed_demo_data(self) -> None:
        if self.fetchone("SELECT id FROM roles WHERE code = ?", ("admin",)):
            return
        roles = [
            ("admin", "Administrator", "Can manage access rules and read all resources"),
            ("user", "Regular user", "Can read regular documents"),
            ("analyst", "Analyst", "Can read documents and reports"),
        ]
        resources = [
            ("documents", "Documents", "Business documents"),
            ("reports", "Reports", "Analytical reports"),
            ("admin-dashboard", "Admin dashboard", "Administration metrics"),
        ]
        actions = [("read", "Read")]
        self.connection.executemany("INSERT INTO roles (code, title, description) VALUES (?, ?, ?)", roles)
        self.connection.executemany("INSERT INTO resources (code, title, description) VALUES (?, ?, ?)", resources)
        self.connection.executemany("INSERT INTO actions (code, title) VALUES (?, ?)", actions)
        rules = [
            ("admin", "documents", "read", 1),
            ("admin", "reports", "read", 1),
            ("admin", "admin-dashboard", "read", 1),
            ("user", "documents", "read", 1),
            ("analyst", "documents", "read", 1),
            ("analyst", "reports", "read", 1),
        ]
        for role, resource, action, allowed in rules:
            self.connection.execute(
                """
                INSERT INTO access_rules (role_id, resource_id, action_id, is_allowed)
                SELECT roles.id, resources.id, actions.id, ?
                FROM roles, resources, actions
                WHERE roles.code = ? AND resources.code = ? AND actions.code = ?
                """,
                (allowed, role, resource, action),
            )
        users = [
            ("admin@example.com", "System", "Administrator", "", hash_password("AdminPass123!"), "admin"),
            ("user@example.com", "Demo", "User", "", hash_password("UserPass123!"), "user"),
        ]
        for email, first, last, middle, password_hash, role_code in users:
            cursor = self.connection.execute(
                "INSERT INTO users (email, first_name, last_name, middle_name, password_hash) VALUES (?, ?, ?, ?, ?)",
                (email, first, last, middle, password_hash),
            )
            self.connection.execute(
                "INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles WHERE code = ?",
                (cursor.lastrowid, role_code),
            )
