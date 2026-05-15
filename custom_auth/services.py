from datetime import datetime, timedelta, timezone
from sqlite3 import IntegrityError

from custom_auth.security import hash_password, hash_token, new_token, verify_password

TOKEN_TTL = timedelta(hours=12)


class AuthenticationError(Exception):
    pass


class ConflictError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def expires_iso() -> str:
    return (datetime.now(timezone.utc) + TOKEN_TTL).isoformat()


def user_to_dict(repo, user):
    roles = [row["code"] for row in repo.fetchall(
        "SELECT roles.code FROM roles JOIN user_roles ON user_roles.role_id = roles.id WHERE user_roles.user_id = ?",
        (user["id"],),
    )]
    return {
        "id": user["id"],
        "email": user["email"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "middle_name": user["middle_name"],
        "is_active": bool(user["is_active"]),
        "roles": roles,
    }


def register(repo, payload):
    if payload.get("password") != payload.get("password_repeat"):
        raise ValueError("Passwords do not match")
    for field in ["email", "first_name", "last_name", "password"]:
        if not payload.get(field):
            raise ValueError("email, first_name, last_name and password are required")
    try:
        cursor = repo.execute(
            """
            INSERT INTO users (email, first_name, last_name, middle_name, password_hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload["email"].strip().lower(),
                payload["first_name"].strip(),
                payload["last_name"].strip(),
                payload.get("middle_name", "").strip(),
                hash_password(payload["password"]),
            ),
        )
    except IntegrityError as exc:
        raise ConflictError("User with this email already exists") from exc
    repo.execute(
        "INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles WHERE code = 'user'",
        (cursor.lastrowid,),
    )
    return user_to_dict(repo, repo.fetchone("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)))


def authenticate(repo, email, password):
    user = repo.fetchone("SELECT * FROM users WHERE email = ? AND is_active = 1", (email.strip().lower(),))
    if user is None or not verify_password(password, user["password_hash"]):
        raise AuthenticationError("Invalid email or password")
    token = new_token()
    repo.execute(
        "INSERT INTO auth_sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
        (user["id"], hash_token(token), expires_iso()),
    )
    return token, user_to_dict(repo, user)


def current_user(repo, token):
    if not token:
        return None
    row = repo.fetchone(
        """
        SELECT users.* FROM auth_sessions
        JOIN users ON users.id = auth_sessions.user_id
        WHERE auth_sessions.token_hash = ?
          AND auth_sessions.revoked_at IS NULL
          AND auth_sessions.expires_at > ?
          AND users.is_active = 1
        """,
        (hash_token(token), now_iso()),
    )
    if row:
        repo.execute("UPDATE auth_sessions SET last_seen_at = ? WHERE token_hash = ?", (now_iso(), hash_token(token)))
    return row


def revoke(repo, token):
    if token:
        repo.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (now_iso(), hash_token(token)),
        )


def soft_delete(repo, user_id):
    repo.execute("UPDATE users SET is_active = 0, deleted_at = ?, updated_at = ? WHERE id = ?", (now_iso(), now_iso(), user_id))
    repo.execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (now_iso(), user_id))


def update_profile(repo, user_id, payload):
    user = repo.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
    values = {"first_name": user["first_name"], "last_name": user["last_name"], "middle_name": user["middle_name"]}
    for field in values:
        if field in payload:
            values[field] = payload[field].strip()
    repo.execute(
        "UPDATE users SET first_name = ?, last_name = ?, middle_name = ?, updated_at = ? WHERE id = ?",
        (values["first_name"], values["last_name"], values["middle_name"], now_iso(), user_id),
    )
    return user_to_dict(repo, repo.fetchone("SELECT * FROM users WHERE id = ?", (user_id,)))


def has_permission(repo, user_id, resource, action):
    return repo.fetchone(
        """
        SELECT access_rules.id
        FROM access_rules
        JOIN user_roles ON user_roles.role_id = access_rules.role_id
        JOIN resources ON resources.id = access_rules.resource_id
        JOIN actions ON actions.id = access_rules.action_id
        WHERE user_roles.user_id = ?
          AND resources.code = ?
          AND actions.code = ?
          AND access_rules.is_allowed = 1
        LIMIT 1
        """,
        (user_id, resource, action),
    ) is not None


def is_admin(repo, user_id):
    return repo.fetchone(
        """
        SELECT roles.id FROM roles
        JOIN user_roles ON user_roles.role_id = roles.id
        WHERE user_roles.user_id = ? AND roles.code = 'admin'
        """,
        (user_id,),
    ) is not None


def list_rules(repo):
    return [dict(row) for row in repo.fetchall(
        """
        SELECT access_rules.id, roles.code AS role, resources.code AS resource,
               actions.code AS action, access_rules.is_allowed
        FROM access_rules
        JOIN roles ON roles.id = access_rules.role_id
        JOIN resources ON resources.id = access_rules.resource_id
        JOIN actions ON actions.id = access_rules.action_id
        ORDER BY access_rules.id
        """
    )]


def upsert_rule(repo, payload):
    repo.execute(
        """
        INSERT INTO access_rules (role_id, resource_id, action_id, is_allowed)
        SELECT roles.id, resources.id, actions.id, ?
        FROM roles, resources, actions
        WHERE roles.code = ? AND resources.code = ? AND actions.code = ?
        ON CONFLICT(role_id, resource_id, action_id) DO UPDATE SET
            is_allowed = excluded.is_allowed,
            updated_at = CURRENT_TIMESTAMP
        """,
        (1 if payload.get("is_allowed", True) else 0, payload["role"], payload["resource"], payload["action"]),
    )
    return list_rules(repo)
