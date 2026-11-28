"""Authentication, session/JWT handling, and role guards for UniSecure."""

from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable

import jwt
from flask import current_app, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.models.db import get_db


def authenticate_user(username: str, password: str):
    """Verify username and password against the users table."""
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username.strip(),),
    ).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def register_student(
    username: str,
    email: str,
    password: str,
    full_name: str,
    identifier_no: str,
    department_id: int = 1,
):
    """Create a new student account and return the inserted user row."""
    db = get_db()
    pw_hash = generate_password_hash(password)
    cursor = db.execute(
        """
        INSERT INTO users
            (username, email, password_hash, full_name, role, department_id, identifier_no)
        VALUES (?, ?, ?, ?, 'student', ?, ?)
        """,
        (
            username.strip(),
            email.strip().lower(),
            pw_hash,
            full_name.strip(),
            department_id,
            identifier_no.strip(),
        ),
    )
    db.commit()
    return db.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()


def issue_jwt_token(user_row) -> str:
    """Issue a signed HS256 JWT for API callers."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_row["id"]),
        "username": user_row["username"],
        "role": user_row["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=4)).timestamp()),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def decode_jwt_token(token: str) -> dict | None:
    """Decode an HS256 JWT token; returns None on invalid or expired token."""
    try:
        return jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=["HS256"],
        )
    except jwt.PyJWTError:
        return None


def load_current_user():
    """Resolve current user from Bearer JWT first, then Flask session cookie."""
    if hasattr(g, "current_user"):
        return g.current_user

    user = None
    db = get_db()

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        claims = decode_jwt_token(token)
        if claims and "sub" in claims:
            user = db.execute(
                "SELECT * FROM users WHERE id = ? AND is_active = 1",
                (int(claims["sub"]),),
            ).fetchone()

    if user is None and session.get("user_id") is not None:
        user = db.execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1",
            (session["user_id"],),
        ).fetchone()

    g.current_user = user
    return user


def _is_api_request() -> bool:
    return request.path.startswith("/api/")


def login_required(fn: Callable) -> Callable:
    """Require an authenticated session or Bearer JWT."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = load_current_user()
        if user is None:
            if _is_api_request():
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("web.login"))
        return fn(*args, **kwargs)

    return wrapper


def roles_required(*allowed_roles: str) -> Callable:
    """Require an authenticated user whose role is in allowed_roles."""

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = load_current_user()
            if user is None:
                if _is_api_request():
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("web.login"))
            if user["role"] not in allowed_roles:
                if _is_api_request():
                    return jsonify({"error": "Forbidden: insufficient role"}), 403
                return jsonify({"error": "Forbidden: insufficient role"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def serialize_user(user_row) -> dict:
    """Return non-sensitive user representation."""
    return {
        "id": user_row["id"],
        "username": user_row["username"],
        "email": user_row["email"],
        "full_name": user_row["full_name"],
        "role": user_row["role"],
        "department_id": user_row["department_id"],
        "identifier_no": user_row["identifier_no"],
        "is_active": bool(user_row["is_active"]),
    }
