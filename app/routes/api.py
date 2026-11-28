"""REST API endpoints for UniSecure (Phase 1 Vulnerable Skeleton)."""

import sqlite3
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, send_file, session
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app.models.db import get_db, log_audit
from app.services.auth_service import (
    authenticate_user,
    issue_jwt_token,
    load_current_user,
    login_required,
    register_student,
    roles_required,
    serialize_user,
)

api_bp = Blueprint("api", __name__)


@api_bp.route("/health", methods=["GET"])
def health():
    """Public health check endpoint."""
    return jsonify({"status": "ok", "service": "UniSecure", "phase": "1-skeleton"})


@api_bp.route("/auth/login", methods=["POST"])
def api_login():
    """Authenticate a user and establish both session cookie and Bearer JWT."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user = authenticate_user(username, password)
    if user is None:
        log_audit(
            "LOGIN_FAILED",
            "auth",
            username,
            "Invalid credentials",
            ip_address=request.remote_addr or "127.0.0.1",
        )
        return jsonify({"error": "Invalid credentials"}), 401

    session.clear()
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    token = issue_jwt_token(user)

    log_audit(
        "LOGIN_SUCCESS",
        "user",
        user["id"],
        f"Logged in via API as {user['role']}",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"token": token, "user": serialize_user(user)})


@api_bp.route("/auth/register", methods=["POST"])
def api_register():
    """Register a new student account."""
    data = request.get_json(silent=True) or {}
    required = ("username", "email", "password", "full_name", "identifier_no")
    missing = [k for k in required if not (data.get(k) or "").strip()]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        user = register_student(
            username=data["username"],
            email=data["email"],
            password=data["password"],
            full_name=data["full_name"],
            identifier_no=data["identifier_no"],
            department_id=int(data.get("department_id", 1)),
        )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username, email, or identifier_no already exists"}), 409

    log_audit(
        "USER_REGISTERED",
        "user",
        user["id"],
        f"Self-registered student {user['username']}",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"user": serialize_user(user)}), 201


@api_bp.route("/auth/logout", methods=["POST"])
@login_required
def api_logout():
    """Clear server session cookie for the authenticated user."""
    user = load_current_user()
    log_audit(
        "LOGOUT",
        "user",
        user["id"],
        "Session cleared via API",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    session.clear()
    return jsonify({"message": "Logged out"})


@api_bp.route("/auth/me", methods=["GET"])
@login_required
def api_me():
    """Return profile of the currently authenticated user."""
    user = load_current_user()
    return jsonify({"user": serialize_user(user)})


@api_bp.route("/courses", methods=["GET"])
@login_required
def list_courses():
    """List course offerings with optional keyword search."""
    q = (request.args.get("q") or "").strip()
    db = get_db()
    sql = """
        SELECT co.id AS offering_id, c.code, c.title, c.credit_hours, c.description,
               co.semester, co.capacity, co.schedule, co.notice_board,
               u.id AS faculty_id, u.full_name AS faculty_name,
               d.code AS department_code
        FROM course_offerings co
        JOIN courses c ON c.id = co.course_id
        JOIN users u ON u.id = co.faculty_id
        JOIN departments d ON d.id = c.department_id
    """
    params: list = []
    if q:
        sql += " WHERE c.code LIKE ? OR c.title LIKE ?"
        like = f"%{q}%"
        params.extend([like, like])
    sql += " ORDER BY c.code"
    rows = db.execute(sql, params).fetchall()
    return jsonify({"courses": [dict(r) for r in rows]})


@api_bp.route("/courses/<int:offering_id>", methods=["GET"])
@login_required
def get_course(offering_id: int):
    """Return details for a single course offering."""
    db = get_db()
    row = db.execute(
        """
        SELECT co.id AS offering_id, c.code, c.title, c.credit_hours, c.description,
               co.semester, co.capacity, co.schedule, co.notice_board,
               u.id AS faculty_id, u.full_name AS faculty_name
        FROM course_offerings co
        JOIN courses c ON c.id = co.course_id
        JOIN users u ON u.id = co.faculty_id
        WHERE co.id = ?
        """,
        (offering_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "Course offering not found"}), 404
    return jsonify({"course": dict(row)})


@api_bp.route("/enrollments", methods=["GET"])
@login_required
def list_enrollments():
    """List enrollments visible to the current role."""
    user = load_current_user()
    db = get_db()
    base_sql = """
        SELECT e.id, e.student_id, s.full_name AS student_name, s.identifier_no,
               e.offering_id, c.code AS course_code, c.title AS course_title,
               co.semester, e.status, e.requested_at
        FROM enrollments e
        JOIN users s ON s.id = e.student_id
        JOIN course_offerings co ON co.id = e.offering_id
        JOIN courses c ON c.id = co.course_id
    """
    if user["role"] == "student":
        rows = db.execute(base_sql + " WHERE e.student_id = ? ORDER BY e.id", (user["id"],)).fetchall()
    elif user["role"] == "faculty":
        rows = db.execute(base_sql + " WHERE co.faculty_id = ? ORDER BY e.id", (user["id"],)).fetchall()
    else:
        rows = db.execute(base_sql + " ORDER BY e.id").fetchall()
    return jsonify({"enrollments": [dict(r) for r in rows]})


@api_bp.route("/enrollments", methods=["POST"])
@roles_required("student", "admin")
def create_enrollment():
    """Submit a course enrollment request with capacity check."""
    user = load_current_user()
    data = request.get_json(silent=True) or {}
    offering_id = data.get("offering_id")
    if not offering_id:
        return jsonify({"error": "offering_id is required"}), 400

    student_id = user["id"] if user["role"] == "student" else int(data.get("student_id", user["id"]))
    db = get_db()
    offering = db.execute("SELECT * FROM course_offerings WHERE id = ?", (offering_id,)).fetchone()
    if offering is None:
        return jsonify({"error": "Course offering not found"}), 404

    current_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM enrollments WHERE offering_id = ? AND status IN ('pending', 'enrolled')",
        (offering_id,),
    ).fetchone()["cnt"]
    if current_count >= offering["capacity"]:
        return jsonify({"error": "Course offering is at full capacity"}), 409

    try:
        cursor = db.execute(
            "INSERT INTO enrollments (student_id, offering_id, status) VALUES (?, ?, 'pending')",
            (student_id, offering_id),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Student already enrolled or pending in this offering"}), 409

    enrollment = db.execute("SELECT * FROM enrollments WHERE id = ?", (cursor.lastrowid,)).fetchone()
    log_audit(
        "ENROLLMENT_REQUESTED",
        "enrollment",
        enrollment["id"],
        f"Student {student_id} requested offering {offering_id}",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"enrollment": dict(enrollment)}), 201


@api_bp.route("/enrollments/<int:enrollment_id>", methods=["GET"])
@login_required
def get_enrollment(enrollment_id: int):
    """Retrieve a single enrollment record."""
    user = load_current_user()
    db = get_db()
    row = db.execute(
        """
        SELECT e.*, co.faculty_id, c.code AS course_code, c.title AS course_title
        FROM enrollments e
        JOIN course_offerings co ON co.id = e.offering_id
        JOIN courses c ON c.id = co.course_id
        WHERE e.id = ?
        """,
        (enrollment_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "Enrollment not found"}), 404
    if user["role"] == "student" and row["student_id"] != user["id"]:
        return jsonify({"error": "Forbidden"}), 403
    if user["role"] == "faculty" and row["faculty_id"] != user["id"]:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"enrollment": dict(row)})


@api_bp.route("/students/<int:student_id>/grades", methods=["GET"])
@login_required
def get_student_grades(student_id: int):
    """Retrieve grades for a student (self, assigned faculty, or admin)."""
    user = load_current_user()
    if user["role"] == "student" and user["id"] != student_id:
        return jsonify({"error": "Forbidden: cannot view another student's grades"}), 403

    db = get_db()
    sql = """
        SELECT g.id AS grade_id, g.enrollment_id, g.score, g.letter_grade, g.published,
               g.updated_at, c.code AS course_code, c.title AS course_title, co.semester
        FROM grades g
        JOIN enrollments e ON e.id = g.enrollment_id
        JOIN course_offerings co ON co.id = e.offering_id
        JOIN courses c ON c.id = co.course_id
        WHERE e.student_id = ?
    """
    params: list = [student_id]
    if user["role"] == "student":
        sql += " AND g.published = 1"
    elif user["role"] == "faculty":
        sql += " AND co.faculty_id = ?"
        params.append(user["id"])

    rows = db.execute(sql, params).fetchall()
    return jsonify({"student_id": student_id, "grades": [dict(r) for r in rows]})


@api_bp.route("/grades/<int:grade_id>", methods=["PATCH"])
@roles_required("faculty", "admin")
def update_grade(grade_id: int):
    """Update a student's grade (assigned faculty or admin)."""
    user = load_current_user()
    db = get_db()
    row = db.execute(
        """
        SELECT g.*, co.faculty_id
        FROM grades g
        JOIN enrollments e ON e.id = g.enrollment_id
        JOIN course_offerings co ON co.id = e.offering_id
        WHERE g.id = ?
        """,
        (grade_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "Grade record not found"}), 404
    if user["role"] == "faculty" and row["faculty_id"] != user["id"]:
        return jsonify({"error": "Forbidden: not assigned to this course offering"}), 403

    data = request.get_json(silent=True) or {}
    score = data.get("score", row["score"])
    letter_grade = data.get("letter_grade", row["letter_grade"])
    published = int(bool(data.get("published", row["published"])))

    db.execute(
        """
        UPDATE grades
        SET score = ?, letter_grade = ?, published = ?, updated_by = ?, updated_at = datetime('now')
        WHERE id = ?
        """,
        (score, letter_grade, published, user["id"], grade_id),
    )
    db.commit()
    updated = db.execute("SELECT * FROM grades WHERE id = ?", (grade_id,)).fetchone()
    log_audit(
        "GRADE_UPDATED",
        "grade",
        grade_id,
        f"score={score}, letter={letter_grade}, published={published}",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"grade": dict(updated)})


@api_bp.route("/documents", methods=["GET"])
@login_required
def list_documents():
    """List documents accessible to the current user."""
    user = load_current_user()
    db = get_db()
    if user["role"] == "admin":
        rows = db.execute("SELECT * FROM documents ORDER BY id").fetchall()
    else:
        rows = db.execute(
            """
            SELECT * FROM documents
            WHERE owner_id = ? OR visibility IN ('course', 'public')
            ORDER BY id
            """,
            (user["id"],),
        ).fetchall()
    return jsonify({"documents": [dict(r) for r in rows]})


@api_bp.route("/documents", methods=["POST"])
@login_required
def upload_document():
    """Upload a document and record its metadata."""
    user = load_current_user()
    if "file" not in request.files:
        return jsonify({"error": "Multipart file field 'file' is required"}), 400

    uploaded = request.files["file"]
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Empty filename"}), 400

    safe_name = secure_filename(uploaded.filename) or "upload.bin"
    title = (request.form.get("title") or safe_name).strip()
    visibility = request.form.get("visibility", "private")
    if visibility not in ("private", "course", "public"):
        visibility = "private"
    offering_id = request.form.get("offering_id", type=int)

    upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    target_path = upload_dir / f"u{user['id']}_{safe_name}"
    uploaded.save(str(target_path))

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO documents (owner_id, offering_id, title, filename, stored_path, mime_type, size_bytes, visibility)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            offering_id,
            title,
            safe_name,
            str(target_path),
            uploaded.mimetype or "application/octet-stream",
            target_path.stat().st_size,
            visibility,
        ),
    )
    db.commit()
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (cursor.lastrowid,)).fetchone()
    log_audit(
        "DOCUMENT_UPLOADED",
        "document",
        doc["id"],
        f"Uploaded {safe_name} ({visibility})",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"document": dict(doc)}), 201


@api_bp.route("/documents/<int:doc_id>", methods=["GET"])
@login_required
def get_document(doc_id: int):
    """Download a document if authorized."""
    user = load_current_user()
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if doc is None:
        return jsonify({"error": "Document not found"}), 404
    if doc["visibility"] == "private" and doc["owner_id"] != user["id"] and user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403

    path = Path(doc["stored_path"])
    if not path.exists():
        return jsonify({"error": "Stored file missing on disk"}), 404
    return send_file(path, as_attachment=True, download_name=doc["filename"])


@api_bp.route("/admin/users", methods=["GET"])
@roles_required("admin")
def admin_list_users():
    """List all user accounts (admin only)."""
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    return jsonify({"users": [serialize_user(r) for r in rows]})


@api_bp.route("/admin/users", methods=["POST"])
@roles_required("admin")
def admin_create_user():
    """Create a user account with an explicit role (admin only)."""
    admin_user = load_current_user()
    data = request.get_json(silent=True) or {}
    required = ("username", "email", "password", "full_name", "role", "identifier_no")
    missing = [k for k in required if not (data.get(k) or "").strip()]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400
    if data["role"] not in ("student", "faculty", "admin"):
        return jsonify({"error": "Invalid role"}), 400

    db = get_db()
    try:
        cursor = db.execute(
            """
            INSERT INTO users
                (username, email, password_hash, full_name, role, department_id, identifier_no)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["username"].strip(),
                data["email"].strip().lower(),
                generate_password_hash(data["password"]),
                data["full_name"].strip(),
                data["role"],
                int(data.get("department_id", 1)),
                data["identifier_no"].strip(),
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Duplicate username, email, or identifier_no"}), 409

    created = db.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    log_audit(
        "ADMIN_USER_CREATED",
        "user",
        created["id"],
        f"Created {created['username']} with role {created['role']}",
        actor_id=admin_user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"user": serialize_user(created)}), 201


@api_bp.route("/admin/roles/<int:user_id>", methods=["PATCH"])
@roles_required("admin")
def admin_update_role(user_id: int):
    """Update a user's role (admin only)."""
    admin_user = load_current_user()
    data = request.get_json(silent=True) or {}
    new_role = data.get("role")
    if new_role not in ("student", "faculty", "admin"):
        return jsonify({"error": "role must be student, faculty, or admin"}), 400

    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        return jsonify({"error": "User not found"}), 404

    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    updated = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    log_audit(
        "ADMIN_ROLE_UPDATED",
        "user",
        user_id,
        f"Changed role from {target['role']} to {new_role}",
        actor_id=admin_user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    return jsonify({"user": serialize_user(updated)})


@api_bp.route("/admin/audit", methods=["GET"])
@roles_required("admin")
def admin_audit_logs():
    """Return recent audit log entries (admin only)."""
    db = get_db()
    rows = db.execute(
        """
        SELECT a.*, u.username AS actor_username
        FROM audit_logs a
        LEFT JOIN users u ON u.id = a.actor_id
        ORDER BY a.id DESC
        LIMIT 50
        """
    ).fetchall()
    return jsonify({"audit_logs": [dict(r) for r in rows]})
