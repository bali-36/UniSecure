"""Web UI routes for UniSecure (Phase 1 Vulnerable Skeleton)."""

import sqlite3
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from app.models.db import get_db, log_audit
from app.services.auth_service import (
    authenticate_user,
    load_current_user,
    login_required,
    register_student,
)

web_bp = Blueprint("web", __name__)


@web_bp.route("/")
def index():
    """Redirect authenticated users to dashboard, otherwise to login."""
    if load_current_user() is not None:
        return redirect(url_for("web.dashboard"))
    return redirect(url_for("web.login"))


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    """Render and handle browser login form."""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = authenticate_user(username, password)
        if user is None:
            log_audit(
                "LOGIN_FAILED",
                "auth",
                username,
                "Invalid web login",
                ip_address=request.remote_addr or "127.0.0.1",
            )
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        log_audit(
            "LOGIN_SUCCESS",
            "user",
            user["id"],
            f"Web login as {user['role']}",
            actor_id=user["id"],
            ip_address=request.remote_addr or "127.0.0.1",
        )
        return redirect(url_for("web.dashboard"))

    return render_template("login.html")


@web_bp.route("/register", methods=["GET", "POST"])
def register():
    """Render and handle student self-registration."""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        full_name = (request.form.get("full_name") or "").strip()
        identifier_no = (request.form.get("identifier_no") or "").strip()
        if not all([username, email, password, full_name, identifier_no]):
            flash("All fields are required.", "warning")
            return render_template("register.html"), 400

        try:
            user = register_student(username, email, password, full_name, identifier_no)
        except sqlite3.IntegrityError:
            flash("Username, email, or roll number already exists.", "danger")
            return render_template("register.html"), 409

        log_audit(
            "USER_REGISTERED",
            "user",
            user["id"],
            f"Web self-registration {user['username']}",
            actor_id=user["id"],
            ip_address=request.remote_addr or "127.0.0.1",
        )
        flash("Account created. Please sign in.", "success")
        return redirect(url_for("web.login"))

    return render_template("register.html")


@web_bp.route("/logout", methods=["POST"])
def logout():
    """Log out current browser user."""
    user = load_current_user()
    if user is not None:
        log_audit(
            "LOGOUT",
            "user",
            user["id"],
            "Web logout",
            actor_id=user["id"],
            ip_address=request.remote_addr or "127.0.0.1",
        )
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("web.login"))


@web_bp.route("/dashboard")
@login_required
def dashboard():
    """Role-aware portal dashboard."""
    user = load_current_user()
    db = get_db()

    offerings = db.execute(
        """
        SELECT co.id AS offering_id, c.code, c.title, co.semester, co.schedule,
               co.notice_board, u.full_name AS faculty_name
        FROM course_offerings co
        JOIN courses c ON c.id = co.course_id
        JOIN users u ON u.id = co.faculty_id
        ORDER BY c.code
        """
    ).fetchall()

    enrollments = []
    grades = []
    users_list = []
    audit_logs = []

    if user["role"] == "student":
        enrollments = db.execute(
            """
            SELECT e.id, c.code, c.title, co.semester, e.status
            FROM enrollments e
            JOIN course_offerings co ON co.id = e.offering_id
            JOIN courses c ON c.id = co.course_id
            WHERE e.student_id = ?
            """,
            (user["id"],),
        ).fetchall()
        grades = db.execute(
            """
            SELECT g.id, c.code, c.title, g.score, g.letter_grade
            FROM grades g
            JOIN enrollments e ON e.id = g.enrollment_id
            JOIN course_offerings co ON co.id = e.offering_id
            JOIN courses c ON c.id = co.course_id
            WHERE e.student_id = ? AND g.published = 1
            """,
            (user["id"],),
        ).fetchall()
    elif user["role"] == "faculty":
        enrollments = db.execute(
            """
            SELECT e.id, s.full_name AS student_name, s.identifier_no,
                   c.code, c.title, e.status
            FROM enrollments e
            JOIN users s ON s.id = e.student_id
            JOIN course_offerings co ON co.id = e.offering_id
            JOIN courses c ON c.id = co.course_id
            WHERE co.faculty_id = ?
            """,
            (user["id"],),
        ).fetchall()
    else:
        users_list = db.execute(
            "SELECT id, username, full_name, role, identifier_no FROM users ORDER BY id"
        ).fetchall()
        audit_logs = db.execute(
            """
            SELECT a.id, a.action, a.target_type, a.target_id, a.details, a.created_at,
                   u.username AS actor_username
            FROM audit_logs a
            LEFT JOIN users u ON u.id = a.actor_id
            ORDER BY a.id DESC
            LIMIT 15
            """
        ).fetchall()

    documents = db.execute(
        """
        SELECT id, title, filename, visibility, owner_id, uploaded_at
        FROM documents
        WHERE ? = 'admin' OR owner_id = ? OR visibility IN ('course', 'public')
        ORDER BY id
        """,
        (user["role"], user["id"]),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        offerings=offerings,
        enrollments=enrollments,
        grades=grades,
        documents=documents,
        users_list=users_list,
        audit_logs=audit_logs,
    )


@web_bp.route("/courses")
@login_required
def courses():
    """Course catalog page with search."""
    user = load_current_user()
    q = (request.args.get("q") or "").strip()
    db = get_db()
    sql = """
        SELECT co.id AS offering_id, c.code, c.title, c.credit_hours, c.description,
               co.semester, co.capacity, co.schedule, co.notice_board,
               u.full_name AS faculty_name
        FROM course_offerings co
        JOIN courses c ON c.id = co.course_id
        JOIN users u ON u.id = co.faculty_id
    """
    params: list = []
    if q:
        sql += " WHERE c.code LIKE ? OR c.title LIKE ?"
        like = f"%{q}%"
        params.extend([like, like])
    sql += " ORDER BY c.code"
    rows = db.execute(sql, params).fetchall()
    return render_template("courses.html", user=user, offerings=rows, q=q)


@web_bp.route("/enrollments/request", methods=["POST"])
@login_required
def request_enrollment_web():
    """Submit enrollment request from web UI."""
    user = load_current_user()
    if user["role"] != "student":
        flash("Only students can submit self-enrollment requests.", "warning")
        return redirect(url_for("web.courses"))

    offering_id = request.form.get("offering_id", type=int)
    if not offering_id:
        flash("Invalid course offering.", "danger")
        return redirect(url_for("web.courses"))

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO enrollments (student_id, offering_id, status) VALUES (?, ?, 'pending')",
            (user["id"], offering_id),
        )
        db.commit()
        log_audit(
            "ENROLLMENT_REQUESTED",
            "enrollment",
            cursor.lastrowid,
            f"Web request for offering {offering_id}",
            actor_id=user["id"],
            ip_address=request.remote_addr or "127.0.0.1",
        )
        flash("Enrollment request submitted.", "success")
    except sqlite3.IntegrityError:
        flash("You already have an enrollment record for this course.", "warning")

    return redirect(url_for("web.dashboard"))


@web_bp.route("/documents/upload", methods=["POST"])
@login_required
def upload_document_web():
    """Handle document upload from dashboard."""
    user = load_current_user()
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file to upload.", "warning")
        return redirect(url_for("web.dashboard"))

    safe_name = secure_filename(uploaded.filename) or "upload.bin"
    title = (request.form.get("title") or safe_name).strip()
    visibility = request.form.get("visibility", "private")
    if visibility not in ("private", "course", "public"):
        visibility = "private"

    upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    target_path = upload_dir / f"u{user['id']}_{safe_name}"
    uploaded.save(str(target_path))

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO documents (owner_id, title, filename, stored_path, mime_type, size_bytes, visibility)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            title,
            safe_name,
            str(target_path),
            uploaded.mimetype or "application/octet-stream",
            target_path.stat().st_size,
            visibility,
        ),
    )
    db.commit()
    log_audit(
        "DOCUMENT_UPLOADED",
        "document",
        cursor.lastrowid,
        f"Web upload {safe_name}",
        actor_id=user["id"],
        ip_address=request.remote_addr or "127.0.0.1",
    )
    flash("Document uploaded.", "success")
    return redirect(url_for("web.dashboard"))


@web_bp.route("/documents/<int:doc_id>/download")
@login_required
def download_document_web(doc_id: int):
    """Download an authorized document from the web UI."""
    user = load_current_user()
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if doc is None:
        flash("Document not found.", "danger")
        return redirect(url_for("web.dashboard"))
    if doc["visibility"] == "private" and doc["owner_id"] != user["id"] and user["role"] != "admin":
        return "Forbidden", 403
    return send_file(doc["stored_path"], as_attachment=True, download_name=doc["filename"])
