"""Functional, auth, role, database, and API verification tests for Phase 1 skeleton."""

import io
import sqlite3
import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    db_path = tmp_path / "test_unisecure.db"
    upload_dir = tmp_path / "uploads"
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(db_path),
            "UPLOAD_FOLDER": str(upload_dir),
            "SECRET_KEY": "test-secret",
            "JWT_SECRET": "test-jwt-secret",
        }
    )
    with app.test_client() as test_client:
        yield test_client, db_path


def _api_login(client, username: str, password: str) -> str:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


def test_health_and_seeded_database(client):
    test_client, db_path = client
    resp = test_client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"

    conn = sqlite3.connect(str(db_path))
    roles = {
        r[0]
        for r in conn.execute("SELECT DISTINCT role FROM users").fetchall()
    }
    conn.close()
    assert roles == {"student", "faculty", "admin"}


def test_authentication_lifecycle_web_and_api(client):
    test_client, _ = client

    # Unauthenticated API and Web checks
    assert test_client.get("/api/auth/me").status_code == 401
    assert test_client.get("/dashboard").status_code == 302

    # Invalid login
    bad = test_client.post("/api/auth/login", json={"username": "bilal", "password": "wrong"})
    assert bad.status_code == 401

    # Valid API login returns JWT + user profile
    token = _api_login(test_client, "bilal", "Student@123")
    me = test_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.get_json()["user"]["role"] == "student"

    # Register a new student and avoid duplicate
    reg = test_client.post(
        "/api/auth/register",
        json={
            "username": "ayesha",
            "email": "ayesha@unisecure.local",
            "password": "Student@123",
            "full_name": "Ayesha Khan",
            "identifier_no": "239999",
        },
    )
    assert reg.status_code == 201
    assert reg.get_json()["user"]["role"] == "student"

    dup = test_client.post(
        "/api/auth/register",
        json={
            "username": "ayesha",
            "email": "ayesha@unisecure.local",
            "password": "Student@123",
            "full_name": "Ayesha Khan",
            "identifier_no": "239999",
        },
    )
    assert dup.status_code == 409


def test_role_boundaries_student_faculty_admin(client):
    test_client, _ = client

    student_token = _api_login(test_client, "bilal", "Student@123")
    faculty_token = _api_login(test_client, "dr.sara", "Faculty@123")
    admin_token = _api_login(test_client, "admin", "Admin@123")

    # Student can view own published grades (bilal id=4), blocked from huraira (id=5)
    own_grades = test_client.get(
        "/api/students/4/grades",
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert own_grades.status_code == 200
    assert len(own_grades.get_json()["grades"]) == 1

    other_grades = test_client.get(
        "/api/students/5/grades",
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert other_grades.status_code == 403

    # Student blocked from grade update and admin endpoints
    assert (
        test_client.patch(
            "/api/grades/1",
            json={"score": 100},
            headers={"Authorization": f"Bearer {student_token}"},
        ).status_code
        == 403
    )
    assert (
        test_client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {student_token}"},
        ).status_code
        == 403
    )

    # Faculty (dr.sara, id=2) can update grade_id=1 (CY-351), blocked on grade_id=2 (CS-301, prof.tariq)
    ok_grade = test_client.patch(
        "/api/grades/1",
        json={"score": 91.0, "letter_grade": "A", "published": True},
        headers={"Authorization": f"Bearer {faculty_token}"},
    )
    assert ok_grade.status_code == 200
    assert ok_grade.get_json()["grade"]["score"] == 91.0

    other_course_grade = test_client.patch(
        "/api/grades/2",
        json={"score": 95.0},
        headers={"Authorization": f"Bearer {faculty_token}"},
    )
    assert other_course_grade.status_code == 403
    assert (
        test_client.get(
            "/api/admin/audit",
            headers={"Authorization": f"Bearer {faculty_token}"},
        ).status_code
        == 403
    )

    # Admin can list users, update role, and inspect audit logs
    users_resp = test_client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert users_resp.status_code == 200
    assert len(users_resp.get_json()["users"]) >= 6

    role_resp = test_client.patch(
        "/api/admin/roles/6",
        json={"role": "faculty"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert role_resp.status_code == 200
    assert role_resp.get_json()["user"]["role"] == "faculty"

    audit_resp = test_client.get(
        "/api/admin/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert audit_resp.status_code == 200
    assert any(a["action"] == "ADMIN_ROLE_UPDATED" for a in audit_resp.get_json()["audit_logs"])


def test_courses_enrollment_and_documents_flow(client):
    test_client, _ = client
    student_token = _api_login(test_client, "bilal", "Student@123")

    # Search courses
    courses = test_client.get(
        "/api/courses?q=CY-351",
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert courses.status_code == 200
    assert len(courses.get_json()["courses"]) == 1

    # Enroll in offering 2 (CY-320)
    enroll = test_client.post(
        "/api/enrollments",
        json={"offering_id": 2},
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert enroll.status_code == 201
    assert enroll.get_json()["enrollment"]["status"] == "pending"

    # Upload and retrieve document
    upload = test_client.post(
        "/api/documents",
        data={
            "title": "Lab 1 Notes",
            "visibility": "private",
            "file": (io.BytesIO(b"hello unisecure"), "notes.txt"),
        },
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert upload.status_code == 201
    doc_id = upload.get_json()["document"]["id"]

    download = test_client.get(
        f"/api/documents/{doc_id}",
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert download.status_code == 200
    assert b"hello unisecure" in download.data


def test_web_ui_login_and_dashboard_rendering(client):
    test_client, _ = client
    resp = test_client.post(
        "/login",
        data={"username": "admin", "password": "Admin@123"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"System Administrator" in resp.data
    assert b"Recent Audit Activity" in resp.data

    courses_page = test_client.get("/courses?q=CY-351")
    assert courses_page.status_code == 200
    assert b"Web Application Security" in courses_page.data
