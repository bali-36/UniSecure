"""Initialize and seed the local UniSecure SQLite database."""

import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
SEED_PATH = Path(__file__).resolve().parent / "seed.sql"

SEED_USERS = [
    (1, "admin", "admin@unisecure.local", "Admin@123", "System Administrator", "admin", 1, "ADM-001"),
    (2, "dr.sara", "sara@unisecure.local", "Faculty@123", "Dr. Sara Malik", "faculty", 1, "FAC-101"),
    (3, "prof.tariq", "tariq@unisecure.local", "Faculty@123", "Prof. Tariq Mahmood", "faculty", 2, "FAC-102"),
    (4, "bilal", "bilal@unisecure.local", "Student@123", "Muhammad Bilal Badar", "student", 1, "231285"),
    (5, "huraira", "huraira@unisecure.local", "Student@123", "Abu Huraira", "student", 1, "231257"),
    (6, "huzaifa", "huzaifa@unisecure.local", "Student@123", "Huzaifa Asad", "student", 1, "233642"),
]


def init_db(db_path: str | Path, upload_dir: str | Path | None = None, reset: bool = False) -> None:
    """Create schema and populate synthetic seed data if the database is empty."""
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    if reset and db_file.exists():
        db_file.unlink()

    if upload_dir is not None:
        Path(upload_dir).mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.executescript(SEED_PATH.read_text(encoding="utf-8"))

        for uid, username, email, raw_pw, full_name, role, dept_id, ident in SEED_USERS:
            conn.execute(
                """
                INSERT OR IGNORE INTO users
                    (id, username, email, password_hash, full_name, role, department_id, identifier_no)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (uid, username, email, generate_password_hash(raw_pw), full_name, role, dept_id, ident),
            )

        conn.executemany(
            """
            INSERT OR IGNORE INTO course_offerings
                (id, course_id, semester, faculty_id, capacity, schedule, notice_board)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "Fall 2026", 2, 40, "Mon/Wed 10:00-11:30", "Phase 1 Skeleton & Threat Model due Week 11."),
                (2, 2, "Fall 2026", 2, 35, "Tue/Thu 11:30-13:00", "Lab 4 packet capture instructions posted."),
                (3, 3, "Fall 2026", 3, 45, "Mon/Wed 14:00-15:30", "Midterm normalization review on Friday."),
            ],
        )

        conn.executemany(
            """
            INSERT OR IGNORE INTO enrollments (id, student_id, offering_id, status)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1, 4, 1, "enrolled"),
                (2, 4, 3, "enrolled"),
                (3, 5, 1, "enrolled"),
                (4, 6, 2, "pending"),
            ],
        )

        conn.executemany(
            """
            INSERT OR IGNORE INTO grades (id, enrollment_id, score, letter_grade, published, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, 88.5, "A", 1, 2),
                (2, 2, 79.0, "B+", 0, 3),
                (3, 3, 84.0, "A-", 1, 2),
            ],
        )

        if upload_dir is not None:
            sample_file = Path(upload_dir) / "cy351_syllabus.txt"
            if not sample_file.exists():
                sample_file.write_text(
                    "UniSecure Synthetic Sample Document: CY-351 Web Application Security Syllabus.\n",
                    encoding="utf-8",
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO documents
                    (id, owner_id, offering_id, title, filename, stored_path, mime_type, size_bytes, visibility)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    1,
                    2,
                    1,
                    "CY-351 Course Syllabus",
                    "cy351_syllabus.txt",
                    str(sample_file),
                    "text/plain",
                    sample_file.stat().st_size,
                    "course",
                ),
            )
            # Private student submission example for later IDOR/BOLA mapping
            submission_file = Path(upload_dir) / "bilal_phase1_draft.txt"
            if not submission_file.exists():
                submission_file.write_text(
                    "Synthetic student submission for Bilal (231285).\n",
                    encoding="utf-8",
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO documents
                    (id, owner_id, offering_id, title, filename, stored_path, mime_type, size_bytes, visibility)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    2,
                    4,
                    1,
                    "Bilal Phase 1 Draft Submission",
                    "bilal_phase1_draft.txt",
                    str(submission_file),
                    "text/plain",
                    submission_file.stat().st_size,
                    "private",
                ),
            )

        conn.execute(
            """
            INSERT OR IGNORE INTO audit_logs (id, actor_id, action, target_type, target_id, details, ip_address)
            VALUES (1, 1, 'SYSTEM_SEED', 'database', 'init', 'Initial synthetic Phase 1 seed completed.', '127.0.0.1')
            """
        )

        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    default_db = BASE_DIR / "instance" / "unisecure.db"
    default_uploads = BASE_DIR / "instance" / "uploads"
    init_db(default_db, default_uploads)
    print(f"Initialized SQLite database at {default_db}")
