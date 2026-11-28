-- UniSecure SQLite Relational Schema (Phase 1 Skeleton)
-- Adapted from Phase 0 MySQL design for local SQLite execution.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student', 'faculty', 'admin')),
    department_id INTEGER REFERENCES departments(id),
    identifier_no TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    credit_hours INTEGER NOT NULL DEFAULT 3,
    department_id INTEGER NOT NULL REFERENCES departments(id),
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS course_offerings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    semester TEXT NOT NULL,
    faculty_id INTEGER NOT NULL REFERENCES users(id),
    capacity INTEGER NOT NULL DEFAULT 40,
    schedule TEXT NOT NULL DEFAULT 'TBD',
    notice_board TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id),
    offering_id INTEGER NOT NULL REFERENCES course_offerings(id),
    status TEXT NOT NULL DEFAULT 'enrolled'
        CHECK (status IN ('pending', 'enrolled', 'dropped', 'completed')),
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (student_id, offering_id)
);

CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id INTEGER NOT NULL UNIQUE REFERENCES enrollments(id) ON DELETE CASCADE,
    score REAL,
    letter_grade TEXT,
    published INTEGER NOT NULL DEFAULT 0,
    updated_by INTEGER REFERENCES users(id),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    offering_id INTEGER REFERENCES course_offerings(id),
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'course', 'public')),
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
