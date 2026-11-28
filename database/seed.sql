-- Synthetic Seed Data for UniSecure (Phase 1)
-- Passwords for all seeded accounts are initialized by database/init_db.py:
--   admin / Admin@123
--   dr.sara / Faculty@123
--   prof.tariq / Faculty@123
--   bilal / Student@123
--   huraira / Student@123
--   huzaifa / Student@123

INSERT OR IGNORE INTO departments (id, code, name) VALUES
    (1, 'CYS', 'Department of Cyber Security'),
    (2, 'CS', 'Department of Computer Science');

INSERT OR IGNORE INTO courses (id, code, title, credit_hours, department_id, description) VALUES
    (1, 'CY-351', 'Web Application Security', 3, 1, 'Secure web architecture, vulnerability assessment, and hardening.'),
    (2, 'CY-320', 'Network & Protocol Security', 3, 1, 'TLS, IPsec, packet analysis, and defensive network architecture.'),
    (3, 'CS-301', 'Database Management Systems', 3, 2, 'Relational modeling, SQL, indexing, and transaction integrity.');

-- Note: Users are seeded via init_db.py so password hashes match Werkzeug hashing.
