# UniSecure – University Management Portal

## Project overview
UniSecure is an original university management portal. It supports three roles: Student, Faculty, and Administrator. The project will be maintained in two states: a deliberately Vulnerable Version for authorized local testing and a Hardened Version with security mitigations.

## Tech stack (Phase 1)
- Backend: Python 3.12 + Flask
- Database: SQLite (`instance/unisecure.db`, adapted from Phase 0 MySQL design for local execution without Docker/WSL)
- Frontend: HTML, CSS, JavaScript, Bootstrap 5
- API testing: Postman / pytest
- Security testing: Burp Suite Community and OWASP ZAP
- Version control: Git

## Planned modules
- Authentication and user profiles
- Student academic dashboard
- Faculty course and grade management
- Course catalog and enrollment workflow
- Academic records
- Document upload and retrieval
- Administration
- Authenticated REST API
- Audit/activity logging

## Roles
- Student: access own academic information and permitted student functions.
- Faculty: manage assigned courses and authorized academic records.
- Administrator: manage accounts, courses, assignments and platform records.

## Branch strategy
- `main`: documentation and stable integration point
- `vulnerable`: intentionally vulnerable application for controlled testing
- `hardened`: remediated application
- `v1-vulnerable`: tag for the final vulnerable state
- `v1-hardened`: tag for the final hardened state

## Planned vulnerability coverage
The project plans to implement and document at least eight distinct issues, including authentication/session weaknesses, BOLA/IDOR, function-level authorization failure, SQL injection, stored XSS, CSRF, CORS misconfiguration, insecure file upload, mass assignment/excessive data exposure, and a business-logic workflow bypass. Final coverage will be confirmed against the implemented application.

## Local setup (Phase 1 Skeleton)
1. Create and activate a Python virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
2. Optional: copy `.env.example` to `.env` (never commit `.env` or real credentials).
3. Initialize and seed the local SQLite database:
   ```powershell
   python database/init_db.py
   ```
4. Run the application:
   ```powershell
   python run.py
   ```
   Open `http://127.0.0.1:5000` in your browser.
5. Run automated tests:
   ```powershell
   pytest -v
   ```

### Seeded synthetic test accounts
- **Admin:** `admin` / `Admin@123`
- **Faculty:** `dr.sara` / `Faculty@123`, `prof.tariq` / `Faculty@123`
- **Student:** `bilal` / `Student@123`, `huraira` / `Student@123`, `huzaifa` / `Student@123`

## Documentation
- Phase 1 Attack-Surface Map & Threat Model: `docs/attack-surface-threat-model.md`

## Ethics and scope
Testing is restricted to the team's own local application and authorized test data. Do not test third-party production systems. Use synthetic records only.

## Team
- Team lead: Muhammad Bilal Badar
- Member 2: Abu Huraira
- Member 3: Huzaifa Asad
