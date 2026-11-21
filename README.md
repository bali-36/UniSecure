# UniSecure – University Management Portal

## Project overview
UniSecure is an original university management portal. It supports three roles: Student, Faculty, and Administrator. The project will be maintained in two states: a deliberately Vulnerable Version for authorized local testing and a Hardened Version with security mitigations.

## Planned stack
- Backend: Python Flask
- Database: MySQL
- Frontend: HTML, CSS, JavaScript, Bootstrap
- API testing: Postman
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

## Local setup
Setup instructions will be added after the application skeleton and dependency list are finalized. Do not commit real credentials. Use `.env.example` for variable names and keep the actual `.env` file out of version control.

## Ethics and scope
Testing is restricted to the team's own local application and authorized test data. Do not test third-party production systems. Use synthetic records only.

## Team
- Team lead: Muhammad Bilal Badar
- Member 2: Abu Huraira
- Member 3: Huzaifa Asad
