# Secure Clinic API

> A production-style healthcare REST API built with FastAPI.
> Implements the complete security stack required for a real-world patient data system — from secrets management to PHI protection.

---

## Overview

This API simulates the backend of a clinic management system.
It demonstrates how authentication, authorisation, data validation, and compliance controls work together in a single FastAPI application — without relying on third-party auth services.

The same security functions used here plug directly into a production FastAPI deployment with no changes to the business logic.

---

## Security Architecture
```
Incoming Request
│
▼
┌──────────────────────┐
│   Rate Limiting      │  (production: Redis-backed sliding window)
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│  Input Validation    │  Pydantic models + regex — rejects bad data early
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│ JWT Verification     │  verify_token() — injected via Depends()
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│ Role-Based Access    │  require_doctor() — chains on top of verify_token()
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│  Business Logic      │  Route handler executes
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│  PHI Protection      │  Phone / email masked before leaving the API
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│  Audit Logging       │  Method · path · status · latency on every request
└──────────────────────┘
```
---

## Security Controls

| Control | Implementation | Standard |
|---------|---------------|----------|
| Secrets management | `python-dotenv` — `SECRET_KEY` never in source | OWASP A02 |
| Password hashing | `bcrypt` with per-password salt | OWASP A02 |
| Authentication | JWT HS256, 24-hour expiry | RFC 7519 |
| Input validation | Pydantic v2 + regex | OWASP A03 |
| SQL injection prevention | Parameterised `?` placeholders | OWASP A03 |
| PHI masking | Phone and email masked in all responses | GDPR · KVKK · HIPAA |
| Audit trail | Structured log per request | HIPAA §164.312 |
| Role-based access | Doctor-only endpoints via `Depends()` chain | OWASP A01 |

---

## API Reference

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/register` | — | Register a new user account |
| `POST` | `/auth/login` | — | Authenticate and receive a JWT |

### Patients

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/patients` | ✅ Bearer | List all patients — PHI masked |
| `GET` | `/patients/{id}` | ✅ Bearer | Retrieve one patient — PHI masked |
| `POST` | `/patients` | 🔒 Doctor | Register a new patient |
| `PATCH` | `/patients/{id}` | 🔒 Doctor | Partially update a patient |
| `DELETE` | `/patients/{id}` | 🔒 Doctor | Remove a patient |

### System

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | — | System status for monitoring tools |

---

## Request / Response Examples

**Register**
```json
POST /auth/register
{
  "user_id": "U001",
  "username": "dr.mitchell",
  "email": "mitchell@clinic.com",
  "password": "SecurePass1!",
  "role": "doctor"
}
```

**Login → JWT**
```json
POST /auth/login
{
  "username": "dr.mitchell",
  "password": "SecurePass1!"
}

// Response
{
  "access_token": "eyJhbGci...",
  "token_type": "bearer",
  "role": "doctor"
}
```

**Get patient — PHI masked**
```json
GET /patients/P001
Authorization: Bearer eyJhbGci...

// Response
{
  "patient_id": "P001",
  "name": "James Anderson",
  "age": 52,
  "email": "ja***@email.com",
  "phone": "****1001",
  "blood_type": "A+",
  "diagnosis": "Hypertension"
}
```

---

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Framework | FastAPI | 0.115+ |
| Validation | Pydantic | v2 |
| ASGI server | Uvicorn | 0.30+ |
| Authentication | PyJWT | 2.x |
| Password hashing | bcrypt | 4.x |
| Secrets | python-dotenv | 1.x |
| Database | SQLite (sqlite3) | built-in |

> **Production note:** SQLite is used here for portability. Replacing it with PostgreSQL requires only changing the connection string — all queries use the standard DB-API 2 interface.

---

## Getting Started

```bash
git clone https://github.com/volkancelebidev/secure-clinic-api.git
cd secure-clinic-api
pip install fastapi uvicorn pydantic bcrypt PyJWT python-dotenv
```

Create `.env` in the project root:

```env
SECRET_KEY=your-secret-key-minimum-32-characters
```

Start the server:

```bash
uvicorn main:app --reload
```

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:8000/docs` | Swagger UI — interactive API explorer |
| `http://127.0.0.1:8000/redoc` | ReDoc — clean API documentation |
| `http://127.0.0.1:8000/health` | Health check endpoint |

---

## Project Structure
```
secure-clinic-api/
├── main.py       # Complete API — routes, models, security, middleware
├── .env          # Secret keys (not committed)
└── .gitignore
```
> A production deployment would split this into `routers/`, `models/`, `schemas/`, `core/security.py`, and `db/` directories. The single-file structure is intentional here to keep the full security flow visible in one place.

---

## Compliance Notes

| Regulation | Controls Implemented |
|------------|---------------------|
| **GDPR** (EU) | PHI masking on all patient responses, audit log per access |
| **KVKK** (Turkey) | Same controls as GDPR — directly applicable |
| **HIPAA** (US) | PHI access logging, bcrypt password storage, role-based access |

---

## Roadmap

- [ ] PostgreSQL + SQLAlchemy (async)
- [ ] Redis-backed rate limiting
- [ ] Refresh token rotation
- [ ] Docker + docker-compose
- [ ] CI/CD with GitHub Actions

---

## What I Learned

- Chaining FastAPI dependencies with `Depends()` to build layered security
- Using Pydantic response models to automatically strip sensitive fields
- Implementing role-based access control without a third-party permissions library
- Writing partial updates safely with `model_dump(exclude_none=True)`
- Building a dynamic `UPDATE` query that only touches supplied fields
- Why `%s` format strings are preferred over f-strings in the `logging` module
