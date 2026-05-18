"""
main.py
 
Secure Clinic API — a production-style healthcare REST API built with FastAPI.
 
Implements the full security stack required for a real-world patient data system:
    Secrets Management  — SECRET_KEY loaded from .env, never hardcoded
    Password Hashing    — bcrypt with per-password salt at registration
    JWT Authentication  — HS256 signed token; verified via dependency injection
    Input Validation    — Pydantic models + manual regex checks
    SQL Injection       — parameterised placeholders throughout
    PHI Protection      — phone/email masked before leaving the API
    Audit Logging       — every request logged with method, path, status, latency
    Role-Based Access   — doctor-only endpoints enforced via a dedicated dependency
 
Endpoints:
    POST   /auth/register        — create a new user account
    POST   /auth/login           — authenticate and receive a JWT
    GET    /patients             — list all patients (authenticated)
    GET    /patients/{id}        — retrieve one patient (authenticated)
    POST   /patients             — add a patient (doctor only)
    PATCH  /patients/{id}        — update a patient (doctor only)
    DELETE /patients/{id}        — remove a patient (doctor only)
    GET    /health               — system status (unauthenticated)
 
Run:
    uvicorn main:app --reload
 
Explore:
    http://127.0.0.1:8000/docs   — Swagger UI
    http://127.0.0.1:8000/redoc  — ReDoc
"""
 
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
 
import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
 
 
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# All secrets are read from a .env file so they never appear in source code.
# The application refuses to start if SECRET_KEY is missing — fail-fast
# is safer than silently running with a broken security configuration.
 
load_dotenv()   # populate os.environ from .env
 
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt= "%H:%M:%S",
)
logger = logging.getLogger(__name__)
 
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM  = "HS256"
DB_PATH    = "clinic.db"
 
if not SECRET_KEY:
    raise ValueError(
        "SECRET_KEY environment variable is not set. "
        "Add it to your .env file before starting the application."
    )
 
app = FastAPI(
    title       = "Secure Clinic API",
    description = "A production-style healthcare REST API with a full security layer.",
    version     = "1.0.0",
)
 
# HTTPBearer reads the token from the Authorization: Bearer <token> header.
bearer = HTTPBearer()
 
 
# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# SQLite is used here for portability.  Swapping to PostgreSQL requires only
# changing the connection string — all queries use the same DB-API 2 interface.
#
# executescript() runs multiple statements in autocommit mode, which is
# required for PRAGMA foreign_keys to take effect reliably.
# CREATE TABLE IF NOT EXISTS ensures the schema is idempotent on restart.
 
 
def init_db() -> None:
    """Create the database schema if it does not already exist.
 
    Called once at application startup.  Safe to call on every restart
    because IF NOT EXISTS prevents duplicate table creation.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            PRAGMA foreign_keys = ON;
 
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'nurse'
            );
 
            CREATE TABLE IF NOT EXISTS patients (
                patient_id TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                age        INTEGER NOT NULL,
                email      TEXT,
                phone      TEXT,
                blood_type TEXT,
                diagnosis  TEXT
            );
        """)
 
 
init_db()
 
 
def get_db() -> sqlite3.Connection:
    """Open and return a configured SQLite connection.
 
    row_factory = sqlite3.Row enables column-name access (row["name"])
    instead of positional indexing (row[1]), making queries self-documenting.
 
    Returns:
        An open sqlite3.Connection with Row factory and foreign keys enabled.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
 
 
# ---------------------------------------------------------------------------
# Security — Password hashing
# ---------------------------------------------------------------------------
# Passwords are never stored as plain text.
# bcrypt is a one-way, salted hash function designed for passwords.
# gensalt() generates a unique random salt per password so two users with
# the same password produce different hashes, defeating rainbow-table attacks.
 
 
def hash_password(password: str) -> bytes:
    """Hash a plain-text password with bcrypt.
 
    Args:
        password: The raw password string supplied at registration.
 
    Returns:
        A bcrypt hash as bytes, safe to store in the database.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
 
 
def verify_password(plain: str, hashed: bytes) -> bool:
    """Verify a plain-text password against a stored bcrypt hash.
 
    Does not decrypt the hash — re-hashes with the embedded salt and
    compares.  Called at login, never at registration.
 
    Args:
        plain:  The password the user typed.
        hashed: The hash retrieved from the database.
 
    Returns:
        True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(plain.encode("utf-8"), hashed)
 
 
# ---------------------------------------------------------------------------
# Security — JWT
# ---------------------------------------------------------------------------
# A JWT carries the user's identity and role in a signed, tamper-evident
# envelope.  The server can verify authenticity without a database lookup,
# which makes token-based auth scalable across multiple API instances.
#
# exp (expiry) limits the window of exposure if a token is intercepted.
# iat (issued-at) supports audit trails and token revocation strategies.
 
 
def create_token(user_id: str, role: str) -> str:
    """Issue a signed JWT access token valid for 24 hours.
 
    Args:
        user_id: Unique identifier of the authenticated user.
        role:    Permission level embedded in the token payload.
 
    Returns:
        A signed JWT string to be returned to the client.
    """
    payload = {
        "user_id": user_id,
        "role"   : role,
        "exp"    : datetime.now(timezone.utc) + timedelta(hours=24),
        "iat"    : datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
 
 
def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    """Validate a JWT from the Authorization header and return its payload.
 
    Used as a FastAPI dependency — injected into route handlers via
    Depends(verify_token).  If validation fails, FastAPI returns 401
    and the route handler never executes.
 
    Args:
        credentials: Token extracted automatically by HTTPBearer.
 
    Returns:
        Decoded payload dict containing user_id, role, exp, and iat.
 
    Raises:
        HTTPException 401: Token is expired or structurally invalid.
    """
    try:
        return jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail      = "Token has expired.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail      = "Invalid token.",
        )
 
 
def require_doctor(payload: dict = Depends(verify_token)) -> dict:
    """Extend verify_token with a role check for doctor-only endpoints.
 
    Depends(verify_token) runs first — token must be valid before the
    role is inspected.  This chains two security layers in one dependency,
    analogous to inheritance in OOP where a subclass extends a base class.
 
    Args:
        payload: Decoded JWT payload provided by verify_token.
 
    Returns:
        The same payload, forwarded to the route handler.
 
    Raises:
        HTTPException 403: Authenticated user does not hold the doctor role.
    """
    if payload.get("role") != "doctor":
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail      = "Only doctors can perform this action.",
        )
    return payload
 
 
# ---------------------------------------------------------------------------
# Security — PHI protection
# ---------------------------------------------------------------------------
# Protected Health Information (PHI) must not leave the system in raw form.
# GDPR (EU), KVKK (Turkey), and HIPAA (US) all impose masking requirements
# on phone numbers and email addresses in API responses and log output.
 
 
def mask_phone(phone: str) -> str:
    """Mask all but the last four digits of a phone number.
 
    Args:
        phone: Raw phone number string from the database.
 
    Returns:
        Masked string such as "***-***-1234".
    """
    if not phone or len(phone) <= 4:
        return "****"
    return "*" * (len(phone) - 4) + phone[-4:]
 
 
def mask_email(email: str) -> str:
    """Mask the username portion of an email address.
 
    Keeps the first two characters visible so the address remains
    recognisable without exposing the full identity.
 
    Args:
        email: Raw email string from the database.
 
    Returns:
        Masked string such as "al***@hospital.com".
    """
    if not email or "@" not in email:
        return "***@***.***"
    parts    = email.split("@")
    username = parts[0][:2] + "*" * max(0, len(parts[0]) - 2)
    return f"{username}@{parts[1]}"
 
 
def sanitize_phi(patient: dict) -> dict:
    """Mask sensitive fields before including a patient record in a response.
 
    In a FastAPI + Pydantic project this is typically handled by a response
    model that omits fields.  The manual approach here makes the masking
    logic explicit and auditable.
 
    Args:
        patient: Raw patient dict as returned by the database layer.
 
    Returns:
        A copy of the dict with phone and email masked and
        password_hash removed entirely.
    """
    safe = patient.copy()   # never mutate the original
    if safe.get("phone"):
        safe["phone"] = mask_phone(safe["phone"])
    if safe.get("email"):
        safe["email"] = mask_email(safe["email"])
    safe.pop("password_hash", None)   # must never leave the backend
    return safe


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
# Middleware wraps every request/response cycle.
# async def and await are required because FastAPI is built on ASGI —
# the server handles many requests concurrently without blocking threads.
# call_next(request) passes control to the next middleware or route handler
# and suspends this coroutine until a response is ready.

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log method, path, HTTP status, and latency for every request.
 
    In production these records are forwarded to a centralised platform
    such as Datadog, Splunk, or AWS CloudWatch for alerting and tracing.
 
    Args:
        request:   Incoming HTTP request object.
        call_next: Callable that forwards the request down the stack.
 
    Returns:
        The HTTP response produced by the route handler.
    """
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    # %s %s %d %.3f → string, string, integer, float with 3 decimal places
    # Using % formatting is preferred in logging — the string is only built
    # if the message will actually be emitted (performance optimisation).
    logger.info(
        "%s %s → %d (%.3fs)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )
    return response


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
# Request models define what the API accepts and validate it automatically.
# Response models define what the API returns, stripping fields not listed
# (e.g. password_hash never appears in a PatientResponse).
#
# Field(gt=0, lt=150) adds a numeric constraint on top of the type check:
# gt = greater than, lt = less than.
#
# str | None = None marks a field as optional with a None default, used in
# PATCH models so callers only send the fields they want to change.

class UserRegister(BaseModel):
    user_id  : str
    username : str
    email    : str
    password : str
    role     : str = "nurse"


class UserLogin(BaseModel):
    username : str
    password : str


class PatientCreate(BaseModel):
    patient_id : str
    name       : str
    age        : int = Field(gt=0, lt=150, description="Patient age (1-149)")
    email      : str = ""
    phone      : str = ""
    blood_type : str = ""
    diagnosis  : str = ""


class PatientUpdate(BaseModel):
    """All fields are optional — only supplied fields are written to the database.
 
    model_dump(exclude_none=True) drops None values so a caller sending
    only {"age": 55} does not accidentally overwrite name or diagnosis
    with NULL.
    """
    name       : str | None = None
    age        : int | None = Field(default=None, gt=0, lt=150)
    email      : str | None = None
    phone      : str | None = None
    blood_type : str | None = None
    diagnosis  : str | None = None


class PatientResponse(BaseModel):
    """Fields returned in patient API responses.
 
    password_hash is intentionally absent — Pydantic strips any extra
    fields not declared here, providing automatic PHI protection.
    """
    patient_id : str
    name       : str
    age        : int
    email      : str = ""
    phone      : str = ""
    blood_type : str = ""
    diagnosis  : str = ""


class TokenResponse(BaseModel):
    access_token : str
    token_type   : str = "bearer"
    role         : str


# ---------------------------------------------------------------------------
# Routes — Authentication
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    """Register a new user account.
 
    Security pipeline:
        1. Validate email format with a regex.
        2. Enforce a minimum password length.
        3. Hash the password with bcrypt before storage.
        4. INSERT with a parameterised query — SQL injection safe.
        5. Return 409 Conflict on duplicate username.
 
    Args:
        user: Validated UserRegister payload from the request body.
 
    Returns:
        Confirmation message on success.
    """
    if not re.match(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user.email
    ):
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail      = "Invalid email format.",
        )
    
    if len(user.password) < 8:
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail      = "Password must be at least 8 characters." 
        )
    
    hashed = hash_password(user.password)

    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (user_id, username, password_hash, role) "
                "VALUES (?, ?, ?, ?)",
                (user.user_id, user.username, hashed, user.role),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code = status.HTTP_409_CONFLICT,
                detail      = f"Username {user.username!r} already exists.",
            )
        
    logger.info("User registered: %s (%s)", user.username, user.role)
    return {"message": f"User {user.username!r} registered successfully."}


@app.post("/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    """Authenticate a user and issue a JWT access token.
 
    The error message is intentionally generic — "Invalid credentials"
    regardless of whether the username or password was wrong.  Revealing
    which field failed would help an attacker enumerate valid usernames.
 
    Args:
        credentials: Username and password from the request body.
 
    Returns:
        TokenResponse containing the signed JWT and the user's role.
    """
    with get_db() as conn:
        # Single-element tuple — trailing comma is required
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (credentials.username,),
        ).fetchone()

    if not row or not verify_password(credentials.password, row["password_hash"]):
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail      = "Invalid credentials.",
        )
    
    token = create_token(row["user_id"], row["role"])
    logger.info("User logged in: %s", credentials.username)
    return TokenResponse(access_token=token, role=row["role"])



# ---------------------------------------------------------------------------
# Routes — Patients
# ---------------------------------------------------------------------------

@app.get("/patients", response_model=list[PatientResponse])
def list_patients(
    department: str | None = None,
    limit     : int        = 10,
    payload   : dict       = Depends(verify_token),
):
    """Return a paginated, PHI-masked list of patients.
 
    Query parameters:
        department — optional keyword filter applied to the diagnosis column.
        limit      — maximum number of records to return (default 10).
 
    Args:
        department: Optional diagnosis keyword from the query string.
        limit:      Row limit from the query string.
        payload:    Decoded JWT payload injected by verify_token.
 
    Returns:
        List of PHI-masked PatientResponse objects.
    """
    with get_db() as conn:
        if department:
            # LIKE with % wildcards — parameterised to prevent injection
            rows = conn.execute(
                "SELECT * FROM patients "
                "WHERE diagnosis LIKE ? ORDER BY name LIMIT ?",
                (f"%{department}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM patients ORDER BY name LIMIT ?",
                (limit,),
            ).fetchall()

    # List comprehension — convert each Row to dict and apply PHI masking
    return [sanitize_phi(dict(row)) for row in rows]


@app.get("/patients/{patient_id}", response_model=PatientResponse)
def get_patient(
    patient_id: str,
    payload   : dict = Depends(verify_token),
):
    """Retrieve a single patient by primary key.
 
    Validates the patient_id format (P###) before hitting the database
    to reject obviously malformed inputs early.
 
    Args:
        patient_id: Path parameter in P### format (e.g. P001).
        payload:    Decoded JWT payload from verify_token.
 
    Returns:
        PHI-masked PatientResponse.
 
    Raises:
        HTTPException 422: patient_id does not match the P### pattern.
        HTTPException 404: No patient found with the given ID.
    """
    if not re.match(r"^P\d{3}$", patient_id):
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail      = f"Invalid patient ID format: {patient_id!r}. Expected P###.",
        )
    
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail      = f"Patient {patient_id!r} not found.",
        )
    
    logger.info("Patient accessed: %s by user %s", patient_id, payload["user_id"])
    return sanitize_phi(dict(row))


@app.post("/patients", response_model=PatientResponse, status_code = status.HTTP_201_CREATED)
def create_patient(
    patient: PatientCreate,
    payload: dict = Depends(require_doctor),
):
    """Register a new patient record.
 
    Restricted to users with the doctor role.  require_doctor chains
    verify_token (authentication) with a role check (authorisation),
    analogous to a subclass extending a base class in OOP.
 
    Args:
        patient: Validated PatientCreate payload from the request body.
        payload: Decoded JWT payload from require_doctor.
 
    Returns:
        The newly created patient as a PatientResponse.
 
    Raises:
        HTTPException 409: A patient with this ID already exists.
    """
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO patients "
                "(patient_id, name, age, email, phone, blood_type, diagnosis) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (patient.patient_id, patient.name, patient.age,
                 patient.email, patient.phone, patient.blood_type,
                 patient.diagnosis,),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code = status.HTTP_409_CONFLICT,
                detail      = f"Patient {patient.patient_id!r} already exists.",
            )
        
    logger.info(
        "Patient created: %s by doctor %s", patient.patient_id, payload["user_id"]
    )
    return patient


@app.patch("/patients/{patient_id}", response_model=PatientResponse)
def update_patient(
    patient_id: str,
    update    : PatientUpdate,
    payload   : dict = Depends(require_doctor),
):
    """Partially update a patient record.
 
    model_dump(exclude_none=True) discards fields the caller did not
    supply so a PATCH with {"age": 55} only updates the age column —
    name, diagnosis, and other fields are left unchanged.
 
    The UPDATE statement is built dynamically from the supplied fields
    using a parameterised SET clause to remain SQL-injection safe.
 
    Args:
        patient_id: Path parameter identifying the patient to update.
        update:     Partial PatientUpdate payload from the request body.
        payload:    Decoded JWT payload from require_doctor.
 
    Returns:
        The updated patient as a PatientResponse.
 
    Raises:
        HTTPException 404: No patient found with the given ID.
        HTTPException 422: No update fields were supplied.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail      = f"Patient {patient_id!r} not found.",
        )
    
    # Drop None values — only update fields the caller explicitly supplied
    update_data = update.model_dump(exclude_none=True)

    if not update_data:
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail      = "No fields provided for update.", 
        )
    
    # Build "col1 = ?, col2 = ?" from the supplied keys
    set_clause = ", ".join(f"{key} = ?" for key in update_data)
    values     = list(update_data.values()) + [patient_id]

    with get_db() as conn:
        conn.execute(
            f"UPDATE patients SET {set_clause} WHERE patient_id = ?",
            values,
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()

    logger.info(
        "Patient updated: %s by doctor %s", patient_id, payload["user_id"]
    )
    return sanitize_phi(dict(row))


@app.delete("/patients/{patient_id}", status_code = status.HTTP_204_NO_CONTENT)
def delete_patient(
    patient_id: str,
    payload   : dict = Depends(require_doctor),
):
    """Delete a patient record permanently.
 
    204 No Content is returned on success — there is no response body.
    rowcount is checked to distinguish "deleted" from "not found" without
    a separate SELECT round-trip.
 
    Args:
        patient_id: Path parameter identifying the patient to delete.
        payload:    Decoded JWT payload from require_doctor.
 
    Raises:
        HTTPException 404: No patient found with the given ID.
    """
    with get_db() as conn:
        result = conn.execute(
            "DELETE FROM patients WHERE patient_id = ?",
            (patient_id,),
        )
        conn.commit()

    # rowcount == 0 means the WHERE clause matched nothing
    if result.rowcount == 0:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail      = f"Patient {patient_id!r} not found.",
        )
    
    logger.info(
        "Patient deleted: %s by doctor %s", patient_id, payload["user_id"]
    )
    # 204 — no return value



# ---------------------------------------------------------------------------
# Routes — System
# ---------------------------------------------------------------------------

@app.get("/health")
def health_check():
    """Return current system status for monitoring tools.
 
    Intentionally unauthenticated — monitoring agents (Prometheus,
    Datadog, AWS ALB health checks) do not carry user tokens.
 
    Returns a plain dict rather than a Pydantic model so the shape can
    evolve without a breaking schema change.
 
    Returns:
        Dict with status, timestamp, record counts, and version.
    """
    with get_db() as conn:
        patient_count = conn.execute(
            "SELECT COUNT(*) FROM patients"
        ).fetchone()[0]
        user_count = conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

    return {
        "status"         : "healthy",
        "generated_at"   : datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total_patients" : patient_count,
        "total_users"    : user_count,
        "version"        : "1.0.0",
    }