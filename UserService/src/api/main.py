import os
from datetime import timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from pydantic import BaseModel, EmailStr, Field
from starlette.responses import JSONResponse

# SECURITY/CRYPTO
import secrets
import hashlib
import hmac
import base64
import time
import uuid

# Note about configuration:
# - This service intentionally avoids reading the .env directly here.
# - The orchestrator is expected to inject environment variables as needed.
# - We provide a .env.example to document required vars.

# --------------------------------------------------------------------------------------
# Constants and RBAC
# --------------------------------------------------------------------------------------

ROLE_ATTENDEE = "attendee"
ROLE_ORGANIZER = "organizer"
ROLE_ADMIN = "admin"
ALL_ROLES = {ROLE_ATTENDEE, ROLE_ORGANIZER, ROLE_ADMIN}

DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --------------------------------------------------------------------------------------
# Utility functions for password hashing and tokens
# --------------------------------------------------------------------------------------

def _get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read an environment variable without raising errors."""
    return os.getenv(name, default)


def _get_secret_key() -> str:
    """
    Retrieves the JWT-like signing secret from environment.
    If not present, a random key is generated at runtime (non-persistent!) which is fine for dev.
    For production, set USERSERVICE_SECRET.
    """
    key = _get_env("USERSERVICE_SECRET")
    if key:
        return key
    # Fallback dev secret - process-unique
    generated = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    return generated


def _get_token_exp_minutes() -> int:
    v = _get_env("USERSERVICE_ACCESS_TOKEN_EXPIRE_MINUTES")
    if v:
        try:
            return max(5, int(v))
        except Exception:
            return DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
    return DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    """
    Hash password with PBKDF2-HMAC-SHA256. Returns salt$iterations$hash
    """
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8")
    iterations = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    hashed = base64.urlsafe_b64encode(dk).decode("utf-8")
    return f"{salt}${iterations}${hashed}"


def _verify_password(password: str, hashed: str) -> bool:
    try:
        salt, iterations_str, enc = hashed.split("$", 2)
        iterations = int(iterations_str)
        recalculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
        recalculated_b64 = base64.urlsafe_b64encode(recalculated).decode("utf-8")
        return hmac.compare_digest(enc, recalculated_b64)
    except Exception:
        return False


def _make_token(payload: dict, expires_in_seconds: int) -> str:
    """
    Create a compact, HMAC-SHA256 signed token. Not a full JWT implementation,
    but structured like it for demonstration/testing without extra dependencies.
    header.payload.signature (base64url-encoded)
    """
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = dict(payload)  # copy
    payload["iat"] = now
    payload["exp"] = now + expires_in_seconds

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    header_b64 = b64(JSONResponse.json_dumps(header).encode("utf-8"))
    payload_b64 = b64(JSONResponse.json_dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    key = _get_secret_key().encode("utf-8")
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    signature_b64 = b64(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _decode_token(token: str) -> dict:
    """
    Verify HMAC and expiration of our compact token.
    Returns the payload dict or raises HTTPException(401).
    """
    def b64decode(s: str) -> bytes:
        # add padding as needed
        padding = '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + padding)

    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 3)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    key = _get_secret_key().encode("utf-8")
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    try:
        provided_sig = b64decode(signature_b64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")

    try:
        payload = JSONResponse.json_loads(b64decode(payload_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    now = int(time.time())
    if "exp" not in payload or now > int(payload["exp"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    return payload


# --------------------------------------------------------------------------------------
# In-memory repository (replaceable later)
# --------------------------------------------------------------------------------------

class InMemoryDB:
    """
    Simple in-memory store suitable for initial scaffolding and tests.
    Replace with a persistent DB implementation later without changing handlers.
    """
    def __init__(self):
        # user_id -> user
        self.users = {}
        # email -> user_id
        self.email_index = {}

    def create_user(self, email: str, password_hash: str, roles: List[str]) -> dict:
        if email.lower() in self.email_index:
            raise ValueError("Email already registered")
        user_id = str(uuid.uuid4())
        user = {
            "id": user_id,
            "email": email.lower(),
            "password_hash": password_hash,
            "roles": list(sorted(set(roles))),
            "is_active": True,
            "is_verified": False,
            "profile": {
                "first_name": "",
                "last_name": "",
                "bio": "",
                "avatar_url": "",
                "phone": "",
            },
            "recovery": {
                "reset_token": None,
                "reset_token_exp": None,
            }
        }
        self.users[user_id] = user
        self.email_index[email.lower()] = user_id
        return user

    def get_user_by_email(self, email: str) -> Optional[dict]:
        user_id = self.email_index.get(email.lower())
        if not user_id:
            return None
        return self.users.get(user_id)

    def get_user(self, user_id: str) -> Optional[dict]:
        return self.users.get(user_id)

    def list_users(self) -> List[dict]:
        return list(self.users.values())

    def update_user(self, user_id: str, updates: dict) -> Optional[dict]:
        user = self.users.get(user_id)
        if not user:
            return None
        user.update(updates)
        return user

    def delete_user(self, user_id: str) -> bool:
        user = self.users.pop(user_id, None)
        if not user:
            return False
        self.email_index.pop(user["email"], None)
        return True

    def set_profile(self, user_id: str, profile: dict) -> Optional[dict]:
        user = self.users.get(user_id)
        if not user:
            return None
        user["profile"] = profile
        return user

    def set_roles(self, user_id: str, roles: List[str]) -> Optional[dict]:
        user = self.users.get(user_id)
        if not user:
            return None
        user["roles"] = list(sorted(set(roles)))
        return user

    def set_password_hash(self, user_id: str, password_hash: str) -> Optional[dict]:
        user = self.users.get(user_id)
        if not user:
            return None
        user["password_hash"] = password_hash
        return user

    def set_recovery_token(self, user_id: str, token: Optional[str], exp: Optional[int]):
        user = self.users.get(user_id)
        if not user:
            return None
        user["recovery"]["reset_token"] = token
        user["recovery"]["reset_token_exp"] = exp
        return user


db = InMemoryDB()

# --------------------------------------------------------------------------------------
# Pydantic models
# --------------------------------------------------------------------------------------

class Token(BaseModel):
    access_token: str = Field(..., description="Bearer access token")
    token_type: str = Field("bearer", description="Token type, always 'bearer'")


class TokenPayload(BaseModel):
    sub: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    roles: List[str] = Field(default_factory=list, description="User roles")


class Profile(BaseModel):
    first_name: str = Field("", description="First name")
    last_name: str = Field("", description="Last name")
    bio: str = Field("", description="Short biography or description")
    avatar_url: str = Field("", description="URL to profile avatar")
    phone: str = Field("", description="Phone number in E.164 format if possible")


class UserPublic(BaseModel):
    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    roles: List[str] = Field(default_factory=list, description="Assigned roles")
    is_active: bool = Field(..., description="Is the user active")
    is_verified: bool = Field(..., description="Has the user's email been verified")
    profile: Profile = Field(default_factory=Profile, description="User profile")


class UserCreate(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    role: str = Field(ROLE_ATTENDEE, description="Initial role: attendee or organizer")


class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="Email")
    password: str = Field(..., description="Password")


class ProfileUpdate(BaseModel):
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    bio: Optional[str] = Field(None, description="Bio")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    phone: Optional[str] = Field(None, description="Phone number")


class PasswordChange(BaseModel):
    old_password: str = Field(..., description="Old password")
    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")


class PasswordResetRequest(BaseModel):
    email: EmailStr = Field(..., description="Email to send reset token to")


class PasswordResetConfirm(BaseModel):
    email: EmailStr = Field(..., description="Email")
    token: str = Field(..., description="Reset token received out-of-band (e.g., email)")
    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")


class RoleUpdate(BaseModel):
    roles: List[str] = Field(..., description="List of roles to assign")


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/token",
    scopes={
        ROLE_ATTENDEE: "Permissions for attendees",
        ROLE_ORGANIZER: "Permissions for organizers",
        ROLE_ADMIN: "Administrator permissions",
    },
)

# --------------------------------------------------------------------------------------
# FastAPI app and metadata
# --------------------------------------------------------------------------------------

openapi_tags = [
    {"name": "health", "description": "Service health and metadata"},
    {"name": "auth", "description": "Authentication and token management"},
    {"name": "users", "description": "User registration and profile endpoints"},
    {"name": "admin", "description": "Administrative endpoints for user management"},
    {"name": "recovery", "description": "Account recovery and password reset flows"},
]

app = FastAPI(
    title="User Service",
    description="User registration, authentication, profiles, and RBAC for the Event Platform.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------------------
# Dependencies and security helpers
# --------------------------------------------------------------------------------------

# PUBLIC_INTERFACE
def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
) -> dict:
    """
    PUBLIC_INTERFACE
    Authenticate the request using the bearer token and ensure required scopes (roles).
    """
    payload = _decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = db.get_user(user_id)
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or unknown user")

    token_roles = set(payload.get("roles", []))
    for scope in security_scopes.scopes:
        if scope not in token_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing required role: {scope}")
    return user


def _user_to_public(user: dict) -> UserPublic:
    return UserPublic(
        id=user["id"],
        email=user["email"],
        roles=user["roles"],
        is_active=user["is_active"],
        is_verified=user["is_verified"],
        profile=Profile(**user["profile"]),
    )

# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------

@app.get("/", tags=["health"], summary="Health check", description="Simple health check endpoint.")
def health_check():
    return {"message": "Healthy", "service": "UserService"}


# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserPublic, tags=["users"], summary="Register a new user", description="Registers a new user as attendee or organizer.")
def register(user_in: UserCreate):
    """Register a new user with a role (attendee or organizer)."""
    initial_role = user_in.role.lower().strip()
    if initial_role not in {ROLE_ATTENDEE, ROLE_ORGANIZER}:
        raise HTTPException(status_code=400, detail="role must be 'attendee' or 'organizer'")
    pwd_hash = _hash_password(user_in.password)
    try:
        user = db.create_user(email=user_in.email, password_hash=pwd_hash, roles=[initial_role])
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    return _user_to_public(user)


# PUBLIC_INTERFACE
@app.post(
    "/auth/token",
    response_model=Token,
    tags=["auth"],
    summary="Obtain access token",
    description="Use email and password to obtain a bearer token. Compatible with OAuth2PasswordRequestForm.",
)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate using email and password and return a bearer token.
    For convenience, username field is treated as email.
    """
    email = form_data.username
    password = form_data.password
    user = db.get_user_by_email(email)
    if not user or not _verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    if not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    access_token_expires = timedelta(minutes=_get_token_exp_minutes())
    payload = TokenPayload(sub=user["id"], email=user["email"], roles=user["roles"]).model_dump()
    token = _make_token(payload=payload, expires_in_seconds=int(access_token_expires.total_seconds()))
    return Token(access_token=token, token_type="bearer")


# PUBLIC_INTERFACE
@app.get("/users/me", response_model=UserPublic, tags=["users"], summary="Get my profile", description="Return the current authenticated user's public profile.")
def read_users_me(current_user: dict = Security(get_current_user, scopes=[])):
    return _user_to_public(current_user)


# PUBLIC_INTERFACE
@app.put("/users/me/profile", response_model=UserPublic, tags=["users"], summary="Update my profile", description="Update profile fields of the current user.")
def update_my_profile(update: ProfileUpdate, current_user: dict = Security(get_current_user, scopes=[])):
    profile = current_user["profile"].copy()
    for field_name, value in update.model_dump(exclude_unset=True).items():
        profile[field_name] = value if value is not None else profile.get(field_name, "")
    db.set_profile(current_user["id"], profile)
    refreshed = db.get_user(current_user["id"])
    return _user_to_public(refreshed)


# PUBLIC_INTERFACE
@app.post("/users/me/change-password", tags=["users"], summary="Change my password", description="Change password for the current user.")
def change_password(body: PasswordChange, current_user: dict = Security(get_current_user, scopes=[])):
    if not _verify_password(body.old_password, current_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    new_hash = _hash_password(body.new_password)
    db.set_password_hash(current_user["id"], new_hash)
    return {"message": "Password changed successfully"}


# PUBLIC_INTERFACE
@app.post("/recovery/request", tags=["recovery"], summary="Request password reset", description="Generate a password reset token for the given email. In production, send via email.")
def request_password_reset(body: PasswordResetRequest):
    user = db.get_user_by_email(body.email)
    # Don't reveal existence of accounts to avoid user enumeration
    if not user:
        return {"message": "If the email exists, a reset token has been generated."}
    token = secrets.token_urlsafe(32)
    exp = int(time.time()) + 15 * 60  # 15 minutes
    db.set_recovery_token(user["id"], token, exp)
    # NOTE: In production, integrate with NotificationService to email the token link.
    return {"message": "If the email exists, a reset token has been generated."}


# PUBLIC_INTERFACE
@app.post("/recovery/confirm", tags=["recovery"], summary="Confirm password reset", description="Reset the password using the token previously issued.")
def confirm_password_reset(body: PasswordResetConfirm):
    user = db.get_user_by_email(body.email)
    if not user:
        # generic response
        return {"message": "If the token is valid, password has been reset."}
    token_stored = user["recovery"].get("reset_token")
    exp = user["recovery"].get("reset_token_exp")
    now = int(time.time())
    if not token_stored or not exp or now > int(exp) or not secrets.compare_digest(token_stored, body.token):
        # generic response
        return {"message": "If the token is valid, password has been reset."}
    db.set_password_hash(user["id"], _hash_password(body.new_password))
    db.set_recovery_token(user["id"], None, None)
    return {"message": "Password has been reset."}


# PUBLIC_INTERFACE
@app.get(
    "/admin/users",
    response_model=List[UserPublic],
    tags=["admin"],
    summary="List users",
    description="List all users (admin only).",
)
def admin_list_users(current_user: dict = Security(get_current_user, scopes=[ROLE_ADMIN])):
    users = db.list_users()
    return [_user_to_public(u) for u in users]


# PUBLIC_INTERFACE
@app.get(
    "/admin/users/{user_id}",
    response_model=UserPublic,
    tags=["admin"],
    summary="Get a user",
    description="Retrieve a user by ID (admin only).",
)
def admin_get_user(user_id: str, current_user: dict = Security(get_current_user, scopes=[ROLE_ADMIN])):
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_public(user)


# PUBLIC_INTERFACE
@app.put(
    "/admin/users/{user_id}/roles",
    response_model=UserPublic,
    tags=["admin"],
    summary="Update user roles",
    description="Assign roles to a user (admin only). Allowed roles: attendee, organizer, admin.",
)
def admin_update_roles(user_id: str, body: RoleUpdate, current_user: dict = Security(get_current_user, scopes=[ROLE_ADMIN])):
    normalized = []
    for r in body.roles:
        role = r.lower().strip()
        if role not in ALL_ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role '{r}'")
        normalized.append(role)
    user = db.set_roles(user_id, normalized)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_public(user)


# PUBLIC_INTERFACE
@app.delete(
    "/admin/users/{user_id}",
    tags=["admin"],
    summary="Delete user",
    description="Delete a user account (admin only).",
)
def admin_delete_user(user_id: str, current_user: dict = Security(get_current_user, scopes=[ROLE_ADMIN])):
    ok = db.delete_user(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted"}


# PUBLIC_INTERFACE
@app.get(
    "/docs/websocket-usage",
    tags=["health"],
    summary="WebSocket usage notes",
    description="This service currently does not expose WebSockets. This endpoint is reserved for documenting real-time features in the future.",
)
def websocket_usage_note():
    """
    PUBLIC_INTERFACE
    Provide guidance for any real-time websocket endpoints (none implemented currently).
    """
    return {
        "websocket_supported": False,
        "note": "No websocket endpoints are currently available in UserService.",
    }
