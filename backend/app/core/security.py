"""
Security Utilities

JWT token creation/validation, password hashing, TOTP 2FA helpers,
RBAC role enforcement, and HMAC command signing.
"""

import base64
import hashlib
import hmac as _hmac
import io
import secrets
import time
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode  # type: ignore
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings

# --- Password Hashing ---
# passlib is incompatible with bcrypt>=4.1; use bcrypt directly
import bcrypt as _bcrypt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- JWT Bearer ---
security_scheme = HTTPBearer()


# ─────────────────────────────────  RBAC  ─────────────────────────────────

ROLE_HIERARCHY: dict[str, int] = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
    "superadmin": 3,
}


def _role_level(role: str) -> int:
    """Return the numeric level for a role string."""
    return ROLE_HIERARCHY.get(role, -1)


def require_role(min_role: str):
    """
    FastAPI dependency factory: enforce minimum RBAC role.

    Usage:
        @router.get("/secret", dependencies=[Depends(require_role("admin"))])
        async def secret_route(): ...

    Or to also receive the user dict:
        current_user: dict = Depends(require_role("analyst"))
    """
    min_level = _role_level(min_role)
    if min_level < 0:
        raise ValueError(f"Unknown role: {min_role}")

    async def _check(
        credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    ) -> dict:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )
        user_role = payload.get("role", "viewer")
        if _role_level(user_role) < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{min_role}' or higher (you have '{user_role}')",
            )
        return payload

    return _check


# ─────────────────────────────  Password  ─────────────────────────────

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt (direct, bypasses passlib bug)."""
    pwd_bytes = password.encode("utf-8")[:72]
    return _bcrypt.hashpw(pwd_bytes, _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return _bcrypt.checkpw(
            plain_password.encode("utf-8")[:72],
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


# ─────────────────────────────  JWT Tokens  ─────────────────────────────

def create_access_token(subject: str, extra_claims: dict | None = None) -> str:
    """Create a JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    """Create a JWT refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_2fa_token(subject: str) -> str:
    """Create a short-lived token for the 2FA verification step (5 min)."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "2fa_pending",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_2fa_token(token: str) -> str:
    """Decode a 2FA-pending token and return the user id (sub)."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "2fa_pending":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA token type",
            )
        return payload["sub"]
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired 2FA token",
        )


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> dict:
    """Extract and validate the current user from the JWT bearer token."""
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    return payload


def create_agent_token(agent_id: str, hostname: str) -> str:
    """Create a long-lived token for agent authentication."""
    expire = datetime.now(timezone.utc) + timedelta(days=365)
    payload = {
        "sub": agent_id,
        "hostname": hostname,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "agent",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def get_current_agent(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> dict:
    """Extract and validate the current agent from the JWT bearer token."""
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "agent":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token",
        )
    return payload


# ─────────────────────────────  TOTP / 2FA  ─────────────────────────────

def generate_totp_secret() -> str:
    """Generate a new random TOTP secret."""
    return pyotp.random_base32()


def get_totp_provisioning_uri(secret: str, username: str) -> str:
    """Build the otpauth:// URI for authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.TOTP_ISSUER)


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code (±1 window)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_totp_qr_base64(provisioning_uri: str) -> str:
    """Generate a QR-code PNG for the provisioning URI, returned as base64."""
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


# ─────────────────────────────  HMAC Command Signing  ─────────────────────────────

def generate_hmac_key() -> str:
    """Generate a cryptographically secure 64-byte hex HMAC key."""
    return secrets.token_hex(64)


def sign_command(payload: dict, hmac_key: str | None = None) -> str:
    """
    Sign a command payload with HMAC-SHA256.

    The payload dict is serialized to a canonical form (sorted JSON),
    then HMAC-signed with the shared key. Returns hex digest.
    """
    key = (hmac_key or settings.REMEDIATION_HMAC_KEY).encode("utf-8")
    import json
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_command_signature(payload: dict, signature: str, hmac_key: str | None = None) -> bool:
    """
    Verify an HMAC-SHA256 signature for a command payload.

    Uses constant-time comparison to prevent timing attacks.
    """
    expected = sign_command(payload, hmac_key)
    return _hmac.compare_digest(expected, signature)


def generate_nonce() -> str:
    """Generate a unique nonce for command replay protection."""
    return f"{int(time.time() * 1000)}-{secrets.token_hex(8)}"
