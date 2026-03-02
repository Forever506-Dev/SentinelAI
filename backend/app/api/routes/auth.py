"""
Authentication Routes

User registration, login, token refresh, profile management,
password reset (via email code), change password, and TOTP 2FA.
"""

import traceback
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    create_2fa_token,
    verify_2fa_token,
    decode_token,
    get_current_user,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp_code,
    generate_totp_qr_base64,
)
from app.core.config import settings
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    TokenResponse,
    RefreshRequest,
    UserResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    ChangePasswordRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TwoFALoginRequest,
)
from app.services.email_service import generate_reset_code, send_reset_email

logger = structlog.get_logger()
router = APIRouter()


# ───────────────────────  Registration  ───────────────────────

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Register a new user account."""
    try:
        existing = await db.execute(
            select(User).where(
                (User.email == payload.email) | (User.username == payload.username)
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email or username already exists",
            )

        user = User(
            email=payload.email,
            username=payload.username,
            hashed_password=hash_password(payload.password),
            full_name=payload.full_name,
            role="analyst",
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Registration error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to an internal error",
        )


# ───────────────────────  Login  ───────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Authenticate user and return JWT tokens.

    If the user has TOTP 2FA enabled and no totp_code is supplied,
    returns a short-lived `two_fa_token` instead of real tokens.
    """
    result = await db.execute(
        select(User).where(User.username == payload.username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # ── 2FA check ──
    if user.totp_enabled and user.totp_secret:
        # If the user supplied a TOTP code inline, verify it
        if payload.totp_code:
            if not verify_totp_code(user.totp_secret, payload.totp_code):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid TOTP code",
                )
        else:
            # Return a 2FA-pending token so the frontend can ask for the code
            two_fa_token = create_2fa_token(subject=str(user.id))
            return {
                "requires_2fa": True,
                "two_fa_token": two_fa_token,
            }

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    access_token = create_access_token(
        subject=str(user.id),
        extra_claims={"role": user.role, "username": user.username},
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/2fa/login", response_model=LoginResponse)
async def login_2fa(
    payload: TwoFALoginRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Complete login by verifying the TOTP code after the 2FA-pending step."""
    user_id = verify_2fa_token(payload.two_fa_token)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not user.totp_secret or not verify_totp_code(user.totp_secret, payload.totp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

    user.last_login = datetime.now(timezone.utc)

    access_token = create_access_token(
        subject=str(user.id),
        extra_claims={"role": user.role, "username": user.username},
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ───────────────────────  Token Refresh  ───────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Refresh an access token using a valid refresh token."""
    token_data = decode_token(payload.refresh_token)

    if token_data.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = token_data["sub"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(
        subject=str(user.id),
        extra_claims={"role": user.role, "username": user.username},
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ───────────────────────  Profile  ───────────────────────

@router.get("/me", response_model=UserResponse)
async def get_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get the current authenticated user's profile."""
    result = await db.execute(
        select(User).where(User.id == current_user["sub"])
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


# ───────────────────────  Password Reset  ───────────────────────

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Request a password-reset code.  Always returns 200 to prevent
    email enumeration, even if the email is not found.
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user:
        code = generate_reset_code()
        user.reset_code = code
        user.reset_code_expires = datetime.now(timezone.utc) + timedelta(minutes=15)
        await send_reset_email(user.email, code)

    return {"message": "If that email is registered, a reset code has been sent."}


@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
    payload: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the emailed code and set a new password."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if (
        not user
        or not user.reset_code
        or user.reset_code != payload.code
        or not user.reset_code_expires
        or user.reset_code_expires < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code",
        )

    user.hashed_password = hash_password(payload.new_password)
    user.reset_code = None
    user.reset_code_expires = None
    user.must_change_password = False

    return {"message": "Password has been reset successfully."}


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Change password for the currently authenticated user."""
    result = await db.execute(select(User).where(User.id == current_user["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    user.hashed_password = hash_password(payload.new_password)
    user.must_change_password = False

    return {"message": "Password changed successfully."}


# ───────────────────────  TOTP 2FA Setup  ───────────────────────

@router.post("/2fa/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Generate a new TOTP secret and QR code for the authenticated user.
    The user must call /2fa/verify with a valid code to finalize setup.
    """
    result = await db.execute(select(User).where(User.id == current_user["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled")

    secret = generate_totp_secret()
    provisioning_uri = get_totp_provisioning_uri(secret, user.username)
    qr_base64 = generate_totp_qr_base64(provisioning_uri)

    # Store the secret provisionally (not enabled until verified)
    user.totp_secret = secret

    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "qr_code_base64": qr_base64,
    }


@router.post("/2fa/verify", status_code=status.HTTP_200_OK)
async def verify_2fa(
    payload: TOTPVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Verify a TOTP code to finalize 2FA setup.
    The user must have called /2fa/setup first.
    """
    result = await db.execute(select(User).where(User.id == current_user["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Call /2fa/setup first")

    if user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled")

    if not verify_totp_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")

    user.totp_enabled = True
    return {"message": "Two-factor authentication enabled successfully."}


@router.delete("/2fa/disable", status_code=status.HTTP_200_OK)
async def disable_2fa(
    payload: TOTPVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Disable 2FA. Requires a valid TOTP code for confirmation."""
    result = await db.execute(select(User).where(User.id == current_user["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled")

    if not verify_totp_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")

    user.totp_secret = None
    user.totp_enabled = False
    return {"message": "Two-factor authentication disabled."}
