"""
Sigil API — Authentication Router

POST /v1/auth/register — Create a new user account
POST /v1/auth/login    — Authenticate and receive a JWT
GET  /v1/auth/me       — Return the current user profile

JWT implementation:
  Prefers ``python-jose`` when available, falls back to a stdlib HMAC-SHA256
  implementation so the service can run without compiled C extensions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import base64
import secrets
import time
from datetime import datetime, timedelta
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from api.config import settings
from api.database import db
from api.models import (
    AuthTokens,
    ErrorResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    RefreshTokenRequest,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Password hashing — stdlib fallback when passlib/bcrypt unavailable
# ---------------------------------------------------------------------------

_pwd_context = None

try:
    from passlib.context import CryptContext

    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # Smoke test to detect runtime failures (e.g. bcrypt version mismatch)
    _pwd_context.hash("__sigil_probe__")
    logger.info("Using passlib/bcrypt for password hashing")
except BaseException:
    _pwd_context = None
    logger.warning("passlib/bcrypt not available — using PBKDF2-SHA256 fallback")


def _pbkdf2_hash(password: str) -> str:
    """Hash a password with PBKDF2-SHA256 (stdlib fallback)."""
    import secrets

    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


def _pbkdf2_verify(password: str, hashed: str) -> bool:
    """Verify a PBKDF2-SHA256 hashed password."""
    try:
        _, _, salt, dk_hex = hashed.split(":")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _hash_password(password: str) -> str:
    """Hash a password using the best available backend."""
    if _pwd_context is not None:
        return _pwd_context.hash(password)
    return _pbkdf2_hash(password)


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash using the appropriate backend."""
    if _pwd_context is not None and not hashed.startswith("pbkdf2:"):
        return _pwd_context.verify(password, hashed)
    if hashed.startswith("pbkdf2:"):
        return _pbkdf2_verify(password, hashed)
    # If passlib is available, try it for any other format
    if _pwd_context is not None:
        try:
            return _pwd_context.verify(password, hashed)
        except Exception:
            return False
    return False


# ---------------------------------------------------------------------------
# JWT helpers — prefer python-jose, fall back to stdlib HMAC-SHA256
# ---------------------------------------------------------------------------

_USE_JOSE = False

try:
    from jose import JWTError as _JoseJWTError, jwt as _jose_jwt

    _USE_JOSE = True
    logger.info("Using python-jose for JWT operations")
except BaseException:
    # Catches ImportError, pyo3 PanicException, and any other failures
    _JoseJWTError = Exception  # type: ignore[misc,assignment]
    _jose_jwt = None  # type: ignore[assignment]
    logger.info("python-jose unavailable — using stdlib HMAC-SHA256 JWT fallback")


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """Create a signed JWT with the given payload."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.jwt_expire_minutes)
    )
    to_encode["exp"] = int(expire.timestamp())

    if _USE_JOSE:
        return _jose_jwt.encode(
            to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm
        )

    # Stdlib HMAC-SHA256 fallback
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps(to_encode).encode())
    signing_input = f"{header}.{payload}"
    signature = hmac.new(
        settings.jwt_secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def _verify_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT.  Raises ``HTTPException`` on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if _USE_JOSE:
        try:
            payload = _jose_jwt.decode(
                token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
            )
            return payload
        except _JoseJWTError as exc:
            raise credentials_exception from exc

    # Stdlib fallback
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token")

        header_b64, payload_b64, sig_b64 = parts

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            settings.jwt_secret.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Invalid signature")

        payload = json.loads(_b64url_decode(payload_b64))

        # Check expiry
        exp = payload.get("exp")
        if exp is not None and time.time() > exp:
            raise ValueError("Token expired")

        return payload
    except HTTPException:
        raise
    except Exception as exc:
        raise credentials_exception from exc


# ---------------------------------------------------------------------------
# OAuth2 bearer scheme (for dependency injection)
# ---------------------------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login", auto_error=False)

# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------
USER_TABLE = "users"


# ---------------------------------------------------------------------------
# Dependency: current authenticated user
# ---------------------------------------------------------------------------


async def get_current_user(
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> UserResponse:
    """FastAPI dependency that extracts and validates the current user from
    the Authorization header.

    Raises 401 if the token is missing, invalid, or the user no longer exists.
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = _verify_token(token)
    user_id: str | None = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await db.select_one(USER_TABLE, {"id": user_id})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return UserResponse(
        id=user["id"],
        email=user["email"],
        name=user.get("name", ""),
        created_at=user.get("created_at", datetime.utcnow()),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    responses={409: {"model": ErrorResponse}},
)
async def register(body: UserCreate) -> TokenResponse:
    """Create a new user account and return an access token.

    - Email must be unique.
    - Password must be at least 8 characters.
    """
    # Check for existing user
    existing = await db.select_one(USER_TABLE, {"email": body.email})
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    user_id = uuid4().hex[:16]
    now = datetime.utcnow()

    user_row = {
        "id": user_id,
        "email": body.email,
        "password_hash": _hash_password(body.password),
        "name": body.name,
        "created_at": now.isoformat(),
    }

    await db.insert(USER_TABLE, user_row)

    token = _create_access_token({"sub": user_id, "email": body.email})
    expires_in = settings.jwt_expire_minutes * 60

    logger.info("User registered: %s (%s)", user_id, body.email)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserResponse(id=user_id, email=body.email, name=body.name, created_at=now),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT",
    responses={401: {"model": ErrorResponse}},
)
async def login(body: UserLogin) -> TokenResponse:
    """Authenticate with email and password.

    Returns a JWT access token on success, or 401 on failure.
    """
    user = await db.select_one(USER_TABLE, {"email": body.email})
    if user is None or not _verify_password(
        body.password, user.get("password_hash", "")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = _create_access_token({"sub": user["id"], "email": user["email"]})
    expires_in = settings.jwt_expire_minutes * 60

    logger.info("User logged in: %s", user["id"])

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            name=user.get("name", ""),
            created_at=user.get("created_at", datetime.utcnow()),
        ),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    responses={401: {"model": ErrorResponse}},
)
async def me(
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> UserResponse:
    """Return the profile of the currently authenticated user.

    Requires a valid Bearer token in the ``Authorization`` header.
    """
    return current_user


@router.post(
    "/refresh",
    response_model=AuthTokens,
    summary="Refresh an access token",
    responses={401: {"model": ErrorResponse}},
)
async def refresh_token(body: RefreshTokenRequest) -> AuthTokens:
    """Exchange a refresh token for a new access token.

    Validates the provided refresh token and, if valid, issues a fresh
    access token.  The refresh token is treated as a JWT with the same
    structure as the access token.
    """
    payload = _verify_token(body.refresh_token)
    user_id: str | None = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token: missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify the user still exists
    user = await db.select_one(USER_TABLE, {"id": user_id})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    new_token = _create_access_token({"sub": user_id, "email": user.get("email", "")})
    expires_in = settings.jwt_expire_minutes * 60

    logger.info("Token refreshed for user: %s", user_id)

    return AuthTokens(
        access_token=new_token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out the current user",
    responses={401: {"model": ErrorResponse}},
)
async def logout(
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> None:
    """Invalidate the current session.

    In a stateless JWT setup this is effectively a no-op on the server side.
    The client should discard its stored tokens.  A token blocklist can be
    added here in the future for immediate revocation.
    """
    logger.info("User logged out: %s", current_user.id)
    return None


# ---------------------------------------------------------------------------
# Password reset helpers
# ---------------------------------------------------------------------------


async def _send_reset_email(email: str, reset_link: str) -> None:
    """Send a password reset email via the notifications service."""
    from api.services.notifications import send_email_notification

    await send_email_notification(
        recipients=[email],
        subject="Reset your Sigil password",
        body_text=(
            f"Click the link below to reset your password (expires in 1 hour):\n\n"
            f"{reset_link}\n\n"
            f"If you didn't request this, ignore this email."
        ),
    )


# ---------------------------------------------------------------------------
# Password reset endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Request a password reset link",
)
async def forgot_password(body: ForgotPasswordRequest) -> ForgotPasswordResponse:
    """Generate a password reset token and send it via email.

    Always returns a success message to prevent email enumeration attacks.
    The reset link is only sent when the email address matches an existing user.
    """
    user = await db.get_user_by_email(body.email)
    if user:
        raw_token = secrets.token_hex(32)  # 64-char hex string
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(hours=1)

        await db.create_password_reset_token(user["id"], token_hash, expires_at)

        reset_link = f"{settings.cors_origins[0]}/reset-password?token={raw_token}"
        try:
            await _send_reset_email(user["email"], reset_link)
        except Exception:
            logger.exception("Failed to send password reset email to %s", user["email"])

        logger.info("Password reset requested for user: %s", user["id"])

    # Always return success to prevent email enumeration
    return ForgotPasswordResponse(
        message="If that email exists, a reset link has been sent."
    )


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    summary="Reset password using a reset token",
    responses={400: {"model": ErrorResponse}},
)
async def reset_password(body: ResetPasswordRequest) -> ResetPasswordResponse:
    """Validate a reset token and update the user's password.

    The token is single-use and expires after 1 hour.
    Returns 400 if the token is invalid or expired.
    """
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    token_record = await db.get_password_reset_token(token_hash)

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Double-check expiry (get_password_reset_token may return None for expired,
    # but guard here for any DB backends that skip expiry filtering)
    expires_at_raw = token_record.get("expires_at")
    if expires_at_raw:
        try:
            expires_dt = datetime.fromisoformat(
                str(expires_at_raw).replace("Z", "").split("+")[0]
            )
            if datetime.utcnow() > expires_dt:
                await db.delete_password_reset_token(token_hash)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Reset token has expired",
                )
        except HTTPException:
            raise
        except (ValueError, TypeError):
            pass

    new_hash = _hash_password(body.new_password)

    await db.update_user_password(token_record["user_id"], new_hash)
    await db.delete_password_reset_token(token_hash)

    logger.info("Password reset completed for user: %s", token_record["user_id"])

    return ResetPasswordResponse(message="Password reset successfully")
