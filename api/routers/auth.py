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
import re
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from typing_extensions import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import (
    HTTPBearer,
    OAuth2PasswordBearer,
)

import httpx

from api.config import settings
from api.database import cache, db
from api.models import (
    AuthTokens,
    ErrorResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Redis-backed rate limiter for login attempts (distributed, survives restarts)
# ---------------------------------------------------------------------------
_LOGIN_WINDOW = 300  # 5 minutes
_LOGIN_MAX_ATTEMPTS = 10  # max 10 attempts per window per IP


async def _check_login_rate_limit(client_ip: str) -> None:
    """Raise 429 if too many login attempts from this IP.

    Uses Redis INCR with TTL for a fixed-window counter that works across
    multiple API instances and survives restarts.  Falls back to in-memory
    counting when Redis is unavailable (via RedisClient internals).
    """
    key = f"ratelimit:login:{client_ip}"
    count = await cache.incr(key, ttl=_LOGIN_WINDOW)
    if count > _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {_LOGIN_WINDOW // 60} minutes.",
        )


# ---------------------------------------------------------------------------
# Redis-backed token blocklist (survives restarts, auto-expires with JWT TTL)
# ---------------------------------------------------------------------------


async def _revoke_token(token: str) -> None:
    """Add a token to the revocation blocklist in Redis.

    The key auto-expires after the JWT lifetime so the blocklist is
    self-cleaning — no manual eviction or memory caps needed.
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ttl = settings.jwt_expire_minutes * 60  # match JWT lifetime
    await cache.set(f"revoked:{token_hash}", "1", ttl=ttl)


async def _is_token_revoked(token: str) -> bool:
    """Check if a token has been revoked."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return await cache.exists(f"revoked:{token_hash}")


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


def _sanitize_display_name(name: str) -> str:
    """Minimal XSS hardening for stored/displayed profile names."""
    cleaned = re.sub(r"(?is)<script.*?>.*?</script>", "", name or "")
    cleaned = re.sub(r"(?i)javascript:", "", cleaned)
    cleaned = cleaned.replace("<", "").replace(">", "")
    return cleaned.strip()


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
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT with the given payload."""
    import time

    to_encode = data.copy()
    # Use time.time() to get current UTC timestamp, avoiding timezone issues
    # with datetime.utcnow().timestamp() which assumes local timezone
    now = int(time.time())
    expire_seconds = (
        expires_delta or timedelta(minutes=settings.jwt_expire_minutes)
    ).total_seconds()
    to_encode["exp"] = now + int(expire_seconds)

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


async def _verify_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT.  Raises ``HTTPException`` on failure."""
    if await _is_token_revoked(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
http_bearer = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------
USER_TABLE = "users"


# ---------------------------------------------------------------------------
# Dependency: current authenticated user
# ---------------------------------------------------------------------------


async def get_current_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
) -> UserResponse:
    """FastAPI dependency that extracts and validates the current user from
    the Authorization header.

    Raises 401 if the token is missing, invalid, or the user no longer exists.
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad request: not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = await _verify_token(token)
    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return UserResponse(
        id=str(user["id"]),
        email=user["email"],
        name=user.get("name", ""),
        created_at=user.get("created_at", datetime.utcnow()),
    )


# ---------------------------------------------------------------------------
# Token verification helpers — reusable token validation logic
# ---------------------------------------------------------------------------

# Auth0 JWKS cache (fetched once, reused)
_auth0_jwks_cache: Optional[dict] = None


async def _get_auth0_jwks() -> dict:
    """Fetch and cache Auth0 JWKS (JSON Web Key Set)."""
    global _auth0_jwks_cache
    if _auth0_jwks_cache is None:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://{settings.auth0_domain}/.well-known/jwks.json"
            )
            resp.raise_for_status()
            _auth0_jwks_cache = resp.json()
    return _auth0_jwks_cache


async def verify_auth0_token(token: str) -> Dict[str, Any]:
    """Verify an Auth0-issued RS256 JWT and return user claims.

    Args:
        token: The JWT token string to verify

    Returns:
        dict containing sub, email, and name from the token payload

    Raises:
        HTTPException: If the token is invalid, expired, or missing required claims
    """
    if not settings.auth0_configured:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is not configured",
        )

    if not _USE_JOSE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is not configured",
        )

    try:
        jwks = await _get_auth0_jwks()

        # Get the signing key
        unverified_header = _jose_jwt.get_unverified_header(token)
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header.get("kid"):
                rsa_key = key
                break

        if not rsa_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signing key",
            )

        payload = _jose_jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=f"https://{settings.auth0_domain}/",
        )
    except HTTPException:
        raise
    except _JoseJWTError as e:
        logger.error("Auth0 JWT validation failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    except Exception as e:
        logger.error("Auth0 JWT validation failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    namespace = "https://api.sigilsec.ai"
    email = payload.get(f"{namespace}/email", payload.get("email", ""))
    name = payload.get(f"{namespace}/name", payload.get("name", ""))
    email_verified = payload.get(
        f"{namespace}/email_verified", payload.get("email_verified")
    )

    if not email or email_verified is not True:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"https://{settings.auth0_domain}/userinfo",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if not resp.is_success:
                    logger.error(
                        "Auth0 /userinfo returned %s: %s", resp.status_code, resp.text
                    )
                    resp.raise_for_status()
                userinfo = resp.json()
                if userinfo.get("sub") and userinfo.get("sub") != payload["sub"]:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired token",
                    )
                email = email or userinfo.get("email", "")
                if not name:
                    name = userinfo.get("name", "")
                email_verified = userinfo.get("email_verified", False)
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Auth0 /userinfo fallback failed: %s", e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    if email_verified is not True:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email must be verified",
        )

    return {
        "sub": payload["sub"],
        "email": email,
        "name": name,
        "email_verified": True,
    }


async def verify_custom_jwt(token: str) -> Dict[str, Any]:
    """Verify a custom JWT token and return user data.

    Args:
        token: The JWT token string to verify

    Returns:
        dict containing user data from the database

    Raises:
        HTTPException: If the token is invalid, expired, or user doesn't exist
    """
    payload = await _verify_token(token)
    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "id": str(user["id"]),
        "email": user["email"],
        "name": user.get("name", ""),
        "role": user.get("role", "member"),
        "team_id": user.get("team_id"),
        "created_at": user.get("created_at", datetime.utcnow()),
    }


def _get_auth_token_from_request(request: Request) -> str:
    """Helper to extract the auth token from the request.

    Args:
        request: FastAPI Request object (auto-injected)

    Returns:
        The bearer token string

    Raises:
        HTTPException: If no token or invalid scheme
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad request: not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return auth_header[7:]  # Remove "Bearer " prefix


# ---------------------------------------------------------------------------
# Unified Auth — supports Auth0 (OAuth) and custom JWT (email/password)
# ---------------------------------------------------------------------------


async def _auto_provision_auth0_user(user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-provision a user in the database on first Auth0 login.

    Matches by email. If no user exists, creates one with an empty password_hash
    (OAuth users don't have passwords in Sigil).

    Returns the user row from the database.
    """
    auth0_sub = user_info.get("sub", "")
    email = user_info.get("email", "").strip().lower()
    if not auth0_sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_columns = await db._table_columns(USER_TABLE)
    if user_columns is not None and "auth0_sub" not in user_columns:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        )

    user = await db.select_one(USER_TABLE, {"auth0_sub": auth0_sub})
    if user is None:
        user = await db.select_one(USER_TABLE, {"email": email})
        if user is not None:
            existing_sub = user.get("auth0_sub")
            if existing_sub and existing_sub != auth0_sub:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                )
            user["auth0_sub"] = auth0_sub
            if user.get("email") != email:
                user["email"] = email
            if user_info.get("name") and not user.get("name"):
                user["name"] = user_info.get("name", "")
            await db.upsert(USER_TABLE, user)

    if user is None:
        user_id = str(uuid4())
        now = datetime.utcnow()
        user_row = {
            "id": user_id,
            "email": email,
            "auth0_sub": auth0_sub,
            "name": user_info.get("name", ""),
            "password_hash": "",  # OAuth users have no password
            "role": "member",
            "created_at": now,
        }
        await db.insert(USER_TABLE, user_row)
        logger.info("Auto-provisioned Auth0 user: %s (%s)", user_id, email)
        user = user_row
    return user


async def get_current_user_unified(request: Request) -> UserResponse:
    """Auth0-only authentication (RS256 JWT).

    Auth0 users are auto-provisioned on first login.
    Email/password authentication now handled by Auth0 Database Connection.
    """
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad request: not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]  # Remove "Bearer " prefix

    # Verify Auth0 token
    if not settings.auth0_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service not configured",
        )

    try:
        user_info = await verify_auth0_token(token)
        user = await _auto_provision_auth0_user(user_info)
        logger.debug("Authentication successful via Auth0")
        return UserResponse(
            id=str(user["id"]),
            email=user["email"],
            name=user.get("name", ""),
            role=user.get("role", "member"),
            team_id=user.get("team_id"),
            created_at=user.get("created_at", datetime.utcnow()),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Auth0 authentication failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


async def _compat_current_user_dependency(request: Request) -> UserResponse:
    """Compatibility bridge for tests patching api.auth.get_current_user."""
    import api.auth as auth_compat

    return await auth_compat.get_current_user(request=request)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_410_GONE,
    summary="DEPRECATED: Use Auth0 Database Connection",
    deprecated=True,
    responses={410: {"model": ErrorResponse}},
)
async def register(body: UserCreate) -> TokenResponse:
    """DEPRECATED: Registration now handled by Auth0 Database Connection.

    Please use the Auth0 Universal Login flow at /api/auth/login instead.
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="This endpoint is deprecated. Please use Auth0 authentication at /api/auth/login",
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_410_GONE,
    summary="DEPRECATED: Use Auth0 Database Connection",
    deprecated=True,
    responses={410: {"model": ErrorResponse}},
)
async def login(body: UserLogin, request: Request) -> TokenResponse:
    """DEPRECATED: Login now handled by Auth0 Database Connection.

    Please use the Auth0 Universal Login flow at /api/auth/login instead.
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="This endpoint is deprecated. Please use Auth0 authentication at /api/auth/login",
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    responses={401: {"model": ErrorResponse}},
)
async def me(
    current_user: Annotated[UserResponse, Depends(_compat_current_user_dependency)],
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
    access token with the standard expiry (``jwt_expire_minutes``).
    The consumed refresh token is revoked so it cannot be replayed.

    Note: To return a new 7-day refresh token alongside the access token,
    add a ``refresh_token`` field to the ``AuthTokens`` model.
    """
    payload = await _verify_token(body.refresh_token)
    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token: missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify the user still exists
    user = await db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Revoke the consumed refresh token to prevent replay
    await _revoke_token(body.refresh_token)

    # Issue a new access token with standard expiry
    new_token = _create_access_token(
        {"sub": user_id, "email": user.get("email", "")},
        expires_delta=timedelta(minutes=settings.jwt_expire_minutes),
    )
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
    response_class=Response,
    summary="Log out the current user",
)
async def logout(
    request: Request,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> Response:
    """Invalidate the current session.

    Adds the Bearer token to an in-memory revocation blocklist so it cannot
    be reused.  The client should also discard its stored tokens.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        await _revoke_token(auth_header[7:])

    logger.info("User logged out: %s", current_user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# NOTE: Password reset endpoints (`/forgot-password`, `/reset-password`) and
# the `_send_reset_email` helper were removed 2026-05-04 per ADR-0002 — Auth0
# Universal Login owns identity, including password reset. The dashboard's
# `/reset-password` page now redirects to `/api/auth/login`, where Auth0's
# hosted "Don't remember your password?" link triggers an Auth0-managed reset
# email. The MSSQL `password_reset_tokens` table and `users.password_hash`
# column remain in the schema as legacy storage but are no longer written to.


@router.get(
    "/verify",
    response_model=Dict[str, Any],
    summary="Verify API key and return user tier information",
    responses={401: {"model": ErrorResponse}},
)
async def verify_api_key(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> Dict[str, Any]:
    """Verify API key and return user tier information for CLI tier checking.

    Returns:
        - valid: True if token is valid
        - user_id: The authenticated user's ID
        - tier: User's current subscription tier (free, pro, team, enterprise)
        - limits: Monthly scan limits and current usage for the user's tier
        - features: Available features for the user's tier
    """
    from api.gates import get_user_plan, PLAN_LIMITS
    from api.database import db
    from datetime import datetime, timezone

    # Get user's current plan tier
    user_tier = await get_user_plan(current_user.id)

    # Get current scan usage for the month
    year_month = datetime.now(timezone.utc).strftime("%Y-%m")
    current_usage = await db.get_scan_usage(current_user.id, year_month)
    monthly_limit = PLAN_LIMITS[user_tier]

    # Define features available per tier
    tier_features = {
        "free": {
            "static_analysis": True,
            "llm_analysis": False,
            "advanced_obfuscation": False,
            "contextual_insights": False,
            "priority_support": False,
            "scan_history": False,
            "team_collaboration": False,
        },
        "pro": {
            "static_analysis": True,
            "llm_analysis": True,
            "advanced_obfuscation": True,
            "contextual_insights": True,
            "priority_support": True,
            "scan_history": True,
            "team_collaboration": False,
        },
        "team": {
            "static_analysis": True,
            "llm_analysis": True,
            "advanced_obfuscation": True,
            "contextual_insights": True,
            "priority_support": True,
            "scan_history": True,
            "team_collaboration": True,
        },
        "enterprise": {
            "static_analysis": True,
            "llm_analysis": True,
            "advanced_obfuscation": True,
            "contextual_insights": True,
            "priority_support": True,
            "scan_history": True,
            "team_collaboration": True,
        },
    }

    return {
        "valid": True,
        "user_id": current_user.id,
        "tier": user_tier.value,
        "limits": {
            "monthly_scans": monthly_limit if monthly_limit > 0 else "unlimited",
            "current_usage": current_usage,
            "remaining": max(0, monthly_limit - current_usage)
            if monthly_limit > 0
            else "unlimited",
        },
        "features": tier_features.get(user_tier.value, tier_features["free"]),
        "upgrade_url": "https://app.sigilsec.ai/upgrade"
        if user_tier.value == "free"
        else None,
    }
