"""
Sigil API — Auth0 Device Flow for CLI Authentication

Implements OAuth 2.0 Device Authorization Flow for the Sigil CLI.

Flow:
1. CLI calls POST /v1/auth/device/code
2. API requests device code from Auth0
3. CLI displays verification URL and user code
4. User visits URL and enters code in browser
5. CLI polls POST /v1/auth/device/token
6. API exchanges device code for access token
7. CLI receives token and stores it

References:
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow
- https://datatracker.ietf.org/doc/html/rfc8628
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status

from api.config import settings
from api.models import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/auth/device", tags=["auth"])


# ── Models ─────────────────────────────────────────────────────────────────


class DeviceCodeResponse:
    """Response from Auth0 device authorization endpoint."""
    
    def __init__(self, data: dict[str, Any]):
        self.device_code: str = data["device_code"]
        self.user_code: str = data["user_code"]
        self.verification_uri: str = data["verification_uri"]
        self.verification_uri_complete: str = data.get("verification_uri_complete", "")
        self.expires_in: int = data["expires_in"]
        self.interval: int = data.get("interval", 5)


class DeviceCodeRequest:
    """Request to initiate device flow."""
    
    client_id: str
    scope: str = "openid profile email offline_access"
    audience: str


class DeviceTokenResponse:
    """Response containing access token from device flow."""
    
    def __init__(self, data: dict[str, Any]):
        self.access_token: str = data["access_token"]
        self.token_type: str = data.get("token_type", "Bearer")
        self.expires_in: int = data.get("expires_in", 86400)
        self.refresh_token: str | None = data.get("refresh_token")
        self.scope: str | None = data.get("scope")


# ── Endpoints ──────────────────────────────────────────────────────────────


@router.post(
    "/code",
    summary="Initiate device authorization flow",
    description="Request a device code and user code for CLI authentication",
    responses={
        200: {
            "description": "Device code generated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                        "user_code": "WDJB-MJHT",
                        "verification_uri": "https://auth.sigilsec.ai/activate",
                        "verification_uri_complete": "https://auth.sigilsec.ai/activate?user_code=WDJB-MJHT",
                        "expires_in": 900,
                        "interval": 5
                    }
                }
            }
        },
        503: {"model": ErrorResponse}
    }
)
async def request_device_code() -> dict[str, Any]:
    """Initiate device authorization flow.
    
    Returns device code and verification URL for user to complete authentication.
    CLI should display the verification_uri and user_code to the user.
    """
    if not settings.auth0_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth0 not configured"
        )
    
    # Request device code from Auth0
    device_auth_url = f"https://{settings.auth0_domain}/oauth/device/code"
    
    payload = {
        "client_id": settings.auth0_client_id,
        "scope": "openid profile email offline_access",
        "audience": settings.auth0_audience,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                device_auth_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            if response.status_code != 200:
                logger.error(
                    "Auth0 device code request failed: %s - %s",
                    response.status_code,
                    response.text
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Failed to initiate device flow"
                )
            
            data = response.json()
            logger.info("Device code requested: %s", data.get("user_code"))
            
            return {
                "device_code": data["device_code"],
                "user_code": data["user_code"],
                "verification_uri": data["verification_uri"],
                "verification_uri_complete": data.get("verification_uri_complete", ""),
                "expires_in": data["expires_in"],
                "interval": data.get("interval", 5),
            }
            
    except httpx.RequestError as e:
        logger.error("Auth0 device code request error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth0 service unavailable"
        )


@router.post(
    "/token",
    summary="Poll for device flow token",
    description="Exchange device code for access token (poll until user completes auth)",
    responses={
        200: {
            "description": "Token granted (user completed authentication)",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "Bearer",
                        "expires_in": 86400,
                        "refresh_token": "v1.MRrT...",
                        "scope": "openid profile email offline_access"
                    }
                }
            }
        },
        400: {
            "description": "Pending (user hasn't completed auth yet) or expired",
            "content": {
                "application/json": {
                    "examples": {
                        "pending": {
                            "value": {"error": "authorization_pending", "error_description": "User has not yet authorized"}
                        },
                        "slow_down": {
                            "value": {"error": "slow_down", "error_description": "Polling too frequently"}
                        },
                        "expired": {
                            "value": {"error": "expired_token", "error_description": "Device code expired"}
                        },
                        "denied": {
                            "value": {"error": "access_denied", "error_description": "User denied authorization"}
                        }
                    }
                }
            }
        },
        503: {"model": ErrorResponse}
    }
)
async def poll_device_token(device_code: str) -> dict[str, Any]:
    """Poll for device flow token.
    
    CLI should call this endpoint repeatedly (respecting the interval)
    until it receives a token or an error.
    
    Returns:
    - 200 with access_token: User completed auth, token granted
    - 400 with authorization_pending: User hasn't completed auth yet (keep polling)
    - 400 with slow_down: CLI is polling too fast (increase interval)
    - 400 with expired_token: Device code expired (restart flow)
    - 400 with access_denied: User denied authorization
    """
    if not settings.auth0_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth0 not configured"
        )
    
    # Exchange device code for token
    token_url = f"https://{settings.auth0_domain}/oauth/token"
    
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": settings.auth0_client_id,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0
            )
            
            data = response.json()
            
            # Success - user completed auth
            if response.status_code == 200:
                logger.info("Device flow token granted")
                return {
                    "access_token": data["access_token"],
                    "token_type": data.get("token_type", "Bearer"),
                    "expires_in": data.get("expires_in", 86400),
                    "refresh_token": data.get("refresh_token"),
                    "scope": data.get("scope"),
                }
            
            # Pending or error
            error = data.get("error", "unknown_error")
            error_description = data.get("error_description", "Unknown error")
            
            # These are expected during polling
            if error in ("authorization_pending", "slow_down"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": error, "error_description": error_description}
                )
            
            # Terminal errors
            if error in ("expired_token", "access_denied"):
                logger.warning("Device flow failed: %s", error)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": error, "error_description": error_description}
                )
            
            # Unknown error
            logger.error("Auth0 device token error: %s - %s", error, error_description)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": error, "error_description": error_description}
            )
            
    except httpx.RequestError as e:
        logger.error("Auth0 device token request error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth0 service unavailable"
        )
