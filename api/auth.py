"""Compatibility shim for legacy imports used in resilience tests."""

from __future__ import annotations

from api.routers import auth as _auth_router


async def get_current_user(*args, **kwargs):
    return await _auth_router.get_current_user_unified(*args, **kwargs)


async def get_current_user_unified(*args, **kwargs):
    return await _auth_router.get_current_user_unified(*args, **kwargs)
