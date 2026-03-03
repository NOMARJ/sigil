"""Compatibility shim for legacy billing service imports in tests."""

from __future__ import annotations

from typing import Any


async def get_subscription(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return {"plan": "free", "status": "active"}
