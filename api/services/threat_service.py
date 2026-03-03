"""Compatibility shim for legacy threat service imports in tests."""

from __future__ import annotations

from typing import Any


async def get_threat_data(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return {}


async def enrich_scan_with_threat_data(scan_data: dict[str, Any]) -> dict[str, Any]:
    return scan_data
