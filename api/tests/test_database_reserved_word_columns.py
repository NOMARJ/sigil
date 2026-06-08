"""Sigil API — bracket-quote reserved-word columns in T-SQL (F1.6).

T-SQL reserves `plan`, `status`, `references` (among others). When MssqlClient
generates SQL, column names must be wrapped in `[]` so that tables like
`subscriptions(plan, status, ...)` and `scans(status)` work.

Failure mode pre-fix: pyodbc.ProgrammingError (42000) "Incorrect syntax near
the keyword 'plan'" on /v1/billing/subscription with any authenticated user
(observed 2026-05-03 from sigil-api revision sigil-api--0000072 logs).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


def _make_client_with_mock_pool() -> tuple[Any, list[tuple[str, tuple]]]:
    """Build a MssqlClient with a captured-SQL pool. Returns (client, captured)."""
    from api.database import MssqlClient

    client = MssqlClient()
    captured: list[tuple[str, tuple]] = []

    cursor = AsyncMock()
    cursor.execute = AsyncMock(
        side_effect=lambda sql, params=None: captured.append((sql, params or ()))
    )
    cursor.fetchone = AsyncMock(return_value=None)
    cursor.fetchall = AsyncMock(return_value=[])
    cursor.description = []

    cursor_cm = MagicMock()
    cursor_cm.__aenter__ = AsyncMock(return_value=cursor)
    cursor_cm.__aexit__ = AsyncMock(return_value=None)

    conn = MagicMock()
    conn.cursor = MagicMock(return_value=cursor_cm)
    conn.commit = AsyncMock()
    conn.rollback = AsyncMock()

    conn_cm = MagicMock()
    conn_cm.__aenter__ = AsyncMock(return_value=conn)
    conn_cm.__aexit__ = AsyncMock(return_value=None)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=conn_cm)
    client._pool = pool

    return client, captured


@pytest.mark.asyncio
async def test_insert_brackets_reserved_word_columns():
    client, captured = _make_client_with_mock_pool()
    await client.insert("subscriptions", {"id": "x", "plan": "pro", "status": "active"})

    assert len(captured) == 1
    sql, _ = captured[0]
    assert "[plan]" in sql, f"plan column not bracketed in INSERT: {sql}"
    assert "[status]" in sql, f"status column not bracketed in INSERT: {sql}"
    assert "[id]" in sql, f"id column should also be bracketed for consistency: {sql}"


@pytest.mark.asyncio
async def test_upsert_brackets_reserved_word_columns():
    client, captured = _make_client_with_mock_pool()
    await client.upsert(
        "subscriptions",
        {"id": "x", "user_id": "u", "plan": "pro", "status": "active"},
        conflict_columns=["user_id"],
    )

    assert len(captured) >= 1
    insert_sql, _ = captured[0]
    assert "[plan]" in insert_sql, f"plan column not bracketed in INSERT: {insert_sql}"
    assert "[status]" in insert_sql, (
        f"status column not bracketed in INSERT: {insert_sql}"
    )


@pytest.mark.asyncio
async def test_select_brackets_reserved_word_columns_in_where():
    client, captured = _make_client_with_mock_pool()
    await client.select("subscriptions", filters={"plan": "pro", "status": "active"})

    assert len(captured) == 1
    sql, _ = captured[0]
    assert "[plan] = ?" in sql, f"plan column not bracketed in WHERE: {sql}"
    assert "[status] = ?" in sql, f"status column not bracketed in WHERE: {sql}"


@pytest.mark.asyncio
async def test_update_brackets_reserved_word_columns():
    client, captured = _make_client_with_mock_pool()
    await client.update(
        "subscriptions", {"plan": "team", "status": "trialing"}, {"user_id": "u"}
    )

    update_sql_calls = [c for c in captured if c[0].startswith("UPDATE ")]
    assert len(update_sql_calls) >= 1
    sql, _ = update_sql_calls[0]
    assert "[plan] = ?" in sql, f"plan column not bracketed in UPDATE SET: {sql}"
    assert "[status] = ?" in sql, f"status column not bracketed in UPDATE SET: {sql}"


@pytest.mark.asyncio
async def test_delete_brackets_reserved_word_columns():
    client, captured = _make_client_with_mock_pool()
    await client.delete("subscriptions", {"plan": "free"})

    assert len(captured) == 1
    sql, _ = captured[0]
    assert "[plan] = ?" in sql, f"plan column not bracketed in DELETE WHERE: {sql}"
