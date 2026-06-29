"""
Regression tests for bot.store._MssqlStore

NOM-615: "Connection is busy with results for another command" race.

The bug: _MssqlStore.upsert reused the original cursor after conn.rollback()
without draining pending results or creating a fresh cursor, causing pyodbc to
raise "Connection is busy" on the subsequent UPDATE execute().

Fix: drain cursor.fetchall() before rollback, then create a fresh cursor for
the UPDATE path.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pyodbc
import pytest


# ---------------------------------------------------------------------------
# Helpers to build a fake aioodbc pool/connection/cursor
# ---------------------------------------------------------------------------


def _make_cursor(*, raise_on_execute=None):
    """Return an async-compatible mock cursor.

    If raise_on_execute is an exception instance it will be raised on the
    first call to cursor.execute(), simulating a UNIQUE constraint violation.
    """
    cursor = MagicMock()
    cursor.description = [("id",), ("ecosystem",)]

    execute_calls = []

    async def _execute(sql, params=None):
        if raise_on_execute and not execute_calls:
            execute_calls.append(sql)
            raise raise_on_execute
        execute_calls.append(sql)

    async def _fetchall():
        return []

    async def _fetchone():
        return None

    cursor.execute = AsyncMock(side_effect=_execute)
    cursor.fetchall = AsyncMock(side_effect=_fetchall)
    cursor.fetchone = AsyncMock(side_effect=_fetchone)
    return cursor


def _make_conn(cursor):
    """Return a mock connection that returns *cursor* from conn.cursor()."""
    conn = MagicMock()
    conn.commit = AsyncMock()
    conn.rollback = AsyncMock()

    async def _cursor():
        return cursor

    conn.cursor = AsyncMock(side_effect=_cursor)
    return conn


class _FakePool:
    """Minimal context-manager pool whose acquire() yields *conn*."""

    def __init__(self, conn):
        self._conn = conn

    def acquire(self):
        return _ConnCtx(self._conn)


class _ConnCtx:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

# bot.config and bot.queue may not be importable in test isolation; stub them.
sys.modules.setdefault(
    "bot.config",
    SimpleNamespace(bot_settings=SimpleNamespace(database_url=None)),
)
sys.modules.setdefault(
    "bot.queue",
    SimpleNamespace(ScanJob=object),
)

from bot.store import _MssqlStore  # noqa: E402


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMssqlStoreUpsert:
    """NOM-615 regression: stale cursor after rollback."""

    @pytest.mark.asyncio
    async def test_insert_path_succeeds(self):
        """Happy path: INSERT succeeds, no UPDATE needed."""
        cursor = _make_cursor()
        conn = _make_conn(cursor)
        store = _MssqlStore(_FakePool(conn))

        result = await store.upsert("t", {"id": "1", "val": "a"}, conflict_columns=["id"])

        assert result == {"id": "1", "val": "a"}
        conn.commit.assert_awaited_once()
        conn.rollback.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_upsert_drains_cursor_before_rollback(self):
        """After a UNIQUE violation the stale cursor must be drained before rollback."""
        integrity_err = pyodbc.IntegrityError("23000", "[23000] ... 2627 ...")
        integrity_err.args = ("23000", "[23000] ... 2627 ...")

        # Track how many cursors are created on the connection.
        cursors_created = []

        first_cursor = _make_cursor(raise_on_execute=integrity_err)
        second_cursor = _make_cursor()
        cursor_sequence = [first_cursor, second_cursor]

        conn = MagicMock()
        conn.commit = AsyncMock()
        conn.rollback = AsyncMock()

        async def _cursor():
            c = cursor_sequence.pop(0)
            cursors_created.append(c)
            return c

        conn.cursor = AsyncMock(side_effect=_cursor)

        store = _MssqlStore(_FakePool(conn))
        result = await store.upsert(
            "t",
            {"id": "1", "val": "b"},
            conflict_columns=["id"],
        )

        assert result == {"id": "1", "val": "b"}

        # fetchall() must have been called on the FIRST (stale) cursor to drain it.
        first_cursor.fetchall.assert_awaited_once()

        # rollback must have been called after drain.
        conn.rollback.assert_awaited_once()

        # A SECOND cursor must have been created for the UPDATE.
        assert len(cursors_created) == 2, (
            "Expected two cursors (first for INSERT, second for UPDATE after rollback)"
        )

        # The UPDATE execute must have run on the second cursor.
        second_cursor.execute.assert_awaited_once()
        update_sql = second_cursor.execute.call_args[0][0]
        assert "UPDATE" in update_sql

        # Final commit must have occurred.
        assert conn.commit.await_count == 1

    @pytest.mark.asyncio
    async def test_upsert_noop_when_no_update_cols(self):
        """If all columns are conflict columns there is nothing to UPDATE."""
        integrity_err = pyodbc.IntegrityError("23000", "[23000] ... 2627 ...")
        integrity_err.args = ("23000", "[23000] ... 2627 ...")

        cursor = _make_cursor(raise_on_execute=integrity_err)
        conn = _make_conn(cursor)
        store = _MssqlStore(_FakePool(conn))

        result = await store.upsert("t", {"id": "1"}, conflict_columns=["id"])

        assert result == {"id": "1"}
        # rollback must still happen.
        conn.rollback.assert_awaited_once()
        # No UPDATE execute — cursor.execute only called once (the failed INSERT).
        assert cursor.execute.await_count == 1

    @pytest.mark.asyncio
    async def test_non_unique_integrity_error_reraises(self):
        """FK / CHECK / NOT NULL violations must propagate, not be swallowed."""
        fk_err = pyodbc.IntegrityError("23000", "[23000] ... 547 ...")
        fk_err.args = ("23000", "[23000] ... 547 ...")

        cursor = _make_cursor(raise_on_execute=fk_err)
        conn = _make_conn(cursor)
        store = _MssqlStore(_FakePool(conn))

        with pytest.raises(pyodbc.IntegrityError):
            await store.upsert("t", {"id": "1", "val": "x"}, conflict_columns=["id"])

    @pytest.mark.asyncio
    async def test_concurrent_upserts_no_busy_error(self):
        """Multiple concurrent upserts must complete without interference.

        This is the primary NOM-615 scenario: two coroutines writing the same
        key concurrently. Before the fix the stale cursor caused pyodbc to
        raise "Connection is busy" on the second execute().
        """
        integrity_err = pyodbc.IntegrityError("23000", "[23000] ... 2627 ...")
        integrity_err.args = ("23000", "[23000] ... 2627 ...")

        results = []

        async def run_upsert(val: str):
            # Each coroutine gets its own independent pool/conn/cursor chain.
            first_c = _make_cursor(raise_on_execute=integrity_err)
            second_c = _make_cursor()
            seq = [first_c, second_c]

            conn = MagicMock()
            conn.commit = AsyncMock()
            conn.rollback = AsyncMock()

            async def _cursor():
                return seq.pop(0)

            conn.cursor = AsyncMock(side_effect=_cursor)
            store = _MssqlStore(_FakePool(conn))
            r = await store.upsert("t", {"id": "1", "val": val}, conflict_columns=["id"])
            results.append(r)

        await asyncio.gather(
            run_upsert("concurrent-a"),
            run_upsert("concurrent-b"),
        )

        assert len(results) == 2
