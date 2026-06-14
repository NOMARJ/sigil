from __future__ import annotations

import sys
import types

import pytest

from api.config import settings
from api.migrations import apply_prod_migration


class FakeCursor:
    def __init__(self, conn: "FakeConnection") -> None:
        self.conn = conn
        self.last_query = ""

    async def __aenter__(self) -> "FakeCursor":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def execute(self, query: str) -> None:
        if query in self.conn.fail_on:
            raise RuntimeError(f"failed query: {query}")
        self.last_query = query
        self.conn.executed.append(query)

    async def fetchone(self) -> tuple[int]:
        return (self.conn.results.get(self.last_query, self.conn.default_result),)


class FakeConnection:
    def __init__(self, default_result: int = 1) -> None:
        self.default_result = default_result
        self.results: dict[str, int] = {}
        self.executed: list[str] = []
        self.fail_on: set[str] = set()
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    async def close(self) -> None:
        self.closed = True

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def install_fake_aioodbc(
    monkeypatch, conn: FakeConnection, *, expected_autocommit: bool = True
) -> None:
    async def connect(*, dsn: str, autocommit: bool) -> FakeConnection:
        assert dsn == "mssql://verified"
        assert autocommit is expected_autocommit
        return conn

    monkeypatch.setitem(sys.modules, "aioodbc", types.SimpleNamespace(connect=connect))
    monkeypatch.setattr(settings, "database_url", "mssql://verified")


@pytest.mark.asyncio
async def test_verify_only_runs_schema_checks_without_applying_sql(monkeypatch) -> None:
    conn = FakeConnection()
    install_fake_aioodbc(monkeypatch, conn)

    result = await apply_prod_migration.main(["--verify-only"])

    assert result == 0
    assert conn.closed is True
    assert len(conn.executed) == len(
        apply_prod_migration.PRODUCTION_SCHEMA_VERIFICATIONS
    )
    assert all("dbo." in query or "s.name = 'dbo'" in query for query in conn.executed)
    assert all("CREATE TABLE" not in query for query in conn.executed)


@pytest.mark.asyncio
async def test_verify_only_returns_drift_exit_code_for_missing_schema(
    monkeypatch,
) -> None:
    conn = FakeConnection(default_result=0)
    install_fake_aioodbc(monkeypatch, conn)

    result = await apply_prod_migration.main(["--verify-only"])

    assert result == 3


@pytest.mark.asyncio
async def test_apply_requires_schema_write_gate(monkeypatch, tmp_path) -> None:
    migration = tmp_path / "migration.sql"
    migration.write_text("SELECT 1", encoding="utf-8")
    conn = FakeConnection()
    install_fake_aioodbc(monkeypatch, conn)
    monkeypatch.delenv("SIGIL_ALLOW_SCHEMA_WRITES", raising=False)

    result = await apply_prod_migration.main(["--apply", str(migration)])

    assert result == 2
    assert conn.executed == []


@pytest.mark.asyncio
async def test_apply_executes_explicit_batches_then_verifies(
    monkeypatch, tmp_path
) -> None:
    migration = tmp_path / "migration.sql"
    migration.write_text("SELECT 1\nGO\nSELECT 2", encoding="utf-8")
    conn = FakeConnection()
    install_fake_aioodbc(monkeypatch, conn, expected_autocommit=False)
    monkeypatch.setenv("SIGIL_ALLOW_SCHEMA_WRITES", "1")

    result = await apply_prod_migration.main(["--apply", str(migration)])

    assert result == 0
    assert conn.executed[:2] == ["SELECT 1", "SELECT 2"]
    assert conn.commits == 1
    assert conn.rollbacks == 0
    assert (
        len(conn.executed)
        == len(apply_prod_migration.PRODUCTION_SCHEMA_VERIFICATIONS) + 2
    )


@pytest.mark.asyncio
async def test_apply_rolls_back_failed_migration_file(monkeypatch, tmp_path) -> None:
    migration = tmp_path / "migration.sql"
    migration.write_text("SELECT 1\nGO\nSELECT broken\nGO\nSELECT 3", encoding="utf-8")
    conn = FakeConnection()
    conn.fail_on.add("SELECT broken")
    install_fake_aioodbc(monkeypatch, conn, expected_autocommit=False)
    monkeypatch.setenv("SIGIL_ALLOW_SCHEMA_WRITES", "1")

    with pytest.raises(RuntimeError):
        await apply_prod_migration.main(["--apply", str(migration)])

    assert conn.executed == ["SELECT 1"]
    assert conn.commits == 0
    assert conn.rollbacks == 1
