"""Apply a T-SQL migration file batch-by-batch against the configured MSSQL DB.

pyodbc/aioodbc cannot process `GO` (it is a sqlcmd batch separator, not T-SQL),
so this splits the file on standalone `GO` lines and executes each batch in its
own autocommit transaction.

Connection comes from `settings.database_url` (env `SIGIL_DATABASE_URL`) — the
secret is read from the process environment, never passed on the command line.

Usage (intended to run inside the sigil-api container, which has VNet access
and the connection secret):

    python -m api.migrations.apply_prod_migration api/migrations/add_credits_system_prod.sql

Idempotent migrations (IF NOT EXISTS / CREATE OR ALTER) make re-runs safe.
"""

from __future__ import annotations

import asyncio
import re
import sys

from api.config import settings


def split_batches(sql: str) -> list[str]:
    """Split on lines that are exactly `GO` (case-insensitive, ignoring
    surrounding whitespace). Returns non-empty trimmed batches."""
    parts = re.split(r"(?im)^[ \t]*GO[ \t]*;?[ \t]*$", sql)
    return [b.strip() for b in parts if b.strip()]


async def main(path: str) -> int:
    if not settings.database_configured:
        print("ERROR: SIGIL_DATABASE_URL not configured — refusing to run.", file=sys.stderr)
        return 2

    with open(path, "r", encoding="utf-8") as fh:
        sql = fh.read()
    batches = split_batches(sql)
    print(f"Applying {path}: {len(batches)} batch(es)")

    import aioodbc

    conn = await aioodbc.connect(dsn=settings.database_url, autocommit=True)
    try:
        for i, batch in enumerate(batches, 1):
            preview = " ".join(batch.split())[:80]
            async with conn.cursor() as cur:
                await cur.execute(batch)
            print(f"  [{i}/{len(batches)}] OK  {preview}")
    finally:
        await conn.close()

    # Verify the objects the F-009 metering path needs.
    conn = await aioodbc.connect(dsn=settings.database_url, autocommit=True)
    try:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT "
                "  (SELECT COUNT(*) FROM sys.tables WHERE name='user_credits'), "
                "  (SELECT COUNT(*) FROM sys.tables WHERE name='credit_transactions'), "
                "  (SELECT COUNT(*) FROM sys.procedures WHERE name='sp_DeductCredits'), "
                "  (SELECT COUNT(*) FROM sys.procedures WHERE name='sp_AddCredits')"
            )
            row = await cur.fetchone()
        labels = ["user_credits", "credit_transactions", "sp_DeductCredits", "sp_AddCredits"]
        print("Verify:")
        ok = True
        for label, present in zip(labels, row):
            print(f"  {label}: {'present' if present else 'MISSING'}")
            ok = ok and bool(present)
        return 0 if ok else 3
    finally:
        await conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m api.migrations.apply_prod_migration <path.sql>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(asyncio.run(main(sys.argv[1])))
