"""Apply a T-SQL migration file batch-by-batch against the configured MSSQL DB.

pyodbc/aioodbc cannot process `GO` (it is a sqlcmd batch separator, not T-SQL),
so this splits the file on standalone `GO` lines and executes each batch in its
own autocommit transaction.

Connection comes from `settings.database_url` (env `SIGIL_DATABASE_URL`) — the
secret is read from the process environment, never passed on the command line.

Usage (intended to run inside the sigil-api container, which has VNet access
and the connection secret):

    python -m api.migrations.apply_prod_migration \
        api/migrations/add_auth0_subscription_columns_prod.sql \
        api/migrations/add_credits_system_prod.sql

Idempotent migrations (IF NOT EXISTS / CREATE OR ALTER) make re-runs safe.
"""

from __future__ import annotations

import asyncio
import re
import sys

from dataclasses import dataclass

from api.config import settings


@dataclass(frozen=True)
class Verification:
    label: str
    query: str


def split_batches(sql: str) -> list[str]:
    """Split on lines that are exactly `GO` (case-insensitive, ignoring
    surrounding whitespace). Returns non-empty trimmed batches."""
    parts = re.split(r"(?im)^[ \t]*GO[ \t]*;?[ \t]*$", sql)
    return [b.strip() for b in parts if b.strip()]


PRODUCTION_SCHEMA_VERIFICATIONS = [
    Verification(
        "users.auth0_sub",
        "SELECT COUNT(*) FROM sys.columns "
        "WHERE object_id = OBJECT_ID('users') AND name = 'auth0_sub'",
    ),
    Verification(
        "users.subscription_tier",
        "SELECT COUNT(*) FROM sys.columns "
        "WHERE object_id = OBJECT_ID('users') AND name = 'subscription_tier'",
    ),
    Verification(
        "idx_users_auth0_sub",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID('users') AND name = 'idx_users_auth0_sub'",
    ),
    Verification(
        "idx_users_subscription_tier",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID('users') AND name = 'idx_users_subscription_tier'",
    ),
    Verification(
        "user_credits",
        "SELECT COUNT(*) FROM sys.tables WHERE name = 'user_credits'",
    ),
    Verification(
        "credit_transactions",
        "SELECT COUNT(*) FROM sys.tables WHERE name = 'credit_transactions'",
    ),
    Verification(
        "interactive_sessions",
        "SELECT COUNT(*) FROM sys.tables WHERE name = 'interactive_sessions'",
    ),
    Verification(
        "IX_sessions_user_active",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID('interactive_sessions') "
        "AND name = 'IX_sessions_user_active'",
    ),
    Verification(
        "IX_sessions_scan",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID('interactive_sessions') "
        "AND name = 'IX_sessions_scan'",
    ),
    Verification(
        "IX_sessions_share_token",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID('interactive_sessions') "
        "AND name = 'IX_sessions_share_token'",
    ),
    Verification(
        "IX_sessions_expiry",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID('interactive_sessions') "
        "AND name = 'IX_sessions_expiry'",
    ),
    Verification(
        "sp_DeductCredits",
        "SELECT COUNT(*) FROM sys.procedures WHERE name = 'sp_DeductCredits'",
    ),
    Verification(
        "sp_AddCredits",
        "SELECT COUNT(*) FROM sys.procedures WHERE name = 'sp_AddCredits'",
    ),
]


async def main(paths: list[str]) -> int:
    if not settings.database_configured:
        print(
            "ERROR: SIGIL_DATABASE_URL not configured — refusing to run.",
            file=sys.stderr,
        )
        return 2

    import aioodbc

    conn = await aioodbc.connect(dsn=settings.database_url, autocommit=True)
    try:
        for path in paths:
            with open(path, "r", encoding="utf-8") as fh:
                sql = fh.read()
            batches = split_batches(sql)
            print(f"Applying {path}: {len(batches)} batch(es)")
            for i, batch in enumerate(batches, 1):
                preview = " ".join(batch.split())[:80]
                async with conn.cursor() as cur:
                    await cur.execute(batch)
                print(f"  [{i}/{len(batches)}] OK  {preview}")
    finally:
        await conn.close()

    conn = await aioodbc.connect(dsn=settings.database_url, autocommit=True)
    try:
        print("Verify:")
        ok = True
        for verification in PRODUCTION_SCHEMA_VERIFICATIONS:
            async with conn.cursor() as cur:
                await cur.execute(verification.query)
                row = await cur.fetchone()
            present = row[0] if row else 0
            label = verification.label
            print(f"  {label}: {'present' if present else 'MISSING'}")
            ok = ok and bool(present)
        return 0 if ok else 3
    finally:
        await conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "usage: python -m api.migrations.apply_prod_migration <path.sql> [path.sql ...]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
