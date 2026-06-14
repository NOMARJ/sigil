"""Apply or verify production T-SQL migrations against the configured MSSQL DB.

pyodbc/aioodbc cannot process `GO` (it is a sqlcmd batch separator, not T-SQL),
so this splits the file on standalone `GO` lines and executes each batch. Apply
mode runs each migration file in a transaction and commits only after every
batch in that file succeeds.

Connection comes from `settings.database_url` (env `SIGIL_DATABASE_URL`) — the
secret is read from the process environment, never passed on the command line.

Usage (intended to run inside the sigil-api container, which has VNet access
and the connection secret):

    python -m api.migrations.apply_prod_migration --verify-only

    SIGIL_ALLOW_SCHEMA_WRITES=1 python -m api.migrations.apply_prod_migration --apply \
        api/migrations/add_auth0_subscription_columns_prod.sql \
        api/migrations/add_credits_system_prod.sql

`--verify-only` is read-only. `--apply` requires SIGIL_ALLOW_SCHEMA_WRITES=1.
"""

from __future__ import annotations

import argparse
import asyncio
import os
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
        "WHERE object_id = OBJECT_ID(N'dbo.users', N'U') AND name = 'auth0_sub'",
    ),
    Verification(
        "users.subscription_tier",
        "SELECT COUNT(*) FROM sys.columns "
        "WHERE object_id = OBJECT_ID(N'dbo.users', N'U') "
        "AND name = 'subscription_tier'",
    ),
    Verification(
        "idx_users_auth0_sub",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID(N'dbo.users', N'U') "
        "AND name = 'idx_users_auth0_sub'",
    ),
    Verification(
        "idx_users_subscription_tier",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID(N'dbo.users', N'U') "
        "AND name = 'idx_users_subscription_tier'",
    ),
    Verification(
        "user_credits",
        "SELECT COUNT(*) FROM sys.tables t "
        "INNER JOIN sys.schemas s ON s.schema_id = t.schema_id "
        "WHERE s.name = 'dbo' AND t.name = 'user_credits'",
    ),
    Verification(
        "credit_transactions",
        "SELECT COUNT(*) FROM sys.tables t "
        "INNER JOIN sys.schemas s ON s.schema_id = t.schema_id "
        "WHERE s.name = 'dbo' AND t.name = 'credit_transactions'",
    ),
    Verification(
        "interactive_sessions",
        "SELECT COUNT(*) FROM sys.tables t "
        "INNER JOIN sys.schemas s ON s.schema_id = t.schema_id "
        "WHERE s.name = 'dbo' AND t.name = 'interactive_sessions'",
    ),
    Verification(
        "IX_sessions_user_active",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID(N'dbo.interactive_sessions', N'U') "
        "AND name = 'IX_sessions_user_active'",
    ),
    Verification(
        "IX_sessions_scan",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID(N'dbo.interactive_sessions', N'U') "
        "AND name = 'IX_sessions_scan'",
    ),
    Verification(
        "IX_sessions_share_token",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID(N'dbo.interactive_sessions', N'U') "
        "AND name = 'IX_sessions_share_token'",
    ),
    Verification(
        "IX_sessions_expiry",
        "SELECT COUNT(*) FROM sys.indexes "
        "WHERE object_id = OBJECT_ID(N'dbo.interactive_sessions', N'U') "
        "AND name = 'IX_sessions_expiry'",
    ),
    Verification(
        "sp_DeductCredits",
        "SELECT COUNT(*) FROM sys.procedures p "
        "INNER JOIN sys.schemas s ON s.schema_id = p.schema_id "
        "WHERE s.name = 'dbo' AND p.name = 'sp_DeductCredits'",
    ),
    Verification(
        "sp_AddCredits",
        "SELECT COUNT(*) FROM sys.procedures p "
        "INNER JOIN sys.schemas s ON s.schema_id = p.schema_id "
        "WHERE s.name = 'dbo' AND p.name = 'sp_AddCredits'",
    ),
]


async def verify_schema(conn) -> int:
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


async def apply_migrations(conn, paths: list[str]) -> None:
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            sql = fh.read()
        batches = split_batches(sql)
        print(f"Applying {path}: {len(batches)} batch(es)")
        try:
            for i, batch in enumerate(batches, 1):
                async with conn.cursor() as cur:
                    await cur.execute(batch)
                print(f"  [{i}/{len(batches)}] OK")
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply or verify Sigil production database migrations."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--verify-only",
        action="store_true",
        help="Run read-only production schema verification checks.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Apply explicit SQL files before running verification checks.",
    )
    parser.add_argument("paths", nargs="*", help="SQL migration files for --apply.")
    return parser.parse_args(argv)


async def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.apply and not args.paths:
        print(
            "ERROR: --apply requires at least one SQL migration path.", file=sys.stderr
        )
        return 2

    if args.verify_only and args.paths:
        print(
            "ERROR: --verify-only does not accept SQL migration paths.", file=sys.stderr
        )
        return 2

    if args.apply and os.environ.get("SIGIL_ALLOW_SCHEMA_WRITES") != "1":
        print(
            "ERROR: --apply requires SIGIL_ALLOW_SCHEMA_WRITES=1.",
            file=sys.stderr,
        )
        return 2

    if not settings.database_configured:
        print(
            "ERROR: SIGIL_DATABASE_URL not configured — refusing to run.",
            file=sys.stderr,
        )
        return 2

    import aioodbc

    conn = await aioodbc.connect(dsn=settings.database_url, autocommit=not args.apply)
    try:
        if args.apply:
            await apply_migrations(conn, args.paths)
        return await verify_schema(conn)
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
