#!/usr/bin/env python3
"""
One-time ETL migration script: Supabase PostgreSQL → Azure SQL Database

Reads all data from Supabase (asyncpg) and writes to Azure SQL (pyodbc).

Usage:
    python -m api.scripts.migrate_supabase_to_mssql \
        --source-url "postgresql://..." \
        --target-dsn "Driver={ODBC Driver 18 for SQL Server};..."

    # Or with environment variables:
    export SUPABASE_DATABASE_URL="postgresql://..."
    export MSSQL_DATABASE_DSN="Driver={ODBC Driver 18 for SQL Server};..."
    python -m api.scripts.migrate_supabase_to_mssql

    # Dry run (count only):
    python -m api.scripts.migrate_supabase_to_mssql --dry-run

    # Migrate specific tables:
    python -m api.scripts.migrate_supabase_to_mssql --tables "teams,users,scans"
"""

import argparse
import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import pyodbc


# Migration order respects foreign key dependencies
MIGRATION_ORDER = [
    "teams",
    "users",
    "scans",
    "threats",
    "signatures",
    "malware_families",
    "publishers",
    "threat_reports",
    "verifications",
    "policies",
    "alerts",
    "audit_log",
    "password_reset_tokens",
    "subscriptions",
    "scan_usage",
    "public_scans",
    "badge_cache",
    "github_installations",
    "github_pr_events",
    "skill_threats",
    "skill_scans",
    "publisher_campaigns",
    "intel_packages",
    "intel_category_trends",
    "intel_provider_trends",
    "intel_publishers",
]

# Column mappings: {table: {source_col: target_col}}
# Source columns not in mapping are passed through unchanged.
# Target columns not in source will use defaults.
COLUMN_MAPPINGS: Dict[str, Dict[str, str]] = {
    "public_scans": {
        "findings": "findings_json",
        "scan_metadata": "metadata_json",
    },
}

# Columns to drop per table (exist in source but not in target)
DROP_COLUMNS: Dict[str, List[str]] = {
    "public_scans": ["duration_ms"],
    "users": [
        "aud",
        "banned_until",
        "confirmation_sent_at",
        "confirmation_token",
        "confirmed_at",
        "deleted_at",
        "email_change",
        "email_change_confirm_status",
        "email_change_sent_at",
        "email_change_token_current",
        "email_change_token_new",
        "email_confirmed_at",
        "instance_id",
        "invited_at",
        "is_anonymous",
        "is_sso_user",
        "is_super_admin",
        "last_sign_in_at",
        "phone",
        "phone_change",
        "phone_change_sent_at",
        "phone_change_token",
        "phone_confirmed_at",
        "raw_app_meta_data",
        "raw_user_meta_data",
        "reauthentication_sent_at",
        "reauthentication_token",
        "recovery_sent_at",
        "recovery_token",
        "updated_at",
    ],
}

# Users: PG already returns our custom columns (id, email, password_hash, name, team_id, role, created_at)
# No column renames needed — just drop the Supabase auth columns that might appear.

# Publisher campaigns: PG has reference_urls, MSSQL schema has [references]
COLUMN_MAPPINGS["publisher_campaigns"] = {
    "reference_urls": "references",
}


def convert_value(val: Any) -> Any:
    """
    Convert PostgreSQL types to MSSQL-compatible types.

    Args:
        val: Value from PostgreSQL

    Returns:
        Value compatible with MSSQL/pyodbc
    """
    if val is None:
        return None
    if isinstance(val, uuid.UUID):
        return str(val)
    if isinstance(val, (dict, list)):
        return json.dumps(val)
    if isinstance(val, datetime):
        return val  # pyodbc handles datetime natively
    if isinstance(val, bool):
        return 1 if val else 0  # MSSQL bit type
    return val


def disable_foreign_keys(conn: pyodbc.Connection, table_name: str) -> None:
    """
    Disable foreign key constraints for a table.

    Args:
        conn: pyodbc connection
        table_name: Table name
    """
    cursor = conn.cursor()
    try:
        cursor.execute(f"ALTER TABLE {table_name} NOCHECK CONSTRAINT ALL")
        conn.commit()
    except pyodbc.Error as e:
        print(f"    Warning: Could not disable FK constraints on {table_name}: {e}")
    finally:
        cursor.close()


def enable_foreign_keys(conn: pyodbc.Connection, table_name: str) -> None:
    """
    Enable foreign key constraints for a table.

    Args:
        conn: pyodbc connection
        table_name: Table name
    """
    cursor = conn.cursor()
    try:
        cursor.execute(f"ALTER TABLE {table_name} CHECK CONSTRAINT ALL")
        conn.commit()
    except pyodbc.Error as e:
        print(f"    Warning: Could not re-enable FK constraints on {table_name}: {e}")
    finally:
        cursor.close()


def truncate_table(conn: pyodbc.Connection, table_name: str) -> None:
    """
    Truncate target table before migration.

    Args:
        conn: pyodbc connection
        table_name: Table name
    """
    cursor = conn.cursor()
    try:
        # Try TRUNCATE first (faster)
        cursor.execute(f"TRUNCATE TABLE {table_name}")
        conn.commit()
    except pyodbc.Error:
        # Fall back to DELETE if TRUNCATE fails due to FK constraints
        try:
            cursor.execute(f"DELETE FROM {table_name}")
            conn.commit()
        except pyodbc.Error as e:
            print(f"    Warning: Could not truncate {table_name}: {e}")
    finally:
        cursor.close()


async def get_table_schema(pool: asyncpg.Pool, table_name: str) -> List[str]:
    """
    Get column names for a table from PostgreSQL.

    Args:
        pool: asyncpg connection pool
        table_name: Table name

    Returns:
        List of column names
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = $1
            ORDER BY ordinal_position
            """,
            table_name,
        )
        return [row["column_name"] for row in rows]


async def migrate_table(
    source_pool: asyncpg.Pool,
    target_conn: pyodbc.Connection,
    table_name: str,
    batch_size: int,
    dry_run: bool,
) -> Tuple[int, int]:
    """
    Migrate a single table from source to target.

    Args:
        source_pool: asyncpg connection pool (PostgreSQL)
        target_conn: pyodbc connection (MSSQL)
        table_name: Table name to migrate
        batch_size: Number of rows per batch insert
        dry_run: If True, only count rows without writing

    Returns:
        Tuple of (source_count, target_count)
    """
    # Read all rows from source
    async with source_pool.acquire() as conn:
        try:
            rows = await conn.fetch(f"SELECT * FROM {table_name}")
        except asyncpg.exceptions.UndefinedTableError:
            print(f"  {table_name}: Table not found in source database (skipping)")
            return 0, 0

    if not rows:
        print(f"  {table_name}: 0 rows (empty)")
        return 0, 0

    source_count = len(rows)

    if dry_run:
        print(f"  {table_name}: {source_count} rows (dry run - not migrated)")
        return source_count, 0

    # Get column names and apply mappings
    raw_cols = list(rows[0].keys())
    drop_cols = set(DROP_COLUMNS.get(table_name, []))
    col_map = COLUMN_MAPPINGS.get(table_name, {})

    # Filter out dropped columns and apply renames
    cols = []
    source_cols = []
    for c in raw_cols:
        if c in drop_cols:
            continue
        source_cols.append(c)
        target_name = col_map.get(c, c)
        # Quote reserved words
        if target_name.lower() in ("plan", "status", "references"):
            cols.append(f"[{target_name}]")
        else:
            cols.append(target_name)

    placeholders = ", ".join(["?" for _ in cols])
    insert_sql = f"INSERT INTO {table_name} ({', '.join(cols)}) VALUES ({placeholders})"

    # Disable FK constraints for this table
    disable_foreign_keys(target_conn, table_name)

    # Truncate target table
    truncate_table(target_conn, table_name)

    # Batch insert
    cursor = target_conn.cursor()
    batch = []
    total_inserted = 0
    skipped = 0

    try:
        for i, row in enumerate(rows, 1):
            values = tuple(convert_value(row[c]) for c in source_cols)
            batch.append(values)

            if len(batch) >= batch_size:
                try:
                    cursor.executemany(insert_sql, batch)
                    total_inserted += len(batch)
                except pyodbc.IntegrityError:
                    # Batch has duplicates — fall back to row-by-row
                    for single_row in batch:
                        try:
                            cursor.execute(insert_sql, single_row)
                            total_inserted += 1
                        except pyodbc.IntegrityError:
                            skipped += 1
                print(f"    Progress: {total_inserted}/{source_count} rows", end="\r")
                batch = []

        # Insert remaining rows
        if batch:
            try:
                cursor.executemany(insert_sql, batch)
                total_inserted += len(batch)
            except pyodbc.IntegrityError:
                for single_row in batch:
                    try:
                        cursor.execute(insert_sql, single_row)
                        total_inserted += 1
                    except pyodbc.IntegrityError:
                        skipped += 1

        target_conn.commit()
        skip_msg = f", {skipped} dupes skipped" if skipped else ""
        print(
            f"    Progress: {total_inserted}/{source_count} rows (complete{skip_msg})"
        )

        # Verify count
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        target_count = cursor.fetchone()[0]

        # Re-enable FK constraints
        enable_foreign_keys(target_conn, table_name)

        status = "OK" if source_count == target_count else "MISMATCH"
        print(f"  {table_name}: {source_count} -> {target_count} rows [{status}]")

        return source_count, target_count

    except Exception as e:
        target_conn.rollback()
        print(f"  {table_name}: ERROR during migration: {e}")
        raise
    finally:
        cursor.close()


async def run_migration(
    source_url: str,
    target_dsn: str,
    tables: Optional[List[str]],
    batch_size: int,
    dry_run: bool,
) -> None:
    """
    Run full migration from PostgreSQL to MSSQL.

    Args:
        source_url: PostgreSQL connection URL
        target_dsn: MSSQL ODBC connection string
        tables: List of tables to migrate (None = all)
        batch_size: Rows per batch insert
        dry_run: If True, only count rows
    """
    print("=" * 80)
    print("Supabase PostgreSQL -> Azure SQL Database Migration")
    print("=" * 80)
    print()

    # Determine which tables to migrate
    if tables:
        migration_tables = [t for t in MIGRATION_ORDER if t in tables]
        print(f"Tables to migrate: {', '.join(migration_tables)}")
    else:
        migration_tables = MIGRATION_ORDER
        print(f"Migrating all {len(migration_tables)} tables")

    print(f"Batch size: {batch_size}")
    print(f"Dry run: {dry_run}")
    print()

    # Connect to source (PostgreSQL)
    print("Connecting to source database (PostgreSQL)...")
    source_pool = await asyncpg.create_pool(source_url, min_size=1, max_size=5)
    print("  Connected to source")

    # Connect to target (MSSQL)
    print("Connecting to target database (MSSQL)...")
    target_conn = pyodbc.connect(target_dsn, autocommit=False)
    print("  Connected to target")
    print()

    # Migration statistics
    total_source_rows = 0
    total_target_rows = 0
    failed_tables = []

    # Migrate each table
    print("Starting migration...")
    print("-" * 80)

    for table_name in migration_tables:
        try:
            source_count, target_count = await migrate_table(
                source_pool, target_conn, table_name, batch_size, dry_run
            )
            total_source_rows += source_count
            total_target_rows += target_count
        except Exception as e:
            print(f"  {table_name}: FAILED - {e}")
            failed_tables.append((table_name, str(e)))

    print("-" * 80)
    print()

    # Summary
    print("Migration Summary:")
    print(f"  Total source rows: {total_source_rows}")
    print(f"  Total target rows: {total_target_rows}")
    print(
        f"  Tables migrated: {len(migration_tables) - len(failed_tables)}/{len(migration_tables)}"
    )

    if failed_tables:
        print()
        print("Failed tables:")
        for table, error in failed_tables:
            print(f"  - {table}: {error}")

    # Cleanup
    await source_pool.close()
    target_conn.close()

    print()
    if failed_tables:
        print("Migration completed with errors.")
        sys.exit(1)
    elif dry_run:
        print("Dry run completed successfully (no data written).")
        sys.exit(0)
    else:
        print("Migration completed successfully.")
        sys.exit(0)


def main() -> None:
    """Parse arguments and run migration."""
    parser = argparse.ArgumentParser(
        description="Migrate data from Supabase PostgreSQL to Azure SQL Database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full migration
  python -m api.scripts.migrate_supabase_to_mssql \\
      --source-url "postgresql://..." \\
      --target-dsn "Driver={ODBC Driver 18 for SQL Server};..."

  # Dry run
  python -m api.scripts.migrate_supabase_to_mssql --dry-run

  # Migrate specific tables
  python -m api.scripts.migrate_supabase_to_mssql --tables "teams,users,scans"

  # Using environment variables
  export SUPABASE_DATABASE_URL="postgresql://..."
  export MSSQL_DATABASE_DSN="Driver={ODBC Driver 18 for SQL Server};..."
  python -m api.scripts.migrate_supabase_to_mssql
        """,
    )

    parser.add_argument(
        "--source-url",
        help="PostgreSQL connection URL (or set SUPABASE_DATABASE_URL env var)",
    )
    parser.add_argument(
        "--target-dsn",
        help="MSSQL ODBC connection string (or set MSSQL_DATABASE_DSN env var)",
    )
    parser.add_argument(
        "--tables",
        help="Comma-separated list of tables to migrate (default: all)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Rows per batch insert (default: 500)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Count rows but don't write to target",
    )

    args = parser.parse_args()

    # Get source URL
    source_url = args.source_url or os.getenv("SUPABASE_DATABASE_URL")
    if not source_url:
        print("Error: --source-url or SUPABASE_DATABASE_URL env var required")
        sys.exit(1)

    # Get target DSN
    target_dsn = args.target_dsn or os.getenv("MSSQL_DATABASE_DSN")
    if not target_dsn:
        print("Error: --target-dsn or MSSQL_DATABASE_DSN env var required")
        sys.exit(1)

    # Parse tables
    tables = None
    if args.tables:
        tables = [t.strip() for t in args.tables.split(",")]

    # Run migration
    asyncio.run(
        run_migration(
            source_url=source_url,
            target_dsn=target_dsn,
            tables=tables,
            batch_size=args.batch_size,
            dry_run=args.dry_run,
        )
    )


if __name__ == "__main__":
    main()
