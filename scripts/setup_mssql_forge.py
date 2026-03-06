#!/usr/bin/env python3
"""
Setup MSSQL Forge Tables and Initial Data Processing

This script helps transition from Supabase to MSSQL for Sigil Forge functionality.
It creates the necessary tables and processes existing data.

Usage:
    python scripts/setup_mssql_forge.py --help
    python scripts/setup_mssql_forge.py --create-tables
    python scripts/setup_mssql_forge.py --process-data --limit 100
    python scripts/setup_mssql_forge.py --verify-setup
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from api.config import settings
from api.database import db

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class MSSQLForgeSetup:
    """Handles MSSQL Forge setup and data migration."""

    def __init__(self):
        self.setup_complete = False

    async def check_connection(self) -> bool:
        """Check if MSSQL database connection works."""
        try:
            await db.connect()
            if not db.connected:
                logger.error(
                    "Database connection failed - check DATABASE_URL environment variable"
                )
                logger.error(
                    "Expected format: Driver={ODBC Driver 18 for SQL Server};Server=...;Database=...;Uid=...;Pwd=..."
                )
                return False

            # Test query
            result = await db.execute_raw_sql("SELECT 1 as test")
            logger.info("✅ Database connection successful")
            return True

        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            logger.error("Make sure you have:")
            logger.error("1. MSSQL/Azure SQL Database running")
            logger.error("2. ODBC Driver 18 for SQL Server installed")
            logger.error("3. Correct DATABASE_URL in environment")
            return False

    async def check_tables_exist(self) -> dict[str, bool]:
        """Check which forge tables already exist."""
        forge_tables = [
            "forge_classification",
            "forge_capabilities",
            "forge_matches",
            "forge_categories",
        ]

        table_status = {}

        for table in forge_tables:
            try:
                count_query = f"SELECT COUNT(*) as count FROM {table}"
                result = await db.execute_raw_sql_single(count_query)
                table_status[table] = True
                logger.info(f"✅ Table {table} exists ({result['count']} rows)")
            except Exception as e:
                table_status[table] = False
                logger.warning(f"❌ Table {table} missing: {e}")

        return table_status

    async def create_forge_tables(self) -> bool:
        """Create forge tables using the migration SQL."""
        logger.info("Creating forge tables...")

        # Read the migration SQL file
        migration_file = (
            Path(__file__).parent.parent
            / "migrations"
            / "004_create_forge_classification.sql"
        )

        if not migration_file.exists():
            logger.error(f"Migration file not found: {migration_file}")
            return False

        try:
            sql_content = migration_file.read_text()

            # Split SQL into individual statements
            statements = [s.strip() for s in sql_content.split("GO") if s.strip()]

            for i, statement in enumerate(statements):
                if statement and not statement.startswith("--"):
                    try:
                        await db.execute_raw_sql(statement)
                        logger.debug(f"Executed statement {i + 1}/{len(statements)}")
                    except Exception as e:
                        # Some statements may fail if tables already exist - that's OK
                        logger.debug(f"Statement {i + 1} result: {e}")

            logger.info("✅ Forge tables creation completed")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to create forge tables: {e}")
            return False

    async def check_public_scans_data(self) -> int:
        """Check how much data is available in public_scans."""
        try:
            result = await db.execute_raw_sql_single(
                "SELECT COUNT(*) as count FROM public_scans"
            )
            count = result["count"]
            logger.info(f"📊 Found {count} records in public_scans table")
            return count
        except Exception as e:
            logger.error(f"❌ Failed to check public_scans: {e}")
            return 0

    async def process_sample_data(self, limit: int = 10) -> bool:
        """Process a sample of public_scans data into forge tables."""
        logger.info(f"Processing {limit} sample records...")

        try:
            from api.services.forge_classifier import (
                forge_classifier,
                ClassificationInput,
                Finding,
                ScanPhase,
                Severity,
            )
            import json

            # Get sample records
            scans = await db.execute_raw_sql(
                f"SELECT TOP ({limit}) * FROM public_scans ORDER BY scanned_at DESC"
            )

            if not scans:
                logger.warning("No data found in public_scans table")
                return False

            processed = 0
            errors = 0

            for scan in scans:
                try:
                    # Check if already classified
                    existing = await db.select_one(
                        "forge_classification",
                        {
                            "ecosystem": scan["ecosystem"],
                            "package_name": scan["package_name"],
                        },
                    )

                    if existing:
                        logger.debug(
                            f"Skipping {scan['ecosystem']}/{scan['package_name']} - already classified"
                        )
                        continue

                    # Parse findings
                    findings_data = json.loads(scan.get("findings_json", "[]"))
                    findings = []
                    for f in findings_data:
                        try:
                            findings.append(
                                Finding(
                                    phase=ScanPhase(f["phase"]),
                                    rule=f["rule"],
                                    severity=Severity(f["severity"]),
                                    file=f["file"],
                                    line=f.get("line", 0),
                                    snippet=f.get("snippet", ""),
                                    weight=f.get("weight", 1.0),
                                    description=f.get("description", ""),
                                    explanation=f.get("explanation", ""),
                                )
                            )
                        except (KeyError, ValueError) as e:
                            logger.debug(f"Invalid finding format: {e}")

                    # Parse metadata
                    metadata = json.loads(scan.get("metadata_json", "{}"))
                    description = metadata.get(
                        "description", metadata.get("summary", "")
                    )

                    # Create classification input
                    input_data = ClassificationInput(
                        ecosystem=scan["ecosystem"],
                        package_name=scan["package_name"],
                        package_version=scan.get("package_version", ""),
                        description=description,
                        scan_findings=findings,
                        metadata=metadata,
                    )

                    # Classify and save
                    result = await forge_classifier.classify_package(input_data)
                    await forge_classifier.save_classification(input_data, result)

                    processed += 1
                    logger.info(
                        f"✅ Classified {scan['ecosystem']}/{scan['package_name']} as {result.category}"
                    )

                except Exception as e:
                    errors += 1
                    logger.error(
                        f"❌ Failed to process {scan.get('package_name', 'unknown')}: {e}"
                    )

            logger.info(
                f"📈 Processing complete: {processed} classified, {errors} errors"
            )
            return processed > 0

        except Exception as e:
            logger.error(f"❌ Failed to process sample data: {e}")
            return False

    async def verify_forge_data(self) -> bool:
        """Verify that forge tables have data."""
        try:
            # Check classification data
            classification_result = await db.execute_raw_sql_single(
                "SELECT COUNT(*) as count FROM forge_classification"
            )
            classification_count = classification_result["count"]

            # Check capabilities data
            capabilities_result = await db.execute_raw_sql_single(
                "SELECT COUNT(*) as count FROM forge_capabilities"
            )
            capabilities_count = capabilities_result["count"]

            # Check categories data
            categories_result = await db.execute_raw_sql_single(
                "SELECT COUNT(*) as count FROM forge_categories"
            )
            categories_count = categories_result["count"]

            logger.info(f"📊 Forge data summary:")
            logger.info(f"   Classifications: {classification_count}")
            logger.info(f"   Capabilities: {capabilities_count}")
            logger.info(f"   Categories: {categories_count}")

            if classification_count > 0 and categories_count > 0:
                logger.info("✅ Forge setup verification passed")
                return True
            else:
                logger.warning("❌ Forge setup verification failed - missing data")
                return False

        except Exception as e:
            logger.error(f"❌ Verification failed: {e}")
            return False

    async def run_setup(
        self, create_tables: bool, process_data: bool, data_limit: int, verify: bool
    ):
        """Run the complete setup process."""
        logger.info("=== MSSQL Forge Setup ===")

        # Check connection
        if not await self.check_connection():
            return False

        # Check existing tables
        table_status = await self.check_tables_exist()

        # Create tables if requested
        if create_tables:
            if not await self.create_forge_tables():
                return False
            # Re-check tables after creation
            table_status = await self.check_tables_exist()

        # Check if all required tables exist
        required_tables = [
            "forge_classification",
            "forge_capabilities",
            "forge_categories",
        ]
        missing_tables = [t for t in required_tables if not table_status.get(t, False)]

        if missing_tables:
            logger.error(f"❌ Missing required tables: {missing_tables}")
            logger.error("Run with --create-tables to create them")
            return False

        # Process data if requested
        if process_data:
            scan_count = await self.check_public_scans_data()
            if scan_count == 0:
                logger.warning(
                    "⚠️ No data in public_scans table - cannot process forge data"
                )
                logger.warning(
                    "You need to run scans first or import data from Supabase"
                )
            else:
                if not await self.process_sample_data(data_limit):
                    return False

        # Verify setup if requested
        if verify:
            if not await self.verify_forge_data():
                return False

        logger.info("🎉 MSSQL Forge setup completed successfully!")
        return True


async def main():
    parser = argparse.ArgumentParser(
        description="Setup MSSQL Forge tables and process initial data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--create-tables",
        action="store_true",
        help="Create forge tables in MSSQL database",
    )
    parser.add_argument(
        "--process-data",
        action="store_true",
        help="Process sample data from public_scans into forge tables",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of records to process (default: 10)",
    )
    parser.add_argument(
        "--verify-setup",
        action="store_true",
        help="Verify that forge setup is working correctly",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check configuration
    if not settings.database_configured:
        logger.error("DATABASE_URL not configured. Set environment variable:")
        logger.error(
            "export DATABASE_URL='Driver={ODBC Driver 18 for SQL Server};Server=...;Database=...;Uid=...;Pwd=...'"
        )
        return 1

    # Run setup
    setup = MSSQLForgeSetup()
    try:
        success = await setup.run_setup(
            create_tables=args.create_tables,
            process_data=args.process_data,
            data_limit=args.limit,
            verify=args.verify_setup,
        )
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.info("Setup interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        return 1
    finally:
        await db.disconnect()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
