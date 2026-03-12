#!/usr/bin/env python3
"""
Azure SQL Database Migration Deployment Script
Deploys SQL migrations from the feature/skills-mcps-strategy branch to Azure SQL Database
"""

import os
import sys
import pyodbc
import re
from pathlib import Path
from typing import List
import logging
from dataclasses import dataclass

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("migration_deployment.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


@dataclass
class Migration:
    name: str
    file_path: str
    order: int
    platform: str  # 'tsql', 'postgresql', 'sqlite'
    description: str


class AzureMigrationDeployer:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.migrations: List[Migration] = []
        self.base_path = Path(__file__).parent.parent

    def detect_sql_platform(self, content: str) -> str:
        """Detect SQL platform based on syntax"""
        content_lower = content.lower()

        # T-SQL indicators
        if any(
            keyword in content_lower
            for keyword in [
                "uniqueidentifier",
                "nvarchar",
                "datetimeoffset",
                "newid()",
                "sys.tables",
                "object_id(",
                "sysdatetimeoffset()",
                "if not exists (select * from sys.",
                "begin...end",
                "print ",
            ]
        ):
            return "tsql"

        # PostgreSQL indicators
        elif any(
            keyword in content_lower
            for keyword in [
                "serial primary key",
                "timestamptz",
                "jsonb",
                "generate_unsubscribe_token()",
                "plpgsql",
                "returns trigger",
            ]
        ):
            return "postgresql"

        # SQLite indicators
        elif (
            any(
                keyword in content_lower
                for keyword in ["datetime('now')", "insert or ignore", "if not exists"]
            )
            and "sys.tables" not in content_lower
        ):
            return "sqlite"

        return "unknown"

    def load_migrations(self) -> None:
        """Load all migration files and determine deployment order"""
        migration_configs = [
            # Core Forge classification (must be first)
            {
                "name": "004_create_forge_classification",
                "path": "migrations/004_create_forge_classification.sql",
                "order": 1,
                "description": "Core Forge classification system tables",
            },
            # Performance optimizations (after core tables)
            {
                "name": "006_performance_optimization",
                "path": "api/migrations/006_performance_optimization.sql",
                "order": 2,
                "description": "Forge performance improvements and indexes",
            },
            # Premium features
            {
                "name": "008_forge_premium_features",
                "path": "api/migrations/008_forge_premium_features.sql",
                "order": 3,
                "description": "Premium Forge features and user tools",
            },
            # Analytics system
            {
                "name": "add_forge_analytics",
                "path": "api/migrations/add_forge_analytics.sql",
                "order": 4,
                "description": "Comprehensive analytics and tracking",
            },
            # Security and enterprise features
            {
                "name": "add_forge_security",
                "path": "api/migrations/add_forge_security.sql",
                "order": 5,
                "description": "Security, access control, and enterprise features",
            },
            # Email subscriptions
            {
                "name": "007_email_subscriptions",
                "path": "api/migrations/007_email_subscriptions.sql",
                "order": 6,
                "description": "Email subscription management",
            },
            # MCP watchdog
            {
                "name": "005_create_mcp_watchdog",
                "path": "api/migrations/005_create_mcp_watchdog.sql",
                "order": 7,
                "description": "MCP server monitoring",
            },
        ]

        for config in migration_configs:
            file_path = self.base_path / config["path"]

            if not file_path.exists():
                logger.warning(f"Migration file not found: {file_path}")
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
                platform = self.detect_sql_platform(content)

                migration = Migration(
                    name=config["name"],
                    file_path=str(file_path),
                    order=config["order"],
                    platform=platform,
                    description=config["description"],
                )

                self.migrations.append(migration)
                logger.info(
                    f"Loaded migration: {migration.name} ({migration.platform})"
                )

            except Exception as e:
                logger.error(f"Error loading migration {config['name']}: {e}")

        # Sort by order
        self.migrations.sort(key=lambda m: m.order)

    def create_migration_tracking_table(self, conn) -> None:
        """Create table to track applied migrations"""
        cursor = conn.cursor()

        tracking_sql = """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'schema_migrations')
        BEGIN
            CREATE TABLE schema_migrations (
                id BIGINT IDENTITY(1,1) PRIMARY KEY,
                migration_name NVARCHAR(255) NOT NULL UNIQUE,
                applied_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
                success BIT NOT NULL DEFAULT 1,
                error_message NVARCHAR(MAX) NULL
            );
            PRINT 'Created schema_migrations table';
        END;
        """

        try:
            cursor.execute(tracking_sql)
            conn.commit()
            logger.info("Migration tracking table ready")
        except Exception as e:
            logger.error(f"Error creating migration tracking table: {e}")
            raise

    def is_migration_applied(self, conn, migration_name: str) -> bool:
        """Check if migration has already been applied"""
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_name = ? AND success = 1",
                migration_name,
            )
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            logger.warning(f"Error checking migration status: {e}")
            return False

    def log_migration_statuses(self, conn, migrations: List[Migration]) -> None:
        """Log current applied status for each migration in order."""
        logger.info("📋 Current migration status:")
        for migration in migrations:
            status = (
                "APPLIED"
                if self.is_migration_applied(conn, migration.name)
                else "PENDING"
            )
            logger.info(
                f"  {migration.order}. {migration.name} [{migration.platform}] - {status}"
            )

    def execute_migration(self, conn, migration: Migration) -> bool:
        """Execute a single migration"""
        cursor = conn.cursor()

        try:
            # Read migration content
            with open(migration.file_path, "r", encoding="utf-8") as f:
                content = f.read()

            logger.info(f"Executing migration: {migration.name}")
            logger.info(f"Description: {migration.description}")

            # Split by GO statements for T-SQL, but handle each GO block as a separate transaction
            if migration.platform == "tsql":
                # Split on GO statements (case insensitive)
                go_blocks = re.split(r"\bGO\b", content, flags=re.IGNORECASE)
            else:
                go_blocks = [content]

            # Execute each GO block as a separate transaction
            for i, block in enumerate(go_blocks):
                block = block.strip()
                if not block:
                    continue

                # Remove comments and empty lines
                lines = [line.strip() for line in block.split("\n")]
                lines = [line for line in lines if line and not line.startswith("--")]

                if not lines:
                    continue

                statement = "\n".join(lines)

                logger.debug(f"Executing GO block {i + 1}/{len(go_blocks)}")

                # Special handling for DDL statements that require autocommit
                requires_autocommit = any(
                    keyword in statement.upper()
                    for keyword in [
                        "CREATE FULLTEXT CATALOG",
                        "DROP FULLTEXT CATALOG",
                        "CREATE FULLTEXT INDEX",
                        "DROP FULLTEXT INDEX",
                    ]
                )

                try:
                    if requires_autocommit:
                        # Switch to autocommit mode for DDL statements
                        conn.autocommit = True
                        cursor.execute(statement)
                        conn.autocommit = False
                    else:
                        # Execute normally and commit
                        cursor.execute(statement)
                        conn.commit()

                except Exception as stmt_error:
                    logger.error(f"Error in GO block {i + 1}: {stmt_error}")
                    logger.error(f"Statement: {statement[:500]}...")
                    if not requires_autocommit:
                        conn.rollback()
                    raise

            # Record successful migration
            cursor.execute(
                """
                IF EXISTS (SELECT 1 FROM schema_migrations WHERE migration_name = ?)
                    UPDATE schema_migrations
                    SET applied_at = SYSDATETIMEOFFSET(), success = 1, error_message = NULL
                    WHERE migration_name = ?;
                ELSE
                    INSERT INTO schema_migrations (migration_name, applied_at, success)
                    VALUES (?, SYSDATETIMEOFFSET(), 1);
                """,
                migration.name,
                migration.name,
                migration.name,
            )
            conn.commit()
            logger.info(f"✅ Migration {migration.name} applied successfully")
            return True

        except Exception as e:
            logger.error(f"❌ Migration {migration.name} failed: {e}")

            # Record failed migration
            try:
                cursor.execute(
                    """
                    IF EXISTS (SELECT 1 FROM schema_migrations WHERE migration_name = ?)
                        UPDATE schema_migrations
                        SET applied_at = SYSDATETIMEOFFSET(), success = 0, error_message = ?
                        WHERE migration_name = ?;
                    ELSE
                        INSERT INTO schema_migrations (migration_name, applied_at, success, error_message)
                        VALUES (?, SYSDATETIMEOFFSET(), 0, ?);
                    """,
                    migration.name,
                    str(e),
                    migration.name,
                    migration.name,
                    str(e),
                )
                conn.commit()
            except Exception:
                pass  # Ignore errors in error recording

            return False

    def deploy_migrations(
        self, dry_run: bool = False, status_only: bool = False
    ) -> None:
        """Deploy all T-SQL migrations to Azure SQL Database"""
        if not self.migrations:
            logger.error("No migrations loaded")
            return

        # Filter to T-SQL migrations only
        tsql_migrations = [m for m in self.migrations if m.platform == "tsql"]

        if not tsql_migrations:
            logger.error("No T-SQL migrations found for Azure SQL Database")
            return

        logger.info(f"Found {len(tsql_migrations)} T-SQL migrations to deploy")

        if dry_run:
            logger.info("DRY RUN - No changes will be made")
            for migration in tsql_migrations:
                logger.info(f"Would deploy: {migration.name} - {migration.description}")
            return

        # Connect to database
        try:
            conn = pyodbc.connect(self.connection_string)
            conn.autocommit = False  # Use transactions
            logger.info("Connected to Azure SQL Database")

        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return

        try:
            # Create migration tracking table
            self.create_migration_tracking_table(conn)
            self.log_migration_statuses(conn, tsql_migrations)

            if status_only:
                logger.info(
                    "Status check complete (--status-only). No migrations were applied."
                )
                return

            # Deploy migrations in order
            successful = 0
            failed = 0

            for migration in tsql_migrations:
                if self.is_migration_applied(conn, migration.name):
                    logger.info(
                        f"⏩ Skipping already applied migration: {migration.name}"
                    )
                    continue

                logger.info(
                    f"🔄 Deploying migration {migration.order}: {migration.name}"
                )

                if self.execute_migration(conn, migration):
                    successful += 1
                else:
                    failed += 1
                    logger.error(
                        f"Migration {migration.name} failed - stopping deployment"
                    )
                    break

            logger.info("\n📊 Deployment Summary:")
            logger.info(f"✅ Successful migrations: {successful}")
            logger.info(f"❌ Failed migrations: {failed}")
            logger.info(f"📊 Total T-SQL migrations processed: {successful + failed}")

            if failed == 0:
                logger.info("🎉 All migrations deployed successfully!")
            else:
                logger.error("💥 Deployment failed - see errors above")

        finally:
            conn.close()
            logger.info("Database connection closed")


def main():
    """Main deployment function"""
    # Get database connection string from environment or Terraform
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        # Try to get from Terraform output
        try:
            import subprocess
            import json

            result = subprocess.run(
                ["terraform", "output", "-json"],
                cwd="../sigil-infra/azure",
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                outputs = json.loads(result.stdout)
                database_url = outputs.get("database_url", {}).get("value")
        except Exception as e:
            logger.error(f"Could not get database URL from Terraform: {e}")

    if not database_url:
        logger.error(
            "DATABASE_URL not found. Set environment variable or run from correct directory."
        )
        sys.exit(1)

    # Parse command line arguments
    dry_run = "--dry-run" in sys.argv
    status_only = "--status-only" in sys.argv

    logger.info("🚀 Starting Azure SQL Migration Deployment")
    logger.info(
        f"Database: {database_url.split('Server=')[1].split(',')[0] if 'Server=' in database_url else 'Unknown'}"
    )

    # Create deployer and run
    deployer = AzureMigrationDeployer(database_url)
    deployer.load_migrations()
    deployer.deploy_migrations(dry_run=dry_run, status_only=status_only)


if __name__ == "__main__":
    main()
