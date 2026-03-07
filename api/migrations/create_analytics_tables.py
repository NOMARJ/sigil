#!/usr/bin/env python3
"""
Migration script to create analytics tables for Pro usage tracking

Run this script to set up the analytics database schema.
Usage: python api/migrations/create_analytics_tables.py
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add the API directory to the path so we can import modules
sys.path.append(str(Path(__file__).parent.parent))

from api.database import db
from api.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def create_analytics_tables():
    """Create the analytics tables in the database."""
    
    try:
        await db.connect()
        logger.info("Connected to database")
        
        # Read the schema file
        schema_file = Path(__file__).parent.parent / 'database' / 'analytics_schema.sql'
        
        if not schema_file.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_file}")
        
        schema_sql = schema_file.read_text()
        logger.info(f"Read schema from {schema_file}")
        
        # Split the schema into individual statements
        statements = [stmt.strip() for stmt in schema_sql.split(';') if stmt.strip()]
        
        logger.info(f"Executing {len(statements)} SQL statements...")
        
        for i, statement in enumerate(statements, 1):
            try:
                # Skip comments and empty statements
                if statement.startswith('--') or not statement:
                    continue
                    
                await db.execute(statement)
                
                # Log table creation specifically
                if 'CREATE TABLE' in statement.upper():
                    table_name = statement.split('CREATE TABLE')[1].split('(')[0].strip()
                    logger.info(f"✓ Created table: {table_name}")
                elif 'CREATE VIEW' in statement.upper():
                    view_name = statement.split('CREATE VIEW')[1].split(' AS')[0].strip()
                    logger.info(f"✓ Created view: {view_name}")
                else:
                    logger.info(f"✓ Executed statement {i}/{len(statements)}")
                    
            except Exception as e:
                logger.error(f"Failed to execute statement {i}: {e}")
                logger.error(f"Statement: {statement[:200]}...")
                raise
        
        logger.info("🎉 Analytics tables created successfully!")
        logger.info("")
        logger.info("Analytics features are now ready:")
        logger.info("  ✓ LLM usage tracking")
        logger.info("  ✓ Threat discovery analytics")
        logger.info("  ✓ User engagement metrics")
        logger.info("  ✓ Churn prediction")
        logger.info("  ✓ Business intelligence reporting")
        
        return True
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False
    finally:
        await db.close()


async def check_tables_exist():
    """Check if analytics tables already exist."""
    try:
        await db.connect()
        
        # Check for the main analytics table
        result = await db.fetch_one("""
            SELECT COUNT(*) as count
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_NAME IN ('user_analytics', 'llm_usage_metrics', 'threat_discoveries')
        """)
        
        return result.get('count', 0) > 0
        
    except Exception as e:
        logger.warning(f"Could not check existing tables: {e}")
        return False
    finally:
        await db.close()


def main():
    """Main migration function."""
    logger.info("🚀 Sigil Analytics Tables Migration")
    logger.info("=" * 50)
    
    if not settings.database_configured:
        logger.error("❌ Database not configured. Set DATABASE_URL environment variable.")
        return False
    
    logger.info(f"Database: {settings.database_url.split('@')[-1] if '@' in settings.database_url else 'configured'}")
    logger.info("")
    
    # Check if tables already exist
    logger.info("Checking for existing analytics tables...")
    if asyncio.run(check_tables_exist()):
        response = input("Analytics tables may already exist. Continue anyway? (y/N): ")
        if response.lower() != 'y':
            logger.info("Migration cancelled.")
            return False
    
    # Run the migration
    success = asyncio.run(create_analytics_tables())
    
    if success:
        logger.info("")
        logger.info("Next steps:")
        logger.info("1. Restart your API server to load the analytics service")
        logger.info("2. Use Pro features to start generating analytics data")
        logger.info("3. Check the /v1/analytics/my/usage endpoint for your usage stats")
        return True
    else:
        logger.error("❌ Migration failed. Check the logs above for details.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)