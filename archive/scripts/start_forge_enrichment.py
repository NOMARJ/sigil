#!/usr/bin/env python3
"""
Start Forge Enrichment Worker

This script starts the forge enrichment worker that processes existing
public_scans and classifications data to make them compatible with the
new Forge Backend API specification.

Usage:
    python scripts/start_forge_enrichment.py
    python scripts/start_forge_enrichment.py --dry-run
    python scripts/start_forge_enrichment.py --batch-size 5 --max-records 100
"""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from api.config import settings
from api.database import db
from bot.config import bot_settings
from bot.worker.forge_enrichment import ForgeEnrichmentWorker

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class EnrichmentController:
    """Controller for the forge enrichment process."""

    def __init__(
        self, dry_run: bool = False, batch_size: int = None, max_records: int = None
    ):
        self.dry_run = dry_run
        self.worker = ForgeEnrichmentWorker()
        self.running = True

        # Override configuration if provided
        if batch_size:
            self.worker.batch_size = batch_size
        else:
            self.worker.batch_size = bot_settings.forge_enrichment_batch_size

        if max_records:
            self.worker.max_records = max_records
        else:
            self.worker.max_records = bot_settings.forge_enrichment_max_records

        self.worker.delay_between_batches = bot_settings.forge_enrichment_delay

    async def start(self):
        """Start the enrichment process."""
        if not bot_settings.forge_enrichment_enabled:
            logger.warning("Forge enrichment is disabled in configuration")
            return

        if not bot_settings.database_configured:
            logger.error("Database not configured - cannot run enrichment worker")
            return

        logger.info("Starting Forge enrichment worker")
        logger.info(f"  Batch size: {self.worker.batch_size}")
        logger.info(f"  Max records: {self.worker.max_records}")
        logger.info(f"  Delay between batches: {self.worker.delay_between_batches}s")
        logger.info(f"  Dry run: {self.dry_run}")

        try:
            await db.connect()
            if not db.connected:
                logger.error("Failed to connect to database")
                return

            logger.info("Database connection established")

            if self.dry_run:
                await self.run_dry_run()
            else:
                await self.run_continuous()

        except KeyboardInterrupt:
            logger.info("Shutting down gracefully...")
        except Exception as e:
            logger.error(f"Enrichment worker failed: {e}", exc_info=True)
        finally:
            await db.disconnect()

    async def run_dry_run(self):
        """Run a dry run to see what would be enriched."""
        logger.info("=== DRY RUN MODE ===")

        pending_records = await self.worker._find_pending_enrichments()

        if not pending_records:
            logger.info("✅ No records need enrichment")
            return

        logger.info(f"📊 Found {len(pending_records)} records that would be enriched:")

        ecosystems = {}
        for record in pending_records:
            ecosystem = record["ecosystem"]
            ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1

        for ecosystem, count in ecosystems.items():
            logger.info(f"  {ecosystem}: {count} packages")

        # Show sample records
        logger.info("\n📋 Sample records:")
        for i, record in enumerate(pending_records[:5]):
            logger.info(
                f"  {i + 1}. {record['ecosystem']}/{record['package_name']} v{record.get('package_version', 'latest')}"
            )

        if len(pending_records) > 5:
            logger.info(f"  ... and {len(pending_records) - 5} more")

        logger.info("\n⚡ To start enrichment, run without --dry-run")

    async def run_continuous(self):
        """Run continuous enrichment."""
        logger.info("Starting continuous enrichment process...")

        # Set up signal handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        records_processed = 0

        while self.running and records_processed < self.worker.max_records:
            try:
                # Find pending records
                pending_records = await self.worker._find_pending_enrichments()

                if not pending_records:
                    logger.info("No more records to enrich, sleeping...")
                    await asyncio.sleep(bot_settings.forge_enrichment_poll_interval)
                    continue

                remaining_budget = self.worker.max_records - records_processed
                batch_records = pending_records[
                    : min(self.worker.batch_size, remaining_budget)
                ]

                logger.info(f"Processing batch of {len(batch_records)} records...")

                # Process batch
                await self.worker._process_batch(batch_records)

                records_processed += len(batch_records)
                logger.info(
                    f"✅ Processed {records_processed}/{self.worker.max_records} records"
                )

                # Sleep between batches
                if records_processed < self.worker.max_records and len(
                    pending_records
                ) > len(batch_records):
                    await asyncio.sleep(self.worker.delay_between_batches)

            except Exception as e:
                logger.error(f"Batch processing failed: {e}", exc_info=True)
                await asyncio.sleep(30)  # Wait before retrying

        if records_processed >= self.worker.max_records:
            logger.info(
                f"✅ Reached max records limit ({self.worker.max_records}), stopping"
            )
        else:
            logger.info("✅ Enrichment process completed")

    def stop(self):
        """Stop the enrichment process."""
        self.running = False


async def main():
    parser = argparse.ArgumentParser(
        description="Start forge enrichment worker for Forge API compatibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/start_forge_enrichment.py
  python scripts/start_forge_enrichment.py --dry-run
  python scripts/start_forge_enrichment.py --batch-size 5 --max-records 100

Environment Variables:
  SIGIL_BOT_FORGE_ENRICHMENT_ENABLED=true/false
  SIGIL_BOT_FORGE_ENRICHMENT_BATCH_SIZE=10
  SIGIL_BOT_FORGE_ENRICHMENT_DELAY=1.0
  SIGIL_BOT_FORGE_ENRICHMENT_MAX_RECORDS=1000
  SIGIL_BOT_FORGE_ENRICHMENT_POLL_INTERVAL=300
        """,
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be enriched without making changes",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        help="Number of records to process per batch (overrides config)",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        help="Maximum number of records to process in this run (overrides config)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate configuration
    if not settings.database_configured:
        logger.error("DATABASE_URL not configured")
        logger.error("Set DATABASE_URL environment variable or configure in .env file")
        return 1

    # Create and start controller
    controller = EnrichmentController(
        dry_run=args.dry_run, batch_size=args.batch_size, max_records=args.max_records
    )

    try:
        await controller.start()
        return 0
    except Exception as e:
        logger.error(f"Failed to start enrichment: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
