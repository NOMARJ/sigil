#!/usr/bin/env python3
"""
Simple Forge Enrichment Worker

A minimal worker that runs enrichment without HTTP endpoints.
This is used to test the basic enrichment functionality in Container Apps.
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from api.database import db
from bot.config import bot_settings
from bot.worker.forge_enrichment import ForgeEnrichmentWorker

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Global state
shutdown_event = asyncio.Event()


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()


async def main():
    """Main enrichment worker function."""
    try:
        logger.info("Starting Simple Forge Enrichment Worker")

        if not bot_settings.forge_enrichment_enabled:
            logger.warning("Forge enrichment is disabled in configuration")
            return

        if not bot_settings.database_configured:
            logger.error("Database not configured")
            return

        # Initialize worker
        worker = ForgeEnrichmentWorker()
        worker.batch_size = bot_settings.forge_enrichment_batch_size
        worker.max_records = bot_settings.forge_enrichment_max_records
        worker.delay_between_batches = bot_settings.forge_enrichment_delay

        logger.info(f"Worker configuration:")
        logger.info(f"  Batch size: {worker.batch_size}")
        logger.info(f"  Max records: {worker.max_records}")
        logger.info(f"  Delay between batches: {worker.delay_between_batches}s")

        await db.connect()
        processed_records = 0

        while not shutdown_event.is_set() and processed_records < worker.max_records:
            try:
                logger.info(
                    f"Looking for pending enrichments... ({processed_records}/{worker.max_records} processed)"
                )

                # Find pending records
                pending_records = await worker._find_pending_enrichments()

                if not pending_records:
                    logger.info("No records pending enrichment, sleeping...")
                    await asyncio.sleep(bot_settings.forge_enrichment_poll_interval)
                    continue

                remaining_budget = worker.max_records - processed_records
                batch_records = pending_records[
                    : min(worker.batch_size, remaining_budget)
                ]

                logger.info(f"Processing batch with {len(batch_records)} records...")

                # Process batch
                await worker._process_batch(batch_records)

                processed_records += len(batch_records)
                logger.info(
                    f"✅ Processed {processed_records}/{worker.max_records} records"
                )

                # Sleep between batches if there are more records and we haven't hit the limit
                if processed_records < worker.max_records and len(
                    pending_records
                ) > len(batch_records):
                    await asyncio.sleep(worker.delay_between_batches)

            except Exception as e:
                logger.error(f"Batch processing failed: {e}", exc_info=True)
                await asyncio.sleep(30)  # Wait before retrying

        if processed_records >= worker.max_records:
            logger.info(
                f"✅ Reached max records limit ({worker.max_records}), stopping"
            )
        else:
            logger.info("✅ Enrichment process stopped by signal")

    except Exception as e:
        logger.error(f"Enrichment worker failed: {e}", exc_info=True)
    finally:
        await db.disconnect()


if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run the worker
    asyncio.run(main())
