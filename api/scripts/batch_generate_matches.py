#!/usr/bin/env python3
"""
Sigil Forge — Batch Match Generation Script

Generates compatibility matches between all classified tools.
Runs after batch_classify_forge.py to create the matching matrix.

Usage:
    python batch_generate_matches.py [options]

Options:
    --limit N               Limit number of tools to process matches for
    --ecosystem ECOSYSTEM   Only generate matches for specific ecosystem
    --dry-run              Show what would be processed without actually generating
    --verbose              Enable detailed logging
"""

import asyncio
import argparse
import logging
import pathlib
import sys
import time
from typing import Any

# Add project root to path to import API modules
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from api.config import settings
from api.database import db
from archive.services.forge_matcher import forge_matcher

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BatchMatchGenerator:
    """Handles batch generation of tool matches."""

    def __init__(self, args):
        self.limit = args.limit
        self.ecosystem_filter = args.ecosystem
        self.dry_run = args.dry_run
        self.verbose = args.verbose

        self.processed_count = 0
        self.matches_generated = 0
        self.error_count = 0

        if self.verbose:
            logging.getLogger("api.services.forge_matcher").setLevel(logging.DEBUG)

    async def get_classifications_to_process(self) -> list[dict[str, Any]]:
        """Get list of classifications that need match generation."""
        filters = {}
        if self.ecosystem_filter:
            filters["ecosystem"] = self.ecosystem_filter

        # Get all classifications
        classifications = await db.select(
            "forge_classification",
            filters,
            order_by="classified_at",
            order_desc=False,
            limit=self.limit,
        )

        logger.info(f"Found {len(classifications)} classifications to process")
        return classifications

    async def generate_matches_for_tool(self, classification: dict[str, Any]) -> bool:
        """Generate matches for a single tool. Returns True if successful."""
        try:
            classification_id = classification["id"]
            ecosystem = classification["ecosystem"]
            package_name = classification["package_name"]
            category = classification["category"]

            logger.info(
                f"Generating matches for {ecosystem}/{package_name} ({category})"
            )

            if self.dry_run:
                logger.info(f"Would generate matches for {ecosystem}/{package_name}")
                return True

            # Check if matches already exist
            existing_matches = await db.select(
                "forge_matches",
                {"primary_classification_id": classification_id},
                limit=1,
            )

            if existing_matches:
                logger.debug(
                    f"Skipping {ecosystem}/{package_name} - matches already exist"
                )
                return True

            # Generate all types of matches
            matches = await forge_matcher.generate_all_matches(classification_id)

            if matches:
                # Save matches to database
                saved_count = await forge_matcher.save_matches(matches)
                logger.info(
                    f"✓ Generated {saved_count} matches for {ecosystem}/{package_name}"
                )
                self.matches_generated += saved_count
            else:
                logger.info(f"No matches found for {ecosystem}/{package_name}")

            return True

        except Exception as e:
            logger.error(
                f"Failed to generate matches for {classification.get('package_name', 'unknown')}: {e}"
            )
            return False

    async def generate_sample_stacks(self):
        """Generate sample Forge Stacks for common use cases."""
        if self.dry_run:
            logger.info("Would generate sample stacks")
            return

        sample_use_cases = [
            "I want my agent to query a PostgreSQL database",
            "I need GitHub API integration for code review",
            "Web search and content summarization",
            "File processing and analysis",
            "Security scanning and vulnerability detection",
        ]

        logger.info("Generating sample Forge Stacks...")

        for use_case in sample_use_cases:
            try:
                stack = await forge_matcher.generate_forge_stack(use_case)
                logger.info(
                    f"✓ Generated stack: {stack['stack']['name']} ({len(stack['tools'])} tools)"
                )
            except Exception as e:
                logger.error(f"Failed to generate stack for '{use_case}': {e}")

    async def run(self):
        """Run the batch match generation process."""
        start_time = time.time()

        try:
            # Connect to database
            await db.connect()
            logger.info("Connected to database")

            # Get classifications to process
            classifications = await self.get_classifications_to_process()

            if not classifications:
                logger.info("No classifications to process")
                return

            total_classifications = len(classifications)
            logger.info(f"Starting match generation for {total_classifications} tools")

            # Process classifications with progress tracking
            for i, classification in enumerate(classifications):
                self.processed_count += 1

                # Show progress every 10 tools
                if i % 10 == 0:
                    progress = (i / total_classifications) * 100
                    elapsed = time.time() - start_time
                    eta = (
                        (elapsed / (i + 1)) * (total_classifications - i - 1)
                        if i > 0
                        else 0
                    )
                    logger.info(
                        f"Progress: {i}/{total_classifications} ({progress:.1f}%) - ETA: {eta / 60:.1f}m"
                    )

                success = await self.generate_matches_for_tool(classification)

                if not success:
                    self.error_count += 1

                # Small delay to prevent overwhelming database
                await asyncio.sleep(0.05)  # 50ms delay

            # Generate sample stacks
            await self.generate_sample_stacks()

            # Final stats
            elapsed = time.time() - start_time
            logger.info("Batch match generation complete!")
            logger.info(f"Processed tools: {self.processed_count}")
            logger.info(f"Matches generated: {self.matches_generated}")
            logger.info(f"Errors: {self.error_count}")
            logger.info(f"Elapsed time: {elapsed / 60:.1f} minutes")

            if self.processed_count > 0:
                logger.info(
                    f"Average matches per tool: {self.matches_generated / self.processed_count:.1f}"
                )

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Batch match generation failed: {e}")
            raise
        finally:
            await db.disconnect()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate matches between classified tools"
    )
    parser.add_argument("--limit", type=int, help="Limit number of tools to process")
    parser.add_argument(
        "--ecosystem", help="Filter by ecosystem (clawhub, mcp, npm, pypi)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be processed"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate configuration
    if not settings.database_configured:
        logger.error("Database not configured. Set DATABASE_URL environment variable.")
        return 1

    # Run batch match generator
    generator = BatchMatchGenerator(args)
    await generator.run()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
