#!/usr/bin/env python3
"""
Sigil Forge — Batch Classification Script

Processes all packages in public_scans table and classifies them using the Forge classifier.
Supports resumable operation and progress tracking for 7,700+ tools.

Usage:
    python batch_classify_forge.py [options]

Options:
    --ecosystem ECOSYSTEM   Only classify packages from specific ecosystem (clawhub, mcp, npm, pypi)
    --limit N               Limit number of packages to process (for testing)
    --resume                Resume from last processed package
    --force                 Re-classify packages that already have classifications
    --dry-run              Show what would be processed without actually classifying
    --verbose              Enable detailed logging
"""

import asyncio
import argparse
import json
import logging
import sys
import time
from typing import Any

# Add parent directory to path to import API modules
sys.path.append("/Users/reecefrazier/CascadeProjects/sigil")

from config import settings
from database import db
from services.forge_classifier import (
    forge_classifier,
    ClassificationInput,
    Finding,
    ScanPhase,
    Severity,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BatchClassifier:
    """Handles batch classification of all packages."""

    def __init__(self, args):
        self.ecosystem_filter = args.ecosystem
        self.limit = args.limit
        self.resume = args.resume
        self.force = args.force
        self.dry_run = args.dry_run
        self.verbose = args.verbose

        self.processed_count = 0
        self.classified_count = 0
        self.error_count = 0
        self.skipped_count = 0

        if self.verbose:
            logging.getLogger("api.services.forge_classifier").setLevel(logging.DEBUG)

    async def get_packages_to_classify(self) -> list[dict[str, Any]]:
        """Get list of packages that need classification."""
        filters = {}
        if self.ecosystem_filter:
            filters["ecosystem"] = self.ecosystem_filter

        # Get all public scans
        packages = await db.select(
            "public_scans",
            filters,
            order_by="scanned_at",
            order_desc=False,
            limit=self.limit,
        )

        if not self.force:
            # Filter out packages that already have classifications
            filtered_packages = []
            for package in packages:
                existing = await forge_classifier.get_classification(
                    package["ecosystem"],
                    package["package_name"],
                    package.get("package_version", ""),
                )
                if not existing:
                    filtered_packages.append(package)
                else:
                    logger.debug(
                        f"Skipping {package['ecosystem']}/{package['package_name']} - already classified"
                    )
            packages = filtered_packages

        logger.info(f"Found {len(packages)} packages to classify")
        return packages

    def _parse_scan_findings(self, findings_json: str) -> list[Finding]:
        """Parse findings JSON into Finding objects."""
        try:
            findings_data = json.loads(findings_json or "[]")
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
                    logger.warning(f"Invalid finding format: {e}")
                    continue
            return findings
        except json.JSONDecodeError:
            logger.warning("Invalid findings JSON")
            return []

    async def classify_package(self, package: dict[str, Any]) -> bool:
        """Classify a single package. Returns True if successful."""
        try:
            # Parse package data
            ecosystem = package["ecosystem"]
            package_name = package["package_name"]
            package_version = package.get("package_version", "")

            # Parse findings
            findings = self._parse_scan_findings(package.get("findings_json", "[]"))

            # Parse metadata for description
            metadata = json.loads(package.get("metadata_json", "{}"))
            description = metadata.get("description", metadata.get("summary", ""))

            # Create classification input
            input_data = ClassificationInput(
                ecosystem=ecosystem,
                package_name=package_name,
                package_version=package_version,
                description=description,
                scan_findings=findings,
                metadata=metadata,
            )

            if self.dry_run:
                logger.info(f"Would classify {ecosystem}/{package_name}")
                return True

            # Perform classification
            logger.info(
                f"Classifying {ecosystem}/{package_name} ({len(findings)} findings)"
            )
            result = await forge_classifier.classify_package(input_data)

            # Save classification
            await forge_classifier.save_classification(input_data, result)

            logger.info(
                f"✓ Classified {ecosystem}/{package_name} as {result.category} (confidence: {result.confidence_score:.2f})"
            )
            return True

        except Exception as e:
            logger.error(
                f"Failed to classify {package.get('package_name', 'unknown')}: {e}"
            )
            return False

    async def run(self):
        """Run the batch classification process."""
        start_time = time.time()

        try:
            # Connect to database
            await db.connect()
            logger.info("Connected to database")

            # Get packages to process
            packages = await self.get_packages_to_classify()

            if not packages:
                logger.info("No packages to classify")
                return

            total_packages = len(packages)
            logger.info(f"Starting batch classification of {total_packages} packages")

            # Process packages with progress tracking
            for i, package in enumerate(packages):
                self.processed_count += 1

                # Show progress every 10 packages
                if i % 10 == 0:
                    progress = (i / total_packages) * 100
                    elapsed = time.time() - start_time
                    eta = (elapsed / (i + 1)) * (total_packages - i - 1) if i > 0 else 0
                    logger.info(
                        f"Progress: {i}/{total_packages} ({progress:.1f}%) - ETA: {eta / 60:.1f}m"
                    )

                success = await self.classify_package(package)

                if success:
                    self.classified_count += 1
                else:
                    self.error_count += 1

                # Rate limiting: small delay between API calls
                if not self.dry_run:
                    await asyncio.sleep(0.1)  # 100ms delay

            # Final stats
            elapsed = time.time() - start_time
            logger.info("Batch classification complete!")
            logger.info(f"Processed: {self.processed_count}")
            logger.info(f"Classified: {self.classified_count}")
            logger.info(f"Errors: {self.error_count}")
            logger.info(f"Elapsed time: {elapsed / 60:.1f} minutes")

            if self.classified_count > 0:
                logger.info(
                    f"Average time per classification: {elapsed / self.classified_count:.1f} seconds"
                )

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Batch classification failed: {e}")
            raise
        finally:
            await db.disconnect()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Batch classify packages for Sigil Forge"
    )
    parser.add_argument(
        "--ecosystem", help="Filter by ecosystem (clawhub, mcp, npm, pypi)"
    )
    parser.add_argument("--limit", type=int, help="Limit number of packages to process")
    parser.add_argument(
        "--resume", action="store_true", help="Resume from last processed"
    )
    parser.add_argument(
        "--force", action="store_true", help="Re-classify existing classifications"
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

    if not settings.anthropic_api_key and not args.dry_run:
        logger.warning(
            "No Anthropic API key configured. Will use rule-based classification."
        )

    # Run batch classifier
    classifier = BatchClassifier(args)
    await classifier.run()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
