#!/usr/bin/env python3
"""
Sigil Known Threats Loader

Loads known malicious packages from known_threats.json into the Supabase database.
Supports incremental updates, validation, and deduplication.

Usage:
    python load_threats.py                  # Load all threats
    python load_threats.py --validate-only  # Validate without loading
    python load_threats.py --force          # Force reload all
    python load_threats.py --campaign "Shai-Hulud Wave 1"  # Load specific campaign
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Optional, Union

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.database import db


class ThreatLoader:
    """Loads and validates known threats."""

    def __init__(self, json_path: Union[str, Path]):
        self.json_path = Path(json_path)
        self.data: dict[str, Any] = {}
        self.stats = {
            "loaded": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "validated": 0,
        }

    def load_json(self) -> None:
        """Load and parse the JSON threat file."""
        if not self.json_path.exists():
            raise FileNotFoundError(f"Threat file not found: {self.json_path}")

        with open(self.json_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

        print(f"✓ Loaded {len(self.data.get('threats', []))} threats from {self.json_path.name}")
        print(f"  Version: {self.data.get('version', 'unknown')}")
        print(f"  Last updated: {self.data.get('last_updated', 'unknown')}")
        print(f"  Campaigns: {len(self.data.get('campaigns', []))}")

    def validate_threat(self, threat: dict[str, Any]) -> tuple[bool, str]:
        """Validate a single threat entry.

        Returns:
            (is_valid, error_message) tuple
        """
        required_fields = ["hash", "package_name", "severity", "ecosystem"]

        # Check required fields
        for field in required_fields:
            if field not in threat:
                return False, f"Missing required field: {field}"

        # Validate hash format (SHA-256)
        hash_val = threat.get("hash", "")
        if not (len(hash_val) == 64 and all(c in "0123456789abcdef" for c in hash_val)):
            return False, f"Invalid hash format (expected SHA-256): {hash_val[:20]}..."

        # Validate severity
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if threat["severity"] not in valid_severities:
            return False, f"Invalid severity: {threat['severity']}"

        # Validate ecosystem
        valid_ecosystems = ["npm", "pypi", "rubygems", "crates.io", "go", "nuget", "huggingface", "maven"]
        ecosystem = threat.get("ecosystem", "")
        if ecosystem and ecosystem not in valid_ecosystems:
            return False, f"Invalid ecosystem: {ecosystem}"

        self.stats["validated"] += 1
        return True, ""

    def validate_all(self) -> bool:
        """Validate all threats.

        Returns:
            True if all valid, False if any errors
        """
        threats = self.data.get("threats", [])
        print(f"\n🔍 Validating {len(threats)} threats...")

        all_valid = True
        errors = []
        seen_hashes = set()

        for i, threat in enumerate(threats, 1):
            # Validate structure
            is_valid, error_msg = self.validate_threat(threat)
            if not is_valid:
                all_valid = False
                errors.append(f"  [{i}] {threat.get('package_name', 'UNKNOWN')}: {error_msg}")
                continue

            # Check for duplicate hashes
            hash_val = threat["hash"]
            if hash_val in seen_hashes:
                all_valid = False
                errors.append(f"  [{i}] {threat.get('package_name', 'UNKNOWN')}: Duplicate hash {hash_val[:16]}...")
            seen_hashes.add(hash_val)

        if errors:
            print(f"\n❌ Validation failed with {len(errors)} errors:")
            for error in errors[:10]:  # Show first 10 errors
                print(error)
            if len(errors) > 10:
                print(f"  ... and {len(errors) - 10} more errors")
        else:
            print(f"✓ All {self.stats['validated']} threats validated successfully")

        return all_valid

    async def load_threats(
        self,
        force: bool = False,
        campaign: Optional[str] = None,
    ) -> None:
        """Load threats into the database.

        Args:
            force: If True, reload all threats even if they exist
            campaign: If provided, only load threats from this campaign
        """
        threats = self.data.get("threats", [])

        # Filter by campaign if specified
        if campaign:
            threats = [t for t in threats if t.get("metadata", {}).get("campaign") == campaign]
            print(f"\n📦 Loading {len(threats)} threats from campaign: {campaign}")
        else:
            print(f"\n📦 Loading {len(threats)} threats...")

        for threat in threats:
            try:
                await self._load_threat(threat, force=force)
            except Exception as e:
                print(f"❌ Error loading {threat.get('package_name', 'UNKNOWN')}: {e}")
                self.stats["errors"] += 1

        self._print_stats()

    async def _load_threat(self, threat: dict[str, Any], force: bool = False) -> None:
        """Load a single threat into the database."""
        threat_hash = threat["hash"]

        # Check if threat already exists
        existing = await db.select_one("threats", {"hash": threat_hash})

        if existing and not force:
            # Threat exists and we're not forcing reload
            self.stats["skipped"] += 1
            return

        # Prepare row for database
        row = {
            "hash": threat_hash,
            "package_name": threat["package_name"],
            "version": threat.get("version", ""),
            "severity": threat["severity"],
            "source": threat.get("source", "research"),
            "description": threat.get("description", ""),
            "confirmed_at": threat.get("confirmed_at"),
        }

        # Upsert to database
        await db.upsert("threats", row)

        if existing:
            self.stats["updated"] += 1
            print(f"  ↻ Updated: {threat['package_name']} ({threat['ecosystem']})")
        else:
            self.stats["loaded"] += 1
            print(f"  + Loaded: {threat['package_name']} ({threat['ecosystem']})")

    def _print_stats(self) -> None:
        """Print loading statistics."""
        print("\n📈 Statistics:")
        print(f"  Loaded:    {self.stats['loaded']}")
        print(f"  Updated:   {self.stats['updated']}")
        print(f"  Skipped:   {self.stats['skipped']}")
        print(f"  Errors:    {self.stats['errors']}")
        print(f"  Validated: {self.stats['validated']}")

        if self.stats["errors"] > 0:
            print(f"\n⚠️  {self.stats['errors']} errors occurred during loading")
        else:
            print("\n✅ All threats loaded successfully!")

    def print_summary(self) -> None:
        """Print summary of threats by campaign and ecosystem."""
        threats = self.data.get("threats", [])

        # Group by ecosystem
        by_ecosystem = {}
        for threat in threats:
            eco = threat.get("ecosystem", "unknown")
            by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1

        # Group by campaign
        by_campaign = {}
        for threat in threats:
            campaign = threat.get("metadata", {}).get("campaign", "unknown")
            by_campaign[campaign] = by_campaign.get(campaign, 0) + 1

        # Group by severity
        by_severity = {}
        for threat in threats:
            sev = threat["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1

        print("\n📊 Threat Database Summary:")
        print(f"  Total threats: {len(threats)}")

        print("\n  By Ecosystem:")
        for eco, count in sorted(by_ecosystem.items(), key=lambda x: x[1], reverse=True):
            print(f"    {eco}: {count}")

        print("\n  By Severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in by_severity:
                print(f"    {sev}: {by_severity[sev]}")

        print("\n  By Campaign (top 10):")
        for campaign, count in sorted(by_campaign.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"    {campaign}: {count}")


async def main() -> int:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Load known threats into Sigil database")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate threats without loading",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force reload all threats (update existing)",
    )
    parser.add_argument(
        "--campaign",
        type=str,
        help="Load only threats from this campaign",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary and exit",
    )
    parser.add_argument(
        "--json-path",
        type=str,
        default=None,
        help="Path to known_threats.json (default: ../data/known_threats.json)",
    )

    args = parser.parse_args()

    # Determine JSON path
    if args.json_path:
        json_path = Path(args.json_path)
    else:
        json_path = Path(__file__).parent.parent / "data" / "known_threats.json"

    # Initialize loader
    loader = ThreatLoader(json_path)

    # Connect to database (unless just printing summary)
    if not args.summary:
        await db.connect()

    try:
        # Load JSON
        loader.load_json()

        # Print summary if requested
        if args.summary:
            loader.print_summary()
            return 0

        # Validate
        if not loader.validate_all():
            print("\n❌ Validation failed. Fix errors before loading.")
            return 1

        # Exit if validate-only
        if args.validate_only:
            print("\n✅ Validation complete. Use without --validate-only to load.")
            return 0

        # Load threats
        await loader.load_threats(force=args.force, campaign=args.campaign)

        return 0 if loader.stats["errors"] == 0 else 1

    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if not args.summary:
            await db.disconnect()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
