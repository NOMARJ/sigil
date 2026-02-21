#!/usr/bin/env python3
"""
Sigil Threat Signature Preloader

Loads threat signatures from threat_signatures.json into the Supabase database.
Supports incremental updates, validation, and deduplication.

Usage:
    python load_signatures.py                  # Load all signatures
    python load_signatures.py --validate-only  # Validate without loading
    python load_signatures.py --force          # Force reload all
    python load_signatures.py --category install_hooks  # Load specific category
"""

import asyncio
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.database import db
from api.models import ScanPhase, Severity


class SignatureLoader:
    """Loads and validates threat signatures."""

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
        """Load and parse the JSON signature file."""
        if not self.json_path.exists():
            raise FileNotFoundError(f"Signature file not found: {self.json_path}")

        with open(self.json_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

        print(f"✓ Loaded {len(self.data.get('signatures', []))} signatures from {self.json_path.name}")
        print(f"  Version: {self.data.get('version', 'unknown')}")
        print(f"  Last updated: {self.data.get('last_updated', 'unknown')}")

    def validate_signature(self, sig: dict[str, Any]) -> tuple[bool, str]:
        """Validate a single signature entry.

        Returns:
            (is_valid, error_message) tuple
        """
        required_fields = ["id", "category", "phase", "severity", "pattern", "description"]

        # Check required fields
        for field in required_fields:
            if field not in sig:
                return False, f"Missing required field: {field}"

        # Validate ID format
        if not re.match(r"^sig-[a-z]+-\d{3,}$", sig["id"]):
            return False, f"Invalid ID format: {sig['id']} (expected sig-category-NNN)"

        # Validate phase enum
        try:
            ScanPhase(sig["phase"])
        except ValueError:
            return False, f"Invalid phase: {sig['phase']}"

        # Validate severity enum
        try:
            Severity(sig["severity"])
        except ValueError:
            return False, f"Invalid severity: {sig['severity']}"

        # Validate regex pattern
        try:
            re.compile(sig["pattern"])
        except re.error as e:
            return False, f"Invalid regex pattern: {e}"

        # Validate weight
        weight = sig.get("weight", 1.0)
        if not isinstance(weight, (int, float)) or weight < 0 or weight > 20:
            return False, f"Invalid weight: {weight} (must be 0-20)"

        # Validate language list
        if "language" in sig:
            if not isinstance(sig["language"], list):
                return False, "Language must be a list"

        self.stats["validated"] += 1
        return True, ""

    def validate_all(self) -> bool:
        """Validate all signatures.

        Returns:
            True if all valid, False if any errors
        """
        signatures = self.data.get("signatures", [])
        print(f"\n🔍 Validating {len(signatures)} signatures...")

        all_valid = True
        errors = []

        for i, sig in enumerate(signatures, 1):
            is_valid, error_msg = self.validate_signature(sig)
            if not is_valid:
                all_valid = False
                errors.append(f"  [{i}] {sig.get('id', 'UNKNOWN')}: {error_msg}")

        if errors:
            print(f"\n❌ Validation failed with {len(errors)} errors:")
            for error in errors[:10]:  # Show first 10 errors
                print(error)
            if len(errors) > 10:
                print(f"  ... and {len(errors) - 10} more errors")
        else:
            print(f"✓ All {self.stats['validated']} signatures validated successfully")

        return all_valid

    async def load_signatures(
        self,
        force: bool = False,
        category: Optional[str] = None,
    ) -> None:
        """Load signatures into the database.

        Args:
            force: If True, reload all signatures even if they exist
            category: If provided, only load signatures from this category
        """
        signatures = self.data.get("signatures", [])

        # Filter by category if specified
        if category:
            signatures = [s for s in signatures if s.get("category") == category]
            print(f"\n📦 Loading {len(signatures)} signatures from category: {category}")
        else:
            print(f"\n📦 Loading {len(signatures)} signatures...")

        for sig in signatures:
            try:
                await self._load_signature(sig, force=force)
            except Exception as e:
                print(f"❌ Error loading {sig.get('id', 'UNKNOWN')}: {e}")
                self.stats["errors"] += 1

        self._print_stats()

    async def _load_signature(self, sig: dict[str, Any], force: bool = False) -> None:
        """Load a single signature into the database."""
        sig_id = sig["id"]

        # Check if signature already exists
        existing = await db.select_one("signatures", {"id": sig_id})

        if existing and not force:
            # Signature exists and we're not forcing reload
            self.stats["skipped"] += 1
            return

        # Prepare row for database
        row = {
            "id": sig_id,
            "phase": sig["phase"],
            "pattern": sig["pattern"],
            "severity": sig["severity"],
            "description": sig["description"],
            "updated_at": datetime.utcnow().isoformat(),
            # Extended fields
            "category": sig.get("category", "unknown"),
            "weight": sig.get("weight", 1.0),
            "language": json.dumps(sig.get("language", ["*"])),
            "cve": json.dumps(sig.get("cve", [])),
            "malware_families": json.dumps(sig.get("malware_families", [])),
            "false_positive_likelihood": sig.get("false_positive_likelihood", "unknown"),
            "created": sig.get("created", datetime.utcnow().date().isoformat()),
        }

        # Upsert to database
        await db.upsert("signatures", row)

        if existing:
            self.stats["updated"] += 1
            print(f"  ↻ Updated: {sig_id}")
        else:
            self.stats["loaded"] += 1
            print(f"  + Loaded: {sig_id}")

    async def load_malware_families(self) -> None:
        """Load malware family metadata into the database."""
        families = self.data.get("malware_families", {})
        if not families:
            return

        print(f"\n📊 Loading {len(families)} malware families...")

        for family_id, family_data in families.items():
            try:
                row = {
                    "id": family_id,
                    "name": family_data["name"],
                    "first_seen": family_data.get("first_seen", "unknown"),
                    "ecosystem": family_data.get("ecosystem", "unknown"),
                    "severity": family_data.get("severity", "HIGH"),
                    "description": family_data.get("description", ""),
                    "iocs": json.dumps(family_data.get("iocs", [])),
                    "signature_ids": json.dumps(family_data.get("signature_ids", [])),
                    "updated_at": datetime.utcnow().isoformat(),
                }

                await db.upsert("malware_families", row)
                print(f"  + Loaded family: {family_id}")

            except Exception as e:
                print(f"❌ Error loading family {family_id}: {e}")

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
            print("\n✅ All signatures loaded successfully!")


async def main() -> int:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Load threat signatures into Sigil database")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate signatures without loading",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force reload all signatures (update existing)",
    )
    parser.add_argument(
        "--category",
        type=str,
        help="Load only signatures from this category",
    )
    parser.add_argument(
        "--json-path",
        type=str,
        default=None,
        help="Path to threat_signatures.json (default: ../data/threat_signatures.json)",
    )

    args = parser.parse_args()

    # Determine JSON path
    if args.json_path:
        json_path = Path(args.json_path)
    else:
        json_path = Path(__file__).parent.parent / "data" / "threat_signatures.json"

    # Initialize loader
    loader = SignatureLoader(json_path)

    # Connect to database
    await db.connect()

    try:
        # Load JSON
        loader.load_json()

        # Validate
        if not loader.validate_all():
            print("\n❌ Validation failed. Fix errors before loading.")
            return 1

        # Exit if validate-only
        if args.validate_only:
            print("\n✅ Validation complete. Use without --validate-only to load.")
            return 0

        # Load signatures
        await loader.load_signatures(force=args.force, category=args.category)

        # Load malware families
        if not args.category:  # Only load families if loading all signatures
            await loader.load_malware_families()

        return 0 if loader.stats["errors"] == 0 else 1

    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback

        traceback.print_exc()
        return 1
    finally:
        # Disconnect from database
        await db.disconnect()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
