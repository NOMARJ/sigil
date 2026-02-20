#!/usr/bin/env python3
"""
Standalone signature validator - no dependencies required.
Can be run without installing the full Sigil API.

Usage:
    python3 validate_signatures_standalone.py
"""

import json
import re
import sys
from pathlib import Path


def validate_signatures():
    """Validate threat_signatures.json without external dependencies."""

    # Load JSON file
    json_path = Path(__file__).parent.parent / "data" / "threat_signatures.json"

    if not json_path.exists():
        print(f"❌ File not found: {json_path}")
        return False

    with open(json_path, "r") as f:
        data = json.load(f)

    print(f"✓ Loaded signature file: {json_path.name}")
    print(f"  Version: {data.get('version', 'unknown')}")
    print(f"  Last updated: {data.get('last_updated', 'unknown')}")
    print(f"  Signature count: {len(data.get('signatures', []))}")
    print()

    # Validate structure
    required_top_level = ["version", "last_updated", "signatures", "categories"]
    for field in required_top_level:
        if field not in data:
            print(f"❌ Missing top-level field: {field}")
            return False

    print(f"🔍 Validating {len(data['signatures'])} signatures...")
    print()

    errors = []
    warnings = []
    stats = {
        "total": 0,
        "by_category": {},
        "by_severity": {},
        "by_phase": {},
    }

    # Valid enums
    valid_phases = ["INSTALL_HOOKS", "CODE_PATTERNS", "NETWORK_EXFIL", "CREDENTIALS", "OBFUSCATION", "PROVENANCE"]
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    valid_categories = set(data.get("categories", []))

    # Track for duplicates
    seen_ids = set()

    for i, sig in enumerate(data["signatures"], 1):
        stats["total"] += 1

        # Required fields
        required_fields = ["id", "category", "phase", "severity", "pattern", "description"]
        for field in required_fields:
            if field not in sig:
                errors.append(f"[{i}] {sig.get('id', 'UNKNOWN')}: Missing field '{field}'")
                continue

        sig_id = sig.get("id", f"unknown-{i}")

        # ID format
        if not re.match(r"^sig-[a-z_]+-\d{3,}$", sig_id):
            errors.append(f"[{i}] {sig_id}: Invalid ID format (expected sig-category-NNN)")

        # Duplicate ID
        if sig_id in seen_ids:
            errors.append(f"[{i}] {sig_id}: Duplicate ID")
        seen_ids.add(sig_id)

        # Phase validation
        phase = sig.get("phase")
        if phase not in valid_phases:
            errors.append(f"[{i}] {sig_id}: Invalid phase '{phase}' (must be one of {valid_phases})")
        else:
            stats["by_phase"][phase] = stats["by_phase"].get(phase, 0) + 1

        # Severity validation
        severity = sig.get("severity")
        if severity not in valid_severities:
            errors.append(f"[{i}] {sig_id}: Invalid severity '{severity}' (must be one of {valid_severities})")
        else:
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

        # Category validation
        category = sig.get("category")
        if category not in valid_categories:
            warnings.append(f"[{i}] {sig_id}: Category '{category}' not in defined categories list")
        stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

        # Regex validation
        pattern = sig.get("pattern", "")
        try:
            re.compile(pattern)
        except re.error as e:
            errors.append(f"[{i}] {sig_id}: Invalid regex pattern: {e}")

        # Weight validation
        weight = sig.get("weight", 1.0)
        if not isinstance(weight, (int, float)):
            errors.append(f"[{i}] {sig_id}: Weight must be a number, got {type(weight).__name__}")
        elif weight < 0 or weight > 20:
            errors.append(f"[{i}] {sig_id}: Weight must be 0-20, got {weight}")

        # Language validation
        if "language" in sig:
            if not isinstance(sig["language"], list):
                errors.append(f"[{i}] {sig_id}: Language must be a list")

    # Print results
    print("📊 Statistics:")
    print(f"  Total signatures: {stats['total']}")
    print(f"\n  By Category:")
    for cat, count in sorted(stats["by_category"].items()):
        print(f"    {cat}: {count}")
    print(f"\n  By Severity:")
    for sev, count in sorted(stats["by_severity"].items(), key=lambda x: valid_severities.index(x[0])):
        print(f"    {sev}: {count}")
    print(f"\n  By Phase:")
    for phase, count in sorted(stats["by_phase"].items()):
        print(f"    {phase}: {count}")
    print()

    # Print warnings
    if warnings:
        print(f"⚠️  {len(warnings)} warnings:")
        for warning in warnings[:5]:
            print(f"  {warning}")
        if len(warnings) > 5:
            print(f"  ... and {len(warnings) - 5} more warnings")
        print()

    # Print errors
    if errors:
        print(f"❌ {len(errors)} errors found:")
        for error in errors[:10]:
            print(f"  {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")
        print()
        print("❌ VALIDATION FAILED")
        return False

    print("✅ ALL SIGNATURES VALID")
    print()
    print("Next steps:")
    print("  1. Install dependencies: pip install -r api/requirements.txt")
    print("  2. Load signatures: python api/scripts/load_signatures.py")
    print("  3. Run tests: pytest api/tests/test_signatures.py")

    return True


if __name__ == "__main__":
    success = validate_signatures()
    sys.exit(0 if success else 1)
