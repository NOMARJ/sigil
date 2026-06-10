#!/usr/bin/env python3
"""Fail when any corpus file's declared count diverges from its actual entries.

CI gate for ADR-0005's rule: counts are derived, never declared. Exit 0 when
every declared count matches reality, 1 on any mismatch, 2 on unreadable file.
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# (file, declared-count path, entries path)
CORPUS_FILES = [
    ("api/data/threat_signatures.json", ("signature_count",), ("signatures",)),
    ("api/data/known_threats.json", ("threat_count",), ("threats",)),
]


def dig(obj: dict, path: tuple):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def main() -> int:
    failures = 0
    for rel_path, count_path, entries_path in CORPUS_FILES:
        file_path = REPO_ROOT / rel_path
        try:
            data = json.loads(file_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR {rel_path}: unreadable ({exc})")
            return 2
        declared = dig(data, count_path)
        entries = dig(data, entries_path)
        actual = len(entries) if isinstance(entries, list) else None
        if declared is None or actual is None:
            print(f"ERROR {rel_path}: missing {'.'.join(count_path)} or {'.'.join(entries_path)}")
            failures += 1
        elif declared != actual:
            print(f"FAIL  {rel_path}: declares {declared}, contains {actual}")
            failures += 1
        else:
            print(f"OK    {rel_path}: {actual} entries, declared count matches")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
