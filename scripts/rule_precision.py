#!/usr/bin/env python3
"""Per-rule precision on a clean control set.

Answers the one question a signature pack cannot answer about itself: *which
rules fire on code that is not malicious?* For every rule that produced a
finding, it reports how many clean packages it hit, how many findings it
produced, at what severity — and, when a `sigil_samples.py` result file is
supplied, how many malicious samples the same rule hit. A rule at the top of
the clean-packages column with a low malicious count is a rule to narrow,
downgrade or mark `"evidence": "corroborate"`.

Every number comes from a real scan run by this script. There is no `random`,
no sampling and no estimation: the control directories are walked in sorted
order and each is scanned once, so a second run on the same inputs reproduces
the same table (see CLAUDE.md, "No Fake Data, Ever").

Usage
-----
    scripts/rule_precision.py <bin> <control_dir> [--samples <sigil_samples.json>]
                              [--out table.json] [--phases <list>] [--top N]

`<control_dir>` holds one directory per clean package. `--samples` takes the
JSON written by the malicious-sample harness (a `{"malicious": [{"rules":
[...]}, ...]}` document) and adds the malicious-hit column. `--out` writes the
full table as JSON; without it the table is printed only.

Example
-------
    scripts/rule_precision.py cli/target/release/sigil /path/to/control \\
        --samples /path/to/sigil_samples.json --out rule_precision.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def scan(binary: str, path: Path, phases: str, timeout: int) -> dict:
    """Scan one directory and return its JSON document (or an error record)."""
    cmd = [binary, "scan", str(path), "--no-cache", "--format", "json"]
    if phases:
        cmd += ["--phases", phases]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s"}
    start = proc.stdout.find("{")
    if start == -1:
        return {"error": f"no JSON on stdout (exit {proc.returncode})"}
    try:
        return json.loads(proc.stdout[start:])
    except json.JSONDecodeError as exc:
        return {"error": f"unparseable JSON: {exc}"}


def malicious_hits(samples_path: Path) -> dict[str, int]:
    """rule id -> number of malicious samples in which that rule fired."""
    doc = json.loads(samples_path.read_text())
    hits: Counter[str] = Counter()
    for sample in doc.get("malicious", []):
        for rule in set(sample.get("rules", [])):
            hits[rule] += 1
    return dict(hits)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Per-rule precision on a clean control set (real scans only)."
    )
    ap.add_argument("binary", help="path to the sigil binary")
    ap.add_argument("control_dir", help="directory of clean package directories")
    ap.add_argument("--samples", help="sigil_samples.json for the malicious-hit column")
    ap.add_argument("--out", help="write the full table here as JSON")
    ap.add_argument(
        "--phases",
        default="",
        help="value for --phases (default: the scanner's default, all phases)",
    )
    ap.add_argument("--top", type=int, default=0, help="print only the top N rules")
    ap.add_argument("--timeout", type=int, default=300, help="per-package scan timeout")
    args = ap.parse_args()

    control = Path(args.control_dir)
    if not control.is_dir():
        print(f"error: {control} is not a directory", file=sys.stderr)
        return 2
    packages = sorted(p for p in control.iterdir() if p.is_dir())
    if not packages:
        print(f"error: no package directories under {control}", file=sys.stderr)
        return 2

    mal = malicious_hits(Path(args.samples)) if args.samples else {}

    per_rule_packages: dict[str, set[str]] = defaultdict(set)
    per_rule_findings: Counter[str] = Counter()
    per_rule_severity: dict[str, str] = {}
    per_package: dict[str, dict] = {}
    errors: dict[str, str] = {}

    for i, pkg in enumerate(packages, 1):
        doc = scan(args.binary, pkg, args.phases, args.timeout)
        if "error" in doc:
            errors[pkg.name] = doc["error"]
            print(f"[{i}/{len(packages)}] {pkg.name}: {doc['error']}", file=sys.stderr)
            continue
        findings = doc.get("findings", [])
        summary = doc.get("summary", {})
        per_package[pkg.name] = {
            "verdict": summary.get("verdict"),
            "score": summary.get("score"),
            "findings": len(findings),
            "max_severity": max(
                (f.get("severity", "Low") for f in findings),
                key=lambda s: SEVERITY_ORDER.get(s, 0),
                default=None,
            ),
        }
        for f in findings:
            per_rule_packages[f["rule"]].add(pkg.name)
            per_rule_findings[f["rule"]] += 1
            # A rule has one severity; keep the highest seen in case a pack
            # ever emits the same id at two levels.
            prev = per_rule_severity.get(f["rule"])
            if prev is None or SEVERITY_ORDER.get(f["severity"], 0) > SEVERITY_ORDER.get(prev, 0):
                per_rule_severity[f["rule"]] = f["severity"]
        print(
            f"[{i}/{len(packages)}] {pkg.name}: {summary.get('verdict')} "
            f"score={summary.get('score')} findings={len(findings)}",
            file=sys.stderr,
        )

    rows = sorted(
        per_rule_packages,
        key=lambda r: (
            -len(per_rule_packages[r]),
            -per_rule_findings[r],
            r,
        ),
    )
    shown = rows[: args.top] if args.top else rows

    scanned = len(per_package)
    print()
    print(f"per-rule precision on {scanned} clean package(s) under {control}")
    if mal:
        print(f"malicious-hit column from {args.samples}")
    print()
    header = f"{'rule':<22} {'pkgs':>5} {'findings':>9} {'severity':<9}"
    if mal:
        header += f" {'malicious':>9}"
    print(header)
    print("-" * len(header))
    for rule in shown:
        line = (
            f"{rule:<22} {len(per_rule_packages[rule]):>5} "
            f"{per_rule_findings[rule]:>9} {per_rule_severity.get(rule, '?'):<9}"
        )
        if mal:
            line += f" {mal.get(rule, 0):>9}"
        print(line)

    verdicts = Counter(v["verdict"] for v in per_package.values())
    high_or_worse = verdicts["HIGH RISK"] + verdicts["CRITICAL RISK"]
    print()
    print(f"verdicts: {dict(verdicts)}")
    print(f"High-or-worse {high_or_worse}/{scanned}, CRITICAL {verdicts['CRITICAL RISK']}/{scanned}")
    if errors:
        print(f"errors: {errors}")

    if args.out:
        table = {
            "data_source": "real scans by scripts/rule_precision.py",
            "binary": args.binary,
            "control_dir": str(control),
            "phases": args.phases or "all",
            "packages_scanned": scanned,
            "samples_file": args.samples,
            "rules": {
                rule: {
                    "clean_packages": sorted(per_rule_packages[rule]),
                    "clean_package_count": len(per_rule_packages[rule]),
                    "clean_findings": per_rule_findings[rule],
                    "severity": per_rule_severity.get(rule),
                    "malicious_samples": mal.get(rule, 0) if mal else None,
                }
                for rule in rows
            },
            "per_package": per_package,
            "errors": errors,
        }
        Path(args.out).write_text(json.dumps(table, indent=1))
        print(f"wrote {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
