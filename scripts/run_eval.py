#!/usr/bin/env python3
"""Honest detection evaluation for the Sigil Rust engine (F-008 US-G3).

Replaces the unverifiable `production_d1_d4_scorecard_80k_scans.json` lineage.
Every number here is produced by actually running the scanner against real,
human-triaged samples. There is NO `random` and no synthetic measurement: the
sample is selected deterministically (sorted, fixed limit), so a second run on
the same dataset commit reproduces the same numbers.

Data sources
------------
* Malicious: Datadog `malicious-software-packages-dataset` — encrypted zips of
  human-triaged malicious npm/PyPI packages. The dataset's public, documented
  archive unlock phrase (see its README) is used only to extract samples for
  static scanning; nothing is executed.
* Clean control: a caller-provided directory of extracted legitimate packages
  (``--control-path``). Used to measure the false-positive rate. If absent, the
  report measures recall only and says so explicitly (no fabricated precision).

Detection is run with offline static phases only (no OSV/provenance network
calls) so the result is deterministic and reproducible.

Usage
-----
    python3 scripts/run_eval.py --dataset datadog \
        --dataset-path /path/to/malicious-software-packages-dataset \
        --out evaluation_results/ [--limit N] [--control-path DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Offline, deterministic detection phases. OSV/provenance feeds are excluded on
# purpose: they make network calls (non-reproducible) and grade dependency CVEs,
# not package maliciousness, which is what this eval measures.
DETECTION_PHASES = "install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection"

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
THRESHOLDS = ["any", "Medium", "High", "Critical"]

# Public, documented unlock phrase for the Datadog sample archives (their README
# publishes it). Not a credential — it gates nothing of value; it is the standard
# malware-sharing convention so AV does not auto-quarantine the zips.
SAMPLE_UNLOCK = "infected"


def resolve_binary() -> str:
    """Locate the Rust sigil binary: $SIGIL_BIN, then PATH, then repo default."""
    env = os.environ.get("SIGIL_BIN")
    if env and Path(env).is_file():
        return env
    on_path = shutil.which("sigil")
    if on_path:
        return on_path
    repo_default = Path(__file__).resolve().parent.parent / "cli" / "target" / "release" / "sigil"
    if repo_default.is_file():
        return str(repo_default)
    sys.exit(
        "error: sigil binary not found. Build it (`cd cli && cargo build --release`) "
        "or set SIGIL_BIN."
    )


@dataclass
class SampleResult:
    path: str
    max_severity: str | None
    finding_count: int
    error: str | None = None

    def detected_at(self, threshold: str) -> bool:
        if self.max_severity is None:
            return False
        if threshold == "any":
            return self.finding_count > 0
        return SEVERITY_ORDER.get(self.max_severity, 0) >= SEVERITY_ORDER[threshold]


def list_sample_zips(dataset_path: Path) -> list[Path]:
    """Every sample zip, sorted for deterministic selection."""
    samples = dataset_path / "samples"
    if not samples.is_dir():
        sys.exit(f"error: no samples/ under {dataset_path} (is this the Datadog dataset?)")
    return sorted(samples.rglob("*.zip"))


def bucket_of(zip_path: Path, dataset_path: Path) -> str:
    """ecosystem/category bucket, e.g. 'npm/malicious_intent'."""
    rel = zip_path.relative_to(dataset_path / "samples").parts
    return f"{rel[0]}/{rel[1]}" if len(rel) >= 2 else "unknown"


def select_samples(zips: list[Path], dataset_path: Path, limit: int | None) -> list[Path]:
    """Deterministic per-bucket selection: first `limit` sorted in each bucket.
    Per-bucket (not global) so a small limit still covers every ecosystem."""
    if limit is None:
        return zips
    by_bucket: dict[str, list[Path]] = {}
    for z in zips:  # zips already sorted
        by_bucket.setdefault(bucket_of(z, dataset_path), []).append(z)
    chosen: list[Path] = []
    for bucket in sorted(by_bucket):
        chosen.extend(by_bucket[bucket][:limit])
    return sorted(chosen)


def dataset_commit(dataset_path: Path) -> str:
    """Pin the dataset to a commit for reproducibility. Prefers `git rev-parse`,
    falls back to a `.commit` file (written when samples are fetched via the raw
    CDN rather than checked out), else 'unknown'."""
    try:
        return subprocess.run(
            ["git", "-C", str(dataset_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pin = dataset_path / ".commit"
        if pin.is_file():
            return pin.read_text().strip()
        return "unknown"


def dataset_fingerprint(dataset_path: Path, selected: list[Path]) -> str:
    """Stable hash of the dataset commit + exact selected sample set, so a report
    is tied to reproducible inputs."""
    h = hashlib.sha256()
    h.update(dataset_commit(dataset_path).encode())
    for z in selected:
        h.update(str(z.relative_to(dataset_path)).encode())
    return h.hexdigest()


def extract_zip(zip_path: Path, dest: Path) -> bool:
    """Extract an encrypted sample. Returns False on failure (never raises so one
    bad zip doesn't abort the run). Files are only read by the static scanner —
    nothing is executed."""
    try:
        subprocess.run(
            ["unzip", "-o", "-qq", "-P", SAMPLE_UNLOCK, str(zip_path), "-d", str(dest)],
            capture_output=True, check=True, timeout=60,
        )
        return any(dest.rglob("*"))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def scan_dir(binary: str, target: Path) -> SampleResult:
    """Run the static scanner on an extracted sample and reduce to max severity."""
    try:
        proc = subprocess.run(
            [binary, "scan", str(target), "--no-cache", "--phases", DETECTION_PHASES, "--format", "json"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return SampleResult(str(target), None, 0, error="scan timeout")
    out = proc.stdout
    start = out.find("[")
    if start == -1:
        # No findings array emitted (clean) — exit 2 would be a real error.
        if proc.returncode == 2:
            return SampleResult(str(target), None, 0, error="scan error (exit 2)")
        return SampleResult(str(target), None, 0)
    try:
        decoder = json.JSONDecoder()
        findings, _ = decoder.raw_decode(out[start:])
    except json.JSONDecodeError as e:
        return SampleResult(str(target), None, 0, error=f"json parse: {e}")
    if not findings:
        return SampleResult(str(target), None, 0)
    max_sev = max(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 0))
    return SampleResult(str(target), max_sev.get("severity"), len(findings))


def evaluate_set(binary: str, zips: list[Path]) -> list[SampleResult]:
    results: list[SampleResult] = []
    total = len(zips)
    for i, z in enumerate(zips, 1):
        with tempfile.TemporaryDirectory(prefix="sigil-eval-") as tmp:
            dest = Path(tmp) / "sample"
            dest.mkdir()
            if not extract_zip(z, dest):
                results.append(SampleResult(str(z), None, 0, error="extract failed"))
            else:
                results.append(scan_dir(binary, dest))
        if i % 50 == 0 or i == total:
            print(f"  scanned {i}/{total}", file=sys.stderr)
    return results


def evaluate_control(binary: str, control_path: Path) -> list[SampleResult]:
    """Scan each immediate subdirectory of control_path as one clean package."""
    pkgs = sorted(p for p in control_path.iterdir() if p.is_dir())
    return [scan_dir(binary, p) for p in pkgs]


@dataclass
class Report:
    generated_at: str
    binary: str
    detection_phases: str
    dataset_commit: str
    dataset_fingerprint: str
    malicious_total: int
    malicious_extract_failures: int
    malicious_scan_errors: int
    recall: dict = field(default_factory=dict)
    control_total: int = 0
    control_flagged: dict = field(default_factory=dict)
    precision: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def build_report(binary: str, dataset_path: Path, fingerprint: str,
                 mal: list[SampleResult], control: list[SampleResult] | None) -> Report:
    commit = dataset_commit(dataset_path)

    extract_fail = sum(1 for r in mal if r.error == "extract failed")
    scan_err = sum(1 for r in mal if r.error and r.error != "extract failed")
    # Recall denominator = samples that were actually scanned (extracted OK).
    scannable = [r for r in mal if r.error != "extract failed"]

    recall = {}
    for t in THRESHOLDS:
        hits = sum(1 for r in scannable if r.detected_at(t))
        recall[t] = {
            "detected": hits,
            "scanned": len(scannable),
            "rate": round(hits / len(scannable), 4) if scannable else None,
        }

    report = Report(
        generated_at=datetime.now(timezone.utc).isoformat(),
        binary=binary,
        detection_phases=DETECTION_PHASES,
        dataset_commit=commit,
        dataset_fingerprint=fingerprint,
        malicious_total=len(mal),
        malicious_extract_failures=extract_fail,
        malicious_scan_errors=scan_err,
        recall=recall,
    )

    if control is not None:
        report.control_total = len(control)
        for t in THRESHOLDS:
            flagged = sum(1 for r in control if r.detected_at(t))
            report.control_flagged[t] = {
                "flagged": flagged,
                "total": len(control),
                "fp_rate": round(flagged / len(control), 4) if control else None,
            }
            tp = recall[t]["detected"]
            fp = flagged
            report.precision[t] = round(tp / (tp + fp), 4) if (tp + fp) else None
        # Honest caveats so the numbers are not misread.
        report.notes.append(
            f"PRECISION IS IMBALANCE-DISTORTED: it was computed on {len(mal)} malicious "
            f"vs {len(control)} clean samples. With far more malicious than clean inputs, "
            "precision looks high even when most clean packages are flagged. Read the "
            "FP-rate column, not precision, as the real-world false-positive signal."
        )
        worst = max(
            (report.control_flagged[t]["fp_rate"] or 0) for t in ("Medium", "High")
        )
        if worst >= 0.5:
            report.notes.append(
                f"HIGH FALSE-POSITIVE RATE: {int(worst*100)}% of clean control packages "
                "(popular, legitimate npm/PyPI) are flagged at Medium/High. The static "
                "phases over-trigger on benign idioms (network calls, base64, env reads, "
                "minified code). Recall is strong but the rule set needs FP-narrowing "
                "before these severities can gate real-world installs without noise."
            )
    else:
        report.notes.append(
            "No --control-path supplied: precision / false-positive rate NOT measured. "
            "Recall is reported alone; do not infer precision."
        )
    return report


def write_outputs(report: Report, out_dir: Path, sample_limit: int | None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "honest_detection_eval.json"
    json_path.write_text(json.dumps(report.__dict__, indent=2))

    lim = "all available" if sample_limit is None else f"{sample_limit} per ecosystem/category bucket"
    lines = [
        "# Sigil Detection Evaluation — Honest Measurement",
        "",
        f"_Generated: {report.generated_at}_",
        "",
        "## Disclosure (mandatory, per CLAUDE.md)",
        "",
        "```",
        "Data Source: Datadog malicious-software-packages-dataset (real, human-triaged "
        "malicious npm/PyPI packages) + caller-provided clean control set.",
        f"Sample Size: {report.malicious_total} malicious samples selected "
        f"({lim}); {report.control_total} clean control packages.",
        "Limitations: Dataset has selection bias (mostly GuardDog-identified, per Datadog's "
        "own disclaimer). Detection uses offline static phases only "
        f"({report.detection_phases}); OSV/provenance network feeds are excluded for "
        "reproducibility. Recall denominator excludes samples that failed to extract.",
        "```",
        "",
        f"- Dataset commit: `{report.dataset_commit}`",
        f"- Reproducibility fingerprint: `{report.dataset_fingerprint}`",
        f"- Scanner: `{report.binary}`",
        f"- Extract failures: {report.malicious_extract_failures} | scan errors: {report.malicious_scan_errors}",
        "",
        "## Recall (malicious samples detected)",
        "",
        "| Threshold | Detected | Scanned | Recall |",
        "|-----------|----------|---------|--------|",
    ]
    for t in THRESHOLDS:
        r = report.recall[t]
        rate = "n/a" if r["rate"] is None else f"{r['rate']*100:.2f}%"
        lines.append(f"| >= {t} | {r['detected']} | {r['scanned']} | {rate} |")

    if report.control_total:
        lines += [
            "",
            "## False-positive rate (clean control flagged) & precision",
            "",
            "| Threshold | Flagged | Control | FP rate | Precision |",
            "|-----------|---------|---------|---------|-----------|",
        ]
        for t in THRESHOLDS:
            c = report.control_flagged[t]
            fp = "n/a" if c["fp_rate"] is None else f"{c['fp_rate']*100:.2f}%"
            prec = report.precision.get(t)
            prec_s = "n/a" if prec is None else f"{prec*100:.2f}%"
            lines.append(f"| >= {t} | {c['flagged']} | {c['total']} | {fp} | {prec_s} |")

    if report.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in report.notes]

    lines += [
        "",
        "## Supersedes",
        "",
        "This report replaces `production_d1_d4_scorecard_80k_scans.json` (moved to "
        "`archive/` with a provenance note). That artifact claimed 80k-scan / 99%+ figures "
        "that could not be reproduced and shared the fabricated 82,415 figure from the "
        "March 14 2026 fake-eval incident. Whatever the numbers above are, they are real.",
        "",
    ]
    (out_dir / "honest_detection_eval.md").write_text("\n".join(lines))
    print(f"wrote {json_path}")
    print(f"wrote {out_dir / 'honest_detection_eval.md'}")


def archive_old_scorecard(out_dir: Path) -> None:
    old = out_dir / "production_d1_d4_scorecard_80k_scans.json"
    if not old.exists():
        return
    archive_dir = Path(__file__).resolve().parent.parent / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    dest = archive_dir / old.name
    shutil.move(str(old), str(dest))
    (archive_dir / "PROVENANCE-production_d1_d4_scorecard.md").write_text(
        "# Provenance: production_d1_d4_scorecard_80k_scans.json\n\n"
        "Archived by scripts/run_eval.py (F-008 US-G3). This scorecard claimed ~80k scans "
        "and 99%+ detection figures that could not be reproduced from any real measurement, "
        "and reused the 82,415 figure tied to the March 14 2026 fabricated-evaluation "
        "incident. It is retained here for audit history only and must NOT be cited as a "
        "result. The reproducible replacement is "
        "`evaluation_results/honest_detection_eval.{json,md}`.\n"
    )
    print(f"archived {old.name} -> archive/ with provenance note")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True, choices=["datadog"])
    ap.add_argument("--dataset-path", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--limit", type=int, default=None,
                    help="max samples per ecosystem/category bucket (deterministic). "
                         "Omit to use every available sample.")
    ap.add_argument("--control-path", type=Path, default=None,
                    help="dir whose immediate subdirs are extracted clean packages")
    args = ap.parse_args()

    binary = resolve_binary()
    dataset_path = args.dataset_path.resolve()

    all_zips = list_sample_zips(dataset_path)
    selected = select_samples(all_zips, dataset_path, args.limit)
    if not selected:
        sys.exit("error: no samples selected")
    fingerprint = dataset_fingerprint(dataset_path, selected)
    print(f"scanning {len(selected)} malicious samples "
          f"(of {len(all_zips)} available) with {binary}", file=sys.stderr)

    mal_results = evaluate_set(binary, selected)

    control_results = None
    if args.control_path:
        cp = args.control_path.resolve()
        if cp.is_dir():
            print(f"scanning clean control set under {cp}", file=sys.stderr)
            control_results = evaluate_control(binary, cp)
        else:
            print(f"warning: --control-path {cp} not a dir; skipping precision",
                  file=sys.stderr)

    report = build_report(binary, dataset_path, fingerprint, mal_results, control_results)
    archive_old_scorecard(args.out)
    write_outputs(report, args.out, args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
