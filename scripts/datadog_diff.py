#!/usr/bin/env python3
"""Per-sample Datadog comparison of two or more Sigil builds.

`run_eval.py` reports recall; this reports *which samples changed* between
builds, and how: the max severity `run_eval.scan_dir` reduces a scan to, the
verdict, and every correlation-chain finding (rule, file, line), in both
directions. It is built on run_eval.py's own functions, so the sample set and
the scan are the ones the recall figures come from:

* selection: ``run_eval.list_sample_zips`` + ``run_eval.select_samples``
  (``--limit`` per bucket), fingerprinted with ``run_eval.dataset_fingerprint``;
* extraction: ``run_eval.extract_zip``, once per sample into
  ``<work>/<i>/sample`` so every build scans identical bytes. Each slot
  records the archive it came from (path and sha256, ``<work>/<i>/source.json``);
  a slot that does not match the selected archive, or has no record (an
  extraction that did not finish), is cleared and extracted again;
* scan: ``run_eval.scan_dir`` unchanged (same command, phases, timeout and
  reduction). Its stdout is captured on the side for the verdict and chains.

There is no ``random`` and nothing simulated: every row is a real scan.

Usage
-----
    python3 scripts/datadog_diff.py \\
        --dataset-path /path/to/malicious-software-packages-dataset --limit 204 \\
        --work /tmp/dd-work --expect-fingerprint 63fcde5b... \\
        --build before=/path/to/sigil-a --build after=/path/to/sigil-b \\
        --out evaluation_results/some_change/datadog
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_eval  # noqa: E402

SEV = {None: 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
# A file whose analysis ran past the per-file time budget is reported with
# this finding and analysed only partly. How far the analysis got depends on
# machine load, so a change on such a sample may be timing, not the build:
# every change says whether either side hit the budget.
BUDGET_RULE = "PROV-BUDGET-001"
# A chain's snippet ends with the sink line's text, which in a malicious sample
# is the malware's own URL or command. Only the link is kept ("CRED-ENV-001
# (@L6) reaches NET-007 (@L8) via encoded (@L7)"), so the report can be
# committed without the repository's self-scan reading it as malware.
LINK = re.compile(r"\S+ \(@L\d+\) reaches \S+ \(@L\d+\)(?: via \S+ \(@L\d+\))?")


def link_of(snippet: str) -> str:
    m = LINK.search(snippet)
    return m.group(0) if m else snippet.split(": ", 1)[0]

_run = subprocess.run
_captured = threading.local()


def _capturing_run(*args, **kwargs):
    proc = _run(*args, **kwargs)
    _captured.stdout = proc.stdout
    return proc


def scan(binary: str, sample: dict) -> dict:
    _captured.stdout = ""
    res = run_eval.scan_dir(binary, Path(sample["dir"]))
    verdict, rules, chains = None, [], []
    try:
        doc = json.loads(_captured.stdout or "")
        verdict = doc.get("summary", {}).get("verdict")
        found = doc.get("findings", [])
        rules = sorted({f.get("rule", "") for f in found})
        chains = sorted(
            [f["rule"], f.get("file", ""), f.get("line"), link_of(f.get("snippet", ""))]
            for f in found if "-CHAIN-" in f.get("rule", "")
        )
    except json.JSONDecodeError:
        pass
    return {"i": sample["i"], "zip": sample["zip"], "max_severity": res.max_severity,
            "finding_count": res.finding_count, "error": res.error, "verdict": verdict,
            "rules": rules, "chains": chains}


def detected(row: dict, threshold: str) -> bool:
    if row["max_severity"] is None:
        return False
    if threshold == "any":
        return row["finding_count"] > 0
    return SEV[row["max_severity"]] >= SEV[threshold]


def diff(before: list[dict], after: list[dict]) -> dict:
    out: dict = {"recall": {}, "severity": [], "verdict": [], "chains": []}
    for t in run_eval.THRESHOLDS:
        out["recall"][t] = [sum(detected(r, t) for r in before), sum(detected(r, t) for r in after)]
    for a, b in zip(before, after):
        budget = [BUDGET_RULE in a["rules"], BUDGET_RULE in b["rules"]]
        if a["max_severity"] != b["max_severity"]:
            out["severity"].append([a["zip"], a["max_severity"], b["max_severity"], budget])
        if a["verdict"] != b["verdict"]:
            out["verdict"].append([a["zip"], a["verdict"], b["verdict"], budget])
        # Whole records, counted: another source or path to the same sink is
        # a change, and so is a second link where there was one.
        ca = Counter(tuple(c) for c in a["chains"])
        cb = Counter(tuple(c) for c in b["chains"])
        lost = [list(c) for c in sorted((ca - cb).elements(), key=repr)]
        gained = [list(c) for c in sorted((cb - ca).elements(), key=repr)]
        if lost or gained:
            out["chains"].append({"zip": a["zip"], "budget_expired": budget, "lost": lost, "gained": gained})
    return out


def prepare(i: int, zip_path: Path, ds: Path, work: Path) -> str:
    """Extract one selected archive into its slot, or reuse the slot when
    its record names this archive with these bytes."""
    slot = work / f"{i:04d}"
    dest = slot / "sample"
    record = slot / "source.json"
    source = {"zip": str(zip_path.relative_to(ds)),
              "sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest()}
    try:
        if json.loads(record.read_text()) == source and dest.is_dir():
            return str(dest)
    except (OSError, json.JSONDecodeError):
        pass
    if slot.exists():
        shutil.rmtree(slot)
    dest.mkdir(parents=True)
    if not run_eval.extract_zip(zip_path, dest):
        sys.exit(f"error: extract failed: {zip_path}")
    record.write_text(json.dumps(source))
    return str(dest)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset-path", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=204)
    ap.add_argument("--work", type=Path, required=True,
                    help="extraction directory, reused slot by slot when the archive matches")
    ap.add_argument("--build", action="append", required=True, help="label=/path/to/sigil (two or more)")
    ap.add_argument("--expect-fingerprint", default=None)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", type=Path, required=True, help="write <out>.json")
    args = ap.parse_args()
    builds = [b.split("=", 1) for b in args.build]
    if len(builds) < 2 or any(len(b) != 2 for b in builds):
        sys.exit("error: pass --build label=path at least twice")

    ds = args.dataset_path
    selected = run_eval.select_samples(run_eval.list_sample_zips(ds), ds, args.limit)
    fingerprint = run_eval.dataset_fingerprint(ds, selected)
    if args.expect_fingerprint and fingerprint != args.expect_fingerprint:
        sys.exit(f"error: fingerprint {fingerprint} != expected {args.expect_fingerprint}")

    samples = [{"i": i, "zip": str(z.relative_to(ds)), "dir": prepare(i, z, ds, args.work)}
               for i, z in enumerate(selected)]

    run_eval.subprocess.run = _capturing_run
    rows: dict[str, list[dict]] = {}
    for label, binary in builds:
        with ThreadPoolExecutor(args.workers) as ex:
            rows[label] = list(ex.map(lambda s, b=binary: scan(b, s), samples))
        errors = sum(r["error"] is not None for r in rows[label])
        print(f"{label}: scanned {len(samples)}, errors {errors}", file=sys.stderr)

    labels = [label for label, _ in builds]
    report = {
        "dataset_commit": run_eval.dataset_commit(ds),
        "fingerprint": fingerprint,
        "limit": args.limit,
        "phases": run_eval.DETECTION_PHASES,
        "builds": dict(builds),
        "diffs": {f"{a}->{b}": diff(rows[a], rows[b]) for a, b in zip(labels, labels[1:])},
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    Path(f"{args.out}.json").write_text(json.dumps(report, indent=1))
    for name, d in report["diffs"].items():
        timing = sum(any(c["budget_expired"]) for c in d["chains"])
        print(f"{name}: recall {d['recall']}; severity changes {len(d['severity'])}; "
              f"verdict changes {len(d['verdict'])}; samples with a chain change {len(d['chains'])} "
              f"({timing} on a sample that hit the time budget)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
