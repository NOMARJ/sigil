#!/usr/bin/env python3
"""Honest FP-adjudication eval on the F-008 corpus (F-009 US-110).

Measures what LLM adjudication (FPAdjudicator, claude-fable-5 with the
claude-opus-4-8 refusal fallback) actually does to the F-008 detector
metrics, in both directions:

  Direction 1 (the win we want):   how many High+ findings on KNOWN-CLEAN
                                   popular packages does adjudication clear
                                   as benign_dual_use?
  Direction 2 (the damage we fear): how many High+ findings on KNOWN-MALICIOUS
                                   samples does adjudication wrongly clear?

Integrity rules (CHARTER II / CLAUDE.md):
  * NO `random` — sample selection is deterministic (sorted, fixed caps).
  * Every verdict is a real claude-fable-5 API response; nothing simulated.
  * Refusals and errors are counted and reported; a refusal is NOT a verdict
    and leaves the finding flagged (conservative).
  * Findings beyond the per-target cap stay flagged (conservative: caps can
    only understate adjudication's benefit, never overstate it).
  * Token usage figures are estimates (~4 chars/token) — the raw HTTP path
    does not surface the API usage object; they are labelled as estimates.

Usage:
    ANTHROPIC_API_KEY=... python3 scripts/eval_fp_adjudication.py \
        --control-path /tmp/control2 \
        --malicious-path /tmp/evalset/samples \
        --out evidence/F-009 \
        [--max-findings-per-control 10] [--malicious-samples 25] \
        [--max-findings-per-malicious 5] [--concurrency 4]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "api"))

# Same offline deterministic phases as the F-008 eval (scripts/run_eval.py).
DETECTION_PHASES = "install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection"
SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CONTEXT_LINES = 30  # lines of code context either side of the finding

# Public, documented unlock phrase for the Datadog sample archives (their
# README publishes it) — the malware-sharing convention so AV doesn't
# auto-quarantine the zips. Same as scripts/run_eval.py. Nothing is executed.
SAMPLE_UNLOCK = "infected"


def extract_sample(zip_path: Path, dest: Path) -> bool:
    """Extract one encrypted sample zip for static scanning only."""
    try:
        subprocess.run(
            ["unzip", "-o", "-qq", "-P", SAMPLE_UNLOCK, str(zip_path), "-d", str(dest)],
            capture_output=True, check=True, timeout=60,
        )
        return any(dest.rglob("*"))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def resolve_binary() -> str:
    """$SIGIL_BIN, then the repo release build — PATH last (F-008 stale-binary
    hazard: a system sigil silently measures the wrong code)."""
    env = os.environ.get("SIGIL_BIN")
    if env and Path(env).is_file():
        return env
    repo_default = REPO / "cli" / "target" / "release" / "sigil"
    if repo_default.is_file():
        return str(repo_default)
    import shutil

    on_path = shutil.which("sigil")
    if on_path:
        return on_path
    sys.exit("no sigil binary found (set SIGIL_BIN)")


def scan_high_findings(binary: str, target: Path) -> tuple[list[dict], str | None]:
    """Scan one directory; return (High+ findings sorted deterministically, error)."""
    try:
        proc = subprocess.run(
            [binary, "scan", str(target), "--no-cache", "--ignore-ledger",
             "--phases", DETECTION_PHASES, "--format", "json"],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return [], "scan timeout"
    out = proc.stdout
    start = out.find("[")
    if start == -1:
        return ([], "scan error (exit 2)") if proc.returncode == 2 else ([], None)
    try:
        findings, _ = json.JSONDecoder().raw_decode(out[start:])
    except json.JSONDecodeError as e:
        return [], f"json parse: {e}"
    high = [f for f in findings if SEVERITY_ORDER.get(f.get("severity"), 0) >= 3]
    # Deterministic order: severity desc, then file, then line.
    high.sort(key=lambda f: (-SEVERITY_ORDER.get(f.get("severity"), 0),
                             f.get("file", ""), f.get("line", 0)))
    return high, None


def code_context(target: Path, finding: dict) -> str:
    """±CONTEXT_LINES of real file content around the finding."""
    rel = finding.get("file", "")
    path = target / rel
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return finding.get("snippet", "")
    lines = text.splitlines()
    line_no = max(int(finding.get("line", 1)), 1)
    lo = max(0, line_no - 1 - CONTEXT_LINES)
    hi = min(len(lines), line_no + CONTEXT_LINES)
    return "\n".join(lines[lo:hi])


async def adjudicate_all(jobs: list[dict], concurrency: int) -> None:
    """Adjudicate each job in-place: job['verdict'] | job['refusal'] | job['error']."""
    from api.services.fp_adjudicator import fp_adjudicator
    from api.services.llm_service import LLMRefusalError

    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(job: dict) -> None:
        nonlocal done
        async with sem:
            try:
                verdict = await fp_adjudicator.adjudicate(job["finding"], job["context"])
                job["verdict"] = verdict
            except LLMRefusalError as e:
                job["refusal"] = {"model": e.model, "category": e.category}
            except Exception as e:  # contract violations, network — keep going
                job["error"] = str(e)[:300]
            done += 1
            if done % 10 == 0 or done == len(jobs):
                print(f"  adjudicated {done}/{len(jobs)}", flush=True)

    await asyncio.gather(*(one(j) for j in jobs))


def is_cleared(job: dict) -> bool:
    """A finding is cleared ONLY by an explicit benign_dual_use verdict."""
    v = job.get("verdict")
    return bool(v) and v.get("classification") == "benign_dual_use"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-path", type=Path, default=Path("/tmp/control2"))
    ap.add_argument("--malicious-path", type=Path, default=Path("/tmp/evalset/samples"))
    ap.add_argument("--out", type=Path, default=REPO / "evidence" / "F-009")
    ap.add_argument("--max-findings-per-control", type=int, default=10)
    ap.add_argument("--malicious-samples", type=int, default=25)
    ap.add_argument("--max-findings-per-malicious", type=int, default=5)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument(
        "--reuse-control", type=Path, default=None,
        help="Path to a previous eval JSON; reuse its control section verbatim "
             "(real, already-paid verdicts) and run only the malicious pass.",
    )
    args = ap.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("LLM_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY not set — this eval makes real API calls only")

    binary = resolve_binary()
    print(f"scanner: {binary}")

    # ---- Control pass (direction 1) ----------------------------------------
    reused_control = None
    if args.reuse_control:
        prev = json.loads(args.reuse_control.read_text())
        reused_control = prev["control"]
        control_targets = []
        control = []
        print(f"reusing control section from {args.reuse_control} "
              f"({reused_control['finding_level']['adjudicated']} real verdicts)")
    else:
        control_targets = sorted(p for p in args.control_path.iterdir() if p.is_dir())
        print(f"control packages: {len(control_targets)}")
        control = []
        for pkg in control_targets:
            high, err = scan_high_findings(binary, pkg)
            entry = {
                "name": pkg.name, "high_total": len(high), "scan_error": err,
                "jobs": [
                    {"target": pkg.name, "finding": f, "context": code_context(pkg, f)}
                    for f in high[: args.max_findings_per_control]
                ],
            }
            entry["capped"] = len(high) > args.max_findings_per_control
            control.append(entry)
            print(f"  {pkg.name}: high+={len(high)} adjudicating={len(entry['jobs'])}"
                  + (" (CAPPED)" if entry["capped"] else ""))

    # ---- Malicious pass (direction 2) --------------------------------------
    # Samples are the Datadog dataset's encrypted zips (same as the F-008 eval):
    # extract each to a temp dir, scan, build contexts from the extracted files,
    # then remove the extraction. Deterministic order: sorted zip paths.
    sample_zips = sorted(args.malicious_path.rglob("*.zip"))
    print(f"malicious sample zips available: {len(sample_zips)}")
    malicious: list[dict] = []
    scanned = 0
    extract_failures = 0
    for zip_path in sample_zips:
        if len(malicious) >= args.malicious_samples:
            break
        with tempfile.TemporaryDirectory(prefix="sigil-fp-eval-") as tmp:
            dest = Path(tmp)
            if not extract_sample(zip_path, dest):
                extract_failures += 1
                continue
            high, err = scan_high_findings(binary, dest)
            scanned += 1
            if err or not high:
                continue  # only samples DETECTED at >=High are in scope
            malicious.append({
                "name": str(zip_path.relative_to(args.malicious_path)),
                "high_total": len(high), "scan_error": None,
                "jobs": [
                    {"target": str(zip_path), "finding": f,
                     "context": code_context(dest, f)}
                    for f in high[: args.max_findings_per_malicious]
                ],
                "capped": len(high) > args.max_findings_per_malicious,
            })
    print(f"malicious: scanned {scanned} samples ({extract_failures} extract failures), "
          f"selected {len(malicious)} detected at >=High")

    # ---- Adjudicate (real API calls) ----------------------------------------
    all_jobs = [j for e in control + malicious for j in e["jobs"]]
    print(f"adjudicating {len(all_jobs)} findings via claude-fable-5 "
          f"(concurrency {args.concurrency}) — real API calls")
    asyncio.run(adjudicate_all(all_jobs, args.concurrency))

    # ---- Metrics -------------------------------------------------------------
    def classify_counts(entries: list[dict]) -> dict:
        c = {"benign_dual_use": 0, "suspicious": 0, "malicious": 0,
             "refused": 0, "error": 0, "adjudicated": 0}
        for e in entries:
            for j in e["jobs"]:
                c["adjudicated"] += 1
                if "verdict" in j:
                    c[j["verdict"]["classification"]] += 1
                elif "refusal" in j:
                    c["refused"] += 1
                else:
                    c["error"] += 1
        return c

    def package_level(entries: list[dict]) -> dict:
        """before = >=1 High+ finding; after = >=1 finding NOT cleared
        (uncapped-only packages can fully clear)."""
        before = sum(1 for e in entries if e["high_total"] > 0)
        after = 0
        cleared_names = []
        for e in entries:
            if e["high_total"] == 0:
                continue
            uncleared = e["capped"] or any(not is_cleared(j) for j in e["jobs"])
            if uncleared:
                after += 1
            else:
                cleared_names.append(e["name"])
        return {"flagged_before": before, "flagged_after": after,
                "fully_cleared": cleared_names}

    malicious_counts = classify_counts(malicious)
    malicious_pkg = package_level(malicious)
    if reused_control is not None:
        control_counts = reused_control["finding_level"]
        control_pkg = reused_control["package_level"]
    else:
        control_counts = classify_counts(control)
        control_pkg = package_level(control)

    usage_in = sum(j["verdict"].get("_usage", {}).get("input_tokens_est", 0)
                   for j in all_jobs if "verdict" in j)
    usage_out = sum(j["verdict"].get("_usage", {}).get("output_tokens_est", 0)
                    for j in all_jobs if "verdict" in j)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary": binary,
        "detection_phases": DETECTION_PHASES,
        "models": {"deep": "claude-fable-5", "fallback": "claude-opus-4-8"},
        "caps": {
            "max_findings_per_control": args.max_findings_per_control,
            "malicious_samples": args.malicious_samples,
            "max_findings_per_malicious": args.max_findings_per_malicious,
        },
        "control": reused_control if reused_control is not None else {
            "packages": len(control_targets),
            "high_findings_total": sum(e["high_total"] for e in control),
            "finding_level": control_counts,
            "package_level": control_pkg,
            "detail": [{k: e[k] for k in ("name", "high_total", "capped")}
                       | {"verdicts": [
                           {"file": j["finding"].get("file"),
                            "line": j["finding"].get("line"),
                            "rule": j["finding"].get("rule"),
                            "severity": j["finding"].get("severity"),
                            **({"classification": j["verdict"]["classification"],
                                "confidence": j["verdict"]["confidence"],
                                "rationale": j["verdict"]["rationale"]}
                               if "verdict" in j else
                               {"refusal": j.get("refusal"), "error": j.get("error")})}
                           for j in e["jobs"]]}
                       for e in control],
        },
        "malicious": {
            "dirs_scanned": scanned,
            "samples_selected": len(malicious),
            "finding_level": malicious_counts,
            "sample_level": malicious_pkg,
            "detail": [{k: e[k] for k in ("name", "high_total", "capped")}
                       | {"verdicts": [
                           {"file": j["finding"].get("file"),
                            "line": j["finding"].get("line"),
                            "rule": j["finding"].get("rule"),
                            "severity": j["finding"].get("severity"),
                            **({"classification": j["verdict"]["classification"],
                                "confidence": j["verdict"]["confidence"],
                                "rationale": j["verdict"]["rationale"]}
                               if "verdict" in j else
                               {"refusal": j.get("refusal"), "error": j.get("error")})}
                           for j in e["jobs"]]}
                       for e in malicious],
        },
        "token_usage_estimated": {"input": usage_in, "output_visible": usage_out,
                                  "note": "~4 chars/token estimates; thinking tokens not visible"},
    }

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "fp-adjudication-eval.json"
    json_path.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {json_path}")
    print(json.dumps({
        "control_finding_level": control_counts,
        "control_package_level": control_pkg,
        "malicious_finding_level": malicious_counts,
        "malicious_sample_level": malicious_pkg,
    }, indent=2))


if __name__ == "__main__":
    main()
