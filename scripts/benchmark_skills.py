#!/usr/bin/env python3
"""Head-to-head skill-scanner benchmark: Sigil against other static skill scanners.

Every number this script prints comes from running each scanner on real input.
There is no ``random`` and no simulated measurement. Samples are enumerated in
sorted order, so a second run over the same corpus commits gives the same set.

What it measures
----------------
For every labelled sample (a skill directory), each scanner's verdict is mapped
onto a shared four-level scale, then:

* **Block** — the verdict a CI or install gate refuses: Sigil ``HIGH RISK`` /
  ``CRITICAL RISK``; SkillSpector recommendation ``DO_NOT_INSTALL`` (severity
  HIGH or CRITICAL).
* **Warn** — Block, plus Sigil ``MEDIUM RISK``; SkillSpector ``CAUTION``.

Detection rate = malicious samples reaching the level / malicious scanned.
False-positive rate = clean samples reaching the level / clean scanned.

Corpora
-------
Pass one or more ``--malicious DIR`` and ``--clean DIR`` roots. A sample is
every directory under a root that contains a ``SKILL.md`` (the directory
itself is scanned), or, with ``--sample-depth N``, every directory exactly N
levels below the root (use this for datasets whose samples are not all
``SKILL.md`` skills).

Scanners
--------
* ``sigil`` — the repo's release build (``$SIGIL_BIN`` overrides), run with an
  isolated ``HOME`` and ``--no-cache`` so no ledger approval or cache hit can
  hide a finding.
* ``skillspector`` — ``skillspector scan <dir> --no-llm --format json`` from
  ``$SKILLSPECTOR_BIN`` or ``PATH``. Static-only on purpose: Sigil's numbers are
  static-only too, and an LLM pass is not reproducible run to run.

Usage
-----
    python3 scripts/benchmark_skills.py \\
        --malicious /data/datadog/ai-skills --sample-depth 2 \\
        --clean /data/anthropics_skills --clean /data/NVIDIA_skills \\
        --tools sigil,skillspector --out evaluation_results/skills_benchmark
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

LEVELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {name: i for i, name in enumerate(LEVELS)}


@dataclass
class Outcome:
    sample: str
    label: str  # "malicious" | "clean"
    corpus: str
    tool: str
    level: str = "NONE"
    findings: int = 0
    rules: list[str] = field(default_factory=list)
    seconds: float = 0.0
    error: str | None = None


def resolve_sigil() -> str | None:
    env = os.environ.get("SIGIL_BIN")
    if env and Path(env).is_file():
        return env
    repo = Path(__file__).resolve().parent.parent / "cli" / "target" / "release" / "sigil"
    if repo.is_file():
        return str(repo)
    return shutil.which("sigil")


def resolve_skillspector() -> str | None:
    env = os.environ.get("SKILLSPECTOR_BIN")
    if env and Path(env).is_file():
        return env
    return shutil.which("skillspector")


def discover(root: Path, depth: int | None) -> list[Path]:
    if depth is not None:
        out = [root]
        for _ in range(depth):
            out = sorted(c for p in out for c in p.iterdir() if c.is_dir())
        return out
    # Hidden directories are NOT skipped: catalogs such as openai/skills keep
    # their skills under `.curated/` and `.system/`. Only VCS and dependency
    # trees are, since a SKILL.md inside them is not a published skill.
    skip = {".git", "node_modules"}
    found: set[Path] = set()
    for skill_md in root.rglob("SKILL.md"):
        if any(part in skip for part in skill_md.relative_to(root).parts[:-1]):
            continue
        found.add(skill_md.parent)
    return sorted(found)


def run_sigil(binary: str, sample: Path, home: str, timeout: int) -> tuple[str, int, list[str], str | None]:
    env = dict(os.environ, HOME=home, SIGIL_NO_TELEMETRY="1")
    proc = subprocess.run(
        [binary, "scan", str(sample), "--format", "json", "--no-cache"],
        capture_output=True, text=True, timeout=timeout, env=env,
    )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return "NONE", 0, [], f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"
    verdict = (doc.get("summary", {}).get("verdict") or doc.get("verdict") or "").upper()
    level = next((lv for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if verdict.startswith(lv)), "NONE")
    findings = doc.get("findings", [])
    if level == "LOW" and not findings:
        level = "NONE"
    return level, len(findings), sorted({f.get("rule", "") for f in findings}), None


def run_skillspector(binary: str, sample: Path, home: str, timeout: int) -> tuple[str, int, list[str], str | None]:
    env = dict(os.environ, HOME=home)
    proc = subprocess.run(
        [binary, "scan", str(sample), "--no-llm", "--format", "json"],
        capture_output=True, text=True, timeout=timeout, env=env,
    )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return "NONE", 0, [], f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"
    issues = doc.get("issues", [])
    sev = (doc.get("risk_assessment", {}).get("severity") or "LOW").upper()
    level = sev if sev in RANK else "NONE"
    if level == "LOW" and not issues:
        level = "NONE"
    return level, len(issues), sorted({i.get("id") or i.get("rule_id") or "" for i in issues}), None


RUNNERS = {"sigil": (resolve_sigil, run_sigil), "skillspector": (resolve_skillspector, run_skillspector)}


def rate(n: int, d: int) -> str:
    return f"{(100.0 * n / d):.1f}%" if d else "n/a"


def summarise(outcomes: list[Outcome], tools: list[str]) -> dict:
    summary: dict = {}
    for tool in tools:
        rows = [o for o in outcomes if o.tool == tool and o.error is None]
        errs = [o for o in outcomes if o.tool == tool and o.error is not None]
        per: dict = {"errors": len(errs)}
        for label in ("malicious", "clean"):
            sel = [o for o in rows if o.label == label]
            per[label] = {
                "scanned": len(sel),
                "block": sum(RANK[o.level] >= RANK["HIGH"] for o in sel),
                "warn": sum(RANK[o.level] >= RANK["MEDIUM"] for o in sel),
                "any": sum(RANK[o.level] >= RANK["LOW"] for o in sel),
                "seconds": round(sum(o.seconds for o in sel), 1),
            }
        summary[tool] = per
    return summary


def render_markdown(summary: dict, outcomes: list[Outcome], args, corpora: dict) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    mal = sum(v for k, v in corpora.items() if k.startswith("malicious:"))
    cln = sum(v for k, v in corpora.items() if k.startswith("clean:"))
    lines = [
        "# Skill scanner head-to-head",
        "",
        f"_Generated {now} by `scripts/benchmark_skills.py`._",
        "",
        "```",
        "Data Source: Real samples. Malicious: " + ", ".join(k.split(":", 1)[1] for k in corpora if k.startswith("malicious:")),
        "             Clean: " + ", ".join(k.split(":", 1)[1] for k in corpora if k.startswith("clean:")),
        f"Sample Size: {mal} malicious, {cln} clean (per-corpus counts below)",
        "Limitations: Static analysis only for every tool (SkillSpector --no-llm, Sigil offline",
        "             phases). 'Clean' means published by a reputable vendor catalog, not audited;",
        "             a vendor skill that legitimately shells out or reads credentials can be a",
        "             correct finding, so the FP column is an upper bound on true false positives.",
        "```",
        "",
        "| Corpus | Samples |",
        "|---|---:|",
    ]
    lines += [f"| {k} | {v} |" for k, v in corpora.items()]
    lines += [
        "",
        "## Results",
        "",
        "| Tool | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Clean blocked (FP) | Clean warned (FP) | Errors | Scan time |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for tool, per in summary.items():
        m, c = per["malicious"], per["clean"]
        lines.append(
            f"| {tool} | {m['block']}/{m['scanned']} ({rate(m['block'], m['scanned'])}) "
            f"| {m['warn']}/{m['scanned']} ({rate(m['warn'], m['scanned'])}) "
            f"| {c['block']}/{c['scanned']} ({rate(c['block'], c['scanned'])}) "
            f"| {c['warn']}/{c['scanned']} ({rate(c['warn'], c['scanned'])}) "
            f"| {per['errors']} | {m['seconds'] + c['seconds']:.0f}s |"
        )
    tools = list(summary)
    if len(tools) == 2:
        a, b = tools
        by = {(o.sample, o.tool): o for o in outcomes if o.error is None}
        samples = sorted({o.sample for o in outcomes})
        label_of = {o.sample: o.label for o in outcomes}
        only_a = [s for s in samples if label_of[s] == "malicious" and (s, a) in by and (s, b) in by
                  and RANK[by[(s, a)].level] >= RANK["HIGH"] > RANK[by[(s, b)].level]]
        only_b = [s for s in samples if label_of[s] == "malicious" and (s, a) in by and (s, b) in by
                  and RANK[by[(s, b)].level] >= RANK["HIGH"] > RANK[by[(s, a)].level]]
        lines += [
            "",
            f"## Malicious samples one tool blocks and the other does not",
            "",
            f"- blocked by {a} only: {len(only_a)}",
            f"- blocked by {b} only: {len(only_b)}",
        ]
        for s in only_b:
            lines.append(f"  - `{s}` — {b}: {by[(s, b)].level} {by[(s, b)].rules[:6]}; {a}: {by[(s, a)].level}")
    lines += ["", "## Clean samples blocked", ""]
    for o in outcomes:
        if o.label == "clean" and o.error is None and RANK[o.level] >= RANK["HIGH"]:
            lines.append(f"- {o.tool}: `{o.sample}` — {o.level} {o.rules[:8]}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--malicious", action="append", default=[], type=Path)
    ap.add_argument("--clean", action="append", default=[], type=Path)
    ap.add_argument("--sample-depth", type=int, default=None,
                    help="treat directories exactly N levels below each --malicious root as samples")
    ap.add_argument("--tools", default="sigil,skillspector")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out", type=Path, default=None, help="write <out>.json and <out>.md")
    args = ap.parse_args()

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    binaries = {}
    for tool in tools:
        if tool not in RUNNERS:
            sys.exit(f"unknown tool {tool!r}; choose from {sorted(RUNNERS)}")
        binary = RUNNERS[tool][0]()
        if binary is None:
            sys.exit(f"{tool} binary not found")
        binaries[tool] = binary

    work: list[tuple[Path, str, str]] = []
    corpora: dict[str, int] = {}
    for label, roots, depth in (("malicious", args.malicious, args.sample_depth), ("clean", args.clean, None)):
        for root in roots:
            samples = discover(root.resolve(), depth)
            corpora[f"{label}:{root.name}"] = len(samples)
            work += [(s, label, root.name) for s in samples]

    home = tempfile.mkdtemp(prefix="skills-bench-home-")
    jobs = [(s, label, corpus, tool) for (s, label, corpus) in work for tool in tools]

    def run(job):
        sample, label, corpus, tool = job
        o = Outcome(sample=str(sample), label=label, corpus=corpus, tool=tool)
        t0 = time.monotonic()
        try:
            o.level, o.findings, o.rules, o.error = RUNNERS[tool][1](binaries[tool], sample, home, args.timeout)
        except subprocess.TimeoutExpired:
            o.error = "timeout"
        o.seconds = round(time.monotonic() - t0, 2)
        return o

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        outcomes = list(pool.map(run, jobs))
    shutil.rmtree(home, ignore_errors=True)

    summary = summarise(outcomes, tools)
    report = render_markdown(summary, outcomes, args, corpora)
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".json").write_text(json.dumps(
            {"summary": summary, "corpora": corpora, "outcomes": [asdict(o) for o in outcomes]}, indent=1))
        args.out.with_suffix(".md").write_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
