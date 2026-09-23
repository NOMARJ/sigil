#!/usr/bin/env python3
"""Rule-level parity against NVIDIA SkillSpector, measured on SkillSpector's own tests.

SkillSpector's test suite is the most complete public statement of what each of
its rules is meant to catch: every test that produces a finding is an example
its authors wrote for that rule. This script turns those examples into a
corpus and asks whether Sigil flags each one.

Two steps:

``capture``
    Runs SkillSpector's analyzer tests under a small pytest plugin that records
    every finding the tests construct, with the source text that produced it,
    then de-duplicates by (rule, file, source). Needs a SkillSpector checkout and
    a Python environment where it is installed with pytest (``uv pip install -e
    <checkout> pytest pytest-asyncio``).

``run``
    Writes each sample into a scratch skill directory under its original file
    name and scans it with Sigil (``--format json --no-cache``, isolated HOME).
    A sample counts as flagged when Sigil reports a finding in that file.
    Prints a per-rule table and, with ``--out``, writes JSON and Markdown.

Read the result with care. The corpus is what SkillSpector's tests *construct*,
which includes findings its later pipeline stages filter out as false positives
(for example EA3 matching "not limited to" in a LICENSE file), test markers for
the YARA loader, and report-formatting fixtures. A rule's parity figure is
"fraction of SkillSpector's own examples Sigil also flags", not a recall figure
on malicious code. The per-rule sample lists in the JSON output make every row
checkable.

No ``random`` anywhere: samples are processed in sorted order and every number
comes from running the two tools.

Usage:
    python3 scripts/skillspector_parity.py capture \\
        --skillspector /path/to/skillspector --python /path/to/venv/bin/python \\
        --corpus parity_corpus.json
    python3 scripts/skillspector_parity.py run --corpus parity_corpus.json \\
        [--rules AR1,AR2] [--out evaluation_results/skillspector_parity]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

# pytest plugin injected into SkillSpector's test run. Records every
# AnalyzerFinding built during a test, with the file text that produced it.
CAPTURE_PLUGIN = r'''
import inspect, json, os
import pytest
from skillspector import models

OUT = os.environ["PARITY_CAPTURE_OUT"]
_current = {"test": None}
_orig = models.AnalyzerFinding.__post_init__

def _find_source(file, matched):
    fr, depth, best = inspect.currentframe(), 0, None
    while fr is not None and depth < 60:
        loc = fr.f_locals
        st = loc.get("state")
        if isinstance(st, dict) and isinstance(st.get("file_cache"), dict):
            if isinstance(st["file_cache"].get(file), str):
                return st["file_cache"][file]
        fc = loc.get("file_cache")
        if isinstance(fc, dict) and isinstance(fc.get(file), str):
            return fc[file]
        if best is None and matched:
            for v in list(loc.values()):
                if isinstance(v, str) and matched in v and len(matched) < len(v) < 300_000:
                    best = v
                    break
        fr, depth = fr.f_back, depth + 1
    return best

def _post_init(self, complete_match):
    _orig(self, complete_match)
    try:
        f = getattr(self.location, "file", None)
        rec = {"test": _current["test"], "rule_id": self.rule_id, "file": f,
               "matched": self.matched_text, "context": self.context,
               "source": _find_source(f, self.matched_text or "")}
        with open(OUT, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass

models.AnalyzerFinding.__post_init__ = _post_init

@pytest.fixture(autouse=True)
def _track(request):
    _current["test"] = request.node.nodeid
    yield
'''

TEST_TARGETS = [
    "tests/nodes/analyzers",
    "tests/unit/test_patterns.py",
    "tests/unit/test_patterns_new.py",
    "tests/test_mcp_least_privilege.py",
    "tests/test_mcp_tool_poisoning.py",
    "tests/test_mcp_rug_pull.py",
]

SEV = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def capture(args: argparse.Namespace) -> int:
    ss = args.skillspector.resolve()
    work = Path(tempfile.mkdtemp(prefix="parity-capture-"))
    (work / "parity_capture.py").write_text(CAPTURE_PLUGIN)
    raw = work / "raw.jsonl"
    env = dict(os.environ, PARITY_CAPTURE_OUT=str(raw),
               PYTHONPATH=f"{work}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
    targets = [t for t in TEST_TARGETS if (ss / t).exists()]
    cmd = [args.python, "-m", "pytest", "-p", "parity_capture", "-q", "-p", "no:cacheprovider", *targets]
    proc = subprocess.run(cmd, cwd=ss, env=env, capture_output=True, text=True)
    print(proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else proc.stderr[-2000:])
    if not raw.exists():
        sys.exit("capture produced no findings; is SkillSpector installed in --python's environment?")

    corpus: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for line in raw.read_text().splitlines():
        r = json.loads(line)
        src = r["source"] or r["context"] or r["matched"]
        if not src:
            continue
        key = hashlib.sha1(((r["file"] or "") + "\0" + src).encode()).hexdigest()
        corpus[r["rule_id"]][key] = {"file": r["file"], "source": src, "matched": r["matched"],
                                     "test": r["test"], "has_full_source": bool(r["source"])}
    head = subprocess.run(["git", "-C", str(ss), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    doc = {"skillspector_commit": head, "rules": {k: corpus[k] for k in sorted(corpus)}}
    args.corpus.write_text(json.dumps(doc))
    total = sum(len(v) for v in corpus.values())
    print(f"captured {total} unique samples across {len(corpus)} SkillSpector rule ids -> {args.corpus}")
    shutil.rmtree(work, ignore_errors=True)
    return 0


def resolve_sigil() -> str:
    env = os.environ.get("SIGIL_BIN")
    if env and Path(env).is_file():
        return env
    repo = Path(__file__).resolve().parent.parent / "cli" / "target" / "release" / "sigil"
    if repo.is_file():
        return str(repo)
    found = shutil.which("sigil")
    if not found:
        sys.exit("sigil binary not found (build cli/ or set SIGIL_BIN)")
    return found


def safe_relpath(f: str | None) -> str:
    if not f:
        return "SKILL.md"
    parts = [p for p in PurePosixPath(f.replace("\\", "/")).parts if p not in ("/", "..", ".")]
    return "/".join(parts[-3:]) or "SKILL.md"


def run(args: argparse.Namespace) -> int:
    sigil = resolve_sigil()
    doc = json.loads(args.corpus.read_text())
    rules = doc.get("rules", doc)
    only = set(args.rules.split(",")) if args.rules else None
    items = [(rid, key, s) for rid in sorted(rules) if not only or rid in only
             for key, s in sorted(rules[rid].items())]
    home = tempfile.mkdtemp(prefix="parity-home-")

    def one(item):
        rid, key, s = item
        d = Path(tempfile.mkdtemp(dir=home)) / "skill"
        rel = safe_relpath(s["file"])
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(s["source"])
        if not (d / "SKILL.md").exists():
            (d / "SKILL.md").write_text("---\nname: sample\ndescription: parity sample\n---\n# Sample\n")
        p = subprocess.run([sigil, "scan", str(d), "--format", "json", "--no-cache"],
                           capture_output=True, text=True, env=dict(os.environ, HOME=home))
        shutil.rmtree(d.parent, ignore_errors=True)
        try:
            out = json.loads(p.stdout)
        except json.JSONDecodeError:
            return {"ss_rule": rid, "key": key, "error": p.stderr[-300:]}
        base = rel.split("/")[-1]
        hits = [f for f in out.get("findings", []) if f.get("file", "").endswith(base)]
        return {"ss_rule": rid, "key": key, "file": rel,
                "sigil_max": max((SEV.get(f["severity"], 0) for f in hits), default=0),
                "sigil_rules": sorted({f["rule"] for f in hits})}

    with ThreadPoolExecutor(args.workers) as ex:
        results = list(ex.map(one, items))
    shutil.rmtree(home, ignore_errors=True)

    agg: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0, 0, 0])
    for r in results:
        a = agg[r["ss_rule"]]
        a[0] += 1
        if "error" in r:
            a[3] += 1
            continue
        a[1] += r["sigil_max"] >= 1
        a[2] += r["sigil_max"] >= 3
    lines = ["| SkillSpector rule | Samples | Sigil flags (any severity) | Sigil ≥ High |", "|---|---:|---:|---:|"]
    tot = [0, 0, 0, 0]
    for rid in sorted(agg, key=lambda x: (x.rstrip("0123456789"), int("".join(c for c in x if c.isdigit()) or 0))):
        n, anyc, high, err = agg[rid]
        tot = [t + v for t, v in zip(tot, agg[rid])]
        lines.append(f"| {rid} | {n} | {anyc} ({100*anyc/n:.0f}%) | {high} ({100*high/n:.0f}%) |")
    n, anyc, high, err = tot
    lines.append(f"| **Total** | **{n}** | **{anyc} ({100*anyc/max(n,1):.1f}%)** | **{high} ({100*high/max(n,1):.1f}%)** |")
    table = "\n".join(lines)
    print(table)
    if err:
        print(f"\n{err} samples produced no parseable Sigil report")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".json").write_text(json.dumps(
            {"skillspector_commit": doc.get("skillspector_commit"), "sigil": sigil, "results": results}, indent=1))
        header = (
            "# Rule-level parity with SkillSpector\n\n"
            "```\n"
            f"Data Source: SkillSpector's own test suite (commit {doc.get('skillspector_commit', 'unknown')}), "
            "every finding its tests construct, de-duplicated\n"
            f"Sample Size: {n} unique samples across {len(agg)} SkillSpector rule ids\n"
            "Limitations: includes findings SkillSpector's later stages filter as false positives and\n"
            "             test-only markers; a row measures agreement with SkillSpector's examples,\n"
            "             not recall on malicious code.\n"
            "```\n\n"
        )
        args.out.with_suffix(".md").write_text(header + table + "\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--skillspector", type=Path, required=True)
    c.add_argument("--python", default=sys.executable)
    c.add_argument("--corpus", type=Path, required=True)
    r = sub.add_parser("run")
    r.add_argument("--corpus", type=Path, required=True)
    r.add_argument("--rules", default="")
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--out", type=Path)
    args = ap.parse_args()
    return capture(args) if args.cmd == "capture" else run(args)


if __name__ == "__main__":
    sys.exit(main())
