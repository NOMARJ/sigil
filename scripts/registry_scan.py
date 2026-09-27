#!/usr/bin/env python3
"""Scan a sample of the official MCP registry with Sigil and aggregate the
results. Every number the report cites comes from these scans; nothing is
sampled at random and nothing is simulated.

Method:
  1. Page through https://registry.modelcontextprotocol.io/v0/servers and keep
     the servers that ship an npm package (registryType == "npm"), newest
     listing per name, until --count unique npm packages are collected.
  2. For each, run `sigil npm <package> --version <v> --format json`: the
     package is downloaded into quarantine (SIGIL_QUARANTINE_DIR) and scanned
     exactly as a user would. The quarantine is kept so the same extracted
     packages can be re-scanned with a later binary (--rescan).
  3. Aggregate grades, verdicts, behaviours, rule frequencies and install-time
     execution into <out>/aggregate.json. Per-package results stay in
     <out>/scans/ and are not part of the published report.

Usage:
    python3 scripts/registry_scan.py --out registry-scan --count 100
    python3 scripts/registry_scan.py --out registry-scan --rescan  # same packages, current binary
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
UA = "sigil-registry-scan/1.0 (+https://github.com/NOMARJ/sigil)"


def get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_npm_servers(count: int, log) -> list[dict]:
    """Newest listing per server name that ships an npm package."""
    seen: dict[str, dict] = {}
    cursor = None
    pages = 0
    while len(seen) < count and pages < 200:
        url = REGISTRY + "?limit=100" + (f"&cursor={urllib.parse.quote(cursor)}" if cursor else "")
        d = get_json(url)
        pages += 1
        for entry in d.get("servers", []):
            s = entry.get("server", {})
            meta = entry.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
            if meta.get("status") not in (None, "active"):
                continue
            for pkg in s.get("packages", []) or []:
                if pkg.get("registryType") != "npm":
                    continue
                ident = pkg.get("identifier")
                if not ident:
                    continue
                key = s.get("name") or ident
                if key in seen and not meta.get("isLatest", True):
                    continue
                seen[key] = {"server": s.get("name"), "title": s.get("title"), "npm": ident,
                             "version": pkg.get("version"), "published": meta.get("publishedAt")}
                break
        cursor = (d.get("metadata") or {}).get("nextCursor") or (d.get("metadata") or {}).get("next_cursor")
        if not cursor:
            break
        log(f"  registry page {pages}: {len(seen)} npm servers so far")
    items = list(seen.values())[:count]
    return items


def resolve_binary() -> str:
    env = os.environ.get("SIGIL_BIN")
    if env and Path(env).is_file():
        return env
    repo = Path(__file__).resolve().parent.parent / "cli" / "target" / "release" / "sigil"
    if repo.is_file():
        return str(repo)
    found = shutil.which("sigil")
    if found:
        return found
    sys.exit("error: sigil binary not found; set SIGIL_BIN")


def parse_document(stdout: str) -> dict | None:
    start = stdout.find("{")
    if start == -1:
        return None
    try:
        return json.loads(stdout[start:])
    except json.JSONDecodeError:
        return None


def scan_npm(binary: str, item: dict, quarantine: Path, timeout: int, log) -> dict:
    spec = item["npm"] + (f"@{item['version']}" if item.get("version") else "")
    args = [binary, "--format", "json", "npm", item["npm"]]
    if item.get("version"):
        args += ["--version", item["version"]]
    env = {**os.environ, "SIGIL_QUARANTINE_DIR": str(quarantine)}
    t0 = time.time()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"npm": spec, "error": f"timeout after {timeout}s", "secs": round(time.time() - t0, 1)}
    doc = parse_document(proc.stdout)
    if doc is None:
        return {"npm": spec, "error": (proc.stderr.strip().splitlines() or ["no JSON"])[-1][:200], "exit": proc.returncode, "secs": round(time.time() - t0, 1)}
    return {"npm": spec, "exit": proc.returncode, "secs": round(time.time() - t0, 1), "document": doc}


def scan_dir(binary: str, path: Path, timeout: int) -> dict | None:
    proc = subprocess.run([binary, "--format", "json", "scan", str(path), "--no-cache"], capture_output=True, text=True, timeout=timeout)
    return parse_document(proc.stdout)


def aggregate(results: list[dict]) -> dict:
    grades = collections.Counter(); verdicts = collections.Counter(); behaviours = collections.Counter()
    rules = collections.Counter(); platforms = collections.Counter(); errors = 0; install_exec = 0; scanned = 0
    sev = collections.Counter(); files = 0
    for r in results:
        doc = r.get("document")
        if not doc:
            errors += 1
            continue
        scanned += 1
        s = doc.get("summary", {})
        grades[s.get("grade", "?")] += 1
        verdicts[s.get("verdict", "?")] += 1
        platforms[s.get("platform", "?")] += 1
        files += int(s.get("files_scanned", 0) or 0)
        for b in (doc.get("profile") or {}).get("behaviors", []) or []:
            behaviours[b] += 1
        seen_rules = set()
        for f in doc.get("findings", []):
            seen_rules.add(f.get("rule"))
            sev[f.get("severity")] += 1
        for rule in seen_rules:
            rules[rule] += 1
        if any(f.get("phase") == "InstallHooks" for f in doc.get("findings", [])):
            install_exec += 1
    return {"scanned": scanned, "errors": errors, "files_scanned_total": files,
            "grades": dict(sorted(grades.items())), "verdicts": dict(verdicts.most_common()),
            "platforms": dict(platforms.most_common()), "findings_by_severity": dict(sev),
            "servers_with_install_hook_findings": install_exec,
            "behaviours": dict(behaviours.most_common(20)),
            "rules_by_servers_hit": dict(rules.most_common(25))}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--rescan", action="store_true", help="re-scan the kept quarantine dirs with the current binary instead of fetching")
    args = ap.parse_args()
    out = args.out; out.mkdir(parents=True, exist_ok=True)
    scans = out / "scans"; scans.mkdir(exist_ok=True)
    quarantine = out / "quarantine"; quarantine.mkdir(exist_ok=True)
    log = lambda m: print(m, file=sys.stderr, flush=True)
    binary = resolve_binary()
    log(f"scanner: {binary}")

    results: list[dict] = []
    if args.rescan:
        items = json.loads((out / "servers.json").read_text())
        for item in items:
            rec = json.loads((scans / (item["npm"].replace("/", "__") + ".json")).read_text()) if (scans / (item["npm"].replace("/", "__") + ".json")).exists() else None
            qdir = rec.get("quarantine_dir") if rec else None
            if not qdir or not Path(qdir).exists():
                results.append({"npm": item["npm"], "error": "no quarantine dir kept"}); continue
            doc = scan_dir(binary, Path(qdir), args.timeout)
            results.append({"npm": item["npm"], "document": doc, "quarantine_dir": qdir} if doc else {"npm": item["npm"], "error": "rescan produced no JSON"})
    else:
        items = list_npm_servers(args.count, log)
        (out / "servers.json").write_text(json.dumps(items, indent=1))
        log(f"scanning {len(items)} npm-packaged servers")
        for i, item in enumerate(items, 1):
            before = {p.name for p in quarantine.iterdir()} if quarantine.exists() else set()
            rec = scan_npm(binary, item, quarantine, args.timeout, log)
            after = {p.name for p in quarantine.iterdir()} if quarantine.exists() else set()
            new = sorted(after - before)
            if new:
                rec["quarantine_dir"] = str(quarantine / new[-1])
            rec["server"] = item.get("server")
            (scans / (item["npm"].replace("/", "__") + ".json")).write_text(json.dumps(rec, indent=1))
            results.append(rec)
            if i % 10 == 0 or i == len(items):
                log(f"  {i}/{len(items)}")
    agg = aggregate(results)
    agg["binary"] = binary
    agg["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    agg["servers_listed"] = len(results)
    (out / "aggregate.json").write_text(json.dumps(agg, indent=1))
    print(json.dumps(agg, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
