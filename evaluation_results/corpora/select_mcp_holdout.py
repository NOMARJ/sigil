#!/usr/bin/env python3
"""Re-derive the out-of-sample MCP-server holdout from its published criteria.

docs/detection/insecure-transport.md describes a holdout of popular MCP
servers that none of the calibration used, but its selection manifest was not
published when this was written (it now is: mcp_holdout146_manifest.json,
selected by ``fetch_mcp_clean.py --mode popular``). This script re-selects
from the stated criteria. The result is a *different* sample (157 selected
here against 148 there); it is recorded in
mcp_holdout_rederived_manifest.json and rebuilt byte for byte with

    python3 evaluation_results/corpora/fetch_mcp_clean.py --out /path/to/mcp_holdout \\
        --from-manifest evaluation_results/corpora/mcp_holdout_rederived_manifest.json

Criteria, and the readings this script had to choose (marked *):

1. Official MCP registry entries marked isLatest and active.
2. Published on npm (registry.npmjs.org), chosen as ``sigil scan mcp:<name>``
   chooses a package.
3. At least 5,000 npm downloads in the 30 days to 2026-09-21
   (2026-08-23..2026-09-21, the npm downloads API).
4. At least 90 days old: * the npm package's ``time.created`` on or before
   2026-06-23.
5. Not one of the 169 in-sample mcp_clean servers (* by server name or by
   npm package: `io.github.cameroncooke/XcodeBuildMCP` publishes the same
   package as the in-sample `com.xcodebuildmcp/XcodeBuildMCP`), and not a
   package on Datadog's malicious npm list (``samples/npm/manifest.json``).
6. At most 3 per namespace: * the most downloaded first, ties by name.

No randomness: every list is sorted. A lookup that still fails after retries
stops the selection (exit 1) rather than reading as zero downloads: a
throttled request silently dropped a server in an earlier run of this logic.
Nothing downloaded is executed.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fetch_mcp_clean as f  # noqa: E402

WINDOW = "2026-08-23:2026-09-21"
CREATED_BY = "2026-06-23"
MIN_DOWNLOADS = 5000
PER_NAMESPACE = 3


def lookup(fn, pkgs: list[str], rounds: int = 4) -> dict:
    """Run `fn` on every package; retry failures in later rounds, slower."""
    out: dict = {}
    todo = list(pkgs)
    for r in range(rounds):
        with ThreadPoolExecutor(4) as ex:
            got = dict(zip(todo, ex.map(fn, todo)))
        out.update({k: v for k, v in got.items() if v is not FAILED})
        todo = [k for k, v in got.items() if v is FAILED]
        if not todo:
            return out
        time.sleep(10 * (r + 1))
    sys.exit(f"error: {len(todo)} lookups still failing: {todo[:10]}")


FAILED = object()


def downloads(pkg: str):
    try:
        return f.get_json(f"https://api.npmjs.org/downloads/point/{WINDOW}/{pkg}").get("downloads", 0)
    except urllib.error.HTTPError as e:
        return 0 if e.code == 404 else FAILED
    except Exception:
        return FAILED


def created(pkg: str):
    try:
        return (f.get_json(f"{f.NPM}/{pkg.replace('/', '%2F')}").get("time") or {}).get("created")
    except urllib.error.HTTPError as e:
        return None if e.code == 404 else FAILED
    except Exception:
        return FAILED


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--registry-dump", type=Path, required=True, help="read/write the enumerated registry")
    ap.add_argument("--in-sample", type=Path, default=Path(__file__).with_name("mcp_clean_manifest.json"))
    ap.add_argument("--datadog-npm-manifest", type=Path, required=True,
                    help="samples/npm/manifest.json of the Datadog dataset")
    ap.add_argument("--out", type=Path, required=True, help="write the selection (JSON) here")
    args = ap.parse_args()

    entries = f.enumerate_registry(args.registry_dump)
    in_sample_servers = [r for r in json.loads(args.in_sample.read_text())["servers"] if "error" not in r]
    in_sample = {r["name"] for r in in_sample_servers}
    in_sample_pkgs = {r["package"] for r in in_sample_servers}
    malicious = set(json.loads(args.datadog_npm_manifest.read_text()))
    pool = []
    for e in entries:
        meta = f.official(e)
        if not meta.get("isLatest") or meta.get("status") != "active":
            continue
        server = e.get("server", {})
        name = server.get("name", "")
        pkg = f.choose_package(server)
        if pkg is None or pkg[0] != "npm" or pkg[1] in malicious:
            continue
        if name in in_sample or pkg[1] in in_sample_pkgs:
            continue
        pool.append({"name": name, "namespace": name.split("/", 1)[0],
                     "server_version": server.get("version"), "registry": "npm",
                     "package": pkg[1], "version": pkg[2]})
    pool.sort(key=lambda r: r["name"])

    pkgs = sorted({r["package"] for r in pool})
    dl = lookup(downloads, pkgs)
    popular = sorted(p for p in pkgs if dl[p] >= MIN_DOWNLOADS)
    born = lookup(created, popular)
    old = [dict(r, downloads_30d=dl[r["package"]], npm_created=born[r["package"]])
           for r in pool
           if r["package"] in born and born[r["package"]] and born[r["package"]][:10] <= CREATED_BY]

    kept: dict[str, list[dict]] = {}
    for r in sorted(old, key=lambda r: (-r["downloads_30d"], r["name"])):
        if len(kept.setdefault(r["namespace"], [])) < PER_NAMESPACE:
            kept[r["namespace"]].append(r)
    chosen = sorted((r for rs in kept.values() for r in rs), key=lambda r: r["name"])
    print(f"candidates {len(pool)}; popular {len(popular)}; old enough {len(old)}; selected {len(chosen)}",
          file=sys.stderr)
    args.out.write_text(json.dumps({"window": WINDOW, "created_by": CREATED_BY, "servers": chosen}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
