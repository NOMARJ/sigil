#!/usr/bin/env python3
"""Build the clean MCP-server corpus used by docs/detection/mcp-server-calibration.md.

Nothing downloaded here is executed. Each selected server's package archive
(the npm tarball or PyPI sdist/wheel its registry entry pins) is downloaded and
unpacked with a safe extractor: members with absolute paths, ``..`` segments,
links or device nodes are skipped, and archive and unpacked sizes are capped.
No install script, build backend or package code runs.

Selection is deterministic: no ``random``, every list is sorted.

1. Enumerate the official MCP registry (``/v0/servers``, paged by cursor) and
   keep entries marked ``isLatest`` with status ``active``.
2. Keep servers that publish an npm package on registry.npmjs.org or a PyPI
   package (the same preference order as ``sigil scan mcp:<name>``: npm, then
   PyPI; for PyPI the sdist, else the first wheel).
3. Keep servers whose *namespace* (the part of the name before ``/``) belongs
   to a publisher in ``PUBLISHERS`` below: a GitHub organisation
   (``io.github.<org>``, which the registry verifies by GitHub org membership)
   or a reverse-DNS domain (``com.<vendor>`` …, which the registry verifies by
   DNS or HTTP challenge) of a known company or established project. The list
   was written by hand from the registry's namespaces; it is the label.
4. Sort by server name and keep at most ``--per-publisher`` servers from each
   namespace, so one prolific publisher cannot dominate, plus ``ALWAYS``.

Label caveat: "published in the official registry by an established publisher"
is not an audit. A vendor server that reads credentials or talks to its own
API is doing its job; a finding on it can still be a true positive.

Usage:
    # Select from the live registry and fetch (writes a new manifest):
    python3 evaluation_results/corpora/fetch_mcp_clean.py \
        --out /home/user/corpora/mcp_clean \
        --manifest evaluation_results/corpora/mcp_clean_manifest.json

    # Rebuild exactly the measured corpus from the committed manifest
    # (same archives, sha256-verified; the registry's "latest" moves over time):
    python3 evaluation_results/corpora/fetch_mcp_clean.py \
        --out /home/user/corpora/mcp_clean \
        --from-manifest evaluation_results/corpora/mcp_clean_manifest.json
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"
MAX_ARCHIVE = 30 * 1024 * 1024  # bytes downloaded
MAX_UNPACKED = 150 * 1024 * 1024  # bytes written per package
MAX_MEMBERS = 20000

# GitHub organisations (namespace io.github.<org>) of known companies and
# established open-source projects.
GITHUB_ORGS = """
appwrite Automattic aws awslabs Azure brave brightdata browserbase browserstack
bytedance ChromeDevTools ClickHouse cloudinary comet-ml configcat containers
couchbase CrowdStrike Decodo dynatrace-oss firebase firecrawl getsentry
GoogleCloudPlatform growthbook localstack mapbox microsoft mongodb-js
motherduckdb mozilla neo4j-contrib neo4j-labs NVIDIA PagerDuty paypal
perplexityai PrefectHQ questdb redis SAP SAP-samples saucelabs Snowflake-Labs
snyk tavily-ai team-telnyx timescale upstash vercel ZenRows zscaler
""".split()

# Reverse-DNS namespaces of vendor domains.
DOMAINS = """
ai.autoblocks ai.dimensions ai.elfa ai.perplexity ai.reka ai.wavespeed
aws.api.us-east-1.ecs-mcp aws.api.us-east-1.eks-mcp
com.aave com.adbutler com.allstacks com.altmetric.mcp com.apideck
com.appfigures com.audioeye com.auth0 com.automox com.blackduck com.blindpay
com.browser-use com.clicksend com.codescene com.cosmicjs com.dbconvert
com.docfork com.easyship com.eclipsesource com.eztexting com.files
com.geekflare com.gitkraken com.growsurf com.hasdata com.hovercode
com.intellegens com.ismalicious com.keboola com.kudosity com.letta
com.macroaxis com.microsoft com.microsoft.esrp com.mux com.mysupermarket
com.offensive360 com.opensolr com.opsmill com.pdfgate com.postman
com.proabono com.pulsemcp com.rootly com.scoutapm com.sigasi com.smartbear
com.stackhawk com.streamkap com.supabase com.synder com.tracklution com.vaiz
com.xcodebuildmcp com.xverum com.zeroheight com.zype.mcp
dev.edgegap dev.openfeature dev.rivet dev.svelte dev.tinify
io.aiven io.capawesome io.carbone io.form io.frase io.fusionauth io.gainium
io.getunleash io.mailtrap io.oxylabs io.prospeo io.qase io.scorecard
io.scrapfly.mcp io.slingdata io.snyk
ly.img
""".split()

PUBLISHERS = {f"io.github.{o}" for o in GITHUB_ORGS} | set(DOMAINS)

# Included regardless of the per-publisher cap: the server whose first live
# scan (HIGH RISK on placeholder keys and a base64 decode) motivated this corpus.
ALWAYS = {"com.pulsemcp/remote-filesystem"}


def get_json(url: str, tries: int = 4):
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sigil-corpus-fetch"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            time.sleep(1 + attempt)
        except Exception:
            time.sleep(1 + attempt)
    raise RuntimeError(f"GET {url} failed")


def enumerate_registry(dump: Path | None) -> list[dict]:
    if dump and dump.is_file():
        return json.loads(dump.read_text())
    out: list[dict] = []
    cursor = None
    while True:
        q = {"limit": "100"}
        if cursor:
            q["cursor"] = cursor
        doc = get_json(REGISTRY + "?" + urllib.parse.urlencode(q))
        out += doc.get("servers", [])
        cursor = doc.get("metadata", {}).get("nextCursor")
        if not cursor or not doc.get("servers"):
            break
    if dump:
        dump.write_text(json.dumps(out))
    return out


def official(entry: dict) -> dict:
    return entry.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})


def choose_package(server: dict):
    """Mirror of cli/src/mcp_registry.rs::choose_package for npm and PyPI."""
    pkgs = server.get("packages") or []
    for want in ("npm", "pypi"):
        for p in pkgs:
            if p.get("registryType") != want or not p.get("identifier"):
                continue
            version = p.get("version") or server.get("version")
            if not version:
                continue
            if want == "npm":
                base = (p.get("registryBaseUrl") or NPM).rstrip("/")
                if base != NPM:
                    continue
            return want, p["identifier"], version
    return None


def select(entries: list[dict], per_publisher: int) -> list[dict]:
    pool = []
    for e in entries:
        meta = official(e)
        if not meta.get("isLatest") or meta.get("status") != "active":
            continue
        server = e.get("server", {})
        name = server.get("name", "")
        ns = name.split("/", 1)[0]
        if ns not in PUBLISHERS and name not in ALWAYS:
            continue
        pkg = choose_package(server)
        if pkg is None:
            continue
        pool.append((name, ns, server, pkg))
    pool.sort(key=lambda t: t[0])
    taken: dict[str, int] = {}
    chosen = []
    for name, ns, server, pkg in pool:
        if name not in ALWAYS and taken.get(ns, 0) >= per_publisher:
            continue
        if name not in ALWAYS:
            taken[ns] = taken.get(ns, 0) + 1
        chosen.append({"name": name, "namespace": ns, "server_version": server.get("version"),
                       "registry": pkg[0], "package": pkg[1], "version": pkg[2]})
    return chosen


def sanitise(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name.replace("/", "__"))


def resolve_url(item: dict) -> tuple[str, str | None]:
    """(archive URL, published sha256 or None)."""
    if item["registry"] == "npm":
        pkg = item["package"].replace("/", "%2F")
        doc = get_json(f"{NPM}/{pkg}/{urllib.parse.quote(item['version'], safe='')}")
        url = doc.get("dist", {}).get("tarball", "")
        if not url.startswith("https://"):
            raise RuntimeError("no https tarball")
        return url, None
    doc = get_json(f"{PYPI}/{urllib.parse.quote(item['package'])}/{urllib.parse.quote(item['version'])}/json")
    urls = doc.get("urls", [])
    for kind in ("sdist", "bdist_wheel"):
        for u in urls:
            if u.get("packagetype") == kind and u.get("url", "").startswith("https://"):
                return u["url"], u.get("digests", {}).get("sha256")
    raise RuntimeError("no sdist or wheel")


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sigil-corpus-fetch"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise RuntimeError(f"archive over {MAX_ARCHIVE} bytes")
    return data


def safe_member(name: str) -> str | None:
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def extract(data: bytes, url: str, dest: Path) -> tuple[int, int, int]:
    """Safe-extract; returns (files written, bytes written, members skipped)."""
    written = files = skipped = 0
    dest.mkdir(parents=True, exist_ok=True)
    if url.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()[:MAX_MEMBERS]
            for info in infos:
                rel = safe_member(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if rel is None or info.is_dir() or mode in (0o120000,):
                    skipped += not info.is_dir()
                    continue
                if written + info.file_size > MAX_UNPACKED:
                    raise RuntimeError("unpacked size cap")
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(zf.read(info))
                written += info.file_size
                files += 1
        return files, written, skipped
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for n, m in enumerate(tf):
            if n >= MAX_MEMBERS:
                raise RuntimeError("member count cap")
            rel = safe_member(m.name)
            if m.isdir():
                continue
            if rel is None or not m.isreg():
                skipped += 1
                continue
            if written + m.size > MAX_UNPACKED:
                raise RuntimeError("unpacked size cap")
            f = tf.extractfile(m)
            if f is None:
                skipped += 1
                continue
            out = dest / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(f.read())
            written += m.size
            files += 1
    return files, written, skipped


def fetch(item: dict, root: Path) -> dict:
    rec = dict(item, dir=sanitise(item["name"]))
    dest = root / rec["dir"]
    try:
        url, published = resolve_url(item)
        rec["url"] = url
        data = download(url)
        digest = hashlib.sha256(data).hexdigest()
        rec["sha256"] = digest
        rec["archive_bytes"] = len(data)
        if published and published != digest:
            raise RuntimeError(f"sha256 mismatch: PyPI says {published}")
        if dest.exists():
            shutil.rmtree(dest)
        rec["files"], rec["unpacked_bytes"], rec["skipped_members"] = extract(data, url, dest)
    except Exception as e:  # recorded, not hidden
        rec["error"] = f"{type(e).__name__}: {e}"[:300]
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
    return rec


def refetch(rec: dict, root: Path) -> dict:
    """Re-download one manifest record and check it is byte-identical."""
    out = {"name": rec["name"], "dir": rec["dir"]}
    dest = root / rec["dir"]
    try:
        data = download(rec["url"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != rec["sha256"]:
            raise RuntimeError(f"sha256 {digest} != manifest {rec['sha256']}")
        if dest.exists():
            shutil.rmtree(dest)
        extract(data, rec["url"], dest)
        out["ok"] = True
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:300]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True, help="corpus root")
    ap.add_argument("--from-manifest", type=Path, default=None,
                    help="rebuild the corpus from a recorded manifest: same URLs, sha256-verified, "
                         "no registry enumeration (the reproducible path)")
    ap.add_argument("--manifest", type=Path, default=None, help="extra copy of MANIFEST.json")
    ap.add_argument("--registry-dump", type=Path, default=None,
                    help="read/write the enumerated registry here (reuse a snapshot)")
    ap.add_argument("--per-publisher", type=int, default=5)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--select-only", action="store_true")
    args = ap.parse_args()

    if args.from_manifest:
        recs = [r for r in json.loads(args.from_manifest.read_text())["servers"] if "error" not in r]
        args.out.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            done = list(pool.map(lambda r: refetch(r, args.out), recs))
        bad = [d for d in done if "error" in d]
        shutil.copy(args.from_manifest, args.out / "MANIFEST.json")
        print(f"rebuilt {len(done) - len(bad)} of {len(done)}; errors {len(bad)}", file=sys.stderr)
        for d in bad:
            print("  ", d["name"], d["error"], file=sys.stderr)
        return 1 if bad else 0

    entries = enumerate_registry(args.registry_dump)
    chosen = select(entries, args.per_publisher)[: args.limit]
    print(f"registry entries {len(entries)}; selected {len(chosen)}", file=sys.stderr)
    if args.select_only:
        for c in chosen:
            print(c["name"], c["registry"], c["package"], c["version"])
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(lambda it: fetch(it, args.out), chosen))
    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "registry": REGISTRY,
        "registry_entries": len(entries),
        "selection": {
            "rule": "isLatest+active; npm (registry.npmjs.org) or PyPI package; namespace in PUBLISHERS; "
                    f"sorted by name; <= {args.per_publisher} per namespace; limit {args.limit}",
            "publishers": sorted(PUBLISHERS),
            "always": sorted(ALWAYS),
        },
        "label": "clean = published in the official MCP registry by an established publisher; not an audit",
        "servers": records,
        "fetched": sum("error" not in r for r in records),
        "errors": sum("error" in r for r in records),
    }
    text = json.dumps(manifest, indent=1, sort_keys=False) + "\n"
    (args.out / "MANIFEST.json").write_text(text)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(text)
    print(f"fetched {manifest['fetched']}, errors {manifest['errors']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
