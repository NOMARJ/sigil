#!/usr/bin/env python3
"""Build the clean MCP-server corpora used by docs/detection/mcp-server-calibration.md.

Nothing downloaded here is executed. Each selected server's package archive
(the npm tarball or PyPI sdist/wheel its registry entry pins) is downloaded and
unpacked with a safe extractor: members with absolute paths, ``..`` segments,
links or device nodes are skipped, and archive and unpacked sizes are capped.
No install script, build backend or package code runs.

Selection is deterministic: no ``random``, every list is sorted. There are two
selection modes, with different labels.

``--mode publishers`` (default; the tuning corpus, mcp_clean_manifest.json):

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

``--mode popular`` (the 146-server holdout corpus, mcp_holdout146_manifest.json):
a second, independent label for servers the tuning corpus never saw.

Three holdout manifests sit next to this script; they are different samples:

- ``mcp_holdout146_manifest.json``: the original holdout this mode selected
  on 2026-09-25 (148 selected, 146 fetched, 2 over the 30 MiB archive cap).
  The MCP false-positive calibration, the insecure-transport pack and the
  correlation-chain measurements scanned this one.
- ``mcp_holdout_manifest.json``: a reconstruction made while this manifest was
  unpublished, used by docs/detection/source-map-correlation.md.
- ``mcp_holdout_rederived_manifest.json``: a re-derivation from the published
  criteria (``select_mcp_holdout.py``, which reuses this module's registry and
  npm helpers), used by docs/detection/correlation-names.md.

1. The same registry enumeration; keep ``isLatest`` + ``active`` entries whose
   chosen package (``choose_package``) is on npm (registry.npmjs.org). PyPI is
   not used: its download statistics (pypistats) are rate-limited and not
   batchable, so the popularity label is npm-only.
2. Drop every server whose name, or whose ``(registry, package)``, appears in
   an ``--exclude-manifest`` (the tuning corpus), and every package named in
   ``--malicious-list`` (the npm ``manifest.json`` of DataDog's
   malicious-software-packages-dataset; a name match excludes all versions,
   including packages listed only for a past compromise).
3. Several servers can ship one npm package: keep the first by server name.
4. Popularity: the package's npm downloads over one explicit 30-day window
   (``--downloads-window``, default npm's current complete ``last-month``
   window, pinned as START:END so every package is counted over the same
   days) must be at least ``--min-downloads``. Unscoped names are queried in
   bulk (128 per request); the API refuses scoped names in bulk, so those are
   queried one by one.
5. Age: the package's first publish (``time.created`` in its npm packument)
   must be at least ``--min-age-days`` before the window's end date.
6. Sort by downloads (descending), then server name; keep at most
   ``--per-publisher`` servers per namespace (compared case-insensitively),
   then the first ``--limit``.

Label caveat: "popular on npm and listed in the official registry" is not an
audit either, and download counts include CI and mirror traffic.

The holdout's threshold (5000 downloads over 2026-08-23:2026-09-21, first
publish on or before 2026-06-23, at most 3 per namespace) was picked from the
selection counts alone, before any scan, so that 100-150 servers pass; the
holdout is reserved for a final measurement and is not used for tuning.

Usage:
    # Select from the live registry and fetch (writes a new manifest):
    python3 evaluation_results/corpora/fetch_mcp_clean.py \
        --out /path/to/corpora/mcp_clean \
        --manifest evaluation_results/corpora/mcp_clean_manifest.json

    # Rebuild exactly the measured corpus from the committed manifest
    # (same archives, sha256-verified; the registry's "latest" moves over time):
    python3 evaluation_results/corpora/fetch_mcp_clean.py \
        --out /path/to/corpora/mcp_clean \
        --from-manifest evaluation_results/corpora/mcp_clean_manifest.json

    # Select the holdout (popular mode) and fetch it. The malicious list is
    # samples/npm/manifest.json from a checkout of
    # github.com/DataDog/malicious-software-packages-dataset:
    python3 evaluation_results/corpora/fetch_mcp_clean.py --mode popular \
        --out /path/to/corpora/mcp_holdout \
        --manifest evaluation_results/corpora/mcp_holdout146_manifest.json \
        --exclude-manifest evaluation_results/corpora/mcp_clean_manifest.json \
        --malicious-list /path/to/malicious-software-packages-dataset/samples/npm/manifest.json \
        --downloads-window 2026-08-23:2026-09-21 --min-downloads 5000 \
        --min-age-days 90 --per-publisher 3 --limit 150

    # Rebuild exactly the 146-server holdout from its committed manifest:
    python3 evaluation_results/corpora/fetch_mcp_clean.py \
        --out /path/to/corpora/mcp_holdout \
        --from-manifest evaluation_results/corpora/mcp_holdout146_manifest.json
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
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
            wait = 1 + attempt
            if e.code == 429:  # rate limited: honour Retry-After, else back off harder
                after = e.headers.get("Retry-After", "")
                wait = max(wait, int(after) if after.isdigit() else 10 * (attempt + 1))
            time.sleep(wait)
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


# --- popularity mode ---------------------------------------------------------

NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point"
BULK_MAX = 128  # the downloads API's bulk limit; it refuses scoped names in bulk


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git_head(path: Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def popular_pool(entries: list[dict], exclude_names: set[str], exclude_pkgs: set[tuple[str, str]],
                 malicious: set[str]) -> tuple[list[dict], dict[str, int], list[str]]:
    """Steps 1-3 of ``--mode popular``: candidates before any npm statistics."""
    counts = {"latest_active": 0, "npm_package": 0, "excluded_tuning_corpus": 0,
              "excluded_malicious_list": 0, "duplicate_package": 0}
    flagged: set[str] = set()
    rows = []
    for e in entries:
        meta = official(e)
        if not meta.get("isLatest") or meta.get("status") != "active":
            continue
        counts["latest_active"] += 1
        server = e.get("server", {})
        pkg = choose_package(server)
        if pkg is None or pkg[0] != "npm":
            continue
        counts["npm_package"] += 1
        name = server.get("name", "")
        if name in exclude_names or (pkg[0], pkg[1]) in exclude_pkgs:
            counts["excluded_tuning_corpus"] += 1
            continue
        if pkg[1] in malicious:
            counts["excluded_malicious_list"] += 1
            flagged.add(pkg[1])
            continue
        rows.append({"name": name, "namespace": name.split("/", 1)[0],
                     "server_version": server.get("version"),
                     "registry": pkg[0], "package": pkg[1], "version": pkg[2]})
    rows.sort(key=lambda r: r["name"])
    pool, seen = [], set()
    for r in rows:
        if r["package"] in seen:
            counts["duplicate_package"] += 1
            continue
        seen.add(r["package"])
        pool.append(r)
    counts["candidates"] = len(pool)
    return pool, counts, sorted(flagged)


def npm_window() -> str:
    """npm's current complete 30-day window, pinned as an explicit START:END range."""
    doc = get_json(f"{NPM_DOWNLOADS}/last-month/npm")
    return f"{doc['start']}:{doc['end']}"


def npm_downloads(pkgs: list[str], window: str, workers: int) -> dict[str, int]:
    """Downloads per package over ``window``; a package the API does not know counts 0."""
    unscoped = sorted(p for p in pkgs if not p.startswith("@"))
    singles = sorted(p for p in pkgs if p.startswith("@"))
    batches = [unscoped[i:i + BULK_MAX] for i in range(0, len(unscoped), BULK_MAX)]
    if batches and len(batches[-1]) == 1:  # a one-name "bulk" query answers in the single shape
        singles += batches.pop()

    def bulk(batch: list[str]) -> dict[str, int]:
        doc = get_json(f"{NPM_DOWNLOADS}/{window}/{','.join(batch)}", tries=8)
        return {p: int((doc.get(p) or {}).get("downloads") or 0) for p in batch}

    def single(pkg: str) -> dict[str, int]:
        try:
            doc = get_json(f"{NPM_DOWNLOADS}/{window}/{urllib.parse.quote(pkg, safe='@')}", tries=8)
        except urllib.error.HTTPError:  # 404: no download record
            return {pkg: 0}
        return {pkg: int(doc.get("downloads") or 0)}

    out: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for part in pool.map(bulk, batches):
            out.update(part)
        for n, part in enumerate(pool.map(single, singles), 1):
            out.update(part)
            if n % 500 == 0:
                print(f"  downloads: {n}/{len(singles)} scoped", file=sys.stderr)
    return out


def npm_created(pkgs: list[str], workers: int) -> dict[str, str | None]:
    """First-publish timestamp (packument ``time.created``) per package; None if unknown."""
    def one(pkg: str) -> tuple[str, str | None]:
        try:
            doc = get_json(f"{NPM}/{pkg.replace('/', '%2F')}", tries=8)
        except urllib.error.HTTPError:
            return pkg, None
        return pkg, (doc.get("time") or {}).get("created")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(one, sorted(pkgs)))


def load_cache(path: Path | None) -> dict:
    if path and path.is_file():
        return json.loads(path.read_text())
    return {}


def save_cache(path: Path | None, cache: dict) -> None:
    if path:
        path.write_text(json.dumps(cache, indent=0, sort_keys=True))


def select_popular(pool: list[dict], downloads: dict[str, int], created: dict[str, str | None],
                   min_downloads: int, cutoff: str, per_namespace: int, limit: int,
                   counts: dict[str, int]) -> list[dict]:
    """Steps 4-6 of ``--mode popular`` (pure: statistics are passed in)."""
    popular = [dict(r, downloads=downloads.get(r["package"], 0)) for r in pool
               if downloads.get(r["package"], 0) >= min_downloads]
    counts["downloads_at_least_threshold"] = len(popular)
    old = []
    for r in popular:
        first = created.get(r["package"])
        if first is None:
            counts["created_unknown"] = counts.get("created_unknown", 0) + 1
            continue
        if first[:10] > cutoff:
            continue
        old.append(dict(r, npm_created=first))
    counts["old_enough"] = len(old)
    old.sort(key=lambda r: (-r["downloads"], r["name"]))
    taken: dict[str, int] = {}
    capped = []
    for r in old:
        ns = r["namespace"].lower()
        if taken.get(ns, 0) >= per_namespace:
            continue
        taken[ns] = taken.get(ns, 0) + 1
        capped.append(r)
    counts["after_namespace_cap"] = len(capped)
    chosen = capped[:limit]
    counts["selected"] = len(chosen)
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


def popular_selection(args: argparse.Namespace, entries: list[dict]) -> tuple[list[dict], dict]:
    """``--mode popular``: returns (chosen servers, the manifest's ``selection`` record)."""
    per = 3 if args.per_publisher is None else args.per_publisher
    limit = 150 if args.limit is None else args.limit
    exclude_names: set[str] = set()
    exclude_pkgs: set[tuple[str, str]] = set()
    exclude_ns: set[str] = set()
    excluded_from = []
    for path in args.exclude_manifest:
        servers = json.loads(path.read_text())["servers"]
        exclude_names |= {s["name"] for s in servers}
        exclude_pkgs |= {(s["registry"], s["package"]) for s in servers}
        exclude_ns |= {s["name"].split("/", 1)[0].lower() for s in servers}
        excluded_from.append({"file": path.name, "servers": len(servers), "sha256": sha256_file(path)})
    malicious: set[str] = set()
    malicious_meta = None
    if args.malicious_list:
        listed = json.loads(args.malicious_list.read_text())
        malicious = set(listed)
        malicious_meta = {
            "source": "DataDog/malicious-software-packages-dataset samples/npm/manifest.json",
            "git_commit": git_head(args.malicious_list.parent),
            "sha256": sha256_file(args.malicious_list),
            "entries": len(listed),
        }
    pool, counts, flagged = popular_pool(entries, exclude_names, exclude_pkgs, malicious)

    window = args.downloads_window or npm_window()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}:\d{4}-\d{2}-\d{2}", window):
        raise SystemExit(f"--downloads-window must be YYYY-MM-DD:YYYY-MM-DD, got {window!r}")
    cache = load_cache(args.stats_cache)
    if cache.get("window") != window:
        cache = {"window": window, "downloads": {}, "created": cache.get("created", {})}
    need = sorted({r["package"] for r in pool} - set(cache["downloads"]))
    if need:
        print(f"npm downloads for {len(need)} packages over {window}", file=sys.stderr)
        cache["downloads"].update(npm_downloads(need, window, args.workers))
        save_cache(args.stats_cache, cache)
    popular = {r["package"] for r in pool if cache["downloads"].get(r["package"], 0) >= args.min_downloads}
    need = sorted(popular - set(cache["created"]))
    if need:
        print(f"npm first-publish dates for {len(need)} packages", file=sys.stderr)
        cache["created"].update(npm_created(need, args.workers))
        save_cache(args.stats_cache, cache)
    end = date.fromisoformat(window.split(":")[1])
    cutoff = (end - timedelta(days=args.min_age_days)).isoformat()
    chosen = select_popular(pool, cache["downloads"], cache["created"], args.min_downloads,
                            cutoff, per, limit, counts)
    # Not a filter: how many selected servers share a publisher namespace with the excluded corpus.
    counts["selected_sharing_namespace_with_excluded"] = sum(
        r["namespace"].lower() in exclude_ns for r in chosen)
    selection = {
        "mode": "popular",
        "rule": "isLatest+active; chosen package on npm (registry.npmjs.org); not in the excluded manifests "
                "(server name or package); package not named in the malicious list; one server per package "
                f"(first by name); npm downloads {window} >= {args.min_downloads}; npm time.created on or "
                f"before {cutoff} ({args.min_age_days} days before {end.isoformat()}); sorted by downloads "
                f"desc, then name; <= {per} per namespace (case-insensitive); limit {limit}",
        "downloads_window": window,
        "min_downloads": args.min_downloads,
        "min_age_days": args.min_age_days,
        "created_on_or_before": cutoff,
        "per_namespace": per,
        "limit": limit,
        "excluded_manifests": excluded_from,
        "malicious_list": malicious_meta,
        "malicious_list_excluded": flagged,
        "pypi": "not used: pypistats is rate-limited and has no bulk query, so the label is npm-only",
        "counts": counts,
    }
    return chosen, selection


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True, help="corpus root")
    ap.add_argument("--from-manifest", type=Path, default=None,
                    help="rebuild the corpus from a recorded manifest: same URLs, sha256-verified, "
                         "no registry enumeration (the reproducible path)")
    ap.add_argument("--manifest", type=Path, default=None, help="extra copy of MANIFEST.json")
    ap.add_argument("--registry-dump", type=Path, default=None,
                    help="read/write the enumerated registry here (reuse a snapshot)")
    ap.add_argument("--mode", choices=("publishers", "popular"), default="publishers",
                    help="selection label: named publishers (tuning corpus) or npm popularity (holdout)")
    ap.add_argument("--per-publisher", type=int, default=None,
                    help="max servers per namespace (default 5 in publishers mode, 3 in popular mode)")
    ap.add_argument("--limit", type=int, default=None,
                    help="max servers (default 200 in publishers mode, 150 in popular mode)")
    ap.add_argument("--exclude-manifest", type=Path, action="append", default=[],
                    help="popular mode: drop servers (by name or package) listed in this manifest; repeatable")
    ap.add_argument("--malicious-list", type=Path, default=None,
                    help="popular mode: npm manifest.json of DataDog's malicious-software-packages-dataset; "
                         "packages named there are dropped")
    ap.add_argument("--min-downloads", type=int, default=5000,
                    help="popular mode: npm downloads over the window at least this (default 5000, "
                         "picked so the holdout came to 100-150 servers)")
    ap.add_argument("--min-age-days", type=int, default=90,
                    help="popular mode: npm first publish at least this many days before the window end")
    ap.add_argument("--downloads-window", default=None,
                    help="popular mode: START:END dates for npm downloads (default npm's current last-month)")
    ap.add_argument("--stats-cache", type=Path, default=None,
                    help="popular mode: read/write npm download counts and first-publish dates here")
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
    if args.mode == "popular":
        chosen, selection = popular_selection(args, entries)
        label = "clean = popular npm-published MCP server from the official registry; popularity is not an audit"
        print(f"registry entries {len(entries)}; "
              + ", ".join(f"{k} {v}" for k, v in selection["counts"].items()), file=sys.stderr)
    else:
        per = 5 if args.per_publisher is None else args.per_publisher
        limit = 200 if args.limit is None else args.limit
        chosen = select(entries, per)[:limit]
        selection = {
            "rule": "isLatest+active; npm (registry.npmjs.org) or PyPI package; namespace in PUBLISHERS; "
                    f"sorted by name; <= {per} per namespace; limit {limit}",
            "publishers": sorted(PUBLISHERS),
            "always": sorted(ALWAYS),
        }
        label = "clean = published in the official MCP registry by an established publisher; not an audit"
        print(f"registry entries {len(entries)}; selected {len(chosen)}", file=sys.stderr)
    if args.select_only:
        for c in chosen:
            extra = f" {c['downloads']}" if "downloads" in c else ""
            print(c["name"], c["registry"], c["package"], c["version"] + extra)
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(lambda it: fetch(it, args.out), chosen))
    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "registry": REGISTRY,
        "registry_entries": len(entries),
        "selection": selection,
        "label": label,
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
