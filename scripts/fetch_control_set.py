#!/usr/bin/env python3
"""Fetch a clean control set of popular npm and PyPI packages for the
evaluation harness and the known-good corpus builder.

"Popular" is measured, not assumed: npm candidates are discovered by walking
the dependency graphs of a seed list of widely used packages and ranked by
the registry's own last-month download counts; PyPI candidates come from the
public top-pypi-packages dataset (30-day downloads). Every archive is fetched
from the official registry over HTTPS and extracted with path checks. Nothing
is executed.

Output layout (what scripts/run_eval.py --control-path and
scripts/build_knowngood.py consume):

    <out>/npm-<name>/package/...      extracted npm tarball
    <out>/pypi-<name>/<name>-<ver>/...  extracted sdist (or wheel contents)
    <out>/manifest.json               ecosystem, name, version, archive url, sha256

Usage:
    python3 scripts/fetch_control_set.py --out control-300 --npm 150 --pypi 150
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

UA = "sigil-control-set/1.0 (+https://github.com/NOMARJ/sigil)"
MAX_ARCHIVE_BYTES = 60_000_000

NPM_SEEDS = [
    "express", "react", "react-dom", "lodash", "axios", "next", "webpack", "vite", "typescript",
    "eslint", "prettier", "jest", "vitest", "mocha", "chalk", "commander", "yargs", "debug",
    "dotenv", "uuid", "moment", "dayjs", "date-fns", "rxjs", "vue", "@angular/core", "svelte",
    "fastify", "koa", "socket.io", "ws", "mongoose", "pg", "mysql2", "redis", "ioredis",
    "prisma", "@prisma/client", "sequelize", "knex", "tailwindcss", "postcss", "autoprefixer",
    "babel-loader", "@babel/core", "esbuild", "rollup", "ts-node", "tsx", "nodemon", "pm2",
    "zod", "joi", "ajv", "class-validator", "graphql", "apollo-server", "@apollo/client",
    "jsonwebtoken", "bcrypt", "passport", "helmet", "cors", "body-parser", "cookie-parser",
    "minimist", "glob", "fs-extra", "rimraf", "semver", "inquirer", "ora", "cross-env",
    "@modelcontextprotocol/sdk", "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core",
]

PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"


def get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("unreachable")


def get_json(url: str):
    return json.loads(get(url).decode("utf-8"))


def safe_extract_tar(data: bytes, dest: Path) -> int:
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve()) + "/"):
                continue  # path escape
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with open(target, "wb") as fh:
                fh.write(src.read())
            count += 1
    return count


def safe_extract_zip(data: bytes, dest: Path) -> int:
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve()) + "/"):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(zf.read(info))
            count += 1
    return count


# ── npm ──────────────────────────────────────────────────────────────────────

def npm_meta(name: str) -> dict:
    return get_json(f"https://registry.npmjs.org/{urllib.request.quote(name, safe='@')}")


def npm_downloads(name: str) -> int:
    try:
        d = get_json(f"https://api.npmjs.org/downloads/point/last-month/{urllib.request.quote(name, safe='@')}")
        return int(d.get("downloads", 0))
    except Exception:
        return 0


def npm_candidates(limit: int, log) -> list[tuple[str, int]]:
    """Walk dependency graphs from the seeds, rank by last-month downloads."""
    seen: dict[str, dict] = {}
    queue = list(NPM_SEEDS)
    while queue and len(seen) < limit * 3:
        name = queue.pop(0)
        if name in seen:
            continue
        try:
            meta = npm_meta(name)
        except Exception as exc:
            log(f"npm meta {name}: {exc}")
            continue
        latest = meta.get("dist-tags", {}).get("latest")
        ver = meta.get("versions", {}).get(latest, {}) if latest else {}
        seen[name] = {"version": latest, "tarball": ver.get("dist", {}).get("tarball")}
        for dep in list(ver.get("dependencies", {}).keys()):
            if dep not in seen and dep not in queue:
                queue.append(dep)
    ranked = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(npm_downloads, n): n for n in seen}
        for fut in as_completed(futs):
            ranked.append((futs[fut], fut.result()))
    ranked.sort(key=lambda t: t[1], reverse=True)
    return [(n, d) for n, d in ranked if seen[n]["tarball"]][:limit], seen


def fetch_npm(name: str, info: dict, out: Path, log) -> dict | None:
    tarball = info["tarball"]
    dest = out / f"npm-{name.replace('/', '__')}"
    if dest.exists():
        return {"ecosystem": "npm", "name": name, "version": info["version"], "url": tarball, "dir": dest.name, "cached": True}
    try:
        data = get(tarball, timeout=120)
    except Exception as exc:
        log(f"npm fetch {name}: {exc}")
        return None
    if len(data) > MAX_ARCHIVE_BYTES:
        log(f"npm {name}: archive too large ({len(data)} bytes), skipped")
        return None
    dest.mkdir(parents=True, exist_ok=True)
    n = safe_extract_tar(data, dest)
    return {"ecosystem": "npm", "name": name, "version": info["version"], "url": tarball,
            "sha256": hashlib.sha256(data).hexdigest(), "files": n, "dir": dest.name}


# ── PyPI ─────────────────────────────────────────────────────────────────────

def pypi_top(limit: int) -> list[str]:
    d = get_json(PYPI_TOP_URL)
    rows = d.get("rows", [])
    return [r["project"] for r in rows[: limit * 2]]


def fetch_pypi(name: str, out: Path, log) -> dict | None:
    try:
        meta = get_json(f"https://pypi.org/pypi/{name}/json")
    except Exception as exc:
        log(f"pypi meta {name}: {exc}")
        return None
    version = meta["info"]["version"]
    urls = meta.get("urls", [])
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    wheel = next((u for u in urls if u.get("packagetype") == "bdist_wheel" and u["filename"].endswith("py3-none-any.whl")), None) \
        or next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
    pick = sdist or wheel
    if not pick:
        log(f"pypi {name}: no archive")
        return None
    dest = out / f"pypi-{name}"
    if dest.exists():
        return {"ecosystem": "pypi", "name": name, "version": version, "url": pick["url"], "dir": dest.name, "cached": True,
                "wheel_url": wheel["url"] if wheel else None, "sdist_url": sdist["url"] if sdist else None}
    try:
        data = get(pick["url"], timeout=120)
    except Exception as exc:
        log(f"pypi fetch {name}: {exc}")
        return None
    if len(data) > MAX_ARCHIVE_BYTES:
        log(f"pypi {name}: archive too large ({len(data)} bytes), skipped")
        return None
    dest.mkdir(parents=True, exist_ok=True)
    if pick["filename"].endswith((".whl", ".zip")):
        n = safe_extract_zip(data, dest)
    else:
        n = safe_extract_tar(data, dest)
    return {"ecosystem": "pypi", "name": name, "version": version, "url": pick["url"],
            "sha256": hashlib.sha256(data).hexdigest(), "files": n, "dir": dest.name,
            "wheel_url": wheel["url"] if wheel else None, "sdist_url": sdist["url"] if sdist else None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--npm", type=int, default=150)
    ap.add_argument("--pypi", type=int, default=150)
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    def log(msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    entries: list[dict] = []
    if args.npm > 0:
        log(f"npm: discovering candidates from {len(NPM_SEEDS)} seeds")
        ranked, seen = npm_candidates(args.npm, log)
        log(f"npm: fetching {len(ranked)} packages")
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(fetch_npm, n, seen[n], out, log) for n, _ in ranked]
            for i, fut in enumerate(as_completed(futs), 1):
                r = fut.result()
                if r:
                    entries.append(r)
                if i % 25 == 0:
                    log(f"  npm {i}/{len(futs)}")
    if args.pypi > 0:
        names = pypi_top(args.pypi)
        log(f"pypi: fetching up to {args.pypi} of {len(names)} candidates")
        got = 0
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(fetch_pypi, n, out, log) for n in names]
            for i, fut in enumerate(as_completed(futs), 1):
                r = fut.result()
                if r:
                    entries.append(r)
                    got += 1
                if i % 25 == 0:
                    log(f"  pypi {i}/{len(futs)} ({got} fetched)")
        # keep only the first `--pypi` by top-list order
        order = {n: i for i, n in enumerate(names)}
        py = sorted([e for e in entries if e["ecosystem"] == "pypi"], key=lambda e: order.get(e["name"], 1e9))[: args.pypi]
        entries = [e for e in entries if e["ecosystem"] != "pypi"] + py
        for e in [x for x in entries if x["ecosystem"] == "pypi"]:
            pass
    manifest = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "packages": sorted(entries, key=lambda e: (e["ecosystem"], e["name"]))}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1))
    log(f"done: {len(manifest['packages'])} packages under {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
