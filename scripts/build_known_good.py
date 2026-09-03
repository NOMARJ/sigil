#!/usr/bin/env python3
"""Build a merged known-good index from a corpus manifest (ADR-0011).

The known-good corpus recognises published code instead of re-judging it: a
file whose SHA-256 matches an indexed release file is moved to
``suppressed_findings`` with attribution, and a *modified sibling* of a
recognised release raises ``KNOWNGOOD-DRIFT-001``. Nothing populated that
corpus until this script existed — the mechanism shipped inert.

What this does
--------------
For every package in the manifest it runs ``sigil known-good build`` at the
archive root and then ``sigil known-good merge`` over the per-release indexes.
All hashing, merging and validation happen in the Rust engine; this script is
an orchestrator, so there is exactly one implementation of the on-disk format
and it is the one ``cargo test`` covers.

Archive roots
-------------
Indexed paths are the paths *inside the published archive*, because drift
detection anchors a release by stripping its indexed path off the scanned path.
Both ecosystems keep their archive root as the single child of the package
directory, so the build root is the package directory itself:

    <corpus>/npm-axios/package/...              -> package/dist/axios.js
    <corpus>/pypi-requests/requests-2.34.2/...  -> requests-2.34.2/requests/api.py

Provenance
----------
``--source-url`` and ``--archive-sha256`` are passed through from the manifest
and recorded per release, so every hash in the shipped index can be traced back
to a specific registry archive and checked against it. An index is a trust
input; "trust these hashes" is only reviewable if their origin is written down.

Determinism
-----------
No randomness, no clock. The build date written into the index comes from the
manifest's own ``generated`` field (or ``--generated``), the work directory is
a fixed path, and the engine sorts releases and files, so the same manifest and
the same package trees always produce byte-identical output.

Usage
-----
    python3 scripts/build_known_good.py \\
        --bin target/release/sigil \\
        --manifest /path/to/control-300/manifest.json \\
        --out /path/to/known-good-index.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

EXPECTED_MANIFEST_KEYS = ("ecosystem", "name", "version", "dir")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def safe_slug(ecosystem: str, name: str, version: str) -> str:
    """A file-name-safe, collision-free slug for one release."""
    slug = f"{ecosystem}-{name}-{version}"
    return "".join(c if (c.isalnum() or c in "-._") else "_" for c in slug)


def package_root(corpus_dir: Path, pkg: dict) -> Path:
    """The directory to hash: the archive root's parent."""
    return corpus_dir / pkg["dir"]


def count_files(root: Path) -> int:
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in Path(dirpath).parts:
            continue
        dirnames[:] = [d for d in dirnames if d != ".git"]
        total += len(filenames)
    return total


def build_one(sigil: str, root: Path, pkg: dict, out_file: Path) -> None:
    cmd = [
        sigil,
        "known-good",
        "build",
        str(root),
        "--ecosystem",
        pkg["ecosystem"],
        "--name",
        pkg["name"],
        "--version",
        str(pkg["version"]),
        "--out",
        str(out_file),
    ]
    if pkg.get("url"):
        cmd += ["--source-url", pkg["url"]]
    if pkg.get("sha256"):
        cmd += ["--archive-sha256", pkg["sha256"]]
    # argv list, no shell; the executable is the sigil binary named by --bin.
    subprocess.run(  # sigil-reviewed-subprocess
        cmd, check=True, capture_output=True, text=True, timeout=600
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_index_manifest(dest: Path, index_path: Path, merged: dict, size: int) -> None:
    """Write the small, committable record of a large index.

    A 10 MB table of hashes does not belong in the repository, but "which
    releases are in the index, from which archives, and is this the index the
    project published" does. Every count here is derived from the index that was
    just written, never declared by hand (ADR-0005).
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    # The manifest names the *published* artifact, not wherever this build
    # happened to write it: a local build path is neither reproducible nor
    # anybody else's business.
    published = f"{merged.get('name') or index_path.stem}.json"
    doc = {
        "format": "sigil-known-good-manifest/v1",
        "name": merged.get("name"),
        "generated": merged.get("generated"),
        "index": {
            "file": published,
            "sha256": sha256_file(index_path),
            "bytes": size,
            "releases": len(merged["releases"]),
            "files": sum(len(r["files"]) for r in merged["releases"]),
        },
        "rebuild": {
            "script": "scripts/build_known_good.py",
            "command": (
                "python3 scripts/build_known_good.py --bin <sigil> "
                "--manifest <corpus>/manifest.json --out {index} --name {name} "
                "--index-manifest cli/packs/known-good/v1/{stem}.manifest.json"
            ).format(
                index=published,
                name=merged.get("name"),
                stem=Path(published).stem,
            ),
            "corpus_manifest_fields": [
                "ecosystem",
                "name",
                "version",
                "url",
                "sha256",
                "dir",
            ],
            "note": (
                "Deterministic: releases and files are sorted by the engine and the "
                "build date comes from the corpus manifest, so the same inputs "
                "reproduce the sha256 above."
            ),
        },
        "releases": [
            {
                "ecosystem": r["ecosystem"],
                "name": r["name"],
                "version": r["version"],
                "source_url": r.get("source_url"),
                "archive_sha256": r.get("archive_sha256"),
                "files": len(r["files"]),
            }
            for r in merged["releases"]
        ],
    }
    dest.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bin", required=True, help="path to the sigil binary")
    ap.add_argument(
        "--manifest",
        required=True,
        help="corpus manifest (ecosystem, name, version, url, sha256, dir per package)",
    )
    ap.add_argument("--out", required=True, help="write the merged index here")
    ap.add_argument(
        "--work",
        default=None,
        help="directory for per-release indexes (default: <out>.parts, reused deterministically)",
    )
    ap.add_argument(
        "--name",
        default=None,
        help="corpus name recorded in the index (default: the out file's stem)",
    )
    ap.add_argument(
        "--generated",
        default=None,
        help="build date recorded in the index (default: the manifest's own 'generated')",
    )
    ap.add_argument(
        "--keep-parts",
        action="store_true",
        help="keep the per-release index files instead of deleting them",
    )
    ap.add_argument(
        "--index-manifest",
        default=None,
        help=(
            "also write an index manifest here: the index's digest, size and "
            "per-release provenance, small enough to commit when the index is not"
        ),
    )
    args = ap.parse_args()

    sigil = str(Path(args.bin).resolve())
    if not os.access(sigil, os.X_OK):
        log(f"error: {sigil} is not executable")
        return 2

    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text())
    corpus_dir = manifest_path.parent
    packages = manifest["packages"]

    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    work = Path(args.work).resolve() if args.work else Path(str(out_path) + ".parts")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    index_name = args.name or out_path.stem
    generated = args.generated or manifest.get("generated")

    # Deterministic order: sort by coordinate, not manifest order.
    packages = sorted(
        packages, key=lambda p: (p["ecosystem"], p["name"], str(p["version"]))
    )

    parts: list[Path] = []
    skipped: list[tuple[str, str]] = []
    total_files = 0

    for i, pkg in enumerate(packages, 1):
        missing = [k for k in EXPECTED_MANIFEST_KEYS if not pkg.get(k)]
        if missing:
            skipped.append((pkg.get("name", "?"), f"manifest entry missing {missing}"))
            continue

        coord = f"{pkg['ecosystem']}:{pkg['name']}@{pkg['version']}"
        root = package_root(corpus_dir, pkg)
        if not root.is_dir():
            skipped.append((coord, f"{root} is not a directory"))
            continue

        n = count_files(root)
        if n == 0:
            # An empty release cannot be indexed: it would recognise nothing
            # and the engine rejects it at validation.
            skipped.append((coord, "no files on disk"))
            continue

        part = work / f"{safe_slug(pkg['ecosystem'], pkg['name'], str(pkg['version']))}.json"
        try:
            build_one(sigil, root, pkg, part)
        except subprocess.CalledProcessError as e:
            skipped.append((coord, f"known-good build failed: {e.stderr.strip()[:200]}"))
            continue
        except subprocess.TimeoutExpired:
            skipped.append((coord, "known-good build timed out"))
            continue

        parts.append(part)
        total_files += n
        if i % 25 == 0 or i == len(packages):
            log(f"  [{i}/{len(packages)}] {coord} ({n} files, {total_files} total)")

    if not parts:
        log("error: nothing indexed")
        return 1

    log(f"merging {len(parts)} release index(es) -> {out_path}")
    merge_cmd = [sigil, "known-good", "merge", *[str(p) for p in sorted(parts)]]
    merge_cmd += ["--out", str(out_path), "--name", index_name]
    if generated:
        merge_cmd += ["--generated", str(generated)]
    # argv list, no shell; the executable is the sigil binary named by --bin.
    result = subprocess.run(  # sigil-reviewed-subprocess
        merge_cmd, capture_output=True, text=True, timeout=1800
    )
    if result.returncode != 0:
        log(result.stderr)
        return 1
    log(result.stderr.strip())

    if not args.keep_parts:
        shutil.rmtree(work)

    size = out_path.stat().st_size
    merged = json.loads(out_path.read_text())
    with_url = sum(1 for r in merged["releases"] if r.get("source_url"))
    with_sha = sum(1 for r in merged["releases"] if r.get("archive_sha256"))

    if args.index_manifest:
        write_index_manifest(Path(args.index_manifest).resolve(), out_path, merged, size)
        log(f"manifest:   {args.index_manifest}")

    log("")
    log(f"index:      {out_path}")
    log(f"name:       {merged.get('name')}   generated: {merged.get('generated')}")
    log(f"releases:   {len(merged['releases'])}")
    log(f"files:      {sum(len(r['files']) for r in merged['releases'])}")
    log(f"provenance: {with_url} release(s) with source_url, {with_sha} with archive_sha256")
    log(f"size:       {size} bytes ({size / 1024 / 1024:.2f} MB minified)")
    if skipped:
        log(f"skipped:    {len(skipped)}")
        for coord, why in skipped[:20]:
            log(f"  - {coord}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
