#!/usr/bin/env python3
"""Fetch and distill upstream living-off-the-land corpora into vendored JSON.

This script is the *upstream ingestion* step for the LOLBin / reverse-shell
signature packs. It downloads pinned upstream sources, extracts the raw attack
command templates, and writes them to ``vendor/<source>.json`` together with a
provenance block (repo, ref, commit, retrieval date, tarball SHA-256, license).

`generate.py` consumes those vendored snapshots to emit the signature packs in
``packs/core/v1/``. Splitting fetch (network) from generate (deterministic)
keeps pack regeneration reproducible and offline.

NO synthetic data: every entry here is parsed verbatim from the named upstream
commit. See CLAUDE.md "No Fake Data" — the provenance block records exactly
where each corpus came from.

Usage:
    python3 tools/corpus-gen/fetch.py            # fetch all sources
    python3 tools/corpus-gen/fetch.py gtfobins   # fetch one source
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import json
import os
import sys
import tarfile
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")

# Pinned upstream sources. Commit SHAs are recorded for provenance; the codeload
# tarball is fetched from the branch ref (codeload does not serve arbitrary SHAs
# as a tarball without auth), and the SHA is recorded so a reviewer can verify
# the branch tip at retrieval time.
SOURCES = {
    "gtfobins": {
        "name": "GTFOBins",
        "repo": "https://github.com/GTFOBins/GTFOBins.github.io",
        "ref": "master",
        "commit": "acd524623f9c406acedd2754ebd9c2431f3675ad",
        "license": "GPL-3.0-or-later (see upstream LICENSE)",
        "site": "https://gtfobins.github.io/",
        "tarball": "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master",
    },
    "lolbas": {
        "name": "LOLBAS",
        "repo": "https://github.com/LOLBAS-Project/LOLBAS",
        "ref": "master",
        "commit": "f06df108eef22dddc5a4ab7d2a11eba6906d05c4",
        "license": "GPL-3.0 (see upstream LICENSE)",
        "site": "https://lolbas-project.github.io/",
        "tarball": "https://codeload.github.com/LOLBAS-Project/LOLBAS/tar.gz/refs/heads/master",
    },
    "revshells": {
        "name": "reverse-shell-generator",
        "repo": "https://github.com/0dayCTF/reverse-shell-generator",
        "ref": "main",
        "commit": "9fda27f91b1b1f370539dd534bc3bbb1f6b49bf6",
        "license": "MIT (see upstream LICENSE)",
        "site": "https://www.revshells.com/",
        "tarball": "https://codeload.github.com/0dayCTF/reverse-shell-generator/tar.gz/refs/heads/main",
    },
}


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sigil-corpus-gen"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (pinned host)
        return resp.read()


def _provenance(key: str, blob: bytes) -> dict:
    src = SOURCES[key]
    return {
        "name": src["name"],
        "repo": src["repo"],
        "ref": src["ref"],
        "commit": src["commit"],
        "site": src["site"],
        "license": src["license"],
        "tarball_url": src["tarball"],
        "tarball_sha256": hashlib.sha256(blob).hexdigest(),
        "retrieved_at": _dt.date.today().isoformat(),
    }


# --------------------------------------------------------------------------
# GTFOBins: YAML files under _gtfobins/<binary> with a `functions:` map.
# --------------------------------------------------------------------------

# Action categories that represent code execution / data movement we care about
# when scanning agent code and install hooks. Privilege-context-only categories
# (sudo/suid/capabilities) reuse the same command bodies and are deduped away.
GTFOBINS_CATEGORIES = {
    "shell",
    "reverse-shell",
    "bind-shell",
    "non-interactive-reverse-shell",
    "non-interactive-bind-shell",
    "command",
    "library-load",
    "file-write",
    "file-read",
    "download",
    "upload",
}


def distill_gtfobins(blob: bytes) -> list[dict]:
    entries: list[dict] = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or "/_gtfobins/" not in member.name:
                continue
            binary = os.path.basename(member.name)
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                doc = yaml.safe_load(fh.read().decode("utf-8", "replace"))
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            funcs = doc.get("functions") or {}
            for category, items in funcs.items():
                if category not in GTFOBINS_CATEGORIES or not isinstance(items, list):
                    continue
                for item in items:
                    code = (item or {}).get("code")
                    if isinstance(code, str) and code.strip():
                        entries.append(
                            {"binary": binary, "category": category, "code": code}
                        )
    entries.sort(key=lambda e: (e["binary"], e["category"], e["code"]))
    return entries


# --------------------------------------------------------------------------
# LOLBAS: YAML files under yml/**/*.yml with a `Commands:` list.
# --------------------------------------------------------------------------


def distill_lolbas(blob: bytes) -> list[dict]:
    entries: list[dict] = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or "/yml/" not in member.name:
                continue
            if not member.name.endswith((".yml", ".yaml")):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                doc = yaml.safe_load(fh.read().decode("utf-8", "replace"))
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            name = doc.get("Name") or os.path.basename(member.name)
            for cmd in doc.get("Commands") or []:
                if not isinstance(cmd, dict):
                    continue
                command = cmd.get("Command")
                if not isinstance(command, str) or not command.strip():
                    continue
                entries.append(
                    {
                        "binary": name,
                        "category": (cmd.get("Category") or "").strip(),
                        "mitre": (cmd.get("MitreID") or "").strip(),
                        "command": command,
                    }
                )
    entries.sort(key=lambda e: (e["binary"], e["category"], e["command"]))
    return entries


# --------------------------------------------------------------------------
# revshells: command objects live in js/data.js as JSON-ish array literals.
# --------------------------------------------------------------------------


def _extract_array(src: str, var_marker: str) -> list[dict]:
    """Pull the `[ {...}, ... ]` literal that follows ``var_marker`` and parse
    each ``{name, command, meta}`` object. The file is JS, not JSON, so we scan
    object-by-object rather than eval()-ing anything."""
    import re

    idx = src.find(var_marker)
    if idx == -1:
        return []
    start = src.find("[", idx)
    if start == -1:
        return []
    depth = 0
    end = start
    for i in range(start, len(src)):
        c = src[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                end = i
                break
    block = src[start : end + 1]
    out: list[dict] = []
    # Split into top-level {...} objects with a string-aware, depth-tracking
    # scan: command payloads legitimately contain `{`/`}` (e.g. `${IFS}`,
    # `awk 'BEGIN{...}'`), so a brace-naive regex would mis-split them.
    for obj in _split_objects(block):
        name = re.search(r'"name"\s*:\s*"((?:[^"\\]|\\.)*)"', obj)
        command = re.search(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)"', obj)
        if not command:
            continue
        meta = re.findall(r'"([a-zA-Z0-9_]+)"', obj.split('"meta"', 1)[-1]) if '"meta"' in obj else []
        out.append(
            {
                "name": _unescape_js(name.group(1)) if name else "",
                "command": _unescape_js(command.group(1)),
                "meta": meta,
            }
        )
    return out


def _split_objects(block: str) -> list[str]:
    """Yield each top-level ``{...}`` object literal from an array block,
    honoring string literals so braces inside payload strings don't confuse
    the depth counter."""
    objs: list[str] = []
    depth = 0
    in_str = False
    quote = ""
    esc = False
    obj_start = -1
    for i, c in enumerate(block):
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                in_str = False
            continue
        if c in ('"', "'", "`"):
            in_str = True
            quote = c
        elif c == "{":
            if depth == 0:
                obj_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and obj_start != -1:
                objs.append(block[obj_start : i + 1])
                obj_start = -1
    return objs


def _unescape_js(s: str) -> str:
    return (
        s.replace('\\"', '"')
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\/", "/")
    )


def distill_revshells(blob: bytes) -> list[dict]:
    data_js = None
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith("js/data.js"):
                fh = tar.extractfile(member)
                if fh is not None:
                    data_js = fh.read().decode("utf-8", "replace")
                break
    if data_js is None:
        return []
    entries: list[dict] = []
    for marker, kind in (
        ("reverseShellCommands", "ReverseShell"),
        ("bindShellCommands", "BindShell"),
    ):
        for obj in _extract_array(data_js, marker):
            entries.append(
                {"type": kind, "name": obj["name"], "command": obj["command"], "meta": obj["meta"]}
            )
    entries.sort(key=lambda e: (e["type"], e["name"], e["command"]))
    return entries


DISTILLERS = {
    "gtfobins": distill_gtfobins,
    "lolbas": distill_lolbas,
    "revshells": distill_revshells,
}


def fetch(key: str) -> None:
    src = SOURCES[key]
    print(f"[fetch] {src['name']} <- {src['tarball']}")
    blob = _download(src["tarball"])
    entries = DISTILLERS[key](blob)
    out = {"source": _provenance(key, blob), "entries": entries}
    os.makedirs(VENDOR, exist_ok=True)
    path = os.path.join(VENDOR, f"{key}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")
    print(f"[fetch] wrote {len(entries)} entries -> {os.path.relpath(path)}")


def main(argv: list[str]) -> int:
    keys = argv[1:] or list(SOURCES)
    for key in keys:
        if key not in SOURCES:
            print(f"unknown source: {key} (known: {', '.join(SOURCES)})", file=sys.stderr)
            return 2
        fetch(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
