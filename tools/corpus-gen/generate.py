#!/usr/bin/env python3
"""Generate Sigil signature packs from the vendored LOLBin / reverse-shell corpora.

Reads ``vendor/{gtfobins,lolbas,revshells}.json`` (produced by ``fetch.py``)
and emits three declarative packs into ``packs/core/v1/``:

  * ``lolbin_unix.json``     — GTFOBins, one consolidated rule per binary
  * ``lolbin_windows.json``  — LOLBAS,    one consolidated rule per binary
  * ``reverse_shells.json``  — revshells, one rule per documented payload

Design notes
------------
* The Sigil engine compiles each rule's regex *per scanned file*, so the
  GTFOBins/LOLBAS packs are consolidated to one rule per binary (an alternation
  of that binary's documented argument shapes) rather than one rule per command.
  This keeps the rule count ~= the binary count instead of the command count.
* Patterns are anchored on the binary name AND require one of its documented
  argument shapes on the same line. Bare binary names never match — that keeps
  false positives down (e.g. `tar` alone is fine; `tar ... --checkpoint-action`
  is not).
* Generic interpreters/shells (python, bash, perl, ...) are excluded from the
  LOLBin packs: their "run arbitrary code" vector is already covered by the
  core code-pattern rules, and the reverse-shell pack carries their full
  payloads. Flagging bare `python -c` would be pure noise.
* This is fully deterministic and offline — same vendored input, same packs.

Run:  python3 tools/corpus-gen/generate.py
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")
# revshells (MIT) is embedded into the Apache-2.0 binary -> packs/core/v1/.
PACKS_CORE = os.path.normpath(os.path.join(HERE, "..", "..", "packs", "core", "v1"))
# GTFOBins / LOLBAS (GPL-3.0) ship as an OPTIONAL, separately-distributed bundle
# loaded at runtime from ~/.sigil/packs/ — NOT compiled into the Apache binary.
# See tools/corpus-gen/README.md (licensing) and packs/lolbin/v1/LICENSE.
PACKS_LOLBIN = os.path.normpath(os.path.join(HERE, "..", "..", "packs", "lolbin", "v1"))

# Interpreters/shells whose abuse is generic code execution (already covered by
# core code-pattern rules and the reverse-shell pack). Excluded from LOLBin packs.
GENERIC_INTERPRETERS = {
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php",
    "lua", "bash", "sh", "zsh", "dash", "ksh", "csh", "tclsh", "expect",
    "gdb", "ghc", "ghci", "irb", "jjs", "rhino", "stap", "tcsh",
}

# GTFOBins action categories -> severity.
GTFO_HIGH = {
    "shell", "reverse-shell", "bind-shell",
    "non-interactive-reverse-shell", "non-interactive-bind-shell",
    "command", "library-load",
}
GTFO_MEDIUM = {"file-write", "file-read", "download", "upload"}

# LOLBAS categories (normalized upper) that are high severity.
LOLBAS_HIGH = {"EXECUTE", "AWLBYPASS", "AWL BYPASS", "UACBYPASS", "UAC BYPASS",
               "CREDENTIALS", "DUMP", "TAMPER"}


# --------------------------------------------------------------------------
# Template -> regex
# --------------------------------------------------------------------------

# Placeholder span matchers applied (in order) before regex-escaping. Each maps
# a literal/placeholder span in the source command to a regex class.
def _placeholder_subs(kind: str):
    common = [
        (re.compile(r"\{[^{}]*\}"), r"\S+"),          # {REMOTEURL:.exe}, {ip}, ...
    ]
    if kind == "gtfobins":
        return [
            (re.compile(r"\$L[A-Z_]+"), r"\S+"),                  # $LFILE, $LURL ...
            (re.compile(r"user@attacker\.com:[^\s]*"), r"\S+"),  # ssh exfil target
            (re.compile(r"attacker\.com"), r"\S+"),
            (re.compile(r"/path/to/[^\s'\"]*"), r"\S+"),
            (re.compile(r"\bDATA\b"), r"\S+"),
        ] + common
    if kind == "revshells":
        return [
            (re.compile(r"\{ip\}"), r"[\w.\-]+"),
            (re.compile(r"\{port\}"), r"\d+"),
            (re.compile(r"\{shell\}"), r"\S+"),
            (re.compile(r"\{[^{}]*\}"), r"\S+"),
        ]
    return common


_SENT = "ZZSENTINEL{}ZZ"  # ASCII-only so re.escape leaves it untouched


def template_to_regex(text: str, kind: str) -> tuple[str, int]:
    """Return (regex, literal_signal) for a command/argument template.

    ``literal_signal`` is the count of literal alphanumeric characters that
    survive placeholder abstraction — used by the caller to prune fragments
    that are too generic to be a reliable signature.
    """
    subs = []  # sentinel -> regex class
    work = text.strip()

    def _stash(repl):
        token = _SENT.format(len(subs))
        subs.append((token, repl))
        return token

    for rx, repl in _placeholder_subs(kind):
        work = rx.sub(lambda _m, r=repl: _stash(r), work)

    # Literal signal = alphanumerics remaining after placeholders are stashed.
    signal = sum(1 for c in work if c.isalnum() and not c.isspace())
    # Subtract the sentinel characters (they are not real literal signal).
    signal -= sum(len(re.sub(r"[^A-Za-z0-9]", "", tok)) for tok, _ in subs)

    escaped = re.escape(work)
    # Collapse any run of literal whitespace into \s+ (commands vary in spacing).
    escaped = re.sub(r"(?:\\?\s)+", r"\\s+", escaped)
    for token, repl in subs:
        escaped = escaped.replace(token, repl)
    return escaped, max(signal, 0)


def _binary_index(tokens: list[str], binary_base: str) -> int:
    bb = binary_base.lower()
    for i, t in enumerate(tokens):
        base = os.path.basename(t).lower()
        if base.endswith(".exe"):
            base = base[:-4]
        if base == bb:
            return i
    return -1


def _anchor(binary: str) -> str:
    # Word-boundary, case-insensitive anchor on the binary name; tolerate an
    # optional .exe suffix (Windows) without requiring it.
    return r"(?i)\b" + re.escape(binary) + r"(?:\.exe)?\b"


def _arg_fragment(command_line: str, binary_base: str, kind: str) -> str | None:
    tokens = command_line.split()
    if not tokens:
        return None
    idx = _binary_index(tokens, binary_base)
    if idx == -1:
        return None
    rest = tokens[idx + 1:]
    if not rest:
        return None
    frag, signal = template_to_regex(" ".join(rest), kind)
    if signal < 2:  # too generic (only placeholders / punctuation)
        return None
    return frag


# --------------------------------------------------------------------------
# Pack assembly
# --------------------------------------------------------------------------

def _sanitize_id(name: str) -> str:
    base = os.path.basename(name)
    if base.lower().endswith(".exe"):
        base = base[:-4]
    return re.sub(r"[^A-Za-z0-9]+", "_", base).strip("_").upper()


def _meta(pack_id: str, name: str, desc: str, src: dict) -> dict:
    return {
        "id": pack_id,
        "name": name,
        "version": "1.0.0",
        "updated_at": _dt.date.today().isoformat(),
        "author": "NOMARJ <hello@sigilsec.ai>",
        "description": (
            f"{desc} Generated from {src['name']} "
            f"({src['repo']}@{src['ref']} {src['commit'][:12]}, "
            f"retrieved {src['retrieved_at']}, {src['license']})."
        ),
    }


def build_gtfobins(data: dict) -> dict:
    src = data["source"]
    by_binary: dict[str, dict] = {}
    for e in data["entries"]:
        binary, category, code = e["binary"], e["category"], e["code"]
        if binary.lower() in GENERIC_INTERPRETERS:
            continue
        for line in code.splitlines():
            frag = _arg_fragment(line, binary, "gtfobins")
            if frag is None:
                continue
            rec = by_binary.setdefault(
                binary, {"frags": set(), "cats": set()}
            )
            rec["frags"].add(frag)
            rec["cats"].add(category)

    rules = []
    for binary in sorted(by_binary):
        rec = by_binary[binary]
        frags = sorted(rec["frags"])
        cats = rec["cats"]
        severity = "high" if cats & GTFO_HIGH else "medium"
        pattern = _anchor(binary) + r"\s+(?:" + "|".join(frags) + r")"
        rules.append({
            "id": f"GTFO-{_sanitize_id(binary)}",
            "phase": "code_patterns",
            "severity": severity,
            "pattern": pattern,
            "description": (
                f"GTFOBins LOLBin abuse: {binary} "
                f"({', '.join(sorted(cats))}) — living-off-the-land binary execution/exfil"
            ),
            "suppress": {"line_contains": ["sigil-reviewed-lolbin"]},
        })
    return {
        "meta": _meta(
            "sigil-core-lolbin-unix",
            "Sigil Core — LOLBin (Unix / GTFOBins)",
            "Detects abuse of legitimate Unix binaries (living-off-the-land) "
            "for shell breakout, file read/write, and exfiltration.",
            src,
        ),
        "rules": rules,
        "provenance_rules": [],
    }


def build_lolbas(data: dict) -> dict:
    src = data["source"]
    by_binary: dict[str, dict] = {}
    for e in data["entries"]:
        binary, category, command = e["binary"], e["category"], e["command"]
        base = os.path.basename(binary)
        if base.lower().endswith(".exe"):
            base = base[:-4]
        if base.lower() in GENERIC_INTERPRETERS:
            continue
        frag = _arg_fragment(command, base, "lolbas")
        if frag is None:
            continue
        rec = by_binary.setdefault(
            base, {"frags": set(), "cats": set(), "mitre": set(), "display": binary}
        )
        rec["frags"].add(frag)
        if category:
            rec["cats"].add(category)
        if e.get("mitre"):
            rec["mitre"].add(e["mitre"])

    rules = []
    for base in sorted(by_binary):
        rec = by_binary[base]
        frags = sorted(rec["frags"])
        cats = rec["cats"]
        severity = "high" if any(c.upper() in LOLBAS_HIGH for c in cats) else "medium"
        pattern = _anchor(base) + r"\s+(?:" + "|".join(frags) + r")"
        mitre = f"; MITRE {', '.join(sorted(rec['mitre']))}" if rec["mitre"] else ""
        rules.append({
            "id": f"LOLBAS-{_sanitize_id(base)}",
            "phase": "code_patterns",
            "severity": severity,
            "pattern": pattern,
            "description": (
                f"LOLBAS abuse: {rec['display']} "
                f"({', '.join(sorted(cats)) or 'n/a'}{mitre}) — Windows living-off-the-land binary"
            ),
            "suppress": {"line_contains": ["sigil-reviewed-lolbin"]},
        })
    return {
        "meta": _meta(
            "sigil-core-lolbin-windows",
            "Sigil Core — LOLBin (Windows / LOLBAS)",
            "Detects abuse of native Windows binaries, scripts and libraries "
            "(living-off-the-land) for execution, download, and AWL bypass.",
            src,
        ),
        "rules": rules,
        "provenance_rules": [],
    }


def build_revshells(data: dict) -> dict:
    src = data["source"]
    rules = []
    seen: set[str] = set()
    idx = 0
    for e in sorted(data["entries"], key=lambda x: (x["type"], x["name"], x["command"])):
        pattern, signal = template_to_regex(e["command"], "revshells")
        if signal < 4 or pattern in seen:
            continue
        seen.add(pattern)
        idx += 1
        kind = "reverse" if e["type"] == "ReverseShell" else "bind"
        rules.append({
            "id": f"RSHELL-{idx:03d}",
            "phase": "network_exfil",
            "severity": "high",
            # Reverse/bind shells are unambiguous C2; weight them at the
            # code-pattern tier (5x) rather than the default network tier (3x).
            "weight": 5,
            "pattern": pattern,
            "description": (
                f"{kind.capitalize()} shell payload ({e['name']}) — "
                f"interactive C2 one-liner"
            ),
            "suppress": {"line_contains": ["sigil-reviewed-revshell"]},
        })
    return {
        "meta": _meta(
            "sigil-core-reverse-shells",
            "Sigil Core — Reverse / Bind Shells",
            "Detects reverse and bind shell command payloads across shells and "
            "languages (interactive C2 establishment).",
            src,
        ),
        "rules": rules,
        "provenance_rules": [],
    }


def _write(pack: dict, out_dir: str, filename: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"[generate] {filename}: {len(pack['rules'])} rules -> {os.path.relpath(path)}")


def _load(name: str) -> dict:
    with open(os.path.join(VENDOR, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    # GPL-3.0 corpora -> optional, separately-distributed bundle (not embedded).
    _write(build_gtfobins(_load("gtfobins")), PACKS_LOLBIN, "lolbin_unix.json")
    _write(build_lolbas(_load("lolbas")), PACKS_LOLBIN, "lolbin_windows.json")
    # MIT corpus -> embedded into the Apache-2.0 binary.
    _write(build_revshells(_load("revshells")), PACKS_CORE, "reverse_shells.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
