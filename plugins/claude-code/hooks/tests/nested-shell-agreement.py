#!/usr/bin/env python3
"""Randomised check of the nested-shell reading of `sigil pip|npm --allow-build-scripts`.

A double-quoted string keeps a backslash that the shell it is handed to then
drops, so `bash -c "`which sigil` pip x --allow-build-s\\\\cripts"` runs
`sigil pip x --allow-build-scripts` while no single reading of the outer text
shows the flag. The hook asks about every such call (over-asking is the
intended failure). This script checks that, on random commands:

  1. the three implementations agree: `sigil hook pretooluse` (native), the
     MCP server's `check_command` tool, and the shell fallback
     (`sigil-guard.sh` with no `sigil` on PATH, so it reads the patterns);
  2. no command that really runs `sigil pip|npm ... --allow-build-scripts` is
     allowed by any of them. "Really runs" is decided by real bash: the
     command is run with stub `sigil`, `pip`, `npm`, `ssh`, `su`, `sudo` and
     `script` programs first on PATH that only record their arguments (the
     stubs for `ssh`, `su`, `sudo` and `script` hand their command to `sh -c`
     as the real ones do). Nothing but those stubs, the shells and `echo`,
     `printf`, `which` and `timeout` is ever started, and the commands are
     built from fixed templates (see below), never from outside input.

Usage:
    nested-shell-agreement.py [--seed N] [--count N] [--sigil PATH] [--guard PATH]

The native binary is `--sigil`, else $SIGIL_BIN, else `sigil` on PATH. Prints
a summary; exits 1 if any command is missed or the implementations disagree.
Data source: commands this script generates (synthetic, seeded); nothing is
taken from a real user or registry. Limitations: the generator covers the
wrappers and spellings in WRAPPERS and FLAGS below, not every shell feature;
a run proves nothing about a spelling it cannot generate.
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GUARD = os.path.join(HERE, "..", "sigil-guard.sh")

FLAG = "--allow-build-scripts"

# How the command word spells `sigil`. `assign` is a prefix the inner script
# needs for it to mean sigil.
HEADS = [
    ("sigil", ""),
    ("`which sigil`", ""),
    ("$(which sigil)", ""),
    ("$(command -v sigil)", ""),
    ("`command -v sigil`", ""),
    ("$S", "S=sigil; "),
    ("${S}", "S=sigil; "),
    ('"sigil"', ""),
    ("'sigil'", ""),
    ("s\\igil", ""),
    ("sig''il", ""),
    ('si"g"il', ""),
]


def flag_forms(rng):
    """(text, prefix) spellings of the flag as the INNERMOST shell reads them.

    Some produce the flag, some a near miss; the oracle decides which.
    """
    n = len(FLAG)
    # A backslash before a random character after the leading dashes.
    k = rng.randrange(2, n)
    backslash = FLAG[:k] + "\\" + FLAG[k:]
    k2 = rng.randrange(2, n)
    empty_quotes = FLAG[:k2] + rng.choice(["''", '""']) + FLAG[k2:]
    return [
        (FLAG, ""),
        (backslash, ""),
        (backslash, ""),
        (empty_quotes, ""),
        ('--"allow-build-scripts"', ""),
        ("'--allow-build-scripts'", ""),
        ("--allow-build-$(printf scripts)", ""),
        ("--allow-build-${F}", "F=scripts; "),
        ("--allow-build-s{cripts,}", ""),
        ("--allow-build-s\\\\cripts", ""),  # a literal backslash: a near miss
        ("--allow-build-scripts-x", ""),  # near miss
        ("--allow-build", ""),  # near miss
        ("-V 1.0", ""),  # no flag at all
        ("", ""),
    ]


def sq(s):
    """`s` as one single-quoted word."""
    return "'" + s.replace("'", "'\\''") + "'"


def dq(s):
    """`s` as one double-quoted word that keeps its text as it is."""
    out = []
    for c in s:
        if c in '\\"$`':
            out.append("\\" + c)
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def ansi(s):
    return "$'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def heredoc_body(s):
    """`s` as the body of a here-document with an unquoted delimiter."""
    return s.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`")


def quote(rng, s):
    return rng.choice([sq, dq, dq, ansi])(s)


def wrap(rng, s, shells):
    """One more level around the script `s`."""
    shell = rng.choice(shells)
    choice = rng.choice(
        [
            "bash -c",
            "sh -c",
            "shell -c",
            "eval",
            "eval-bare",
            "ssh",
            "su",
            "sudo",
            "echo|sh",
            "printf|bash",
            "heredoc-q",
            "heredoc",
            "source",
            "dot",
            "timeout",
            "env",
            "script",
        ]
    )
    if choice == "bash -c":
        return "bash -c " + quote(rng, s)
    if choice == "sh -c":
        return "sh -c " + quote(rng, s)
    if choice == "shell -c":
        return shell + " -c " + quote(rng, s)
    if choice == "eval":
        return "eval " + quote(rng, s)
    if choice == "eval-bare":
        # No quoting of the script at all: the outer shell reads it, then
        # eval reads what is left.
        return "eval " + s if "\n" not in s else "eval " + quote(rng, s)
    if choice == "ssh":
        return "ssh host " + quote(rng, s)
    if choice == "su":
        return "su -c " + quote(rng, s)
    if choice == "sudo":
        return "sudo bash -c " + quote(rng, s)
    if choice == "echo|sh":
        return "echo " + quote(rng, s) + " | sh"
    if choice == "printf|bash":
        return "printf '%s\\n' " + quote(rng, s) + " | bash"
    if choice == "heredoc-q":
        return "bash <<'EOF'\n" + s + "\nEOF"
    if choice == "heredoc":
        return "bash <<EOF\n" + heredoc_body(s) + "\nEOF"
    if choice == "source":
        return "source <(echo " + quote(rng, s) + ")"
    if choice == "dot":
        return ". <(printf '%s\\n' " + quote(rng, s) + ")"
    if choice == "timeout":
        return "timeout 5 bash -c " + quote(rng, s)
    if choice == "env":
        return "env X=1 bash -c " + quote(rng, s)
    return "script -qec " + quote(rng, s) + " /dev/null"


def generate(rng, shells):
    head, assign = rng.choice(HEADS)
    manager = rng.choice(["pip", "npm"])
    opts = rng.choice(["", "", "--format json "])
    arg = rng.choice(["x", "requests==1.0", "left-pad@1.3.0", "'a b'"])
    flag, flag_assign = rng.choice(flag_forms(rng))
    tail = rng.choice(["", "", " && echo done", "; echo 'done'"])
    inner = f"{assign}{flag_assign}{head} {opts}{manager} {arg} {flag}{tail}"
    levels = rng.choice([0, 1, 1, 2, 2, 3])
    cmd = inner
    for _ in range(levels):
        cmd = wrap(rng, cmd, shells)
    return cmd


STUB = """#!/bin/sh
# Records one call: the program name, then one line per argument.
{
  printf 'CALL %s\\n' "$(basename "$0")"
  for a in "$@"; do printf 'ARG %s\\n' "$a"; done
} >> "$SIGIL_FUZZ_LOG"
exit 0
"""

STUBS_THAT_RUN = {
    # ssh joins what follows the host and has the remote shell run it.
    "ssh": 'shift\nexec sh -c "$*"\n',
    "su": 'if [ "$1" = -c ]; then shift; exec sh -c "$1"; fi\nexit 0\n',
    "sudo": 'exec "$@"\n',
    # `script -qec CMD /dev/null`
    "script": 'while [ $# -gt 0 ]; do case "$1" in -*c) shift; exec sh -c "$1" ;; *) shift ;; esac; done\nexit 0\n',
}


def make_stubs(root):
    bindir = os.path.join(root, "bin")
    os.makedirs(bindir)
    for name in ("sigil", "pip", "npm"):
        path = os.path.join(bindir, name)
        with open(path, "w") as f:
            f.write(STUB)
        os.chmod(path, 0o755)
    for name, body in STUBS_THAT_RUN.items():
        path = os.path.join(bindir, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
    return bindir


def really_runs_the_flag(cmd, root, bindir):
    """Run `cmd` under real bash with stubs only; did a sigil pip/npm call get the flag?"""
    log = os.path.join(root, "calls.log")
    open(log, "w").close()
    env = {
        "PATH": bindir + ":/usr/bin:/bin",
        "HOME": root,
        "SIGIL_FUZZ_LOG": log,
        "LC_ALL": "C",
    }
    try:
        subprocess.run(
            ["bash", "-c", cmd],
            env=env,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        pass
    calls, current = [], None
    with open(log, errors="replace") as f:
        for line in f.read().split("\n"):
            if line.startswith("CALL "):
                current = [line[5:]]
                calls.append(current)
            elif line.startswith("ARG ") and current is not None:
                current.append(line[4:])
    for call in calls:
        if call[0] == "sigil" and len(call) > 1 and FLAG in call[1:]:
            managers = [a for a in call[1:] if a in ("pip", "npm")]
            if managers:
                return True
    return False


def native_decisions(sigil, cmds):
    out = []
    for cmd in cmds:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
        }
        p = subprocess.run(
            [sigil, "hook", "pretooluse"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=60,
        )
        out.append(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"])
    return out


def mcp_decisions(sigil, cmds):
    lines = []
    for i, cmd in enumerate(cmds):
        lines.append(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {"name": "check_command", "arguments": {"command": cmd}},
                }
            )
        )
    p = subprocess.run(
        [sigil, "mcp"], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=600
    )
    by_id = {}
    for line in p.stdout.splitlines():
        if line.strip():
            r = json.loads(line)
            by_id[r["id"]] = r["result"]["structuredContent"]["decision"]
    return [by_id[i] for i in range(len(cmds))]


def fallback_decisions(guard, cmds, root):
    # No sigil on PATH: the guard reads its own patterns.
    path = "/usr/bin:/bin"
    out = []
    for cmd in cmds:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
        }
        p = subprocess.run(
            ["sh", guard],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env={"PATH": path, "HOME": root, "LC_ALL": "C"},
            timeout=120,
        )
        out.append(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--sigil", default=os.environ.get("SIGIL_BIN") or shutil.which("sigil"))
    ap.add_argument("--guard", default=DEFAULT_GUARD)
    ap.add_argument("--show", type=int, default=15, help="how many problems to print")
    args = ap.parse_args()
    if not args.sigil or not os.path.exists(args.sigil):
        sys.exit("no sigil binary: pass --sigil or set SIGIL_BIN")
    guard = os.path.abspath(args.guard)
    if shutil.which("sigil") and os.path.realpath(shutil.which("sigil")) != os.path.realpath(args.sigil):
        print("note: another sigil is on PATH; the fallback is run with a PATH that has none")

    rng = random.Random(args.seed)
    shells = ["bash", "sh"] + (["dash"] if shutil.which("dash") else [])
    seen, cmds = set(), []
    while len(cmds) < args.count:
        cmd = generate(rng, shells)
        if cmd not in seen:
            seen.add(cmd)
            cmds.append(cmd)

    with tempfile.TemporaryDirectory(prefix="sigil-nested-") as root:
        bindir = make_stubs(root)
        truth = [really_runs_the_flag(c, root, bindir) for c in cmds]
        native = native_decisions(args.sigil, cmds)
        mcp = mcp_decisions(args.sigil, cmds)
        fallback = fallback_decisions(guard, cmds, root)

    asks = lambda d: d in ("ask", "deny")  # noqa: E731
    missed = [
        (c, n, m, f)
        for c, t, n, m, f in zip(cmds, truth, native, mcp, fallback)
        if t and not (asks(n) and asks(m) and asks(f))
    ]
    disagree = [
        (c, n, m, f)
        for c, n, m, f in zip(cmds, native, mcp, fallback)
        if len({n, m, f}) != 1
    ]
    ran = sum(truth)
    benign = [i for i, t in enumerate(truth) if not t]
    over = sum(1 for i in benign if asks(native[i]))
    print(f"seed {args.seed}: {len(cmds)} generated commands, {ran} really run the flag under bash")
    print(
        f"native: {sum(asks(n) for n in native)} ask/deny; mcp: {sum(asks(m) for m in mcp)}; "
        f"fallback: {sum(asks(f) for f in fallback)}"
    )
    print(
        f"of {len(benign)} commands that do not run the flag, native asked about {over} "
        f"(over-asking, by design)"
    )
    print(f"missed (allowed although it runs the flag): {len(missed)}")
    for c, n, m, f in missed[: args.show]:
        print(f"  MISSED native={n} mcp={m} fallback={f}: {c!r}")
    print(f"disagreements between native, mcp and fallback: {len(disagree)}")
    for c, n, m, f in disagree[: args.show]:
        print(f"  DISAGREE native={n} mcp={m} fallback={f}: {c!r}")
    sys.exit(1 if missed or disagree else 0)


if __name__ == "__main__":
    main()
