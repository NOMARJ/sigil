"""
Sigil API — Scan Analysis Service

Implements the six-phase scan logic:
    1. Install Hooks   — setup.py, npm postinstall, Makefile hooks
    2. Code Patterns   — eval, exec, pickle, child_process, etc.
    3. Network / Exfil — outbound HTTP, webhooks, raw sockets
    4. Credentials     — ENV vars, API keys, SSH keys, tokens
    5. Obfuscation     — base64, charCode, hex encoding tricks
    6. Provenance      — git history anomalies, binaries, hidden files

Each phase runs a set of compiled regex rules against file content and
produces ``Finding`` objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from api.models import Finding, ScanPhase, Severity


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    phase: ScanPhase
    severity: Severity
    pattern: re.Pattern[str]
    description: str = ""
    weight: float = 1.0
    file_glob: str = "*"  # Restrict to certain file patterns (unused for now)


# ---------------------------------------------------------------------------
# Built-in rule sets — one list per phase
# ---------------------------------------------------------------------------


def _compile(rules: list[dict]) -> list[Rule]:  # type: ignore[type-arg]
    """Helper to compile raw rule dicts into ``Rule`` objects."""
    compiled: list[Rule] = []
    for r in rules:
        compiled.append(
            Rule(
                id=r["id"],
                phase=r["phase"],
                severity=r["severity"],
                pattern=re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE),
                description=r.get("description", ""),
                weight=r.get("weight", 1.0),
            )
        )
    return compiled


INSTALL_HOOK_RULES = _compile(
    [
        {
            "id": "install-setup-py-cmdclass",
            "phase": ScanPhase.INSTALL_HOOKS,
            "severity": Severity.CRITICAL,
            "pattern": r"cmdclass\s*=\s*\{",
            "description": "setup.py overrides cmdclass — may execute code during install",
            "weight": 1.0,
        },
        {
            "id": "install-npm-postinstall",
            "phase": ScanPhase.INSTALL_HOOKS,
            "severity": Severity.CRITICAL,
            "pattern": r"\"(pre|post)install\"\s*:",
            "description": "npm lifecycle script — runs automatically on install",
            "weight": 1.0,
        },
        {
            "id": "install-pip-setup-exec",
            "phase": ScanPhase.INSTALL_HOOKS,
            "severity": Severity.CRITICAL,
            "pattern": r"setup\s*\([\s\S]*?(subprocess|os\.system|exec|eval)\s*\(",
            "description": "setup.py executes code at install time",
            "weight": 1.2,
        },
        {
            "id": "install-makefile-curl",
            "phase": ScanPhase.INSTALL_HOOKS,
            "severity": Severity.HIGH,
            "pattern": r"(curl|wget)\s+.+\|\s*(sh|bash)",
            "description": "Makefile/script pipes remote content to shell",
            "weight": 1.0,
        },
    ]
)

CODE_PATTERN_RULES = _compile(
    [
        {
            "id": "code-eval",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"\beval\s*\(",
            "description": "Dynamic code execution via eval()",
        },
        {
            "id": "code-exec",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"\bexec\s*\(",
            "description": "Dynamic code execution via exec()",
        },
        {
            "id": "code-pickle-load",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"pickle\.(loads?|Unpickler)\s*\(",
            "description": "Pickle deserialization — arbitrary code execution risk",
        },
        {
            "id": "code-child-process",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"(child_process|subprocess)\.(exec|spawn|call|run|Popen)\s*\(",
            "description": "Spawns child process / shell command",
        },
        {
            "id": "code-compile",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.MEDIUM,
            "pattern": r"\bcompile\s*\(.+['\"]exec['\"]",
            "description": "compile() with exec mode — dynamic code generation",
        },
        {
            "id": "code-importlib",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.MEDIUM,
            "pattern": r"__import__\s*\(|importlib\.import_module\s*\(",
            "description": "Dynamic module import",
        },
    ]
)

NETWORK_EXFIL_RULES = _compile(
    [
        {
            "id": "net-http-request",
            "phase": ScanPhase.NETWORK_EXFIL,
            "severity": Severity.MEDIUM,
            "pattern": r"(requests\.(get|post|put)|urllib\.request\.urlopen|http\.client\.HTTP|fetch\s*\(|axios\.(get|post)|httpx\.(get|post|AsyncClient))\s*\(",
            "description": "Outbound HTTP request",
        },
        {
            "id": "net-webhook",
            "phase": ScanPhase.NETWORK_EXFIL,
            "severity": Severity.HIGH,
            "pattern": r"(webhook|discord\.com/api/webhooks|hooks\.slack\.com)",
            "description": "Webhook URL — potential data exfiltration endpoint",
        },
        {
            "id": "net-raw-socket",
            "phase": ScanPhase.NETWORK_EXFIL,
            "severity": Severity.HIGH,
            "pattern": r"socket\.socket\s*\(|net\.createConnection\s*\(",
            "description": "Raw socket creation — may bypass HTTP monitoring",
        },
        {
            "id": "net-dns-exfil",
            "phase": ScanPhase.NETWORK_EXFIL,
            "severity": Severity.HIGH,
            "pattern": r"dns\.(resolve|lookup)|getaddrinfo\s*\(",
            "description": "DNS query — possible DNS exfiltration technique",
        },
    ]
)

CREDENTIAL_RULES = _compile(
    [
        {
            "id": "cred-env-access",
            "phase": ScanPhase.CREDENTIALS,
            "severity": Severity.MEDIUM,
            "pattern": r"(os\.environ|process\.env)\[?['\"]?(AWS_|GITHUB_|API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)",
            "description": "Reads sensitive environment variable",
        },
        {
            "id": "cred-hardcoded-key",
            "phase": ScanPhase.CREDENTIALS,
            "severity": Severity.HIGH,
            "pattern": r"(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*['\"][A-Za-z0-9+/=]{16,}['\"]",
            "description": "Hardcoded credential or API key",
        },
        {
            "id": "cred-ssh-private",
            "phase": ScanPhase.CREDENTIALS,
            "severity": Severity.CRITICAL,
            "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "description": "Embedded SSH/TLS private key",
        },
        {
            "id": "cred-aws-key",
            "phase": ScanPhase.CREDENTIALS,
            "severity": Severity.CRITICAL,
            "pattern": r"AKIA[0-9A-Z]{16}",
            "description": "AWS access key ID pattern",
        },
    ]
)

OBFUSCATION_RULES = _compile(
    [
        {
            "id": "obf-base64-decode",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"(base64\.(b64decode|decodebytes)|atob)\s*\(",
            "description": "Base64 decoding — may hide malicious payloads",
        },
        {
            "id": "obf-charcode",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"(String\.fromCharCode|chr)\s*\(",
            "description": "Character code construction — may obfuscate strings",
        },
        {
            "id": "obf-hex-decode",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"(\\x[0-9a-fA-F]{2}){4,}|bytes\.fromhex\s*\(",
            "description": "Hex-encoded data — may hide malicious payloads",
        },
        {
            "id": "obf-reverse-string",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.MEDIUM,
            "pattern": r"\[::-1\]|\.reverse\(\)\.join\(",
            "description": "String reversal technique — potential obfuscation",
        },
    ]
)

PROVENANCE_RULES = _compile(
    [
        {
            "id": "prov-hidden-file",
            "phase": ScanPhase.PROVENANCE,
            "severity": Severity.LOW,
            "pattern": r"^\.",
            "description": "Hidden file detected",
            "weight": 1.0,
        },
        {
            "id": "prov-binary-in-repo",
            "phase": ScanPhase.PROVENANCE,
            "severity": Severity.MEDIUM,
            "pattern": r"\.(exe|dll|so|dylib|bin|dat)$",
            "description": "Binary file in repository",
            "weight": 1.5,
        },
        {
            "id": "prov-minified",
            "phase": ScanPhase.PROVENANCE,
            "severity": Severity.LOW,
            "pattern": r"\.min\.(js|css)$",
            "description": "Minified file — harder to audit",
            "weight": 1.0,
        },
    ]
)

ALL_RULES: list[Rule] = (
    INSTALL_HOOK_RULES
    + CODE_PATTERN_RULES
    + NETWORK_EXFIL_RULES
    + CREDENTIAL_RULES
    + OBFUSCATION_RULES
    + PROVENANCE_RULES
)


# ---------------------------------------------------------------------------
# Text-safe check
# ---------------------------------------------------------------------------

_TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".sh",
    ".bash",
    ".zsh",
    ".md",
    ".rst",
    ".txt",
    ".html",
    ".css",
    ".scss",
    ".xml",
    ".csv",
    ".env",
    ".lock",
    ".conf",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cs",
    ".php",
    ".pl",
    ".lua",
    ".r",
    ".R",
    ".swift",
    ".kt",
    ".gradle",
    ".cmake",
    ".make",
    ".Makefile",
}


def _is_scannable(path: Path) -> bool:
    """Return True if the file is likely a text file we should scan."""
    if path.suffix in _TEXT_EXTENSIONS:
        return True
    # Also accept files with no extension (scripts, Makefile, Dockerfile, etc.)
    if path.suffix == "" and path.stat().st_size < 1_000_000:
        return True
    return False


# ---------------------------------------------------------------------------
# Phase-specific scanner
# ---------------------------------------------------------------------------


@dataclass
class PhaseResult:
    """Findings collected by a single scan phase."""

    phase: ScanPhase
    findings: list[Finding] = field(default_factory=list)


def _scan_content(content: str, file_path: str, rules: list[Rule]) -> Iterator[Finding]:
    """Run *rules* against *content* and yield ``Finding`` objects."""
    for rule in rules:
        for match in rule.pattern.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            # Extract a snippet: the matching line +-0 context
            lines = content.splitlines()
            idx = line_no - 1
            start = max(0, idx - 1)
            end = min(len(lines), idx + 2)
            snippet = "\n".join(lines[start:end])

            yield Finding(
                phase=rule.phase,
                rule=rule.id,
                severity=rule.severity,
                file=file_path,
                line=line_no,
                snippet=snippet[:500],  # Cap snippet length
                weight=rule.weight,
            )


def _scan_filename(file_path: str, rules: list[Rule]) -> Iterator[Finding]:
    """Run *rules* against the filename itself (used for provenance checks)."""
    name = Path(file_path).name
    for rule in rules:
        if rule.pattern.search(name):
            yield Finding(
                phase=rule.phase,
                rule=rule.id,
                severity=rule.severity,
                file=file_path,
                line=0,
                snippet=name,
                weight=rule.weight,
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_directory(path: str | Path) -> list[Finding]:
    """Perform a full six-phase scan of a directory tree.

    Returns a flat list of ``Finding`` objects from all phases.
    """
    root = Path(path)
    if not root.exists():
        return []

    all_findings: list[Finding] = []

    # Phases 1-5: content-based scanning
    content_rules = (
        INSTALL_HOOK_RULES
        + CODE_PATTERN_RULES
        + NETWORK_EXFIL_RULES
        + CREDENTIAL_RULES
        + OBFUSCATION_RULES
    )

    for file_path in _walk_files(root):
        rel = str(file_path.relative_to(root))

        # Phase 6 (provenance) — filename-based checks
        all_findings.extend(_scan_filename(rel, PROVENANCE_RULES))

        # Phases 1-5 — content checks
        if _is_scannable(file_path):
            try:
                content = file_path.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            all_findings.extend(_scan_content(content, rel, content_rules))

    return all_findings


def scan_content(content: str, filename: str = "<stdin>") -> list[Finding]:
    """Scan a single blob of content (all phases) and return findings.

    Useful when scan content is submitted directly rather than from disk.
    """
    findings: list[Finding] = []

    findings.extend(_scan_filename(filename, PROVENANCE_RULES))
    findings.extend(_scan_content(content, filename, ALL_RULES))

    return findings


def _walk_files(root: Path) -> Iterator[Path]:
    """Yield all regular files under *root*, skipping common noise dirs."""
    skip_dirs = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
    }
    for child in sorted(root.iterdir()):
        if child.name in skip_dirs:
            continue
        if child.is_file():
            yield child
        elif child.is_dir():
            yield from _walk_files(child)


def count_scannable_files(path: str | Path) -> int:
    """Return the count of scannable files under *path*."""
    root = Path(path)
    if not root.exists():
        return 0
    return sum(1 for _ in _walk_files(root))
