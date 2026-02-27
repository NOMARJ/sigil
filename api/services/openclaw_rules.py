"""
Sigil API — OpenClaw-Specific Scan Rules

Detection rules specifically designed for OpenClaw/ClawHub skills.
These catch threats that VirusTotal cannot: prompt injection, metadata
mismatch, tool poisoning, and undeclared access patterns.

VirusTotal partnership (Feb 7 2026) explicitly says: "A skill that uses
natural language to instruct an agent to do something malicious won't
trigger a virus signature."

These rules fill that gap.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from api.models import Finding, ScanPhase, Severity


# ---------------------------------------------------------------------------
# Rule definition (reusable with scanner.py's Rule format)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenClawRule:
    """A detection rule specific to OpenClaw/ClawHub skills."""

    id: str
    phase: ScanPhase
    severity: Severity
    pattern: re.Pattern[str]
    description: str = ""
    weight: float = 1.0


# ---------------------------------------------------------------------------
# Phase 7: Prompt Injection Rules (Critical — this is the differentiator)
# ---------------------------------------------------------------------------

PROMPT_INJECTION_RULES: list[OpenClawRule] = [
    OpenClawRule(
        id="prompt-injection-override",
        phase=ScanPhase.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(ignore\s+(all\s+)?previous\s+instructions?"
            r"|disregard\s+(all\s+)?(previous\s+)?instructions?"
            r"|forget\s+everything"
            r"|you\s+are\s+now\b"
            r"|override\s+(system\s+)?prompt"
            r"|new\s+instructions?\s*:"
            r"|from\s+now\s+on,?\s+you)",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill contains prompt injection override phrases — "
            "attempts to hijack the agent's instruction context"
        ),
        weight=1.0,
    ),
    OpenClawRule(
        id="hidden-exfil-instruction",
        phase=ScanPhase.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(send\s+(all\s+)?(the\s+)?(conversation|chat|history|context|data|content|output)"
            r"\s+(to|via|using)\s+"
            r"|POST\s+(to\s+)?https?://(?!github\.com|api\.openai\.com|api\.anthropic\.com)"
            r"|exfiltrate"
            r"|forward\s+(all\s+)?(messages?|data|content)\s+to"
            r"|upload\s+(the\s+)?(conversation|data|content)\s+to)",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill instructs agent to send conversation data or content "
            "to an external endpoint — potential data exfiltration"
        ),
        weight=1.0,
    ),
    OpenClawRule(
        id="conditional-trigger",
        phase=ScanPhase.PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(if\s+(the\s+)?user\s+(mentions?|says?|asks?\s+about|types?)\s+['\"]"
            r"|when\s+(the\s+)?user\s+(mentions?|says?|asks?\s+about)"
            r".*?(also|first|secretly|quietly|silently)\s+(run|execute|send|post|call))",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill contains conditional trigger that activates hidden "
            "behavior based on user keywords"
        ),
        weight=1.0,
    ),
    OpenClawRule(
        id="jailbreak-persona",
        phase=ScanPhase.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(you\s+are\s+(DAN|AIM|STAN|DUDE|Cooper|JailBreak|UnlimitedGPT)"
            r"|Developer\s+Mode\s+(enabled|activated|on)"
            r"|Do\s+Anything\s+Now"
            r"|act\s+as\s+an?\s+(unrestricted|unfiltered|uncensored)"
            r"|pretend\s+(you\s+are|to\s+be)\s+an?\s+AI\s+without\s+(restrictions?|limits?|rules?))",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill contains known jailbreak persona patterns — "
            "attempts to bypass safety guardrails"
        ),
        weight=1.0,
    ),
]


# ---------------------------------------------------------------------------
# Phase 8: Skill Security Rules
# ---------------------------------------------------------------------------

SKILL_SECURITY_RULES: list[OpenClawRule] = [
    OpenClawRule(
        id="tool-poisoning",
        phase=ScanPhase.SKILL_SECURITY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(redefine\s+(the\s+)?(git|npm|pip|curl|wget|ssh|docker|kubectl)\s+command"
            r"|override\s+(the\s+)?(default|standard|normal)\s+(behavior|behaviour)\s+of"
            r"|replace\s+(the\s+)?(git|npm|pip|curl|wget)\s+tool"
            r"|shadow\s+(the\s+)?(built-?in|system|default)\s+(git|npm|pip|curl|wget))",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill redefines or shadows common tool names with altered "
            "behavior — potential tool poisoning attack"
        ),
        weight=1.0,
    ),
    OpenClawRule(
        id="shell-execution-in-instructions",
        phase=ScanPhase.SKILL_SECURITY,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(run\s+(the\s+)?command\s*[:`]"
            r"|execute\s*[:`]\s*(rm\s|chmod\s|curl\s.*\|\s*(sh|bash)|wget\s.*\|\s*(sh|bash))"
            r"|pip\s+install\s+-g"
            r"|npm\s+install\s+-g"
            r"|sudo\s+(rm|chmod|chown|apt|yum|dnf|brew)"
            r"|curl\s+-[a-zA-Z]*s[a-zA-Z]*L?\s+https?://\S+\s*\|\s*(sh|bash))",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill instructs agent to execute shell commands that modify "
            "system state — potential system compromise"
        ),
        weight=1.0,
    ),
    OpenClawRule(
        id="undeclared-env-access",
        phase=ScanPhase.SKILL_SECURITY,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(\$\{?[A-Z][A-Z0-9_]{2,}\}?"
            r"|process\.env\.[A-Z][A-Z0-9_]{2,}"
            r"|os\.environ\[?['\"][A-Z][A-Z0-9_]{2,}"
            r"|getenv\(['\"][A-Z][A-Z0-9_]{2,})",
            re.MULTILINE,  # No IGNORECASE — avoids matching $home, $path, etc.
        ),
        description=(
            "Skill references environment variables — check if these are "
            "declared in skill metadata"
        ),
        weight=0.6,  # Lower weight since env access may be declared
    ),
    OpenClawRule(
        id="base64-in-markdown",
        phase=ScanPhase.SKILL_SECURITY,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?<!\!\[)(?<!data:image/)[A-Za-z0-9+/]{50,}={0,2}(?!\])",
            re.MULTILINE,
        ),
        description=(
            "Long base64-encoded string in markdown file — may hide "
            "malicious payloads or obfuscated instructions"
        ),
        weight=1.0,
    ),
    OpenClawRule(
        id="metadata-mismatch-bins",
        phase=ScanPhase.SKILL_SECURITY,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(requires?\s*:\s*\n[\s\S]*?bins?\s*:"
            r"|\.(exe|dll|so|dylib|bin|cmd|bat|ps1)\b)",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill references binary executables — verify these are "
            "declared in metadata requirements"
        ),
        weight=0.4,  # Reduced weight — binary refs may be legitimate
    ),
    OpenClawRule(
        id="excessive-permissions",
        phase=ScanPhase.SKILL_SECURITY,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(filesystem.*network.*credential"
            r"|read.*write.*execute.*network"
            r"|full[_\s]access"
            r"|unrestricted[_\s]access"
            r"|access[_\s]everything)",
            re.IGNORECASE | re.MULTILINE,
        ),
        description=(
            "Skill requests broad filesystem, network, AND credential "
            "access simultaneously without clear justification"
        ),
        weight=0.5,
    ),
]


ALL_OPENCLAW_RULES: list[OpenClawRule] = PROMPT_INJECTION_RULES + SKILL_SECURITY_RULES


# ---------------------------------------------------------------------------
# Scanner function
# ---------------------------------------------------------------------------


def scan_openclaw_content(
    content: str, file_path: str = "<skill>"
) -> list[Finding]:
    """Run OpenClaw-specific rules against content.

    Returns a list of Finding objects for any matches.
    """
    findings: list[Finding] = []

    for rule in ALL_OPENCLAW_RULES:
        for match in rule.pattern.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            lines = content.splitlines()
            idx = line_no - 1
            start = max(0, idx - 1)
            end = min(len(lines), idx + 2)
            snippet = "\n".join(lines[start:end])

            findings.append(
                Finding(
                    phase=rule.phase,
                    rule=rule.id,
                    severity=rule.severity,
                    file=file_path,
                    line=line_no,
                    snippet=snippet[:500],
                    weight=rule.weight,
                )
            )

    return findings


def scan_openclaw_directory(directory: str) -> list[Finding]:
    """Scan an extracted OpenClaw skill directory with all rules.

    Runs both the standard Sigil scanner and the OpenClaw-specific rules.
    """
    from pathlib import Path

    from api.services.scanner import scan_directory as sigil_scan_directory

    root = Path(directory)
    all_findings: list[Finding] = []

    # Run standard Sigil scan
    all_findings.extend(sigil_scan_directory(directory))

    # Run OpenClaw-specific rules on text files
    text_exts = {".md", ".txt", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv"}

    def walk(path: Path) -> Iterator[Path]:
        for child in sorted(path.iterdir()):
            if child.name in skip_dirs:
                continue
            if child.is_file():
                yield child
            elif child.is_dir():
                yield from walk(child)

    if root.exists():
        for file_path in walk(root):
            if file_path.suffix in text_exts or file_path.name in (
                "SKILL.md", "Makefile", "Dockerfile"
            ):
                try:
                    content = file_path.read_text(errors="replace")
                    rel = str(file_path.relative_to(root))
                    all_findings.extend(scan_openclaw_content(content, rel))
                except (OSError, PermissionError):
                    continue

    return all_findings
