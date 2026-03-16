"""
Sigil Scanner v1 (Legacy)

Original scanner implementation preserved for rollback capability.
This version has higher false positive rates but provides fallback
for situations where v2 enhancements cause issues.

IMPORTANT: This is the original scanner before false positive fixes.
Only use when explicitly requested via SCANNER_VERSION=1.0.0.
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from api.models import Finding, ScanPhase, Severity, Confidence


# Original v1 patterns (before false positive fixes)
@dataclass
class ScanRule:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence = Confidence.HIGH  # v1 always used HIGH confidence
    weight: float = 1.0
    description: str = ""


def _build_v1_rules() -> dict[ScanPhase, list[ScanRule]]:
    """Build the original v1 scanner rules (before false positive fixes)."""
    
    rules = {
        ScanPhase.INSTALL_HOOKS: [
            ScanRule(
                "npm-postinstall",
                re.compile(r'"postinstall"\s*:', re.IGNORECASE),
                Severity.CRITICAL,
                weight=10.0,
                description="NPM postinstall hook detected"
            ),
            ScanRule(
                "setup-cmdclass",
                re.compile(r'cmdclass\s*=', re.IGNORECASE),
                Severity.CRITICAL,
                weight=10.0,
                description="Python setup.py cmdclass hook detected"
            ),
        ],
        
        ScanPhase.CODE_PATTERNS: [
            # Original v1 exec detection (flagged ALL exec usage)
            ScanRule(
                "code-exec-dangerous",
                re.compile(r'\b(exec|eval)\s*\(', re.IGNORECASE),
                Severity.HIGH,
                weight=5.0,
                description="Code execution detected"
            ),
            # Original v1 flagged ALL .exec() calls as dangerous
            ScanRule(
                "regexp-exec-dangerous",
                re.compile(r'\.exec\s*\(', re.IGNORECASE),
                Severity.HIGH,
                weight=5.0,
                description="Potentially dangerous execution pattern"
            ),
            ScanRule(
                "pickle-usage",
                re.compile(r'\bpickle\.(loads?|dumps?)\s*\(', re.IGNORECASE),
                Severity.HIGH,
                weight=4.0,
                description="Pickle serialization detected"
            ),
        ],
        
        ScanPhase.NETWORK_EXFIL: [
            # Original v1 flagged ALL network requests as suspicious
            ScanRule(
                "network-request",
                re.compile(r'\b(fetch|axios|requests?\.(?:get|post))\s*\(', re.IGNORECASE),
                Severity.MEDIUM,
                weight=3.0,
                description="Network request detected"
            ),
            ScanRule(
                "webhook-usage",
                re.compile(r'\bhttps?://.*webhook', re.IGNORECASE),
                Severity.HIGH,
                weight=4.0,
                description="Webhook URL detected"
            ),
        ],
        
        ScanPhase.CREDENTIALS: [
            ScanRule(
                "env-access",
                re.compile(r'\bprocess\.env\[|os\.environ\[', re.IGNORECASE),
                Severity.MEDIUM,
                weight=2.0,
                description="Environment variable access"
            ),
            ScanRule(
                "api-key-pattern",
                re.compile(r'\b["\']?[a-z_]*(?:api|key|token|secret)[a-z_]*["\']?\s*[:=]', re.IGNORECASE),
                Severity.MEDIUM,
                weight=2.0,
                description="Potential API key or secret"
            ),
        ],
        
        ScanPhase.OBFUSCATION: [
            # Original v1 flagged ALL base64 usage as suspicious
            ScanRule(
                "base64-decode",
                re.compile(r'\b(atob|base64\.(?:decode|b64decode))\s*\(', re.IGNORECASE),
                Severity.HIGH,
                weight=4.0,
                description="Base64 decoding detected"
            ),
            # Original v1 flagged ALL String.fromCharCode as obfuscation
            ScanRule(
                "charcode-obfuscation",
                re.compile(r'String\.fromCharCode\s*\(', re.IGNORECASE),
                Severity.HIGH,
                weight=4.0,
                description="Character code obfuscation detected"
            ),
            ScanRule(
                "hex-encoding",
                re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE),
                Severity.MEDIUM,
                weight=2.0,
                description="Hexadecimal encoding detected"
            ),
        ],
        
        ScanPhase.PROVENANCE: [
            ScanRule(
                "suspicious-filename",
                re.compile(r'\.(tmp|temp|bak|old)$|^\.', re.IGNORECASE),
                Severity.LOW,
                weight=1.0,
                description="Suspicious filename pattern"
            ),
        ],
    }
    
    return rules


def scan_directory_v1(directory: str) -> list[Finding]:
    """
    Scan directory with original Scanner v1 logic.
    
    This is the legacy scanner preserved for rollback capability.
    It has higher false positive rates than v2 but provides compatibility.
    """
    findings = []
    rules = _build_v1_rules()
    
    directory_path = Path(directory)
    if not directory_path.exists():
        return findings
    
    # Scan all files (v1 didn't have sophisticated filtering)
    for file_path in directory_path.rglob("*"):
        if file_path.is_file():
            try:
                # Try to read file content
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Apply all rules to the content
                for phase, phase_rules in rules.items():
                    for rule in phase_rules:
                        matches = rule.pattern.finditer(content)
                        for match in matches:
                            # Calculate line number
                            line_num = content[:match.start()].count('\n') + 1
                            
                            # Extract snippet around match
                            lines = content.split('\n')
                            snippet_start = max(0, line_num - 2)
                            snippet_end = min(len(lines), line_num + 1)
                            snippet = '\n'.join(lines[snippet_start:snippet_end])
                            
                            finding = Finding(
                                phase=phase,
                                rule=rule.name,
                                severity=rule.severity,
                                confidence=rule.confidence,  # Always HIGH in v1
                                file=str(file_path.relative_to(directory_path)),
                                line=line_num,
                                snippet=snippet[:500],  # Limit snippet length
                                weight=rule.weight,
                                description=rule.description,
                                explanation=""  # v1 didn't have explanations
                            )
                            findings.append(finding)
                            
            except (UnicodeDecodeError, PermissionError):
                # Skip files that can't be read
                continue
    
    return findings


def count_scannable_files_v1(directory: str) -> int:
    """Count scannable files using v1 logic (counts all files)."""
    try:
        directory_path = Path(directory)
        if not directory_path.exists():
            return 0
        
        # v1 counted all files
        return sum(1 for _ in directory_path.rglob("*") if _.is_file())
        
    except Exception:
        return 0


# Compatibility function for systems expecting the original interface
def scan_directory(directory: str) -> list[Finding]:
    """Legacy compatibility wrapper."""
    return scan_directory_v1(directory)


def count_scannable_files(directory: str) -> int:
    """Legacy compatibility wrapper."""
    return count_scannable_files_v1(directory)