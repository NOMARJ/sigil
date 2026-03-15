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

# Import models with fallback handling
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from api.models import Finding, ScanPhase, Severity
except ImportError:
    import importlib.util

    models_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models.py")
    spec = importlib.util.spec_from_file_location("models", models_path)
    models_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(models_module)
    Finding = models_module.Finding
    ScanPhase = models_module.ScanPhase
    Severity = models_module.Severity
try:
    from api.services.explanations import get_explanation
except ImportError:
    from services.explanations import get_explanation


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
            "id": "code-exec-dangerous",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"(?:^|[^.\w])(exec|os\.system|subprocess\.call)\s*\(",
            "description": "Dynamic code execution via exec(), os.system(), or subprocess.call()",
        },
        {
            "id": "code-exec-child-process",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"child_process\.exec\s*\(",
            "description": "Node.js child_process.exec() - shell command execution",
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
        {
            "id": "net-http-exe-download",
            "phase": ScanPhase.NETWORK_EXFIL,
            "severity": Severity.CRITICAL,
            "pattern": r"http://[^/\s]+/[^\s]*/?(download|payload|agent|install|setup|bin).*\.(exe|sh|dmg|pkg|msi|run|bin)",
            "description": "Downloads executable over unencrypted HTTP — MitM risk (OpenClaw pattern)",
            "weight": 1.5,
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

# Enhanced obfuscation detection rules for gap closure
ENHANCED_OBFUSCATION_RULES = _compile(
    [
        # Base64 Chain Detection
        {
            "id": "obf-base64-nested-chain",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.CRITICAL,
            "pattern": r"(base64\.(b64decode|decodebytes)|atob)\s*\([^)]*?(base64\.(b64decode|decodebytes)|atob)\s*\(",
            "description": "Nested Base64 chain decoding — advanced obfuscation technique",
            "weight": 2.0,
        },
        {
            "id": "obf-base64-dynamic-key",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"(base64\.(b64decode|decodebytes)|atob)\s*\(\s*[\w\+\.\[\]]+\s*\+\s*[\w\+\.\[\]]+",
            "description": "Base64 decoding with dynamic key construction",
            "weight": 1.5,
        },
        {
            "id": "obf-base64-mixed-encoding",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"urllib\.parse\.unquote\s*\(\s*(base64\.(b64decode|decodebytes)|atob)\s*\(|base64\.(b64decode|decodebytes)\s*\(\s*urllib\.parse\.unquote",
            "description": "Mixed Base64 and URL encoding chain",
            "weight": 1.8,
        },
        {
            "id": "obf-base64-pickle-combo",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.CRITICAL,
            "pattern": r"pickle\.(loads?|Unpickler)\s*\(\s*(base64\.(b64decode|decodebytes)|atob)\s*\(",
            "description": "Pickle deserialization with Base64 decoding — dangerous combination",
            "weight": 2.5,
        },
        {
            "id": "obf-hex-base64-chain",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"(base64\.(b64decode|decodebytes)|atob)\s*\(\s*bytes\.fromhex\s*\(|bytes\.fromhex\s*\([^)]+\)\.decode\(\).*\n.*base64\.(b64decode|decodebytes)",
            "description": "Hex to Base64 decoding chain",
            "weight": 1.7,
        },
        # Unicode Steganography Detection
        {
            "id": "obf-unicode-zero-width",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"[\u200B-\u200D\uFEFF]",  # Zero-width characters
            "description": "Zero-width Unicode characters detected — potential steganography",
            "weight": 1.5,
        },
        {
            "id": "obf-unicode-rtl-override",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"[\u202E\u202D\u2066-\u2069]",  # RTL/LTR override characters
            "description": "Unicode directional override characters — text direction attack",
            "weight": 1.8,
        },
        {
            "id": "obf-unicode-invisible-chars",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.MEDIUM,
            "pattern": r"[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]",  # Combining characters
            "description": "Invisible combining characters detected — potential payload hiding",
            "weight": 1.3,
        },
        {
            "id": "obf-unicode-homograph",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.MEDIUM,
            "pattern": r"[а-яё].*\.(com|org|net|gov|edu)",  # Cyrillic chars in domains (basic check)
            "description": "Potential Unicode homograph attack in domain",
            "weight": 1.2,
        },
        # Dynamic Property Access Detection
        {
            "id": "obf-dynamic-property-access",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"(window|global|this|document)\s*\[\s*[\"\']?[\w]+[\"\']?\s*\+\s*[\"\']?[\w]+[\"\']?\s*\]|(window|global|this|document)\s*\[\s*\w+\s*\]\s*\(",
            "description": "Dynamic property access with string concatenation or variable reference",
            "weight": 1.6,
        },
        {
            "id": "obf-dynamic-function-constructor",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.CRITICAL,
            "pattern": r"Function\s*\.\s*constructor\s*\(.*\.join\s*\(|new\s+Function\s*\(\s*[\w\[\]\.]+\s*\+",
            "description": "Dynamic Function constructor with string building",
            "weight": 2.2,
        },
        # Additional enhanced patterns for gap closure
        {
            "id": "obf-unicode-escape-sequences",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}",
            "description": "Multiple Unicode escape sequences — potential payload encoding",
            "weight": 1.4,
        },
        {
            "id": "obf-mixed-script-identifiers",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.MEDIUM,
            "pattern": r"[\u0100-\u017F\u0180-\u024F\u1E00-\u1EFF].*[a-zA-Z].*[\u0400-\u04FF]",
            "description": "Mixed script characters in identifiers — potential homograph attack",
            "weight": 1.2,
        },
        {
            "id": "obf-javascript-string-fromcharcode-chain",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+",
            "description": "JavaScript String.fromCharCode chain — character-based obfuscation",
            "weight": 1.6,
        },
        {
            "id": "obf-base64-url-double-encoding",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"decodeURIComponent\s*\(\s*(base64\.(b64decode|decodebytes)|atob)",
            "description": "Base64 with URL decoding — double encoding obfuscation",
            "weight": 1.7,
        },
        {
            "id": "obf-python-compile-exec-chain",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.CRITICAL,
            "pattern": r"exec\s*\(\s*compile\s*\(\s*[\w\.]+\s*\+\s*[\w\.]+",
            "description": "Python compile+exec with string concatenation — advanced code execution",
            "weight": 2.1,
        },
        {
            "id": "obf-import-time-execution",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"__import__\s*\(\s*[\"\'][\w\.]+[\"\']\s*\)\s*\.\s*\w+\s*\(",
            "description": "Dynamic import with immediate method execution — import-time side effect",
            "weight": 1.8,
        },
        {
            "id": "obf-encoded-import-names",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.MEDIUM,
            "pattern": r"__import__\s*\(\s*(chr\s*\(|String\.fromCharCode|base64\.|atob)",
            "description": "Dynamic import with encoded module names — import obfuscation",
            "weight": 1.5,
        },
        {
            "id": "obf-reflection-method-calls",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"getattr\s*\(\s*\w+\s*,\s*[\"\'][\w]+[\"\']?\s*\+\s*[\"\'][\w]+[\"\']?\s*\)",
            "description": "Python getattr with concatenated attribute names — reflection-based obfuscation",
            "weight": 1.6,
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

# Novel Vector Rules - Advanced supply chain attack patterns
NOVEL_VECTOR_RULES = _compile(
    [
        # --- Supply Chain Polymorphism (7 patterns) ---
        {
            "id": "novel-polymorphic-deps",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.CRITICAL,
            "pattern": r"fs\.(write|writeFile).*package\.json|dependencies.*fs\.(write|writeFile)",
            "description": "Self-modifying package.json dependencies detected",
            "weight": 1.5,
        },
        {
            "id": "novel-version-hijack",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"[\"\'][\^~]?\d+\.\d+\.\d+\s*\|\|\s*[\^~]?\d{2,}\.|\>=\d+\.\d+\.\d+\s*<\d+\.\d+\.\d+\s*\|\|\s*\>=\d{2,}",
            "description": "Suspicious version range that could allow hijacking",
            "weight": 1.2,
        },
        {
            "id": "novel-git-url-hijack",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"git\+(ssh|https?)://[^@]+@[^/]+/.*#(?!main|master|v\d+)",
            "description": "Git dependency with non-standard branch reference",
            "weight": 1.1,
        },
        {
            "id": "novel-transitive-confusion",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.MEDIUM,
            "pattern": r"require\(['\"][\./]*node_modules/[^/]+/node_modules/",
            "description": "Direct access to transitive dependencies",
            "weight": 1.0,
        },
        {
            "id": "novel-registry-redirect",
            "phase": ScanPhase.NETWORK_EXFIL,
            "severity": Severity.HIGH,
            "pattern": r"registry.*https?://[^\"']*(?<!npmjs\.org)(?<!pypi\.org)|publishConfig.*registry",
            "description": "Non-standard package registry configured",
            "weight": 1.3,
        },
        {
            "id": "novel-phantom-dependency",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"require\.resolve\([^)]+\).*catch.*require\([^)]+\)",
            "description": "Phantom dependency pattern with fallback",
            "weight": 1.1,
        },
        {
            "id": "novel-dependency-swapping",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"Module\._load\s*=|require\.cache\[[^\]]+\]\s*=|module\.exports\s*=.*require\(",
            "description": "Runtime dependency replacement detected",
            "weight": 1.2,
        },
        # --- Build-Time Code Generation (6 patterns) ---
        {
            "id": "novel-template-injection",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"new Function\([^)]*`|\$\{[^}]*eval|template\s*\([^)]*\).*exec",
            "description": "Template literal code injection pattern",
            "weight": 1.2,
        },
        {
            "id": "novel-macro-expansion",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"define\s*\([^)]*exec|macro\s*\([^)]*Function|__macro__.*eval",
            "description": "Macro expansion with code execution",
            "weight": 1.1,
        },
        {
            "id": "novel-source-map-poison",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.MEDIUM,
            "pattern": r"sourceMappingURL\s*=.*data:.*base64|sourceMap\s*:.*atob\(",
            "description": "Inline source map with base64 payload",
            "weight": 1.0,
        },
        {
            "id": "novel-ast-manipulation",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"(esprima|acorn|babel)\.parse.*traverse.*enter.*Function\(|AST.*node\.type.*=|transform.*CallExpression.*eval",
            "description": "AST manipulation with code generation",
            "weight": 1.3,
        },
        {
            "id": "novel-webpack-plugin",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.CRITICAL,
            "pattern": r"class\s+\w+Plugin.*apply\s*\(compiler\).*eval|compiler\.(plugin|hooks).*Function\(|webpack.*plugin.*exec\(",
            "description": "Webpack plugin with dynamic code execution",
            "weight": 1.4,
        },
        {
            "id": "novel-babel-transform",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"babel.*transform.*visitor.*Function\(|transformSync.*plugins.*eval|preset.*visitor.*exec",
            "description": "Babel transformer with code injection",
            "weight": 1.2,
        },
        # --- Cross-Language Bridge Exploits (6 patterns) ---
        {
            "id": "novel-wasm-payload",
            "phase": ScanPhase.OBFUSCATION,
            "severity": Severity.HIGH,
            "pattern": r"WebAssembly\.(instantiate|compile)|Uint8Array\s*\(\s*\[[\d\s,]{50,}",
            "description": "Large WASM binary payload detected",
            "weight": 1.3,
        },
        {
            "id": "novel-native-binding",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"require\(['\"]\.\.?/build/.*\.node|bindings\([^)]+\).*exec|napi.*dlopen.*system",
            "description": "Native binding with suspicious behavior",
            "weight": 1.2,
        },
        {
            "id": "novel-ffi-boundary",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.CRITICAL,
            "pattern": r"ffi\.(Library|Function).*\bsystem\b|Foreign.*invoke.*exec|ctypes.*CDLL.*os\.system",
            "description": "FFI boundary violation with command execution",
            "weight": 1.5,
        },
        {
            "id": "novel-python-js-bridge",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"PythonShell|python-shell|pyodide|Pyodide",
            "description": "Python-JavaScript bridge with code execution",
            "weight": 1.2,
        },
        {
            "id": "novel-rust-bridge",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"wasm_bindgen.*#\[wasm_bindgen\].*unsafe|wasm-pack.*--target.*eval|rustwasm.*Memory.*grow",
            "description": "Rust-WASM bridge with unsafe operations",
            "weight": 1.1,
        },
        {
            "id": "novel-jni-exploit",
            "phase": ScanPhase.CODE_PATTERNS,
            "severity": Severity.HIGH,
            "pattern": r"Java\.type.*Runtime.*exec|jni.*CallStaticMethod.*system|JNI.*GetMethodID.*ProcessBuilder",
            "description": "JNI exploitation pattern detected",
            "weight": 1.2,
        },
    ]
)

ALL_RULES: list[Rule] = (
    INSTALL_HOOK_RULES
    + CODE_PATTERN_RULES
    + NETWORK_EXFIL_RULES
    + CREDENTIAL_RULES
    + OBFUSCATION_RULES
    + ENHANCED_OBFUSCATION_RULES
    + PROVENANCE_RULES
    + NOVEL_VECTOR_RULES
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


def _is_eval_in_safe_context(content: str, match_start: int) -> bool:
    """Check if eval() is in a safe context (string literal, regex, comment)."""
    # Check if we're inside a string literal
    before = content[:match_start]

    # Count unescaped quotes to determine if we're inside a string
    in_single_quote = False
    in_double_quote = False
    in_template_literal = False
    escape_next = False

    for char in before:
        if escape_next:
            escape_next = False
            continue

        if char == "\\":
            escape_next = True
            continue

        if not in_single_quote and not in_template_literal and char == '"':
            in_double_quote = not in_double_quote
        elif not in_double_quote and not in_template_literal and char == "'":
            in_single_quote = not in_single_quote
        elif not in_double_quote and not in_single_quote and char == "`":
            in_template_literal = not in_template_literal

    if in_single_quote or in_double_quote or in_template_literal:
        return True

    # Check if we're in a regex literal (basic heuristic)
    line_start = before.rfind("\n")
    line_content = content[line_start + 1 : match_start + 10]
    if re.search(r"/.*eval.*/", line_content):
        return True

    # Check if we're in a comment
    line_before = before[line_start + 1 :]
    if "//" in line_before or line_before.strip().startswith("#"):
        return True

    # Check if we're inside a block comment /* */
    last_block_comment_start = before.rfind("/*")
    last_block_comment_end = before.rfind("*/")
    if last_block_comment_start > last_block_comment_end:
        return True

    return False


def _is_charcode_benign(content: str, match_start: int) -> bool:
    """Check if String.fromCharCode() usage is benign (single character, Excel columns, etc.)."""
    # Extract the line containing the match for context analysis
    line_start = content.rfind("\n", 0, match_start)
    line_end = content.find("\n", match_start)
    if line_end == -1:
        line_end = len(content)

    line = content[line_start + 1 : line_end]

    # Pattern 1: Single character generation like String.fromCharCode(64 + col)
    if re.search(r"String\.fromCharCode\s*\(\s*\d+\s*[\+\-]\s*\w+\s*\)", line):
        return True

    # Pattern 2: Single static character like String.fromCharCode(65)
    if re.search(r"String\.fromCharCode\s*\(\s*\d{1,3}\s*\)", line):
        return True

    # Pattern 3: Excel column generation patterns
    if re.search(
        r"(col|column|char|letter).*String\.fromCharCode", line, re.IGNORECASE
    ):
        return True

    # Pattern 4: Single chr() call with reasonable number
    if re.search(r"chr\s*\(\s*\d{1,3}\s*\)", line):
        return True

    return False


# Known-safe domains for API calls
SAFE_DOMAINS = {
    "api.anthropic.com",
    "api.openai.com",
    "api.groq.com",
    "api.cohere.ai",
    "bedrock-runtime.us-east-1.amazonaws.com",
    "bedrock-runtime.us-west-2.amazonaws.com",
    "bedrock-runtime.eu-west-1.amazonaws.com",
    "bedrock-runtime.ap-southeast-2.amazonaws.com",
    "huggingface.co",
    "api.huggingface.co",
    "localhost",
    "127.0.0.1",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "pypi.python.org",
    "files.pythonhosted.org",
}


def _is_http_request_safe(content: str, match_start: int) -> bool:
    """Check if HTTP request is to a known-safe domain."""
    # Extract context around the match to find URL
    line_start = content.rfind("\n", 0, match_start)
    line_end = content.find("\n", match_start)
    if line_end == -1:
        line_end = len(content)

    # Get a wider context (3 lines) to catch URLs that might be on different lines
    context_start = line_start
    for _ in range(2):  # Go back up to 2 more lines
        prev_line = content.rfind("\n", 0, context_start - 1)
        if prev_line == -1:
            break
        context_start = prev_line

    context_end = line_end
    for _ in range(2):  # Go forward up to 2 more lines
        next_line = content.find("\n", context_end + 1)
        if next_line == -1:
            break
        context_end = next_line

    context = content[context_start:context_end]

    # Look for URL patterns in the context
    url_patterns = [
        r'https?://([^/\s\'"]+)',
        r'["\']https?://([^/\s\'"]+)["\']',
        r'url\s*[:=]\s*["\']https?://([^/\s\'"]+)["\']',
    ]

    for pattern in url_patterns:
        matches = re.findall(pattern, context)
        for domain in matches:
            # Clean up domain (remove port, etc.)
            clean_domain = domain.split(":")[0].lower()
            if clean_domain in SAFE_DOMAINS:
                return True

    return False


def _adjust_severity_by_file_context(severity: Severity, file_path: str) -> Severity:
    """Adjust severity based on file context (documentation, tests, etc.)."""
    file_path_lower = file_path.lower()

    # Documentation files - reduce severity by 2 levels
    if (
        file_path_lower.endswith(".md")
        or "readme" in file_path_lower
        or file_path_lower.startswith("docs/")
        or "/docs/" in file_path_lower
    ):
        if severity == Severity.CRITICAL:
            return Severity.MEDIUM
        elif severity == Severity.HIGH:
            return Severity.LOW
        elif severity == Severity.MEDIUM:
            return Severity.LOW
        return severity

    # Test files - reduce severity by 1 level
    if (
        ".test." in file_path_lower
        or "tests/" in file_path_lower
        or "/tests/" in file_path_lower
        or file_path_lower.endswith("_test.py")
        or file_path_lower.endswith("_test.js")
    ):
        if severity == Severity.CRITICAL:
            return Severity.HIGH
        elif severity == Severity.HIGH:
            return Severity.MEDIUM
        return severity

    return severity


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
            # Context-aware filtering for specific rules
            if rule.id == "code-eval" and _is_eval_in_safe_context(
                content, match.start()
            ):
                continue
            if rule.id == "obf-charcode" and _is_charcode_benign(
                content, match.start()
            ):
                continue
            if rule.id == "net-http-request" and _is_http_request_safe(
                content, match.start()
            ):
                continue

            line_no = content[: match.start()].count("\n") + 1
            # Extract a snippet: the matching line +-0 context
            lines = content.splitlines()
            idx = line_no - 1
            start = max(0, idx - 1)
            end = min(len(lines), idx + 2)
            snippet = "\n".join(lines[start:end])

            # Apply file context severity adjustment
            adjusted_severity = _adjust_severity_by_file_context(
                rule.severity, file_path
            )

            yield Finding(
                phase=rule.phase,
                rule=rule.id,
                severity=adjusted_severity,
                file=file_path,
                line=line_no,
                snippet=snippet[:500],  # Cap snippet length
                weight=rule.weight,
                description=rule.description,
                explanation=get_explanation(rule.id),
            )

    # Enhanced multi-line pattern detection for nested Base64 chains
    if _detect_base64_chain_pattern(content):
        # Find the first base64 decode call to get line number
        base64_match = re.search(
            r"(base64\.(b64decode|decodebytes)|atob)\s*\(", content
        )
        if base64_match:
            line_no = content[: base64_match.start()].count("\n") + 1
            lines = content.splitlines()
            idx = line_no - 1
            start = max(0, idx - 1)
            end = min(len(lines), idx + 4)  # Show more context for multi-line patterns
            snippet = "\n".join(lines[start:end])

            yield Finding(
                phase=ScanPhase.OBFUSCATION,
                rule="obf-base64-nested-chain",
                severity=Severity.CRITICAL,
                file=file_path,
                line=line_no,
                snippet=snippet[:500],
                weight=2.0,
                description="Nested Base64 chain decoding — advanced obfuscation technique",
                explanation=get_explanation("obf-base64-nested-chain"),
            )

    # Enhanced multi-line pattern detection for hex+Base64 chains
    if _detect_hex_base64_chain_pattern(content):
        hex_match = re.search(r"bytes\.fromhex\s*\(", content)
        if hex_match:
            line_no = content[: hex_match.start()].count("\n") + 1
            lines = content.splitlines()
            idx = line_no - 1
            start = max(0, idx - 1)
            end = min(len(lines), idx + 4)
            snippet = "\n".join(lines[start:end])

            yield Finding(
                phase=ScanPhase.OBFUSCATION,
                rule="obf-hex-base64-chain",
                severity=Severity.HIGH,
                file=file_path,
                line=line_no,
                snippet=snippet[:500],
                weight=1.7,
                description="Hex to Base64 decoding chain",
                explanation=get_explanation("obf-hex-base64-chain"),
            )


def _detect_base64_chain_pattern(content: str) -> bool:
    """Detect Base64 chain patterns across multiple lines."""
    # Count Base64 decode calls
    base64_calls = len(
        re.findall(r"(base64\.(b64decode|decodebytes)|atob)\s*\(", content)
    )

    # Look for variable assignment patterns with Base64 decode followed by another Base64 decode using that variable
    if base64_calls >= 2:
        # Pattern: var = base64.decode(...); other_var = base64.decode(var)
        lines = content.split("\n")
        base64_vars = []

        for line in lines:
            # Look for Base64 decode assignment
            b64_assign_match = re.search(
                r"(\w+)\s*=\s*(base64\.(b64decode|decodebytes)|atob)\s*\(", line
            )
            if b64_assign_match:
                var_name = b64_assign_match.group(1)
                base64_vars.append(var_name)
                continue

            # Check if this line uses a previously decoded variable in another Base64 decode
            for var in base64_vars:
                pattern = rf"(base64\.(b64decode|decodebytes)|atob)\s*\(\s*{re.escape(var)}\s*\)"
                if re.search(pattern, line):
                    return True

        # Also check if any variable from Base64 decode is used in another Base64 decode
        for var in base64_vars:
            for line in lines:
                if var in line and re.search(
                    rf"(base64\.(b64decode|decodebytes)|atob)\s*\([^)]*{re.escape(var)}[^)]*\)",
                    line,
                ):
                    return True

    return False


def _detect_hex_base64_chain_pattern(content: str) -> bool:
    """Detect hex encoding followed by Base64 decoding patterns."""
    # Look for bytes.fromhex followed by Base64 decode
    if "bytes.fromhex" in content and re.search(
        r"(base64\.(b64decode|decodebytes)|atob)", content
    ):
        lines = content.split("\n")
        hex_vars = []

        for line in lines:
            # Look for hex decode assignment: var = bytes.fromhex(...).decode()
            hex_assign_match = re.search(
                r"(\w+)\s*=\s*bytes\.fromhex\s*\([^)]+\)\.decode\s*\(\s*\)", line
            )
            if hex_assign_match:
                var_name = hex_assign_match.group(1)
                hex_vars.append(var_name)
                continue

            # Check if hex variable is used in Base64 decode
            for var in hex_vars:
                if var in line and re.search(
                    rf"(base64\.(b64decode|decodebytes)|atob)\s*\(\s*{re.escape(var)}\s*\)",
                    line,
                ):
                    return True

    return False


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
                description=rule.description,
                explanation=get_explanation(rule.id),
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
        + ENHANCED_OBFUSCATION_RULES
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
