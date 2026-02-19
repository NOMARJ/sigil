"""
Sigil API — Seed Data

Populates the threat database with known malicious packages, pattern signatures
for each scan phase, and sample publisher reputation entries.

Usage:
    python -m api.seed_data           # Insert via the database module
    python api/seed_data.py           # Standalone execution

All data is based on real-world supply-chain attack examples documented by
security researchers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from uuid import uuid4

from api.database import db
from api.models import ScanPhase, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known malicious packages (real-world examples)
# ---------------------------------------------------------------------------

MALICIOUS_PACKAGES: list[dict] = [
    # npm supply-chain attacks
    {
        "hash": "a3c7e0d1f2b4e56789abcdef01234567890abcdef01234567890abcdef012345",
        "package_name": "event-stream",
        "version": "3.3.6",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Backdoored via flatmap-stream dependency to steal Bitcoin wallet keys (2018)",
    },
    {
        "hash": "b4d8f1e2a3c5d67890abcdef12345678901abcdef12345678901abcdef123456",
        "package_name": "ua-parser-js",
        "version": "0.7.29",
        "severity": "CRITICAL",
        "source": "npm-advisory",
        "description": "Hijacked npm account; cryptominer and password stealer injected (2021)",
    },
    {
        "hash": "c5e9a2f3b4d6e78901abcdef23456789012abcdef23456789012abcdef234567",
        "package_name": "colors",
        "version": "1.4.1",
        "severity": "HIGH",
        "source": "community",
        "description": "Maintainer protest — introduced infinite loop corrupting output (2022)",
    },
    {
        "hash": "d6f0b3a4c5e7f89012abcdef34567890123abcdef34567890123abcdef345678",
        "package_name": "faker",
        "version": "6.6.6",
        "severity": "HIGH",
        "source": "community",
        "description": "Maintainer protest — all functionality replaced with ENDMOSSAD header (2022)",
    },
    {
        "hash": "e7a1c4b5d6f8a90123abcdef45678901234abcdef45678901234abcdef456789",
        "package_name": "node-ipc",
        "version": "10.1.1",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Protestware — overwrites files with heart emoji on Russian/Belarusian IPs (2022)",
    },
    {
        "hash": "f8b2d5c6e7a9b01234abcdef56789012345abcdef56789012345abcdef567890",
        "package_name": "coa",
        "version": "2.0.3",
        "severity": "CRITICAL",
        "source": "npm-advisory",
        "description": "Hijacked npm account; malware injected to steal credentials (2021)",
    },
    {
        "hash": "a9c3e6d7f8b0c12345abcdef67890123456abcdef67890123456abcdef678901",
        "package_name": "rc",
        "version": "1.2.9",
        "severity": "CRITICAL",
        "source": "npm-advisory",
        "description": "Hijacked npm account; malware injected to steal credentials (2021)",
    },
    {
        "hash": "b0d4f7e8a9c1d23456abcdef78901234567abcdef78901234567abcdef789012",
        "package_name": "peacenotwar",
        "version": "9.1.3",
        "severity": "HIGH",
        "source": "community",
        "description": "Protestware dependency used by node-ipc to target specific geolocations (2022)",
    },
    {
        "hash": "c1e5a8f9b0d2e34567abcdef89012345678abcdef89012345678abcdef890123",
        "package_name": "es5-ext",
        "version": "0.10.53",
        "severity": "MEDIUM",
        "source": "community",
        "description": "Contained protestware postinstall script displaying anti-war message (2022)",
    },
    {
        "hash": "d2f6b9a0c1e3f45678abcdef90123456789abcdef90123456789abcdef901234",
        "package_name": "crossenv",
        "version": "7.1.0",
        "severity": "CRITICAL",
        "source": "npm-advisory",
        "description": "Typosquat of cross-env; steals npm tokens and environment variables",
    },
    # PyPI supply-chain attacks
    {
        "hash": "e3a7c0b1d2f4a56789abcdef01234567890abcdef01234567890abcdef012340",
        "package_name": "ctx",
        "version": "2.1",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Hijacked PyPI package; exfiltrates AWS keys and environment variables (2022)",
    },
    {
        "hash": "f4b8d1c2e3a5b67890abcdef12345678901abcdef12345678901abcdef123451",
        "package_name": "phpass",
        "version": "0.1",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Hijacked PyPI package; payload in setup.py exfiltrates system info (2022)",
    },
    {
        "hash": "a5c9e2d3f4b6c78901abcdef23456789012abcdef23456789012abcdef234562",
        "package_name": "colourama",
        "version": "0.1.6",
        "severity": "CRITICAL",
        "source": "internal",
        "description": "Typosquat of colorama; contains reverse shell and keylogger",
    },
    {
        "hash": "b6d0f3e4a5c7d89012abcdef34567890123abcdef34567890123abcdef345673",
        "package_name": "python3-dateutil",
        "version": "2.9.1",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Typosquat of python-dateutil; steals git credentials and SSH keys",
    },
    {
        "hash": "c7e1a4f5b6d8e90123abcdef45678901234abcdef45678901234abcdef456784",
        "package_name": "jeIlyfish",
        "version": "0.9.0",
        "severity": "CRITICAL",
        "source": "internal",
        "description": "Typosquat of jellyfish (capital I vs l); steals SSH keys and project credentials",
    },
    {
        "hash": "d8f2b5a6c7e9f01234abcdef56789012345abcdef56789012345abcdef567895",
        "package_name": "urllib",
        "version": "1.21.1",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Typosquat of urllib3; contains credential harvesting code in setup.py",
    },
    {
        "hash": "e9a3c6b7d8f0a12345abcdef67890123456abcdef67890123456abcdef678906",
        "package_name": "python-mongo",
        "version": "0.1",
        "severity": "HIGH",
        "source": "internal",
        "description": "Typosquat targeting pymongo users; exfiltrates environment variables",
    },
    {
        "hash": "f0b4d7c8e9a1b23456abcdef78901234567abcdef78901234567abcdef789017",
        "package_name": "discordio",
        "version": "1.0.0",
        "severity": "CRITICAL",
        "source": "community",
        "description": "Typosquat of discord.io; contains Discord token stealer",
    },
    {
        "hash": "a1c5e8d9f0b2c34567abcdef89012345678abcdef89012345678abcdef890128",
        "package_name": "easyrequests",
        "version": "1.0.0",
        "severity": "HIGH",
        "source": "community",
        "description": "Typosquat of requests; contains obfuscated code that downloads payloads",
    },
    {
        "hash": "b2d6f9e0a1c3d45678abcdef90123456789abcdef90123456789abcdef901239",
        "package_name": "mathjs-min",
        "version": "2.0.0",
        "severity": "CRITICAL",
        "source": "npm-advisory",
        "description": "Typosquat of mathjs; postinstall script installs cryptominer",
    },
    {
        "hash": "c3e7a0f1b2d4e56789abcdef01234567890abcdef01234567890abcdef01234a",
        "package_name": "lodash-utils",
        "version": "1.0.1",
        "severity": "CRITICAL",
        "source": "internal",
        "description": "Typosquat of lodash; steals npm tokens and publishes to attacker registry",
    },
    {
        "hash": "d4f8b1a2c3e5f67890abcdef12345678901abcdef12345678901abcdef12345b",
        "package_name": "fallguys",
        "version": "1.0.6",
        "severity": "CRITICAL",
        "source": "npm-advisory",
        "description": "Discord token grabber disguised as game API; accesses browser localStorage",
    },
]


# ---------------------------------------------------------------------------
# Pattern signatures for each scan phase
# ---------------------------------------------------------------------------

SIGNATURES: list[dict] = [
    # --- Install Hooks (Phase 1) ---
    {
        "id": "sig-install-postinstall",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"\"(pre|post)install\"\s*:",
        "severity": Severity.CRITICAL.value,
        "description": "npm lifecycle hook — preinstall/postinstall",
    },
    {
        "id": "sig-install-cmdclass",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"cmdclass\s*=\s*\{",
        "severity": Severity.CRITICAL.value,
        "description": "Python setup.py cmdclass override",
    },
    {
        "id": "sig-install-setup-exec",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"setup\s*\([\s\S]*?(subprocess|os\.system|exec|eval)\s*\(",
        "severity": Severity.CRITICAL.value,
        "description": "setup.py executes code at install time",
    },
    {
        "id": "sig-install-curl-pipe",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"(curl|wget)\s+.+\|\s*(sh|bash)",
        "severity": Severity.HIGH.value,
        "description": "Pipes remote content to shell during install",
    },
    {
        "id": "sig-install-npm-prepare",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"\"prepare\"\s*:",
        "severity": Severity.MEDIUM.value,
        "description": "npm prepare lifecycle script",
    },
    {
        "id": "sig-install-pip-confuse",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"setup\(\s*name\s*=.*install_requires.*http",
        "severity": Severity.HIGH.value,
        "description": "setup.py with suspicious install_requires pointing to URLs",
    },
    {
        "id": "sig-install-gem-ext",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"Gem::Specification.*extensions\s*=",
        "severity": Severity.HIGH.value,
        "description": "Ruby gem with native extension — runs code at install",
    },
    {
        "id": "sig-install-cargo-build",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"build\.rs.*Command::new",
        "severity": Severity.MEDIUM.value,
        "description": "Cargo build script executing external commands",
    },
    {
        "id": "sig-install-gradle-exec",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"task.*type:\s*Exec",
        "severity": Severity.MEDIUM.value,
        "description": "Gradle Exec task — runs arbitrary commands at build time",
    },
    {
        "id": "sig-install-makefile-download",
        "phase": ScanPhase.INSTALL_HOOKS.value,
        "pattern": r"(curl|wget)\s+-[sS]*o\s+",
        "severity": Severity.MEDIUM.value,
        "description": "Makefile downloads a file during build",
    },
    # --- Code Patterns (Phase 2) ---
    {
        "id": "sig-code-eval",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"\beval\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Dynamic code execution via eval()",
    },
    {
        "id": "sig-code-exec",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"\bexec\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Dynamic code execution via exec()",
    },
    {
        "id": "sig-code-pickle",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"pickle\.(loads?|Unpickler)\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Pickle deserialization — arbitrary code execution risk",
    },
    {
        "id": "sig-code-child-process",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"(child_process|subprocess)\.(exec|spawn|call|run|Popen)\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Spawns child process or shell command",
    },
    {
        "id": "sig-code-compile",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"\bcompile\s*\(.+['\"]exec['\"]",
        "severity": Severity.MEDIUM.value,
        "description": "compile() with exec mode — dynamic code generation",
    },
    {
        "id": "sig-code-importlib",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"__import__\s*\(|importlib\.import_module\s*\(",
        "severity": Severity.MEDIUM.value,
        "description": "Dynamic module import",
    },
    {
        "id": "sig-code-new-function",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"new\s+Function\s*\(",
        "severity": Severity.HIGH.value,
        "description": "JavaScript Function constructor — dynamic code creation",
    },
    {
        "id": "sig-code-yaml-load",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"yaml\.load\s*\(",
        "severity": Severity.MEDIUM.value,
        "description": "Unsafe YAML loading — may deserialize arbitrary objects",
    },
    {
        "id": "sig-code-marshal-loads",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"marshal\.loads?\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Python marshal deserialization — code execution risk",
    },
    {
        "id": "sig-code-ctypes",
        "phase": ScanPhase.CODE_PATTERNS.value,
        "pattern": r"ctypes\.(cdll|windll|CDLL)\s*[\.(]",
        "severity": Severity.HIGH.value,
        "description": "Loading native library via ctypes — potential for native code execution",
    },
    # --- Network / Exfil (Phase 3) ---
    {
        "id": "sig-net-http-request",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"(requests\.(get|post|put)|urllib\.request\.urlopen|fetch\s*\(|axios\.(get|post))\s*\(",
        "severity": Severity.MEDIUM.value,
        "description": "Outbound HTTP request",
    },
    {
        "id": "sig-net-webhook",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"(webhook|discord\.com/api/webhooks|hooks\.slack\.com)",
        "severity": Severity.HIGH.value,
        "description": "Webhook URL — possible exfiltration endpoint",
    },
    {
        "id": "sig-net-socket",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"socket\.socket\s*\(|net\.createConnection\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Raw socket creation",
    },
    {
        "id": "sig-net-dns-exfil",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"dns\.(resolve|lookup)|getaddrinfo\s*\(",
        "severity": Severity.HIGH.value,
        "description": "DNS query — possible DNS exfiltration technique",
    },
    {
        "id": "sig-net-ftp",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"ftplib\.FTP\s*\(|ftp\.connect\s*\(",
        "severity": Severity.HIGH.value,
        "description": "FTP connection — potential for data exfiltration",
    },
    {
        "id": "sig-net-telegram",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"api\.telegram\.org/bot",
        "severity": Severity.CRITICAL.value,
        "description": "Telegram bot API — commonly used for C2/exfil in malware",
    },
    {
        "id": "sig-net-ngrok",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"ngrok\.io|\.ngrok\.app",
        "severity": Severity.HIGH.value,
        "description": "Ngrok tunnel URL — may expose local services or exfiltrate data",
    },
    {
        "id": "sig-net-pastebin",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"pastebin\.com/raw/|ghostbin\.com|hastebin\.com",
        "severity": Severity.HIGH.value,
        "description": "Paste service URL — common C2 payload hosting",
    },
    {
        "id": "sig-net-ip-literal",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "severity": Severity.MEDIUM.value,
        "description": "HTTP request to raw IP address — suspicious in packages",
    },
    {
        "id": "sig-net-websocket",
        "phase": ScanPhase.NETWORK_EXFIL.value,
        "pattern": r"WebSocket\s*\(|ws://|wss://",
        "severity": Severity.MEDIUM.value,
        "description": "WebSocket connection — potential persistent C2 channel",
    },
    # --- Credentials (Phase 4) ---
    {
        "id": "sig-cred-env-access",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"(os\.environ|process\.env)\[?['\"]?(AWS_|GITHUB_|API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)",
        "severity": Severity.MEDIUM.value,
        "description": "Reads sensitive environment variable",
    },
    {
        "id": "sig-cred-hardcoded-key",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*['\"][A-Za-z0-9+/=]{16,}['\"]",
        "severity": Severity.HIGH.value,
        "description": "Hardcoded credential or API key",
    },
    {
        "id": "sig-cred-private-key",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL.value,
        "description": "Embedded SSH/TLS private key",
    },
    {
        "id": "sig-cred-aws",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL.value,
        "description": "AWS access key ID pattern",
    },
    {
        "id": "sig-cred-github-token",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": Severity.CRITICAL.value,
        "description": "GitHub personal access token or fine-grained token",
    },
    {
        "id": "sig-cred-stripe-key",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}",
        "severity": Severity.CRITICAL.value,
        "description": "Stripe secret key",
    },
    {
        "id": "sig-cred-google-api",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": Severity.HIGH.value,
        "description": "Google API key pattern",
    },
    {
        "id": "sig-cred-jwt-secret",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"jwt[_-]?secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "severity": Severity.HIGH.value,
        "description": "Hardcoded JWT secret",
    },
    {
        "id": "sig-cred-database-url",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"(postgres|mysql|mongodb)://[^\s'\"]+:[^\s'\"]+@",
        "severity": Severity.CRITICAL.value,
        "description": "Database connection string with embedded credentials",
    },
    {
        "id": "sig-cred-npm-token",
        "phase": ScanPhase.CREDENTIALS.value,
        "pattern": r"//registry\.npmjs\.org/:_authToken=",
        "severity": Severity.CRITICAL.value,
        "description": "npm registry authentication token",
    },
    # --- Obfuscation (Phase 5) ---
    {
        "id": "sig-obf-base64",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"(base64\.(b64decode|decodebytes)|atob)\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Base64 decoding — payload obfuscation",
    },
    {
        "id": "sig-obf-charcode",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"(String\.fromCharCode|chr)\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Character code construction — string obfuscation",
    },
    {
        "id": "sig-obf-hex",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"(\\x[0-9a-fA-F]{2}){4,}|bytes\.fromhex\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Hex-encoded data — payload obfuscation",
    },
    {
        "id": "sig-obf-reverse-string",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"\[::-1\]|\.reverse\(\)\.join\(",
        "severity": Severity.MEDIUM.value,
        "description": "String reversal — obfuscation technique",
    },
    {
        "id": "sig-obf-rot13",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"codecs\.decode\s*\(.+['\"]rot.?13['\"]",
        "severity": Severity.MEDIUM.value,
        "description": "ROT13 decoding — simple obfuscation technique",
    },
    {
        "id": "sig-obf-unicode-escape",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"(\\u[0-9a-fA-F]{4}){4,}",
        "severity": Severity.MEDIUM.value,
        "description": "Unicode escape sequences — may obfuscate strings",
    },
    {
        "id": "sig-obf-zlib-decompress",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"zlib\.decompress\s*\(",
        "severity": Severity.HIGH.value,
        "description": "Zlib decompression — may unpack obfuscated payload",
    },
    {
        "id": "sig-obf-long-string",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"['\"][A-Za-z0-9+/=]{200,}['\"]",
        "severity": Severity.MEDIUM.value,
        "description": "Very long encoded string — possible embedded payload",
    },
    {
        "id": "sig-obf-lambda-chain",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"(lambda\s+\w+\s*:.*){3,}",
        "severity": Severity.MEDIUM.value,
        "description": "Chained lambda expressions — code obfuscation technique",
    },
    {
        "id": "sig-obf-jsfuck",
        "phase": ScanPhase.OBFUSCATION.value,
        "pattern": r"\(\s*!\s*\[\s*\]\s*\+\s*\[\s*\]\s*\)",
        "severity": Severity.CRITICAL.value,
        "description": "JSFuck-style obfuscation pattern",
    },
    # --- Provenance (Phase 6) ---
    {
        "id": "sig-prov-hidden-file",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"^\.",
        "severity": Severity.LOW.value,
        "description": "Hidden file detected",
    },
    {
        "id": "sig-prov-binary",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.(exe|dll|so|dylib|bin|dat)$",
        "severity": Severity.MEDIUM.value,
        "description": "Binary file in repository",
    },
    {
        "id": "sig-prov-minified",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.min\.(js|css)$",
        "severity": Severity.LOW.value,
        "description": "Minified file — harder to audit",
    },
    {
        "id": "sig-prov-wasm",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.wasm$",
        "severity": Severity.MEDIUM.value,
        "description": "WebAssembly binary — cannot be source-audited",
    },
    {
        "id": "sig-prov-pyc",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.pyc$",
        "severity": Severity.MEDIUM.value,
        "description": "Compiled Python bytecode — may differ from source",
    },
    {
        "id": "sig-prov-sourcemap-absent",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.min\.js$",
        "severity": Severity.LOW.value,
        "description": "Minified JS without source map",
    },
    {
        "id": "sig-prov-git-submodule",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.gitmodules$",
        "severity": Severity.LOW.value,
        "description": "Git submodule reference — external code dependency",
    },
    {
        "id": "sig-prov-vendor-dir",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"vendor/|third_party/",
        "severity": Severity.LOW.value,
        "description": "Vendored dependency directory — unmanaged code",
    },
    {
        "id": "sig-prov-dockerfile",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"Dockerfile",
        "severity": Severity.INFO.value,
        "description": "Dockerfile present — container build instructions",
    },
    {
        "id": "sig-prov-ci-config",
        "phase": ScanPhase.PROVENANCE.value,
        "pattern": r"\.(github|gitlab-ci|circleci|travis)",
        "severity": Severity.INFO.value,
        "description": "CI/CD configuration detected",
    },
]


# ---------------------------------------------------------------------------
# Publisher reputation entries
# ---------------------------------------------------------------------------

PUBLISHERS: list[dict] = [
    {
        "publisher_id": "marak",
        "trust_score": 15.0,
        "total_packages": 24,
        "flagged_count": 2,
        "notes": "Maintainer of colors/faker — introduced protest-ware in Jan 2022",
    },
    {
        "publisher_id": "riaevangelist",
        "trust_score": 5.0,
        "total_packages": 40,
        "flagged_count": 3,
        "notes": "Maintainer of node-ipc and peacenotwar — geo-targeted file corruption",
    },
    {
        "publisher_id": "nickcbass",
        "trust_score": 0.0,
        "total_packages": 1,
        "flagged_count": 1,
        "notes": "Published crossenv typosquat package stealing npm tokens",
    },
    {
        "publisher_id": "hacktask",
        "trust_score": 0.0,
        "total_packages": 5,
        "flagged_count": 5,
        "notes": "Multiple typosquat packages on PyPI targeting popular libraries",
    },
    {
        "publisher_id": "tj",
        "trust_score": 95.0,
        "total_packages": 278,
        "flagged_count": 0,
        "notes": "Prolific open-source author — express, co, mocha, etc. Highly trusted.",
    },
    {
        "publisher_id": "sindresorhus",
        "trust_score": 98.0,
        "total_packages": 1100,
        "flagged_count": 0,
        "notes": "Major npm ecosystem contributor — thousands of well-maintained packages",
    },
    {
        "publisher_id": "ljharb",
        "trust_score": 97.0,
        "total_packages": 500,
        "flagged_count": 0,
        "notes": "TC39 delegate, maintains many foundational JS packages",
    },
    {
        "publisher_id": "unknown-new-publisher",
        "trust_score": 30.0,
        "total_packages": 1,
        "flagged_count": 0,
        "notes": "Brand-new account with single package — low trust until established",
    },
    {
        "publisher_id": "abandoned-account-123",
        "trust_score": 20.0,
        "total_packages": 3,
        "flagged_count": 1,
        "notes": "Account inactive for 3+ years, one package later found compromised",
    },
    {
        "publisher_id": "company-verified-org",
        "trust_score": 90.0,
        "total_packages": 45,
        "flagged_count": 0,
        "notes": "Verified organization account — corporate-maintained packages",
    },
]


# ---------------------------------------------------------------------------
# Seeding logic
# ---------------------------------------------------------------------------


async def seed_threats() -> int:
    """Insert known malicious package records into the threats table."""
    count = 0
    now = datetime.utcnow()
    for pkg in MALICIOUS_PACKAGES:
        row = {
            "id": uuid4().hex[:16],
            "hash": pkg["hash"],
            "package_name": pkg["package_name"],
            "version": pkg.get("version", ""),
            "severity": pkg.get("severity", "HIGH"),
            "source": pkg.get("source", "community"),
            "confirmed_at": (now - timedelta(days=count * 7)).isoformat(),
            "description": pkg.get("description", ""),
            "created_at": now.isoformat(),
        }
        try:
            await db.upsert("threats", row)
            count += 1
        except Exception:
            logger.warning("Failed to seed threat: %s", pkg["package_name"])
    logger.info("Seeded %d threat entries", count)
    return count


async def seed_signatures() -> int:
    """Insert pattern signatures into the signatures table."""
    count = 0
    now = datetime.utcnow()
    for sig in SIGNATURES:
        row = {
            "id": sig["id"],
            "phase": sig["phase"],
            "pattern": sig["pattern"],
            "severity": sig.get("severity", "MEDIUM"),
            "description": sig.get("description", ""),
            "updated_at": now.isoformat(),
        }
        try:
            await db.upsert("signatures", row)
            count += 1
        except Exception:
            logger.warning("Failed to seed signature: %s", sig["id"])
    logger.info("Seeded %d signature entries", count)
    return count


async def seed_publishers() -> int:
    """Insert publisher reputation entries."""
    count = 0
    now = datetime.utcnow()
    for pub in PUBLISHERS:
        row = {
            "id": uuid4().hex[:16],
            "publisher_id": pub["publisher_id"],
            "trust_score": pub.get("trust_score", 50.0),
            "total_packages": pub.get("total_packages", 0),
            "flagged_count": pub.get("flagged_count", 0),
            "first_seen": (now - timedelta(days=365)).isoformat(),
            "last_active": now.isoformat(),
            "notes": pub.get("notes", ""),
        }
        try:
            await db.upsert("publishers", row)
            count += 1
        except Exception:
            logger.warning("Failed to seed publisher: %s", pub["publisher_id"])
    logger.info("Seeded %d publisher entries", count)
    return count


async def seed_all() -> dict[str, int]:
    """Run all seed functions and return counts."""
    threats = await seed_threats()
    signatures = await seed_signatures()
    publishers = await seed_publishers()
    return {
        "threats": threats,
        "signatures": signatures,
        "publishers": publishers,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _main() -> None:
    """Standalone entry point for seeding."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    await db.connect()
    try:
        result = await seed_all()
        logger.info("Seed complete: %s", result)
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(_main())
