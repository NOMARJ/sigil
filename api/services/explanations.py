"""
Sigil API — Finding Explanations Registry

Maps each scanner rule ID to a human-readable explanation that describes:
  - What was detected and why it matters
  - Why this severity level was assigned
  - What a reviewer should consider
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Rule explanations — keyed by rule ID from scanner.py
# ---------------------------------------------------------------------------

RULE_EXPLANATIONS: dict[str, str] = {
    # --- Phase 1: Install Hooks (CRITICAL) ------------------------------------
    "install-setup-py-cmdclass": (
        "This package overrides Python's setup.py cmdclass, which allows arbitrary "
        "code to execute during pip install. This is the primary attack vector for "
        "malicious PyPI packages — attackers use it to steal credentials, install "
        "backdoors, or download additional payloads before the developer ever runs "
        "the code. Rated CRITICAL because it executes automatically with no user "
        "interaction required."
    ),
    "install-npm-postinstall": (
        "npm lifecycle scripts like postinstall run automatically during package "
        "installation with no user interaction required. This is the #1 attack "
        "vector for malicious npm packages — attackers embed data theft or backdoor "
        "installation in these hooks. Rated CRITICAL because code executes before "
        "the developer can review it."
    ),
    "install-pip-setup-exec": (
        "This setup.py calls subprocess, os.system, exec, or eval during package "
        "installation. Legitimate packages rarely need to execute arbitrary commands "
        "at install time. This pattern is commonly used by malicious packages to "
        "download and run payloads, exfiltrate environment variables, or establish "
        "persistence. Rated CRITICAL because it runs with the installer's full "
        "permissions."
    ),
    "install-makefile-curl": (
        "A script or Makefile pipes content from a remote URL directly into a shell "
        "(curl | sh or wget | bash). This is inherently dangerous because the "
        "remote content can change at any time, and the command runs with the "
        "current user's permissions. Rated HIGH because it requires manual "
        "execution (unlike install hooks) but still executes arbitrary remote code."
    ),
    # --- Phase 2: Code Patterns (HIGH/MEDIUM) ---------------------------------
    "code-eval": (
        "eval() dynamically executes a string as code at runtime. In a dependency, "
        "this is concerning because it can execute obfuscated malicious payloads "
        "that static analysis tools can't inspect. While some legitimate uses exist "
        "(template engines, REPLs), eval in a library dependency warrants careful "
        "review of what's being evaluated. Rated HIGH due to arbitrary code "
        "execution risk."
    ),
    "code-exec": (
        "exec() dynamically executes a string or code object as Python code. Like "
        "eval(), this enables arbitrary code execution that bypasses static "
        "analysis. Malicious packages often use exec() to run base64-decoded "
        "payloads or dynamically constructed attack code. Rated HIGH due to "
        "arbitrary code execution risk."
    ),
    "code-pickle-load": (
        "Pickle deserialization can execute arbitrary Python code embedded in the "
        "pickled data. An attacker who controls the pickle payload can achieve full "
        "remote code execution. This is especially dangerous in packages that load "
        "pickle files from untrusted sources or network responses. Rated HIGH "
        "because it's a well-known deserialization attack vector."
    ),
    "code-child-process": (
        "This code spawns a child process or shell command using subprocess, "
        "child_process, or similar APIs. While common in build tools and CLI "
        "utilities, in a library dependency this can indicate command injection "
        "or payload execution. Review what commands are being executed and whether "
        "user input can influence them. Rated HIGH because shell execution enables "
        "arbitrary system commands."
    ),
    "code-compile": (
        "compile() with exec mode generates a code object that can be executed "
        "dynamically. This is a less common but equally capable alternative to "
        "eval/exec for running arbitrary code. Rated MEDIUM because it requires "
        "an additional exec() call to actually execute, making it slightly less "
        "direct."
    ),
    "code-importlib": (
        "Dynamic module imports via __import__() or importlib.import_module() can "
        "load and execute arbitrary Python modules at runtime. This is used "
        "legitimately for plugin systems, but in a dependency it could import "
        "malicious modules or side-load code from unexpected locations. Rated "
        "MEDIUM because the imported module name is usually visible in context."
    ),
    # --- Phase 3: Network / Exfiltration (MEDIUM-CRITICAL) --------------------
    "net-http-request": (
        "Any outbound HTTP request from a package is flagged because malicious "
        "packages commonly use HTTP calls to exfiltrate stolen credentials or "
        "download second-stage payloads. This is rated MEDIUM because the pattern "
        "alone doesn't indicate malice — many packages legitimately call APIs — "
        "but it warrants review to verify the destination is expected and no "
        "sensitive data is being transmitted."
    ),
    "net-webhook": (
        "Webhook URLs (especially Discord, Slack, or Telegram) are the most common "
        "exfiltration channel for malicious packages. Attackers send stolen "
        "credentials, tokens, and environment variables to webhook endpoints they "
        "control. Rated HIGH because webhook URLs in a dependency almost always "
        "indicate data exfiltration intent."
    ),
    "net-raw-socket": (
        "Raw socket creation bypasses HTTP-level monitoring and can be used for "
        "covert data exfiltration, reverse shells, or custom protocol communication "
        "with attacker infrastructure. Rated HIGH because legitimate packages "
        "rarely need raw sockets — most use HTTP libraries instead."
    ),
    "net-dns-exfil": (
        "DNS queries can be used as a covert exfiltration channel by encoding "
        "stolen data in subdomain labels (e.g., stolen-token.attacker.com). This "
        "technique bypasses most firewalls and HTTP monitoring. Rated HIGH because "
        "DNS resolution in a library dependency is uncommon and DNS exfiltration is "
        "a well-documented attack technique."
    ),
    "net-http-exe-download": (
        "This code downloads an executable file over unencrypted HTTP, which is "
        "vulnerable to man-in-the-middle attacks. An attacker on the network can "
        "replace the downloaded binary with a malicious one. This pattern matches "
        "the OpenClaw attack technique. Rated CRITICAL because it combines remote "
        "code execution with transport-layer vulnerability."
    ),
    # --- Phase 4: Credentials (MEDIUM-CRITICAL) -------------------------------
    "cred-env-access": (
        "This code reads sensitive environment variables (AWS keys, API tokens, "
        "passwords, etc.). While many applications legitimately read configuration "
        "from environment variables, a dependency doing so is suspicious — "
        "especially if it also makes outbound network requests. Review whether "
        "this package needs access to these variables. Rated MEDIUM because "
        "environment access alone isn't malicious without an exfiltration path."
    ),
    "cred-hardcoded-key": (
        "A string matching the pattern of an API key, secret key, access token, "
        "or password is hardcoded in the source. This could be an accidentally "
        "committed credential (security risk for the publisher) or a deliberately "
        "embedded attacker-controlled token. Rated HIGH because hardcoded "
        "credentials are a security anti-pattern regardless of intent."
    ),
    "cred-ssh-private": (
        "An SSH or TLS private key is embedded in the source code. This is almost "
        "always a serious security issue — either an accidentally committed key "
        "(which should be revoked immediately) or a deliberately planted key for "
        "unauthorized access. Rated CRITICAL because private keys grant "
        "authentication access to systems."
    ),
    "cred-aws-key": (
        "A string matching the AWS access key ID pattern (AKIA followed by 16 "
        "alphanumeric characters) was detected. If this is a real AWS key, it "
        "could provide access to cloud infrastructure. Attackers may embed AWS "
        "keys to access their own infrastructure, or these may be accidentally "
        "committed publisher credentials. Rated CRITICAL because AWS keys can "
        "grant broad infrastructure access."
    ),
    # --- Phase 5: Obfuscation (HIGH/MEDIUM) -----------------------------------
    "obf-base64-decode": (
        "Base64 decoding is used to hide the true content of strings from static "
        "analysis. Malicious packages commonly base64-encode URLs, commands, or "
        "entire payloads to evade pattern-matching scanners. While legitimate uses "
        "exist (parsing binary data, handling encoded APIs), base64 decoding in a "
        "dependency warrants inspection of what's being decoded. Rated HIGH because "
        "this is the most common obfuscation technique in supply chain attacks."
    ),
    "obf-charcode": (
        "Character code construction (String.fromCharCode in JS, chr() in Python) "
        "builds strings character by character to hide their content from static "
        "analysis. This is a classic obfuscation technique used to conceal "
        "malicious URLs, shell commands, or code strings. Rated HIGH because "
        "legitimate code rarely constructs strings this way."
    ),
    "obf-hex-decode": (
        "Hex-encoded data or bytes.fromhex() can hide malicious payloads as "
        "sequences of hex characters. Like base64, this prevents direct inspection "
        "of the encoded content. Commonly used to embed shell commands, URLs, or "
        "code that would otherwise be caught by pattern scanners. Rated HIGH "
        "because hex encoding in dependency code is unusual."
    ),
    "obf-reverse-string": (
        "String reversal ([::-1] in Python, .reverse().join() in JS) is a simple "
        "obfuscation technique that hides keywords from grep-style scanners. For "
        "example, 'metsys.so' reversed is 'os.system'. Rated MEDIUM because it's "
        "a weaker obfuscation method that's sometimes used legitimately."
    ),
    # --- Phase 6: Provenance (LOW/MEDIUM) -------------------------------------
    "prov-hidden-file": (
        "A hidden file (name starts with '.') was detected in the package. While "
        "many hidden files are normal (.gitignore, .eslintrc), unexpected hidden "
        "files in a package could contain configuration overrides, cached "
        "credentials, or disguised scripts. Rated LOW because most hidden files "
        "are benign — review if the filename is unusual."
    ),
    "prov-binary-in-repo": (
        "A binary file (.exe, .dll, .so, .dylib, .bin, .dat) was found in the "
        "package. Binary files cannot be audited through source code review and "
        "could contain compiled malware or backdoors. Rated MEDIUM because "
        "some packages legitimately include pre-built binaries, but they cannot "
        "be verified without reverse engineering."
    ),
    "prov-minified": (
        "A minified file (.min.js, .min.css) was found. Minified code is extremely "
        "difficult to audit for malicious patterns because variable names and "
        "formatting are stripped. Attackers sometimes inject malicious code into "
        "minified bundles where it's nearly invisible. Rated LOW because minified "
        "files are common in frontend packages — but the original source should "
        "be available for comparison."
    ),
}


def get_explanation(rule_id: str) -> str:
    """Return the explanation for a rule, or empty string if not found."""
    return RULE_EXPLANATIONS.get(rule_id, "")
