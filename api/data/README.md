# Sigil Threat Signature Database

This directory contains the threat signature database for Sigil's malicious code detection system.

## Files

- **threat_signatures.json** - Primary threat signature database (247 signatures)
- **load_signatures.py** - Signature loading and validation script
- **test_signatures.py** - Comprehensive test suite

## Quick Start

### Load Signatures into Database

```bash
# Validate signatures without loading
python api/scripts/load_signatures.py --validate-only

# Load all signatures
python api/scripts/load_signatures.py

# Force reload (update existing)
python api/scripts/load_signatures.py --force

# Load specific category
python api/scripts/load_signatures.py --category install_hooks
```

### Run Tests

```bash
# Run all signature tests
pytest api/tests/test_signatures.py -v

# Run specific test category
pytest api/tests/test_signatures.py::TestSignatureValidation -v
```

## Signature Database Structure

### Schema

```json
{
  "version": "1.0.0",
  "last_updated": "2026-02-20T00:00:00Z",
  "signature_count": 247,
  "categories": ["install_hooks", "code_execution", ...],
  "signatures": [...],
  "malware_families": {...}
}
```

### Signature Entry

Each signature has:

```json
{
  "id": "sig-install-001",
  "category": "install_hooks",
  "phase": "INSTALL_HOOKS",
  "severity": "CRITICAL",
  "weight": 10.0,
  "pattern": "cmdclass\\s*=\\s*\\{",
  "description": "Python setup.py cmdclass override",
  "language": ["python"],
  "cve": [],
  "malware_families": ["setup-backdoor"],
  "false_positive_likelihood": "low",
  "created": "2024-01-15"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (format: `sig-{category}-{NNN}`) |
| `category` | string | Yes | Category: `install_hooks`, `code_execution`, `network_exfil`, `credentials`, `obfuscation`, `provenance`, `supply_chain`, `evasion` |
| `phase` | string | Yes | Scan phase enum: `INSTALL_HOOKS`, `CODE_PATTERNS`, `NETWORK_EXFIL`, `CREDENTIALS`, `OBFUSCATION`, `PROVENANCE` |
| `severity` | string | Yes | Severity enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `weight` | float | No | Score multiplier (0-20, default: 1.0) |
| `pattern` | string | Yes | Regex pattern (must be valid Python regex) |
| `description` | string | Yes | Human-readable description |
| `language` | array | No | Target languages (e.g., `["python", "javascript"]`) |
| `cve` | array | No | Related CVE identifiers |
| `malware_families` | array | No | Known malware families using this pattern |
| `false_positive_likelihood` | string | No | `very_low`, `low`, `medium`, `high`, `very_high` |
| `created` | string | No | Creation date (YYYY-MM-DD) |

## Categories

### 1. Install Hooks (CRITICAL)

**Weight: 10-12x**

Detects code that executes automatically during package installation:

- Python `setup.py` cmdclass overrides
- npm lifecycle scripts (preinstall, postinstall)
- Cargo `build.rs` exploitation
- Ruby gem installation hooks
- Makefile install targets with remote execution

**Why Critical:** Executes before user review, with full system permissions.

### 2. Code Execution (HIGH)

**Weight: 4-10x**

Detects dangerous code execution patterns:

- Dynamic code execution (`eval`, `exec`, `compile`)
- Unsafe deserialization (pickle, YAML, marshal)
- Subprocess/shell execution
- Foreign function interfaces (FFI, ctypes)
- Server-Side Template Injection (SSTI)

**Why High:** Building blocks for most malicious payloads.

### 3. Network Exfiltration (MEDIUM-HIGH)

**Weight: 3-10x**

Detects data exfiltration and C2 communication:

- Discord/Telegram/Slack webhooks
- Raw sockets and WebSockets
- Reverse shells
- DNS tunneling
- Cloud metadata service (IMDS) access
- Reverse proxy tunnels (ngrok, localtunnel)

**Why Variable:** Common in legitimate software; context-dependent.

### 4. Credentials (MEDIUM-CRITICAL)

**Weight: 2-10x**

Detects credential access and leakage:

- API keys (OpenAI, Anthropic, AWS, GitHub, Slack)
- Private keys (SSH, TLS, GPG)
- JWT tokens
- Environment variable access
- Cloud credential files

**Why Variable:** Many apps legitimately read env vars; focus on known key formats.

### 5. Obfuscation (HIGH)

**Weight: 3-9x**

Detects payload hiding techniques:

- Base64/hex encoding
- Unicode escapes and homoglyphs
- Character code construction
- JavaScript obfuscators (javascript-obfuscator.io)
- PyArmor protection

**Why High:** Strong indicator of malicious intent; rare in legitimate code.

### 6. Provenance (LOW-MEDIUM)

**Weight: 1-3x**

Metadata and file-based indicators:

- Hidden files
- Binary executables
- Minified files
- Suspicious author names

**Why Low:** High false positive rate; used for context enrichment.

### 7. Supply Chain (HIGH-CRITICAL)

**Weight: 7-12x**

Supply chain attack patterns:

- Dependency confusion indicators
- Typosquatting patterns
- Empty dependency lists
- Test/temp maintainer accounts

**Why High:** Targets package ecosystem trust.

### 8. Evasion (HIGH-CRITICAL)

**Weight: 8-10x**

Sandbox and detection evasion:

- Prompt injection attempts
- Sandbox/VM detection
- Long delays (time bombs)
- Future date checks

**Why High:** Actively attempts to bypass security controls.

## Malware Families

The database includes known malware family metadata:

- **Shai-Hulud** - Self-propagating npm worm (Sep 2024)
- **MUT-8694** - Cross-ecosystem attack (npm + PyPI)
- **Hugging Face Poisoned Models** - ML model pickle exploits
- And more...

## Adding New Signatures

### 1. Edit `threat_signatures.json`

Add to the `signatures` array:

```json
{
  "id": "sig-{category}-{next_number}",
  "category": "code_execution",
  "phase": "CODE_PATTERNS",
  "severity": "HIGH",
  "weight": 6.0,
  "pattern": "your_regex_pattern_here",
  "description": "Clear description of what this detects",
  "language": ["python"],
  "false_positive_likelihood": "medium"
}
```

### 2. Validate

```bash
python api/scripts/load_signatures.py --validate-only
```

### 3. Test the Pattern

Add a test case in `api/tests/test_signatures.py`:

```python
def test_your_new_pattern(self, signature_file):
    sig = self.get_signature("sig-{category}-{number}", signature_file)
    pattern = re.compile(sig["pattern"])

    # Should match
    assert pattern.search("malicious code example")

    # Should not match
    assert not pattern.search("benign code example")
```

### 4. Load into Database

```bash
python api/scripts/load_signatures.py --force
```

## Best Practices

### Pattern Design

1. **Be specific**: Avoid overly broad patterns that match legitimate code
2. **Test edge cases**: Include positive and negative test cases
3. **Optimize performance**: Avoid catastrophic backtracking (test with long strings)
4. **Use word boundaries**: `\b` for whole-word matches
5. **Escape metacharacters**: Use `\\.` for literal dots

### Severity Guidelines

- **CRITICAL**: Immediate code execution, credential leakage, install hooks
- **HIGH**: Code execution, obfuscation, known exploit patterns
- **MEDIUM**: Network calls, env var access, common patterns
- **LOW**: Metadata indicators, provenance signals

### Weight Guidelines

- **10-12x**: Install hooks, multi-stage payloads, confirmed exploits
- **7-9x**: Obfuscation, evasion, supply chain attacks
- **4-6x**: Code execution, dangerous APIs
- **2-3x**: Network calls, credential access
- **1x**: Metadata, provenance

### False Positive Management

Set `false_positive_likelihood` to help users prioritize:

- **very_low**: Pattern is highly specific (e.g., private key headers)
- **low**: Rarely seen in legitimate code (e.g., obfuscation)
- **medium**: Sometimes legitimate (e.g., subprocess calls)
- **high**: Common pattern (e.g., HTTP requests)
- **very_high**: Ubiquitous (e.g., minified files)

## API Integration

The signature database integrates with the Sigil API:

### Get All Signatures

```python
from api.services.threat_intel import get_signatures

# Get all signatures
response = await get_signatures()

# Get signatures updated after timestamp
from datetime import datetime
response = await get_signatures(since=datetime(2024, 1, 1))
```

### Get Statistics

```python
from api.services.threat_intel import get_signature_stats

stats = await get_signature_stats()
# Returns: {total, by_category, by_severity, by_phase, last_updated}
```

### Reload from JSON

```python
from api.services.threat_intel import reload_signatures_from_json

result = await reload_signatures_from_json("/path/to/threat_signatures.json")
```

## Maintenance

### Updating Signatures

1. Research new malware campaigns and CVEs
2. Add signatures following the schema
3. Validate with `--validate-only`
4. Test patterns thoroughly
5. Update `version` and `last_updated` in JSON
6. Load with `--force` to update database
7. Commit changes with detailed message

### Quarterly Review

- Review false positive reports
- Update weights based on real-world data
- Add new malware family signatures
- Deprecate outdated patterns
- Update CVE references

## Resources

### Threat Intelligence Sources

- [Xygeni Supply Chain Security](https://xygeni.io/blog/)
- [CISA Security Alerts](https://www.cisa.gov/news-events/alerts)
- [Socket.dev Blog](https://socket.dev/blog)
- [JFrog Security Research](https://jfrog.com/blog/)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/)
- [Stacklok Security](https://stacklok.com/blog)

### Regex Testing

- [Regex101](https://regex101.com/) - Test patterns (select Python flavor)
- [RegExr](https://regexr.com/) - Interactive regex tester

### Related Documentation

- [docs/threat-model.md](../../docs/threat-model.md) - Sigil threat model
- [docs/malicious-signatures.md](../../docs/malicious-signatures.md) - Research compilation
- [docs/detection-patterns.md](../../docs/detection-patterns.md) - Implementation guide

## License

Threat signature database is part of Sigil by NOMARK.

---

**Last Updated:** 2026-02-20
**Database Version:** 1.0.0
**Signature Count:** 247
