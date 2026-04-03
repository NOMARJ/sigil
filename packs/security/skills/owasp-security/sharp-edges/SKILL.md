---
name: sharp-edges
description: "Identify error-prone APIs, dangerous configurations, and footgun designs in code. Part of the Nomark Method Layer 1 security scanning. Use whenever reviewing code for safety, someone asks 'is this code safe', 'dangerous patterns', 'footgun check', or when analyzing code that uses complex or risky APIs."
---

# Sharp Edges Detector

Adapted from Trail of Bits' sharp-edges skill. Identifies API usage patterns and code constructs that are technically valid but frequently lead to security vulnerabilities or reliability failures.

## What You're Looking For

### Dangerous Function Calls
- `eval()`, `exec()`, `Function()` with user-controlled input
- `innerHTML`, `dangerouslySetInnerHTML` with unsanitized data
- `subprocess.call(shell=True)` or `os.system()` with string interpolation
- `pickle.loads()`, `yaml.load()` (unsafe deserializer), `JSON.parse()` on untrusted input without schema validation
- `Math.random()` or `random.random()` for security-sensitive operations (use crypto.randomBytes or secrets module)

### SQL and Injection Vectors
- String concatenation or template literals in SQL queries
- ORM raw query methods with unparameterized input
- LDAP, XPath, or command injection via string interpolation
- GraphQL queries built from user input without validation

### Concurrency and Race Conditions
- TOCTOU (Time-of-Check-Time-of-Use) patterns: checking a condition and acting on it in separate operations
- Shared mutable state without synchronization
- Non-atomic read-modify-write sequences
- File operations without proper locking

### Path and File Operations
- Path construction from user input without canonicalization
- Directory traversal via `../` in user-supplied paths
- Symlink following without verification
- Temporary file creation with predictable names

### Cryptographic Footguns
- MD5 or SHA1 for password hashing (use bcrypt, scrypt, or argon2)
- ECB mode for encryption
- Hardcoded IVs or nonces
- Custom cryptographic implementations
- Insufficient key lengths

### Type and Memory Safety
- Unchecked type assertions/casts
- Integer overflow in arithmetic used for allocation or indexing
- Buffer operations without bounds checking
- Null pointer dereference patterns

## Scan Protocol

```
1. Parse the changed files into AST (or analyze textually for config files)
2. Walk the AST looking for known dangerous patterns
3. For each finding, assess:
   - Is the input user-controlled? (worse) or internal? (less bad)
   - Is there sanitization/validation nearby? (might be OK)
   - Is this in a test file? (lower severity)
4. Classify and report
```

## Output Format

```
SHARP-EDGES SCAN — [timestamp]
Files scanned: [count]

⚠️ [file:line] eval() called with variable input
   Risk: Code injection if input is user-controlled
   Fix: Use a parser or whitelist of allowed operations
   Severity: HIGH (if user input) / MEDIUM (if internal)

⚠️ [file:line] SQL query uses string template
   Risk: SQL injection
   Fix: Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId])
   Severity: HIGH

✅ No critical sharp edges detected
```
