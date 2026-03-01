# Troubleshooting

## Binary Not Found

**Symptom:** `{"error": true, "message": "Sigil CLI not found..."}`

**Solutions:**
1. Run setup: `bash <skill_root>/scripts/setup.sh`
2. Manual install: `brew install nomarj/tap/sigil`, `npm install -g @nomark/sigil`, or `cargo install sigil-cli`
3. If installed but not in PATH, add: `export PATH="$PATH:$HOME/.local/bin"`

## Wrong Binary (Bash Wrapper)

**Symptom:** scan.sh produces unstructured text instead of JSON.

**Cause:** The bash wrapper (`bin/sigil`) was installed instead of the Rust binary. The bash wrapper does not support `--format json`.

**Solution:** Install the Rust binary:
```bash
curl -sSL https://sigilsec.ai/install.sh | sh
```

## jq or python3 Not Available

**Symptom:** `{"error": true, "message": "report.sh requires jq or python3..."}`

**Cause:** JSON merging and report formatting require either `jq` or `python3`.

**Solutions:**
- Install jq: `brew install jq` (macOS), `apt install jq` (Linux)
- Python 3 is pre-installed on most macOS and Linux systems

## Scan Timeouts

**Symptom:** `"error": "Scan timed out after 30s"` in skills audit.

**Cause:** Large skill directories take longer than the 30-second timeout.

**Solutions:**
- Scan the skill directory directly: `bash <skill_root>/scripts/scan.sh /path/to/skill`
- The direct scan has no timeout

## False Positives

**Common false positive scenarios:**

1. **Test files**: Test fixtures that contain intentionally malicious patterns (e.g., `test_malware_detection.py` with `eval()` calls). These are expected.

2. **Documentation**: Code examples in markdown or documentation files showing dangerous patterns for educational purposes.

3. **Build tools**: Legitimate build scripts (`Makefile`, `setup.py`) that use install hooks for compilation steps.

4. **Obfuscation in dependencies**: Minified JavaScript files (`.min.js`) may trigger obfuscation rules.

**Recommendation:** Review each finding in context. The file path and line number help determine whether a pattern is legitimate or suspicious.

## Permission Denied

**Symptom:** `Permission denied` when running setup.sh.

**Solutions:**
- setup.sh installs to `~/.local/bin/` which should be user-writable
- If using a custom install directory, ensure it is writable
- Do not run with sudo unless necessary

## No Output from Scan

**Symptom:** `{"error": true, "message": "Scan produced no output..."}`

**Possible causes:**
- The target path does not exist
- The target is empty (no files to scan)
- The sigil binary crashed (check stderr)

**Solution:** Verify the target path exists and contains files. Try running `sigil scan <path>` directly to see error output.
