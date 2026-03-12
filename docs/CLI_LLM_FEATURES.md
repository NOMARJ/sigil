# CLI LLM Features for Pro Users

## Overview

The Sigil CLI now supports **LLM-powered enhanced scanning** for authenticated users with Pro, Team, or Enterprise subscriptions. This feature provides AI-driven threat analysis beyond static pattern matching.

## Authentication Required

Enhanced scanning requires authentication. Users must first log in:

```bash
sigil login --token YOUR_API_TOKEN
```

Or use interactive login:

```bash
sigil login
```

## Usage

### Basic Enhanced Scan

```bash
sigil scan /path/to/code --enhanced
```

### Enhanced Scan with Verbose Output

```bash
sigil scan /path/to/code --enhanced --verbose
```

### Combined with Other Features

```bash
# Enhanced scan + threat intelligence enrichment
sigil scan /path/to/code --enhanced --enrich

# Enhanced scan + cloud submission
sigil scan /path/to/code --enhanced --submit
```

## How It Works

1. **Static Analysis (Phases 1-8)**: Runs local pattern-based detection
2. **File Collection**: Gathers up to 50 text files (max 100KB each) for LLM analysis
3. **API Submission**: Sends file contents to `/v1/scan-enhanced` endpoint
4. **LLM Analysis (Phase 9)**: AI-powered threat detection including:
   - Zero-day vulnerability detection
   - Obfuscation pattern analysis
   - Contextual threat correlation
   - Advanced remediation suggestions
5. **Results**: Displays combined static + LLM findings

## File Selection Criteria

The CLI automatically selects files for LLM analysis based on:

- **Text file extensions**: py, js, ts, jsx, tsx, rs, go, java, c, cpp, rb, php, sh, yaml, json, etc.
- **Size limit**: Files under 100KB
- **Maximum count**: Up to 50 files per scan (cost control)

Binary files and large files are automatically skipped.

## Error Handling

### Not Authenticated
```
error: Enhanced scanning requires authentication. Run: sigil login
```

### No Pro Subscription
```
warning: Pro subscription required for LLM analysis. Upgrade at https://app.sigilsec.ai/upgrade
```

### No Readable Files
```
warning: no readable files found for LLM analysis
```

### LLM Analysis Failure
If LLM analysis fails, the CLI continues with static analysis results:
```
warning: Enhanced analysis failed: [error message]
  Continuing with static analysis results only
```

## Subscription Tiers

| Feature | Free | Pro | Team | Enterprise |
|---------|------|-----|------|------------|
| Static Analysis (Phases 1-8) | ✅ | ✅ | ✅ | ✅ |
| LLM Analysis (Phase 9) | ❌ | ✅ | ✅ | ✅ |
| Zero-day Detection | ❌ | ✅ | ✅ | ✅ |
| Contextual Analysis | ❌ | ✅ | ✅ | ✅ |
| Advanced Remediation | ❌ | ✅ | ✅ | ✅ |

## API Endpoint

The CLI calls the following API endpoint for enhanced scanning:

```
POST /v1/scan-enhanced
Authorization: Bearer <token>

{
  "target": "cli-scan",
  "target_type": "directory",
  "files_scanned": 42,
  "findings": [...],
  "metadata": {
    "file_contents": {
      "src/main.py": "...",
      "lib/utils.js": "..."
    }
  }
}
```

## Cost Optimization

The CLI implements several cost control measures:

1. **File limit**: Maximum 50 files per scan
2. **Size limit**: Files over 100KB are skipped
3. **Extension filtering**: Only text files are analyzed
4. **Binary detection**: Unreadable files are automatically excluded

## Examples

### Scan a Python Package
```bash
sigil scan ./my-package --enhanced --verbose
```

Output:
```
sigil: scanning ./my-package...
collecting file contents for LLM analysis...
Collected 12 files for LLM analysis
submitting 12 files for enhanced LLM analysis...

sigil: Enhanced LLM analysis completed
  Scan ID: abc123def456
  
  FINDINGS (15 total):
  [HIGH] Phase 9 (LLM Analysis): Potential obfuscated backdoor in src/utils.py:42
  [MEDIUM] Phase 2 (Code Patterns): Dangerous eval() usage in lib/parser.py:18
  ...
```

### Scan a Git Repository
```bash
sigil clone https://github.com/user/repo --enhanced
```

### Check Capabilities
```bash
# Verify your subscription tier supports LLM features
curl -H "Authorization: Bearer $TOKEN" https://api.sigilsec.ai/v1/scan-capabilities
```

## Troubleshooting

### Token Not Found
If you see authentication errors, ensure your token is stored:
```bash
cat ~/.sigil/token
```

### Offline Mode
Enhanced scanning requires internet connectivity. If offline:
```
warning: Sigil cloud is unreachable (running in offline mode)
```

### Rate Limiting
Enhanced scans have stricter rate limits (20 requests/60 seconds) compared to basic scans (30 requests/60 seconds).

## Implementation Details

### Code Changes

1. **`cli/src/api.rs`**: Added `submit_enhanced_scan()` method
2. **`cli/src/main.rs`**: 
   - Added `--enhanced` flag to `Scan` command
   - Added `collect_file_contents()` helper function
   - Updated `cmd_scan()` to support LLM analysis
3. **API Integration**: Calls `/v1/scan-enhanced` endpoint with file contents

### Security Considerations

- File contents are transmitted over HTTPS
- Authentication token required for all enhanced scans
- Server-side tier validation prevents unauthorized access
- File size limits prevent excessive data transmission

## Future Enhancements

- [ ] Configurable file limits via CLI flags
- [ ] Support for custom file extension filters
- [ ] Caching of LLM analysis results
- [ ] Incremental analysis for large repositories
- [ ] Local LLM support for air-gapped environments
