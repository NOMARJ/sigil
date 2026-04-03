# Lessons Learned

## 2026-03-15 - Bugfix: P0 Unicode Boundary Crash in Rust CLI

- **Bug**: `byte index 200 is not a char boundary; it is inside '─' (bytes 198..201)` panic when scanning files with Unicode characters near byte position 200
- **Root Cause**: Unsafe string slicing `&line[..200]` in `phases.rs` line 44-47 that cuts through multi-byte UTF-8 characters
- **Additional Issues**: `std::fs::read_to_string()` panics on invalid UTF-8, no binary file detection
- **Fix Applied**: 
  - Replaced unsafe slicing with safe char boundary detection using `char_indices()` and `take_while()`
  - Replaced `std::fs::read_to_string()` with `std::fs::read()` + `String::from_utf8_lossy()` 
  - Added binary file detection (skip files containing null bytes)
  - Implemented global panic handler to catch remaining panics and log as SCAN_ERROR
- **Rule**: Always use `char_indices()` for string truncation in Rust, never slice strings directly with byte indices
- **Rule**: Use `String::from_utf8_lossy()` instead of `read_to_string()` for robust file processing
- **Rule**: Check for null bytes to detect binary files before text processing

## Test Coverage Added
- Created `tests/fixtures/unicode-boundary/sbcs-data.js` with box-drawing characters around byte 200
- Created `tests/fixtures/binary/packed.bin` with null bytes to test binary file handling  
- Added `test-unicode-fix.sh` script to verify the fix prevents panics

## 2026-03-13 - Bugfix: React Hooks Dependencies and Python Module Imports

- **Bug**: React Hook useEffect/useCallback missing dependencies causing ESLint warnings
- **Fix**: Wrapped functions with useCallback and added proper dependency arrays
- **Rule**: Always include function dependencies in useCallback/useEffect dependency arrays; use useCallback for functions passed to dependency arrays

- **Bug**: Python test imports failing with "No module named 'models.suppression_rules'"  
- **Fix**: Created missing `__init__.py` file in `api/models/` directory to make it a proper Python package
- **Rule**: All Python directories containing modules must have `__init__.py` files to be importable as packages

- **Bug**: Verification report showed failing imports despite file existence
- **Fix**: Module structure issue - directory without `__init__.py` cannot be imported as package
- **Rule**: When adding new model subdirectories, always create `__init__.py` files for proper package structure

## 2026-03-13 - Bugfix: Bot Attestation Key Configuration

- **Bug**: Attestation endpoints returning "Public key not configured" despite working implementation
- **Root Cause**: Bot signing keys (SIGIL_BOT_PUBLIC_KEY) missing from API settings configuration system
- **Fix**: Added bot_public_key, bot_public_key_file, bot_signing_key_id to Settings class and updated attestation router to use settings instead of raw os.getenv() calls
- **Rule**: When endpoints expect environment variables, ensure they're properly configured in the Settings class with pydantic-settings prefix handling

- **Bug**: Python 3.9 compatibility issues with `str | None` union syntax in Pydantic models  
- **Fix**: Replace `str | None` with `Union[str, None]` for Python 3.9 compatibility
- **Rule**: Use `Union[T, None]` instead of `T | None` for backwards compatibility with Python < 3.10

## 2026-03-15 - Bugfix: P1 Pattern Matching False Positives in Sigil Scanner

- **Bug**: Scanner flagging legitimate code patterns as security threats with high false positive rate
- **Critical Issues Fixed**:
  - `RegExp.exec()` flagged as dangerous shell execution (JavaScript regex matching vs process execution)
  - `eval()` in string literals and regex patterns flagged as code execution
  - Documentation files getting same severity as source code (34/43 findings in docs)
  - Single-character `String.fromCharCode()` flagged as obfuscation (Excel column generation)
  - Anthropic/OpenAI API calls flagged as suspicious network activity

- **Fixes Applied**:
  - **Context-aware exec() detection**: Split into `code-exec-dangerous` for actual execution vs safe regex methods
  - **String literal detection**: Added `_is_eval_in_safe_context()` to parse quotes and detect eval() in strings/regex
  - **File context classification**: Added `_adjust_severity_by_file_context()` reducing docs by 2 levels, tests by 1 level
  - **Benign charcode detection**: Added `_is_charcode_benign()` for single-character generation patterns
  - **Safe domains allowlist**: Added `SAFE_DOMAINS` set for legitimate API endpoints (Anthropic, OpenAI, GitHub, etc.)

- **Architecture**: Enhanced `_scan_content()` with pre-filtering pipeline that checks rule context before yielding findings
- **Testing**: Created comprehensive validation suite - all 10 test cases pass (7 false positive fixes + 3 threat detection validation)
- **Rule**: Always implement context-aware pattern matching for security scanners to distinguish legitimate vs malicious usage
- **Rule**: File type should influence finding severity - documentation and tests need reduced sensitivity
- **Rule**: Maintain allowlists for known-safe domains/APIs to reduce false positives in network scanning

## Patterns Added

- Context-aware security pattern matching prevents false positives while maintaining threat detection
- File classification systems should adjust severity based on file purpose (docs, tests, source)
- API security scanners need domain allowlists for legitimate services  
- String literal parsing essential for distinguishing code execution from documentation/patterns
- React hooks must include all dependencies or be wrapped with useCallback to prevent infinite re-renders
- Python package directories require `__init__.py` even if they only contain a single module
- Test imports should match the actual package structure after path manipulation with sys.path.insert()
- Environment variables used by endpoints must be defined in Settings class for proper configuration management
- Always include key generation utilities when adding cryptographic key requirements to prevent deployment issues