# Phase B — Scanner mechanics (US-B1..B4)

Date: 2026-06-10. All verification on `cli/target/release/sigil` (release build), cache cleared first.

## US-B1 — walker exclusions + ignore files + parallel traversal
- `ignore::WalkBuilder` replaces raw `walkdir`; hard-excludes node_modules/.git/target/dist/build/.next/__pycache__/.venv/venv/.tox/.mypy_cache/.pytest_cache; honors `.sigilignore` always and `.gitignore` only inside real git repos (`require_git(true)` — a malicious `.gitignore` in an extracted tarball cannot hide files). Content phases run via rayon `par_iter`, results flattened in file order (deterministic). Files >10MB skipped for content (still seen by Provenance).
- **Done-when:** `time ./cli/target/release/sigil scan .` → `real 2.18` (was: did not finish in 30 min, debug). files_scanned=1170, duration_ms=905.
- Tests: `walker_tests::{excludes_default_dirs, walks_dotfiles_but_not_git_dir, respects_sigilignore_always, gitignore_ignored_without_git_dir_tarball_evasion}` pass.

## US-B2 — Unicode normalization (PUA / bidi / zero-width)
- `scanner/normalize.rs`: `inspect_invisible` emits UNICODE-001 (PUA), -002 (bidi/Trojan-Source), -003 (zero-width cloaking) — High in instruction files (CLAUDE.md/SKILL.md/.cursorrules/.claude/…), Medium elsewhere. `normalize_for_matching` strips cloaking chars before every pattern phase so `ev<ZWJ>al(` matches as `eval(`; emoji-internal ZWJ (non-ASCII neighbors) preserved.
- **Done-when:** `cargo test` unicode group passes against PUA/bidi/ZWJ fixtures (labeled SYNTHETIC); clean CJK+emoji file → 0 findings (negative control).

## US-B3 — context suppression (kill the .d.ts FP class)
- `scanner/context.rs::is_declaration_file` (.d.ts/.d.mts/.d.cts/.pyi); `scan_code_patterns` early-returns for declaration files.
- **Done-when:** `./cli/target/release/sigil scan test-repo --format json` → 3 findings, all `malicious.js`; `types.d.ts` now 0 (was 4 of 7).

## US-B4 — honest fixture corpus
- `tests/fixtures/{install_hooks,code_patterns,prompt_injection,inference_security,clean,unicode}` + `MANIFEST.json` with Data Source / Sample Size / Limitations and per-case expected phase+severity; every case marked synthetic and traced to a published advisory shape.
- **Done-when:** `fixtures_tests::fixture_corpus_matches_manifest` runs each fixture through `run_scan`, asserts expected phase ≥ severity (and clean cases produce zero findings). Passes.

## Full suite
`cargo test` → **18 passed; 0 failed** (6 scoring + 4 walker + 6 normalize + 1 context + 1 fixtures).

## Bugs fixed in passing (both real, both shipped in this phase)
1. **Single-file scan produced empty rel_path.** `sigil scan <file>` did `strip_prefix(path=file)` → "" → filename-gated phases (install hooks on "setup.py") silently never fired. Fixed: strip against parent when target is a file. Caught by the install_hooks fixture.
2. **Cache served stale verdicts across scanner upgrades.** `CacheEntry` validated only a hand-bumped schema version, so new detection logic returned cached old findings (observed: .d.ts suppression appeared not to work until `clear-cache`). Fixed: cache entries now carry `scanner_version = CARGO_PKG_VERSION` and are invalidated on mismatch.
