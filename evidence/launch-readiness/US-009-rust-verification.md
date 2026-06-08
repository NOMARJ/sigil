# US-009 — Rust CLI Build & Test Verification (HIGH-002)

**Story:** F-007 / US-009 · **Linear:** NOM-1077 · **Executor:** environment (run on CI, owner-approved)
**Date:** 2026-06-08 · **Depends on:** US-008

> **Data Source:** Real GitHub Actions CI run (ubuntu-latest), not local (local has no Rust toolchain)
> **Sample Size:** `cli/` crate — `sigil-cli` v1.1.2, 6 unit tests
> **Limitations:** Runs on CI's pinned toolchain; local workstation still has no default toolchain.

## Result: PASS ✅

`cargo build` + `cargo test` succeed for `cli/` on the `rust-cli.yml` workflow (US-008).

- **Toolchain:** `rustc 1.90.0-x86_64-unknown-linux-gnu` (pinned)
- **Build:** `Finished \`test\` profile [unoptimized + debuginfo] target(s) in 1.58s`
- **Tests (verbatim):**
  ```
  running 6 tests
  test scanner::scoring::tests::test_critical_risk_by_score ... ok
  test scanner::scoring::tests::test_critical_risk_install_hook_escalation ... ok
  test scanner::scoring::tests::test_high_risk_verdict ... ok
  test scanner::scoring::tests::test_low_risk_no_findings ... ok
  test scanner::scoring::tests::test_medium_risk_verdict ... ok
  test scanner::scoring::tests::test_low_risk_verdict ... ok

  test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
  ```
- **Run:** GitHub Actions `Rust CLI` workflow, run `27110957847` (PR #116), conclusion **success**.

## First-run triage (filed, not hidden)

The workflow's first execution (PR #115 merge to main, run `27110891927`) **failed** at `cargo build`:

```
error: failed to parse manifest at .../clap_builder-4.6.0/Cargo.toml
Caused by:
  feature `edition2024` is required
  The package requires the Cargo feature called `edition2024`, but that feature
  is not stabilized in this version of Cargo (1.82.0 ...).
```

This is exactly the MSRV risk flagged in `US-008-rust-ci.md` §4: a transitive dependency
(`clap_builder 4.6.0`, via `clap 4.6.1`) requires Rust edition 2024 (Cargo ≥ 1.85.0). Remediation:
bumped the pinned toolchain `1.82.0 → 1.90.0` (PR #116, commit on `fix/rust-ci-toolchain`). The
re-run (above) is green. No test was skipped, ignored, or masked.

## AC verification

- [x] `cargo test` (CI) exits 0 for `cli/` — `test result: ok. 6 passed`
- [x] Evidence captures toolchain version (`rustc 1.90.0`) and full test output
- [x] The first-run failure (MSRV/edition2024) was filed and triaged, not hidden

**HIGH-002 is closed:** the Rust CLI is now verifiable in CI (`rust-cli.yml` on `main`), runs
green on every push/PR touching `cli/**`.
