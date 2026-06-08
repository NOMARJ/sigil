# US-008 — Rust CLI Verification CI Job (HIGH-002)

**Story:** F-007 / US-008 · **Linear:** NOM-1076 · **Executor:** agent (buildable)
**Date:** 2026-06-08

> **Data Source:** Real local tooling state + real actionlint run (not CI runtime)
> **Sample Size:** 1 workflow file (`.github/workflows/rust-cli.yml`)
> **Limitations:** The workflow is DRAFTED and committed but has not executed on GitHub
> (running it = US-009, environment/operator-gated). Validation below is local.

## 1. Why local `cargo --version` failed (HIGH-002 root cause)

```
$ cargo --version
error: rustup could not choose a version of cargo to run, because one wasn't
specified explicitly, and no default is configured.
$ rustup toolchain list
no installed toolchains
```

The workstation has `rustup 1.29.0` but **no installed toolchain and no default**, so every
`cargo` invocation fails before reaching the crate. The Rust CLI (`cli/`, `sigil-cli` v1.1.2,
edition 2021) was therefore *unverifiable locally* — the launch-readiness report's CLI claims
could not be exercised. This is a toolchain-availability gap, not a code defect.

## 2. How the CI job closes it

`.github/workflows/rust-cli.yml` runs on `ubuntu-latest` (which ships `rustup`) and:

1. `rustup toolchain install 1.82.0 --profile minimal --component clippy,rustfmt`
2. `rustup default 1.82.0`  ← pinned, reproducible (edition 2021 needs ≥1.56; 1.82.0 is a real stable)
3. `cargo build --verbose`
4. `cargo test --verbose`

All steps use `defaults.run.working-directory: cli`, so `cargo` operates against the existing
`cli/Cargo.toml`. The job is path-filtered to `cli/**` and the workflow file itself. `checkout`
is SHA-pinned to the same SHA already used in `.github/workflows/ci.yml`
(`actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`) — no unverified third-party
action SHAs introduced. Toolchain install uses the runner's preinstalled `rustup` (no extra
action dependency).

## 3. Validation (verbatim)

```
$ python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/rust-cli.yml')); ..."
YAML OK — jobs: ['test-rust-cli'] | references cli working-directory: cli

$ actionlint --version
1.7.12

$ actionlint .github/workflows/rust-cli.yml
ACTIONLINT CLEAN   (exit 0, no diagnostics)
```

actionlint (installed via Homebrew for this verification) reports zero diagnostics. pyyaml
confirms the structure and the `cli` working-directory binding to `cli/Cargo.toml`.

## 4. Operator action required (not done under probation)

- **Enabling on protected branches:** merging this workflow to `main` makes it run on
  push/PR to `main`. Adding it as a *required status check* on the `main` branch protection
  rule is an operator action (GitHub repo settings → Branches), not performed here.
- **First green run = US-009:** the actual `cargo test` pass/fail is environment-gated
  (US-009). It executes either on the first CI run after merge, or via an operator-approved
  local `rustup default stable && cd cli && cargo test`. Until then HIGH-002 is *mechanism in
  place, result pending*.
- Optional enhancement: add `actions/cache` for `~/.cargo` + `cli/target` (SHA-pinned per repo
  policy) to speed runs — omitted from the draft to avoid an unverified action SHA.

## AC verification

- [x] Workflow runs a pinned toolchain (`rustup default 1.82.0`) then `cargo test` against `cli/`
- [x] YAML validates — `actionlint` CLEAN (exit 0); references existing `cli/Cargo.toml` via working-directory
- [x] Evidence explains the local `cargo --version` failure and how CI closes it (§1–§2)
- [x] Workflow drafted/committed; protected-branch enablement noted as operator action (§4)
