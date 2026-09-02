<!-- Thanks for the pull request. One feature or fix per PR; small PRs get reviewed faster. -->

## What changed and why

<!-- A few sentences. Link the issue this closes, if any: "Closes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New or improved scan rule (`cli/packs/core/v1/`)
- [ ] New feature
- [ ] Documentation
- [ ] Refactor / maintenance

## Checklist

From [CONTRIBUTING.md](../CONTRIBUTING.md):

- [ ] Branch is from `main` and the PR is focused on one change.
- [ ] Tests added or updated for any new scan rule or behaviour.
- [ ] `cd cli && cargo test` passes.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` is clean and `cargo fmt` has been run (Rust); `ruff` and `black` are clean (Python).
- [ ] Docs updated if CLI behaviour, scan output, or configuration changed.
- [ ] Commit messages are imperative and concise.

Self-scan gate:

- [ ] `sigil scan . --fail-on high` passes on this branch (the repository scans itself in CI).
- [ ] Any new `.sigilignore` entries are scoped to specific paths and carry a written rationale.
- [ ] Any new inline `sigil:ignore RULE-ID -- reason` markers name the rule and give a reason.

Scan rules only:

- [ ] Fixtures added under `tests/fixtures/<phase>/` with a matching case in `tests/fixtures/MANIFEST.json` (`expect_phase`, `expect_min_severity`, `source`, `synthetic`), plus a benign counterpart that must not fire.
- [ ] Fixtures are synthetic or defanged; no live payload, credential, or endpoint is committed.
- [ ] The rule carries `remediation`, `references`, and `tags`.
- [ ] Rule IDs follow the pack's family prefix and are unique.

Output changes only:

- [ ] No new top-level `--format json` key sorts before `"findings"` (ADR-0010; `findings_array_is_still_the_first_array_in_the_document` covers this).

## Evidence

<!-- Paste the relevant test output, the self-scan summary line, or before/after scan output. No invented numbers: if you measured something, say how. -->
