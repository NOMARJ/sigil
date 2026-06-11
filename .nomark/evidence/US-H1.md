# Evidence — US-H1: Digest-keyed ledger match API (F-010)

**Date:** 2026-06-11
**Files:** `cli/src/ledger.rs`

## What was built
- `ledger::match_approved_in(dir, root)` / `match_approved(root)` — pins `root` and returns the approved `LedgerRecord` on exact `artifact_digest` equality. Drifted content returns `None` (drift stays with `detect_rugpull`). Empty pins never match (digest-of-nothing guard).
- `ledger::remove_in(dir, id)` / `remove(id)` — approval revocation, for US-H2 to call from `sigil reject`.

## Verification (fresh run)

`cargo test ledger::tests`:
```
running 14 tests
test ledger::tests::match_approved_unknown_content_returns_none ... ok
test ledger::tests::match_approved_empty_directory_never_matches ... ok
test ledger::tests::match_approved_drifted_content_returns_none ... ok
test ledger::tests::match_approved_exact_content_returns_record ... ok
test ledger::tests::ledger_remove_revokes_approval ... ok
(+ 9 pre-existing ledger/rugpull tests)
test result: ok. 14 passed; 0 failed
```

Full suite: `cargo test` → `test result: ok. 123 passed; 0 failed; 0 ignored`

TDD: tests written first; confirmed failing with E0425 (missing functions) before implementation.
