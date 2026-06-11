# Evidence: US-111 — `sigil explain` CLI surface for LLM adjudication

**Date:** 2026-06-11 · **Feature:** F-009 · **Branch:** feature/sigil-pro-fable

## Change
- **`cli/src/explain.rs`** (new): `sigil explain <scan-json> [--finding N] [--endpoint URL]`.
  Parses `sigil scan -f json` output (concatenated JSON docs — banner, summary, findings array, verdict), normalizes CLI finding fields to the API schema (`NetworkExfil`→`network_exfil`, `High`→`HIGH`), submits the scan (`POST /v1/scan`, bearer token from `~/.sigil/token`), then requests adjudication (`POST /v1/scans/{id}/findings/{n}/adjudicate`). Renders classification (color-coded) + confidence + rationale + model. Status mapping: 402 → upgrade message with `upgrade_url` + reset date (exit 2); 422 → refusal explanation with category (exit 2); 401/403 → login hint (exit 2); success → exit 0.
- **`cli/src/main.rs`**: `Explain` subcommand + dispatch (`--finding` long-only: `-f` collides with the global `--format`).
- **`cli/src/api.rs`**: `load_token` widened to `pub(crate)` (one-line, no behavior change).
- **D6 capability-minimal honoured:** the CLI contains no LLM client, no API key handling, no model names in request paths — outbound traffic goes only to the configured Sigil endpoint; the server owns model access and metering.
- No new dependencies (integration tests use a stdlib `TcpListener` mock + `CARGO_BIN_EXE_sigil`).

## Verification (run fresh 2026-06-11)
TDD Red: 4 integration tests failed — `explain` unrecognized subcommand (right reason). Mid-Green fix: clap debug-assert caught the `-f` short-flag collision.

```
$ cargo test --manifest-path cli/Cargo.toml explain        # story AC
test result: ok. 3 passed (unit: multi-doc parse, no-array reject, phase/severity normalize)
test result: ok. 4 passed (integration: verdict render, 402 upgrade, index range, no token)
$ cargo test --manifest-path cli/Cargo.toml                 # full suite
test result: ok. 132 passed; 0 failed   (unit)
test result: ok. 4 passed; 0 failed     (integration)
```

## Transcript (real binary, real axios scan, local mock API)

Scan input is a real `sigil scan` of `/tmp/control2/npm-axios` (F-008 control set, 50 findings). The API is a local mock returning the US-107 endpoint's exact response shapes — a live end-to-end against api.sigilsec.ai is blocked on the same Anthropic billing issue as US-110 and lands with US-112 ops verification.

```
$ sigil explain axios-scan.json --finding 0 --endpoint http://127.0.0.1:8731
sigil: verdict: benign_dual_use
  confidence: 91%
  rationale: The flagged webhook URL appears in CHANGELOG.md release notes describing a
  paramsSerializer callback feature — documentation text, not executable exfiltration code.
  No taint path from runtime input to the URL.
  model: claude-fable-5
exit: 0

$ sigil explain axios-scan.json --finding 999 --endpoint http://127.0.0.1:9
error: finding index 999 out of range — scan has 50 finding(s)
exit: 2

$ HOME=/tmp/empty sigil explain axios-scan.json --endpoint http://127.0.0.1:9
error: not authenticated — run `sigil login` first
exit: 2
```

402 path (from the integration test, mock returning the US-105 structured denial):
```
sigil: LLM analysis allowance exhausted for your plan. Upgrade to Pro for unmetered AI analysis.
  allowance resets: 2026-07-01T00:00:00
  Upgrade to Pro: https://www.sigilsec.ai/pricing
exit: 2
```

## Notes
- The adjudication verdict text in the transcript above is mock data (clearly labelled — the mock returns the US-107 response contract verbatim); every CLI behavior shown is the real binary.
- Pre-existing CLI ScanResponse struct (`api.rs`) expects `id` but the API returns `scan_id` — affects the legacy `--submit` flow, not explain (which parses `scan_id` directly). Logged as follow-up, out of story scope.
