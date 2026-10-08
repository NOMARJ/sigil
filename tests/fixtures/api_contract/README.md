# CLI ↔ API contract fixtures

Request and response bodies exchanged between the `sigil` CLI and the Sigil
API for `sigil scan --submit`, `--enhanced`, `--enrich`, `sigil report` and
`sigil explain`. Both sides test against them:

- `cli/src/api.rs` (`contract_fixture_tests`): the current CLI builds
  `cli-current/` from the scan in `cli-1.3.7/scan_submit.json` and parses
  every response in `api-patched/` and `api-deployed/`, including the 403
  body for a Free plan's threat lookup. It also checks that CLI 1.3.7's
  response type parses the `api-patched/` scan response but not the
  `--enhanced` one, for which no LLM analysis ran.
- `api/tests/test_cli_contract.py`: every request body here is accepted by the
  API models and endpoints, including the released CLI's, and the API's 403
  body for a Free plan's threat lookup is the one captured here. An
  `--enhanced` response carries the `id` CLI 1.3.7 needs only when LLM
  analysis ran.
- `cli-current/phases.json` lists every phase the CLI has (`Phase::ALL`), in
  the serde spelling (`InstallHooks`) and the API spelling the CLI sends
  (`install_hooks`). The Rust test `phases_fixture_lists_every_cli_phase`
  fails when the CLI's phases differ from this list; the Python tests check
  each entry against the API's `ScanPhase` and its Rust-engine phase map.

| Directory | What it holds |
| --- | --- |
| `cli-1.3.7/` | Request bodies sent by the released CLI 1.3.7 |
| `cli-current/` | Request bodies sent by the CLI built from this tree, and `phases.json` |
| `dashboard/` | The body the dashboard's `submitReport` (`dashboard/src/lib/api.ts`) builds |
| `api-patched/` | Responses from the API in this tree |
| `api-deployed/` | Responses from the API before the contract fix (the code at the PR's base) |

**Data source:** captured, not hand-written, except `dashboard/report.json`
and `cli-current/phases.json`. On 2026-10-05 both CLI binaries scanned the
same five-file synthetic fixture (an npm `postinstall` running a local
script, an `eval` call, a POST to `collector.example.invalid`, and an OpenAI
client with a hard-coded `base_url`) and sent their requests through a
loopback proxy to the API app running locally with its in-memory store; the
proxy recorded each request and response body. `cli-current/explain_scan.json`
was captured again the same way on the same day, after `sigil explain` was
changed to send the fixed target `sigil-explain`; only `target` changed.
`api-patched/scan_enhanced_response_free_plan.json` was captured again the
same way on the same day, after `/v1/scan-enhanced` stopped sending the `id`
alias when no LLM analysis ran; only `id` (now absent), `scan_id` and
`created_at` changed.

`api-patched/scan_response.json` and
`api-patched/scan_enhanced_response_free_plan.json` were captured again on
2026-10-08, in process with the API's test client and its in-memory store
instead of through the loopback proxy, from `cli-current/scan_submit.json`
and `cli-current/scan_enhanced.json`, after the API gave the Inference
Security phase its weight of 5 (it had defaulted to 1.0). Only `risk_score`
(304.0 to 384.0), the ids and `created_at` changed; the verdict is
`CRITICAL_RISK` in both.

`api-patched/report_response.json` was captured again on 2026-10-08, in
process with the API's test client and its in-memory store, from
`cli-current/report.json`; only `id` and `report_id` changed (the report id
is the 12-character hex id, as in `api-deployed/`, not a GUID).

The `api-deployed/` responses come from the CLI built from this tree talking
to the API at the PR's base. That API refuses the Inference Security phase
(HTTP 422 on the five-file scan), so its scan and `--enhanced` responses are
for a four-file variant of the fixture without the OpenAI client file:
`files_scanned` 4 and three findings. Its report response is for the current
CLI's report body, and its threat lookup for the same seeded entry as
`api-patched/`.

`dashboard/report.json` was written by hand from `submitReport`, with example
values. `cli-current/phases.json` was written by hand from `Phase::ALL` and is
checked against it by the Rust test above.

**Sample size:** one capture per command and CLI version: five findings per
scan request (three in the `api-deployed/` scan responses), one report, one
threat lookup with a seeded match, one refused threat lookup.

**Limitations:** the API ran in memory mode, not against MSSQL, so these show
request validation and response shapes, not database behaviour. The `--enhanced`
responses are from a Free plan account: in memory mode the plan lookup used by
`/v1/scan-enhanced` (a stored procedure) always reports Free. Ids, timestamps
and `duration_ms` are whatever the run produced.
