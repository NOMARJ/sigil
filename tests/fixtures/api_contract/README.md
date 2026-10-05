# CLI ↔ API contract fixtures

Request and response bodies exchanged between the `sigil` CLI and the Sigil
API for `sigil scan --submit`, `--enhanced`, `--enrich`, `sigil report` and
`sigil explain`. Both sides test against them:

- `cli/src/api.rs` (`contract_fixture_tests`): the current CLI builds
  `cli-current/` from the scan in `cli-1.3.7/scan_submit.json` and parses
  every response in `api-patched/` and `api-deployed/`.
- `api/tests/test_cli_contract.py`: every request body here is accepted by the
  API models and endpoints, including the released CLI's.

| Directory | What it holds |
| --- | --- |
| `cli-1.3.7/` | Request bodies sent by the released CLI 1.3.7 |
| `cli-current/` | Request bodies sent by the CLI built from this tree |
| `dashboard/` | The body the dashboard's `submitReport` (`dashboard/src/lib/api.ts`) builds |
| `api-patched/` | Responses from the API in this tree |
| `api-deployed/` | Responses from the API before the contract fix (the code at the PR's base) |

**Data source:** captured, not hand-written, except `dashboard/report.json`.
On 2026-10-05 both CLI binaries scanned the same five-file synthetic fixture
(an npm `postinstall` running a local script, an `eval` call, a POST to
`collector.example.invalid`, and an OpenAI client with a hard-coded
`base_url`) and sent their requests through a loopback proxy to the API app
running locally with its in-memory store; the proxy recorded each request and
response body. `dashboard/report.json` was written by hand from
`submitReport`, with example values.

**Sample size:** one capture per command and CLI version: five findings per
scan request, one report, one threat lookup with a seeded match.

**Limitations:** the API ran in memory mode, not against MSSQL, so these show
request validation and response shapes, not database behaviour. The `--enhanced`
responses are from a Free plan account: in memory mode the plan lookup used by
`/v1/scan-enhanced` (a stored procedure) always reports Free. Ids, timestamps
and `duration_ms` are whatever the run produced.
