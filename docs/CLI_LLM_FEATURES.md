# `sigil scan --enhanced` (Pro LLM analysis)

`sigil scan <dir> --enhanced` uploads files from the scanned directory, with
the scan result, to the Sigil API for LLM analysis, a Pro plan feature. This
page describes what it sends and what you get back today. The
[`sigil login`](cli.md#sigil-login) section of the CLI reference and
[Data Handling, section 3](data-handling.md#3-pro-enhanced-scan-and-ai-investigation)
are the reference for the data it sends.

## Current status: no LLM findings yet

The API does not return LLM findings for `--enhanced` yet. It scores and
stores the scan and answers with its static analysis. The API keeps the
uploaded files out of the stored scan; an API without the update stores them
with the scan record (see [API update rollout](cli.md#api-update-rollout) and
[Data Handling](data-handling.md#3-pro-enhanced-scan-and-ai-investigation)).
The response:

- on a Free plan, with a note that LLM analysis needs a Pro plan. The plan is
  checked after the upload, so the files are still sent;
- on a Pro plan, because its LLM step does not run for this request: it fails,
  and the API returns the static result with the name of the error.

The CLI says which of these happened (see [Output](#output)). Never use
`--enhanced` on code you are not allowed to share: the files are uploaded
whatever the outcome.

## Usage

```bash
sigil login                              # store a token; --enhanced refuses to run without one
sigil scan ./my-project --enhanced --no-cache
```

`--enhanced` runs only on a fresh scan: a re-scan of unchanged content served
from the cache skips it, and the CLI warns on stderr that it did, hence
`--no-cache`. For a
repository URL, `sigil scan` runs the `sigil clone` workflow, which ignores
`--enhanced`; clone first, then scan `~/.sigil/quarantine/<id>`.

## What is sent

The CLI walks the target directory and collects up to 50 files with a common
text or code extension (`py`, `js`, `ts`, `rs`, `go`, `sh`, `yaml`, `json`,
`md`, `txt` and others), each 100,000 bytes or smaller and without a NUL byte.
It does not apply the scan's exclusions (`.sigilignore`, policy excludes), so
ignored files can be uploaded. With the files goes the same scan request that
`--submit` sends: every active finding with its flagged source line
(`snippet`), including findings in files that were not uploaded (a secret
flagged in `.env`, for example), the number of files scanned, and the CLI's
own score and verdict, under the fixed target name `cli-scan` instead of the
scanned path.

The request, as captured from the CLI (`tests/fixtures/api_contract/cli-current/scan_enhanced.json`,
shortened to one finding and one file):

```http
POST /v1/scan-enhanced
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "cli-scan",
  "target_type": "directory",
  "files_scanned": 5,
  "findings": [
    {
      "phase": "code_patterns",
      "rule": "CODE-001",
      "severity": "HIGH",
      "file": "src/app.js",
      "line": 2,
      "snippet": "eval() call — arbitrary code execution: return eval(userInput);",
      "weight": 5,
      "fingerprint": "92f2b4fe7e61a6d3edaa7b744c6e48f8"
    }
  ],
  "metadata": {
    "source": "sigil-scan-enhanced",
    "cli_score": 58,
    "cli_verdict": "HIGH_RISK",
    "file_contents": {
      "src/app.js": "<the file's full text>"
    }
  }
}
```

The API keeps the findings and the scan's own metadata keys (`source`,
`cli_score`, `cli_verdict`, and `hash`, `hashes`, `publisher` and
`publisher_id` when present) with the scan record, but not `file_contents`,
nor any other key: only its LLM step sees the files. (An API without the
update stored the files with the scan record; see
[API update rollout](cli.md#api-update-rollout) and
[Data Handling](data-handling.md#3-pro-enhanced-scan-and-ai-investigation).)

## What comes back

The response is the API's scan response: `scan_id`, `target`, `files_scanned`,
`findings` (as stored), the API's own `risk_score` and `verdict`, `status`,
and `metadata`, which says what happened to the LLM step:

| Outcome | `metadata` |
|---------|------------|
| LLM analysis ran | `llm_analysis_performed: true`, `enhanced_findings_count`; LLM findings are added to `findings` with phase `llm_analysis` |
| Free plan | `upgrade_required: true`, `upgrade_message`, `upgrade_url` |
| Pro plan, LLM step failed | `llm_analysis_performed: false`, `llm_error` (the exception type), `fallback_to_static: true` |
| Pro plan, no files in the request | `llm_analysis_performed: false`, `reason` |

The response also carries `id`, a copy of `scan_id`, but only when LLM analysis
ran: CLI 1.3.7 reads `id`, and prints a success message for any response that
has it.

## Output

What the current CLI prints for each outcome (`report_enhanced_outcome`,
`cli/src/main.rs`):

| Outcome | Message |
|---------|---------|
| LLM analysis ran | `sigil: enhanced LLM analysis completed: N LLM finding(s) (scan id: ...)`, then one line per LLM finding |
| Free plan | `warning: LLM analysis needs a Pro plan: the files were sent, but the API returned only its static analysis (scan id: ...)` |
| LLM step did not run | `warning: the API did not run LLM analysis (server reported: <llm_error or reason>); it returned only its static analysis (scan id: ...)` |
| Request failed (HTTP error, network, parse) | `warning: Enhanced analysis failed: <error>` and `Continuing with static analysis results only` |
| Not logged in | `error: Enhanced scanning requires authentication. Run: sigil login` (exit code 2) |
| No file to upload | `warning: no readable files found for LLM analysis` |

The warnings and errors go to stderr. The success message goes to stdout
with `-f text` and to stderr with any other `-f` format, so a JSON or SARIF
report on stdout stays valid. LLM findings are printed for information: they
do not change the verdict, the exit code or the scan report in any `-f`
format.

CLI 1.3.7 prints `sigil: Enhanced LLM analysis completed` to stdout, after
the report, for any response it can parse. The API puts `id` in the response
only when LLM analysis ran, so for a response without it 1.3.7
prints ``warning: Enhanced analysis failed: failed to parse response: ...
missing field `id` ...`` and `Continuing with static analysis results only`
on stderr instead. Upgrade the CLI to see which outcome it was.

## Plans

LLM analysis is a Pro, Team and Enterprise feature; static analysis runs
locally on every plan. `GET /v1/scan-capabilities` returns what your
account's plan includes:

```bash
curl -H "Authorization: Bearer $(cat ~/.sigil/token)" https://api.sigilsec.ai/v1/scan-capabilities
```

`/v1/scan-enhanced` allows 20 requests per minute, and each accepted request
counts against the plan's monthly scan quota, like `--submit`.

`--enhanced` already stores the scan, so `sigil scan --enhanced --submit`
stores it once and uses one unit of the quota: after `--enhanced` returns a
scan id, `--submit` prints that id (`results submitted to Sigil cloud by the
--enhanced upload (scan id: ...); --submit sent nothing more`) and does not
upload again. If `--enhanced` failed, or the API returned no scan id,
`--submit` uploads as it does without `--enhanced`. CLI 1.3.7 uploads twice:
two scan records, two units of the quota.

## Troubleshooting

- **`error: Enhanced scanning requires authentication`**: run `sigil login`.
  The token is stored in `~/.sigil/token`; it expires and the CLI does not
  refresh it.
- **`API error: 401 ...`**: the token expired. Run `sigil login` again.
- **Offline**: the request fails with a warning and the scan result stands.
- **`warning: --enhanced was skipped: the result came from the cache ...`**
  (on stderr): the scan was served from the cache, so nothing was uploaded and
  no scan was stored. Add `--no-cache`. The warning names every cloud option
  the run skipped (`--submit`, `--enrich`, `--enhanced`), and the exit code is
  that of the cached result. CLI 1.3.7 skips them without a message.
