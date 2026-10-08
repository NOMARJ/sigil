# Data Handling — What Sigil Transmits, Per Tier

> **Status:** Normative. Marketing copy, docs, and UI text MUST NOT make a
> stronger privacy claim than this document. Every statement below is tied to
> a code path so it can be re-verified after changes.
>
> This is an engineering disclosure, not the legal privacy policy. The legal
> policy lives at [sigilsec.ai/privacy](https://sigilsec.ai/privacy).

## Summary table

| Mode | Source code transmitted? | What leaves your machine | Where it goes |
| --- | --- | --- | --- |
| Default CLI, logged in or not | **No** | For `sigil scan` of a tree with a lockfile: the listed dependencies' names and versions, and the IDs of any `CVE-` advisories found | OSV (`api.osv.dev`), the npm and PyPI registries, and FIRST EPSS (`api.first.org`); the CISA KEV catalogue is downloaded from `www.cisa.gov` |
| Scan submission (`sigil scan --submit`, after `sigil login`) | **Flagged lines only** | Finding metadata + the source-line excerpts shown in scan output | Sigil API |
| AI explanation (`sigil explain <scan.json>`, after `sigil login`) | **Flagged lines only** | Every finding in that saved scan report: metadata + the flagged source line | Sigil API → LLM provider (the finding being adjudicated) |
| Pro enhanced scan / AI investigation | **Yes — collected text files** | For CLI `--enhanced`, up to 50 eligible text files under the target directory, collected independently of scan exclusions, plus the scan result: every finding with its flagged source line, including findings in files outside those 50; investigation sends finding context | Sigil API → LLM provider |
| Optional LLM review (`sigil scan --llm-review`, off by default) | **Yes — masked excerpts** | Per finding at Medium or above: rule, title, path, masked matched line and up to 6 masked lines on each side | The model endpoint you configure (Anthropic, or an OpenAI-compatible endpoint), directly, not via Sigil |

## 1. Default CLI, logged in or not (Open Source tier)

All eight scan phases run locally: no telemetry, no account, no upload of
code. Logging in does not change what a plain scan sends. This is the only
mode for which the claim **"your code never leaves your machine"** is true,
and marketing copy must scope that claim to this mode.

It is not "no network calls", though. By default, `sigil scan` and
`sigil baseline` of a tree with a `requirements.txt`, `package-lock.json`,
`Cargo.lock` or `go.mod` (`fresh_scan`, `cli/src/main.rs`) send each listed
dependency's name and version to OSV (`api.osv.dev`, `cli/src/feeds/osv.rs`),
and look npm and PyPI packages up on `registry.npmjs.org` and `pypi.org`
(`cli/src/provenance/mod.rs`). When an advisory found that way has an ID
starting `CVE-`, the scan also downloads the CISA KEV catalogue from
`www.cisa.gov` and sends those CVE IDs to FIRST's EPSS API (`api.first.org`,
`cli/src/feeds/enrichment.rs`). Without a connection these lookups are
skipped. A `--phases` filter turns them off, and `sigil clone`, `pip` and
`npm` do not run them.

Optional network features the user explicitly invokes download data or send
a hash; they do not upload source code. They are signature updates via
`sigil fetch` (`get_signatures`); the `sigil scan --enrich` hash lookup
(`compute_directory_hash`, `cli/src/main.rs`), which sends a SHA-256 of the
paths and sizes of every file under the directory; and `sigil report`
(`report_threat`), which sends the hash, threat type and description you give
it.

## 2. Scan submission (`sigil scan --submit`)

With `--submit` (normally after `sigil login`, whose token it sends), the CLI
submits scan results to the Sigil API (`SigilClient::submit_scan`,
`scan_request_body`, `cli/src/api.rs`). The request carries the number of
files scanned, the CLI's own score and verdict, the fixed target name
`cli-scan` (not the scanned path), and each active `Finding` (findings
suppressed by a policy, a trust-ledger approval or a `sigil:ignore` marker
are not sent). A `Finding` includes:

- `rule`, `phase`, `severity`, `weight` — pattern metadata
- `file`, `line` — the path and line number of the match
- `snippet` — **the flagged source line itself** (`cli/src/scanner/mod.rs`,
  `Finding.snippet`)
- `fingerprint`, and where they apply the advisory's `kev` and `epss`
  values, the `locator` inside an archive, and the rule's `evidence` class

CLI 1.3.7 posted its whole `ScanResult` instead: the same findings, score
and verdict, plus any ledger- or inline-suppressed findings (snippets
included) with their attributions: the ledger approval (`suppressed_by`: the
approved source, its ledger id and the approval date) and each inline
suppression's `file:line RULE-ID — reason` note (`inline_suppressions`),
whose reason is the text written in the `sigil:ignore` marker; and the scan
duration, the platform it detected, and the engine version, corpus digest,
rule count and rule IDs. The API keeps only the active findings and the
file count from such a request.

So authenticated submissions transmit *excerpts of your source code*: the
specific lines that triggered a rule, exactly as they appear in your scan
output. Full files are **not** uploaded on this path. Do not describe this
tier as "metadata only" without also disclosing the flagged-line excerpts.

`sigil explain <scan.json>` (`cmd_explain`, `cli/src/explain.rs`) sends the
same kind of data, read from a saved `-f json` report: with the stored token
it posts every finding in that report, `snippet` included, to
`POST /v1/scan` under the fixed target name `sigil-explain` (CLI 1.3.7 named
the scan after the report file, its name without the extension), then asks the API to adjudicate one finding (`--finding`,
default the first) at `POST /v1/scans/{id}/findings/{n}/adjudicate`
(`api/routers/scan.py`). The API passes that finding and its flagged line to
the configured LLM provider (`api/services/fp_adjudicator.py`).

## 3. Pro enhanced scan and AI investigation

Pro features exist to have an AI read and reason about your code. They
transmit source code by design:

- `SigilClient::submit_enhanced_scan` (`cli/src/api.rs`) uploads a
  `file_contents` map to `POST /v1/scan-enhanced`. The CLI independently
  collects up to 50 eligible text files under the target directory; this
  collection does not apply scanner exclusions such as `.sigilignore`.
  Ignored files can therefore be uploaded. Review the target directory
  before requesting enhanced analysis. The same request carries what
  `--submit` sends (section 2): the active `findings`, each with its
  `snippet` (the flagged source line), including findings in files outside
  the uploaded ones (a secret flagged in `.env`, for example). With
  `--submit` as well, the current CLI sends this one request and not a second
  one, since this request already stores the scan (CLI 1.3.7 sends both).
  The API holds the uploaded files only while it handles the request, for
  its LLM step:
  the scan record it stores keeps the findings and the scan's own metadata
  keys (`source`, `cli_score`, `cli_verdict`, and `hash`, `hashes`,
  `publisher` and `publisher_id` when present) but not the files, nor any
  other key of the request's metadata (`submit_enhanced_scan`,
  `api/routers/scan.py`). An API without the update stores the request,
  files included, with the scan record, and every scan endpoint that returns
  a stored scan returns that record's metadata, files included, to the
  account that sent the scan and to its team: the detail endpoints
  (`GET /v1/scans/{id}`, `GET /scans/{id}`) and the list endpoints
  (`GET /scans`, `GET /v1/scans`), for as long as the record is kept, or
  until the database migration that ships with the update
  (`api/migrations/011_remove_uploaded_files_from_scan_metadata.sql`) is
  applied, which removes the keys `file_contents` and `content` from every
  stored scan (see [API update rollout](cli.md#api-update-rollout)). The
  API's LLM step does not
  currently run for this endpoint, so it answers with its static analysis;
  the CLI reports that rather than an analysis (CLI 1.3.7 reports a failed
  enhanced analysis).
- The investigation service (`api/services/finding_investigator.py`) builds
  LLM prompts containing the finding's `code_snippet` plus surrounding
  context lines.
- The context expander (`api/services/context_expander.py`) reads
  additional related files (`full_path.read_text(...)`) — e.g. modules
  imported by the flagged file — and includes their contents as
  investigation context.

That prompt is sent to the configured LLM provider (`api/llm_config.py`;
Anthropic by default, OpenAI/Azure configurable). Code shared with a
provider is subject to that provider's data-usage terms.

**User guidance:** never run Pro investigation on code you are not permitted
to share with a third-party processor. The free tier's offline scan remains
available for that code.

## 4. Optional LLM review (`sigil scan --llm-review`)

Off unless `--llm-review`, the organisation policy or a policy file named with
`--config` (`llm_review: true`) turns it on; a `.sigil.yml` found by discovery
cannot. An organisation policy can lock it off. When on, `llm_review::run`
(`cli/src/llm_review/mod.rs`) sends, for each active finding at Medium or
above: the rule id, title and remediation text, the severity and phase, the
file path and line, the matched text, and up to 6 lines on each side of the
line. Everything taken from the scanned tree is masked first
(`cli/src/llm_review/mask.rs`): private-key blocks (tracked from the top of
the file), every match of a credential or secret rule, common token shapes,
`Authorization` values, URL passwords, the values of secret-named keys (quoted
or not, in code, env, INI and YAML files) and high-entropy strings; invisible
characters are shown as visible markers. Secret files (`.env*`, private keys,
`.npmrc`, `.netrc`, cloud credential files), symbolic links, paths outside the
scanned tree, and in a single-file scan every other file, are never read. The
request goes
straight from the CLI to the endpoint you configure: the Anthropic Messages
API (`ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`) or an OpenAI-compatible
endpoint (`SIGIL_LLM_ENDPOINT`, or `llm_endpoint` in the organisation
policy). Nothing goes to the Sigil API on this path. Masking is pattern-based
and can miss a secret that matches no pattern. What is sent is subject to the
provider's data-usage terms. Full detail: [llm-review.md](llm-review.md).

## Rules for copy and docs (enforced by review)

1. "No code leaves your machine" / "no source code is transmitted" — only
   when explicitly scoped to the CLI without `--submit`, `--enhanced`,
   `--llm-review` or `sigil explain`. Never "fully offline" without
   qualification: by default `sigil scan` looks lockfile dependencies up
   online (section 1).
2. Any surface that sells or enables Pro must disclose that Pro uploads
   relevant source files for AI analysis.
3. Statements about scan submission (`--submit`) must mention flagged-line
   excerpts, not claim "metadata only".
4. Changes to `Finding`, `submit_scan`, `submit_enhanced_scan`,
   `finding_investigator`, `context_expander`, or `cli/src/llm_review/`
   require re-verifying this document in the same PR.
