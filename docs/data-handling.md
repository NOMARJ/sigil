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
| Offline / unauthenticated CLI (default) | **No** | Nothing | Nowhere |
| Authenticated (`sigil login`) scan submission | **Flagged lines only** | Finding metadata + the source-line excerpts shown in scan output | Sigil API |
| Pro enhanced scan / AI investigation | **Yes — relevant files** | Full contents of files relevant to a finding | Sigil API → LLM provider |
| Optional LLM review (`sigil scan --llm-review`, off by default) | **Yes — masked excerpts** | Per finding at Medium or above: rule, title, path, masked matched line and up to 6 masked lines on each side | The model endpoint you configure (Anthropic, or an OpenAI-compatible endpoint), directly, not via Sigil |

## 1. Offline / unauthenticated CLI (Open Source tier)

All eight scan phases run locally. With no login, the CLI makes no network
calls during a scan: no telemetry, no account, no upload. This is the only
mode for which the claim **"your code never leaves your machine"** is true,
and marketing copy must scope that claim to this mode.

Optional network features the user explicitly invokes (OSV feed sync,
signature updates via `get_signatures`) download data; they do not upload
source code.

## 2. Authenticated scan submission (`sigil login`)

When authenticated, the CLI submits scan results to the Sigil API
(`ApiClient::submit_scan`, `cli/src/api.rs`). The submitted `ScanResult`
contains each `Finding`, and a `Finding` includes:

- `rule`, `phase`, `severity`, `weight` — pattern metadata
- `file`, `line` — the path and line number of the match
- `snippet` — **the flagged source line itself** (`cli/src/scanner/mod.rs`,
  `Finding.snippet`)

So authenticated submissions transmit *excerpts of your source code*: the
specific lines that triggered a rule, exactly as they appear in your scan
output. Full files are **not** uploaded on this path. Do not describe this
tier as "metadata only" without also disclosing the flagged-line excerpts.

## 3. Pro enhanced scan and AI investigation

Pro features exist to have an AI read and reason about your code. They
transmit source code by design:

- `ApiClient::submit_enhanced_scan` (`cli/src/api.rs`) uploads a
  `file_contents` map — full text of the scanned files included in the
  request — to `POST /v1/scan-enhanced`.
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

Off unless `--llm-review` or a scan policy (`llm_review: true`) turns it on;
an organisation policy can lock it off. When on, `llm_review::run`
(`cli/src/llm_review/mod.rs`) sends, for each active finding at Medium or
above: the rule id, title and remediation text, the severity and phase, the
file path and line, the matched text, and up to 6 lines on each side of the
line. Everything taken from the scanned tree is masked first
(`cli/src/llm_review/mask.rs`): private-key blocks, every match of a
credential or secret rule, common token shapes, `Authorization` values, URL
passwords, secret-named assignments and high-entropy strings. Secret files
(`.env*`, private keys, `.npmrc`, `.netrc`, cloud credential files), symbolic
links and paths outside the scanned tree are never read. The request goes
straight from the CLI to the endpoint you configure: the Anthropic Messages
API (`ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`) or an OpenAI-compatible
endpoint (`SIGIL_LLM_ENDPOINT`, or `llm_endpoint` in the organisation
policy). Nothing goes to the Sigil API on this path. Masking is pattern-based
and can miss a secret that matches no pattern. What is sent is subject to the
provider's data-usage terms. Full detail: [llm-review.md](llm-review.md).

## Rules for copy and docs (enforced by review)

1. "No code leaves your machine" / "fully offline" / "no source code is
   transmitted" — only when explicitly scoped to the unauthenticated CLI
   without `--llm-review`.
2. Any surface that sells or enables Pro must disclose that Pro uploads
   relevant source files for AI analysis.
3. Statements about the authenticated tier must mention flagged-line
   excerpts, not claim "metadata only".
4. Changes to `Finding`, `submit_scan`, `submit_enhanced_scan`,
   `finding_investigator`, `context_expander`, or `cli/src/llm_review/`
   require re-verifying this document in the same PR.
