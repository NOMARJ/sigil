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

## Rules for copy and docs (enforced by review)

1. "No code leaves your machine" / "fully offline" / "no source code is
   transmitted" — only when explicitly scoped to the unauthenticated CLI.
2. Any surface that sells or enables Pro must disclose that Pro uploads
   relevant source files for AI analysis.
3. Statements about the authenticated tier must mention flagged-line
   excerpts, not claim "metadata only".
4. Changes to `Finding`, `submit_scan`, `submit_enhanced_scan`,
   `finding_investigator`, or `context_expander` require re-verifying this
   document in the same PR.
