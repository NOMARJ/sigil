# Sigil Architecture

## Overview

Sigil is an automated security auditing system for AI agent code, built around a **quarantine-first** workflow. Nothing executes, installs, or enters your working environment until it has been scanned, scored, and explicitly approved. The exception is code the package tools run while downloading: `sigil pip` of a package with no compatible wheel lets `pip download` run its `setup.py` before the scan, and `sigil npm` of a local directory or a git spec (a git URL, or a hosted shorthand such as `owner/repo` or `github:owner/repo`; a scoped name typed without its `@`, like `langchain/community`, is one) lets `npm pack` run the package's lifecycle scripts before the scan: `prepack`, `prepare` and `postpack` for a directory, and for a git spec, scripts including `preinstall`, `install`, `postinstall` and `prepare` (see [`sigil pip`](cli.md#sigil-pip) and [`sigil npm`](cli.md#sigil-npm)).

The system is organized into three layers that can operate independently or in concert.

## Three-Layer System

```
+-----------------------------------------------------------------------+
|                          DEVELOPER MACHINE                            |
|                                                                       |
|  +-------------------------+                                          |
|  |      CLI (cli/, Rust)   |   bin/sigil is the legacy bash CLI       |
|  |  - quarantine manager   |                                          |
|  |  - 8-phase scanner      |   Runs locally. No account needed.       |
|  |  - verdict engine       |                                          |
|  +----------+--------------+                                          |
|             |                                                         |
|             | (optional, authenticated)                                |
+-----------------------------------------------------------------------+
              |
              v
+-----------------------------------------------------------------------+
|                          SIGIL CLOUD                                   |
|                                                                       |
|  +-------------------------+     +----------------------------+       |
|  |   API Service (FastAPI) |     |   Dashboard (Next.js)      |       |
|  |  - scan submission      |     |  - scan history            |       |
|  |  - threat intel lookups |     |  - team management         |       |
|  |  - publisher reputation |     |  - policy configuration    |       |
|  |  - pattern signatures   |     |  - threat intelligence     |       |
|  |  - marketplace verify   |     |  - verdict overrides       |       |
|  +----------+--------------+     +----------------------------+       |
|             |                                                         |
|  +----------+--------------+     +----------------------------+       |
|  |  Azure SQL (MSSQL)      |     |   Redis (cache)            |       |
|  |  - scan results         |     |  - threat intel TTL cache  |       |
|  |  - user accounts        |     |  - rate limiting           |       |
|  |  - threat signatures    |     |  - session tokens          |       |
|  |  - publisher profiles   |     |                            |       |
|  +-------------------------+     +----------------------------+       |
+-----------------------------------------------------------------------+
```

### 1. CLI -- Developer Layer

**Location:** `cli/` (Rust). `bin/sigil` is the legacy bash CLI it superseded.

The CLI is the primary interface for developers. It manages the quarantine directory, runs all eight scan phases locally, and produces a risk score and verdict. Key responsibilities:

- Quarantine lifecycle management (clone, download, scan, approve, reject)
- Eight-phase security analysis with weighted scoring
- Shell alias installation for transparent protection (`gclone`, `safepip`, `safenpm`)
- Git pre-commit hook installation
- Dependency lookups for lockfiles (OSV advisories, npm/PyPI provenance)
- Optional authenticated mode for cloud threat intelligence

The CLI keeps its state under `~/.sigil/`, creating each path on first use (the full layout is in [Directory Structure](configuration.md#directory-structure)):

```
~/.sigil/
  quarantine/    # Untrusted code awaiting review; approved code stays here too
  ledger/        # Content pins recorded by sigil approve
  cache/         # Cached scan results
  config.json    # Values set with sigil config
```

### 2. API Service -- Intelligence Layer

**Location:** `api/`

A Python FastAPI service that provides cloud-backed threat intelligence, scan history, and collaborative security data. It receives what the CLI's cloud options send: a directory hash for `--enrich`, the scan result with each finding's file path and flagged source line for `--submit`, file contents for the Pro `--enhanced` analysis, and, for `sigil explain`, every finding in a saved scan JSON file, flagged source lines included, for server-side LLM adjudication of one of them (see [data-handling.md](data-handling.md)).

Responsibilities:

- Accept and store scan results from CLI clients
- Serve threat intelligence lookups (hash-based, publisher-based)
- Distribute updated pattern signatures via delta sync
- Manage user authentication (JWT-based)
- Provide marketplace verification endpoints
- Aggregate anonymous scan telemetry for community threat detection

### 3. Dashboard -- Visibility Layer

**Location:** `dashboard/`

A Next.js web application that provides a visual interface for scan history, team management, policy configuration, and threat intelligence browsing. Built with:

- Next.js 16 with App Router
- React 19
- Tailwind CSS for styling
- TypeScript throughout

## Component Diagram

```
                  Developer Workstation
                  ====================

  +--------+    +--------+    +--------+    +---------+
  | gclone |    |safepip |    |safenpm |    |  audit  |
  +---+----+    +---+----+    +---+----+    +----+----+
      |             |             |              |
      +------+------+------+-----+--------------+
             |             |
             v             v
       +-----+-----+ +----+------+
       | Quarantine | | Scanner   |
       | Manager    | | Engine    |
       | (copy to   | | (8 phases |
       |  ~/.sigil/ | |  + deps*) |
       |  quarantine)|            |
       +-----+------+ +----+-----+
             |              |
             v              v
       +-----+--------------+-----+
       |     Verdict Engine        |
       | (evidence -> risk level)  |
       +-----+--------------------+
             |
     +-------+--------+
     |                 |
     v                 v
  approve           reject
  (pin digest       (delete from
   in ledger/)       quarantine/)

                        |
            (cloud options only)
                        |
                        v

                  Sigil Cloud
                  ===========

  +------------------+     +-------------------+
  |  FastAPI Service  |<--->|  Next.js Dashboard|
  |  POST /v1/scan    |     |  Scan history     |
  |  GET  /v1/threat  |     |  Team management  |
  |  GET  /v1/sigs    |     |  Threat browser   |
  +--------+----------+     +-------------------+
           |
    +------+------+
    |             |
    v             v
  +------+  +-------+
  |Azure |  | Redis |
  | SQL  |  | Cache |
  +------+  +-------+
```

\* Lockfile dependency lookups (OSV, npm/PyPI provenance) run only for `sigil scan` and `sigil baseline` of a directory; the scans behind `gclone`, `safepip` and `safenpm` (`sigil clone`, `pip`, `npm`) run the eight phases without them.

## Data Flow

### Scan Submission Flow

```
1. SUBMISSION
   User runs: sigil clone <url>
        |
        v
2. QUARANTINE
   Code is cloned/downloaded into ~/.sigil/quarantine/<id>/
   Nothing is executed. No install hooks run.
        |
        v
3. ANALYSIS (8 phases, all local)
   Phase 1: Install Hook Scanner     (weight 10x)
   Phase 2: Code Pattern Scanner     (weight 5x)
   Phase 3: Network/Exfil Scanner    (weight 3x)
   Phase 4: Credential Scanner       (weight 2x)
   Phase 5: Obfuscation Scanner      (weight 5x)
   Phase 6: Provenance Scanner       (weight 1-3x)
   Phase 7: Prompt Injection Scanner (weight 10x)
   Phase 8: Skill Security Scanner   (weight 5x)
        |
        + Decode worklist, correlation, typosquat and dependency-source checks
        (lockfile dependency lookups run only for sigil scan and sigil baseline)
        |
        v
4. SCORING
   Each finding contributes severity score x its weight: the phase weight,
   unless the rule sets its own
   (Low 1, Medium 2, High 3, Critical 5; at most three per rule and file).
   The score is informational; the verdict reads the evidence.
        |
        v
5. VERDICT (see docs/cli.md, Verdicts and Scoring)
   LOW RISK       Nothing that reaches MEDIUM           (review, then approve)
   MEDIUM RISK    Medium+ in the code, High anywhere,   (manual review)
                  or 10+ points of Medium+ findings
   HIGH RISK      High/Critical in the code that is a   (do not approve
                  real part of the package               without review)
   CRITICAL RISK  A standalone Critical rule, or two    (reject)
                  different corroborating ones
        |
        v
6. ACTION
   User runs: sigil approve <id>  -- pins its digest in ~/.sigil/ledger/ (code stays in quarantine)
          or: sigil reject <id>   -- deletes from quarantine
```

### Threat Intelligence Flow (Authenticated Mode)

```
1. CLI authenticates via sigil login (token stored in ~/.sigil/token)
2. With sigil scan --submit, CLI sends the scan to POST /v1/scan:
   - Each active finding: rule, phase, severity, file path, line,
     flagged source line
   - Files scanned, the CLI's score and verdict, target name "cli-scan"
   sigil explain also posts a saved report's findings there (without the
   score and verdict, under the target name "sigil-explain")
3. API scores the findings, stores the scan for the dashboard's scan
   history and returns its id. Scan history shows the API's score and
   verdict, which can differ from the CLI's; the CLI's are kept in the
   scan's metadata as cli_score and cli_verdict. It also looks up package
   hashes and a publisher named in the request metadata, which the CLI
   does not send
4. sigil fetch (Pro plan) downloads updated threat signatures via GET /v1/signatures (delta sync)
5. Signatures are cached locally for offline use; content scanned before the
   fetch (in any directory) keeps its cached result until sigil clear-cache
   or --no-cache
```

## Technology Stack

| Component | Current | Future / Planned |
|-----------|---------|-----------------|
| **CLI** | Rust (`cli/`) via clap, walkdir, regex; `bin/sigil` is the legacy bash CLI | -- |
| **API** | Python 3.11+ with FastAPI | -- |
| **Dashboard** | Next.js 16, React 19, Tailwind CSS | -- |
| **Database** | Azure SQL (MSSQL) via aioodbc/pyodbc | -- |
| **Cache** | Redis | -- |
| **Auth** | Auth0-issued JWTs, verified with python-jose; bcrypt for legacy password hashes | -- |
| **HTTP Client** | httpx (API), reqwest (Rust CLI) | -- |
| **External Scanners** | None by default; YARA-X `yr` or `yara` when installed, for custom YARA rules the built-in engine cannot evaluate (the legacy bash CLI used semgrep, bandit, trufflehog, safety) | npm audit, pip-audit |
| **CI/CD** | GitHub Actions | -- |

### Key Dependencies

**API (`api/requirements.txt`):**
- fastapi, uvicorn -- web framework and ASGI server
- pydantic, pydantic-settings -- configuration and validation
- httpx -- async HTTP client for threat intel queries
- python-jose, bcrypt -- JWT verification and legacy password hashes
- aioodbc, pyodbc -- Azure SQL (MSSQL) database client
- redis -- cache client

**Dashboard (`dashboard/package.json`):**
- next 16.3.3 -- React framework
- react 19.2.1 -- UI library
- @auth0/nextjs-auth0 -- sign-in
- tailwindcss -- utility CSS
- typescript -- type safety

**CLI Rust (`cli/Cargo.toml`):**
- clap -- argument parsing
- tokio -- async runtime
- reqwest -- HTTP client
- regex, walkdir, glob -- file scanning
- sha2, hex -- hash computation
- colored, indicatif -- terminal output

## Offline vs Authenticated Mode

### Offline Mode (Default)

All eight scan phases run locally. This is the default behavior and requires no account. The CLI uses built-in pattern matching; `sigil scan` of a directory with a lockfile also looks the listed dependencies up in OSV (and npm/PyPI packages on their registry), and skips those lookups when there is no connection.

What works offline:
- All eight scan phases with full scoring
- Quarantine management (approve, reject, list)
- Shell aliases and git hooks
- Report generation

What is unavailable offline:
- Threat intelligence lookups (known malicious hashes)
- Community threat signature updates (`sigil fetch`)
- Scan history in the dashboard
- Team management and policies (dashboard only; the CLI does not fetch them)

### Authenticated Mode

`sigil login` stores a token; a plain scan does not change and sends nothing to the Sigil API. The cloud options use the token:

- **Threat intelligence (Pro plan):** `sigil scan --enrich` looks the directory hash up in a database of known malicious packages. That hash covers the directory's file paths and sizes, while the database is keyed by package-artifact hashes, so it matches only an entry recorded for that exact directory: no match does not mean the code is safe
- **Signature updates (Pro plan):** `sigil fetch` downloads new detection patterns, which later fresh scans apply (content scanned before the fetch, in that directory or a copy of it, needs `sigil clear-cache` or `--no-cache`)
- **Scan history:** `sigil scan --submit` sends the scan result, flagged source lines included, to the Sigil API for the web dashboard's scan history
- **Pro analysis:** `sigil scan --enhanced` uploads up to 50 text files from the directory, collected without the scan's exclusions, for LLM analysis, plus the scan result: every finding with its flagged source line, including findings in files outside those 50. The API does not yet return LLM findings for it: it stores the scan, but not the uploaded files, and answers with its static analysis, and the CLI says so (CLI 1.3.7 prints `Enhanced analysis failed`)
- **Finding adjudication:** `sigil explain <scan.json>` uploads every finding in the saved scan result, flagged source lines included, and asks the server to adjudicate one with an LLM

The `sigil scan` cloud options (`--enrich`, `--submit`, `--enhanced`) run only on a fresh scan: a re-scan of unchanged content served from the cache skips them without a message, so add `--no-cache`. CLI 1.3.7 sends `--submit`, `--enhanced` on a scan with findings, and `sigil report` in shapes the API accepts only from the update that added CLI compatibility (`api/models.py`), and shows an `--enrich` match only from that update; a scan with an Inference Security (`INFER-*`) finding needs it from any CLI version, and so does a reliable `sigil report` (the API before it gives a report a 12-character id, which the `UNIQUEIDENTIFIER` column in `schema.sql` does not accept). Cloud results are informational: an `--enrich` match or an LLM finding from `--enhanced` is printed, but does not change the verdict, the exit code or the `-f` report.

## Threat Intelligence Pipeline

```
  Community Scans                     Manual Reports
  (automated metadata)                (POST /v1/report)
        |                                   |
        v                                   v
  +-----+-----------------------------------+------+
  |              Threat Aggregator                  |
  |  - Deduplicate findings                         |
  |  - Correlate across packages/versions           |
  |  - Score publisher behavior over time           |
  +-----+------------------------------------------+
        |
        v
  +-----+------------------------------------------+
  |           Signature Generator                   |
  |  - Extract new patterns from confirmed threats  |
  |  - Version and tag signatures                   |
  |  - Compute delta updates for sync               |
  +-----+------------------------------------------+
        |
        v
  +-----+------------------------------------------+
  |           Distribution                          |
  |  - GET /v1/signatures (delta sync)              |
  |  - Cached at Redis layer (configurable TTL)     |
  |  - CLI fetches with `sigil fetch`               |
  +------------------------------------------------+
```

The pipeline ensures that when any user in the community encounters a malicious package, the detection pattern is available to every CLI that next runs `sigil fetch` (content scanned before that fetch, in any directory, is re-checked only after `sigil clear-cache` or with `--no-cache`). Scan submissions carry finding metadata (rule IDs, severities, file paths) plus the flagged source-line excerpts (`Finding.snippet`), as does `sigil explain`; full source files are transmitted only by the Pro enhanced-scan path, which uploads up to 50 text files from the scanned directory, collected without the scan's exclusions, for LLM analysis. See `docs/data-handling.md` for the complete per-tier data flow.
