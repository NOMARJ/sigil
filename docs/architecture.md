# Sigil Architecture

## Overview

Sigil is an automated security auditing system for AI agent code, built around a **quarantine-first** workflow. Nothing executes, installs, or enters your working environment until it has been scanned, scored, and explicitly approved.

The system is organized into three layers that can operate independently or in concert.

## Three-Layer System

```
+-----------------------------------------------------------------------+
|                          DEVELOPER MACHINE                            |
|                                                                       |
|  +-------------------------+                                          |
|  |      CLI (bin/sigil)    |   Bash today, Rust (cli/) in future      |
|  |  - quarantine manager   |                                          |
|  |  - 6-phase scanner      |   Runs fully offline. No account needed. |
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
|  |  PostgreSQL (Supabase)  |     |   Redis (cache)            |       |
|  |  - scan results         |     |  - threat intel TTL cache  |       |
|  |  - user accounts        |     |  - rate limiting           |       |
|  |  - threat signatures    |     |  - session tokens          |       |
|  |  - publisher profiles   |     |                            |       |
|  +-------------------------+     +----------------------------+       |
+-----------------------------------------------------------------------+
```

### 1. CLI -- Developer Layer

**Location:** `bin/sigil` (Bash), `cli/` (future Rust binary)

The CLI is the primary interface for developers. It manages the quarantine directory, runs all six scan phases locally, and produces a risk score and verdict. Key responsibilities:

- Quarantine lifecycle management (clone, download, scan, approve, reject)
- Six-phase security analysis with weighted scoring
- Shell alias installation for transparent protection (`gclone`, `safepip`, `safenpm`)
- Git pre-commit hook installation
- Integration with external scanners (semgrep, bandit, trufflehog, safety)
- Optional authenticated mode for cloud threat intelligence

The CLI stores all state under `~/.sigil/`:

```
~/.sigil/
  quarantine/    # Untrusted code awaiting scan
  approved/      # Code that passed review
  logs/          # Scan execution logs
  reports/       # Detailed scan reports (text)
  config         # User configuration
```

### 2. API Service -- Intelligence Layer

**Location:** `api/`

A Python FastAPI service that provides cloud-backed threat intelligence, scan history, and collaborative security data. The API never receives source code -- only pattern match metadata (which rules triggered, file types, risk scores).

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

- Next.js 14 with App Router
- React 18
- Tailwind CSS for styling
- Supabase JS client for real-time data
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
       | (copy to   | | (6 phases |
       |  ~/.sigil/ | |  + ext)   |
       |  quarantine)|            |
       +-----+------+ +----+-----+
             |              |
             v              v
       +-----+--------------+-----+
       |     Verdict Engine        |
       |  (score -> risk level)    |
       +-----+--------------------+
             |
     +-------+--------+
     |                 |
     v                 v
  approve           reject
  (move to          (delete from
   approved/)        quarantine/)

                        |
            (if authenticated)
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
  |Supa- |  | Redis |
  |base  |  | Cache |
  +------+  +-------+
```

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
3. ANALYSIS (6 phases, all local)
   Phase 1: Install Hook Scanner     (weight 10x)
   Phase 2: Code Pattern Scanner     (weight 5x)
   Phase 3: Network/Exfil Scanner    (weight 3x)
   Phase 4: Credential Scanner       (weight 2x)
   Phase 5: Obfuscation Scanner      (weight 5x)
   Phase 6: Provenance Scanner       (weight 1-3x)
        |
        + External scanners (semgrep, bandit, trufflehog, safety)
        + Dependency analysis
        + Permission/scope analysis
        |
        v
4. SCORING
   Each finding contributes to a cumulative risk score.
   Score = sum of (finding_count * phase_weight)
        |
        v
5. VERDICT
   Score 0      -> CLEAN          (safe to approve)
   Score 1-9    -> LOW RISK       (review flagged items)
   Score 10-24  -> MEDIUM RISK    (manual review recommended)
   Score 25-49  -> HIGH RISK      (do not approve without review)
   Score 50+    -> CRITICAL RISK  (reject -- multiple red flags)
        |
        v
6. ACTION
   User runs: sigil approve <id>  -- moves to ~/.sigil/approved/
          or: sigil reject <id>   -- deletes from quarantine
```

### Threat Intelligence Flow (Authenticated Mode)

```
1. CLI authenticates via sigil login (JWT token stored locally)
2. After local scan completes, CLI sends metadata to POST /v1/scan:
   - Which rules triggered
   - File type distribution
   - Risk score and verdict
   - Package name/version/hash (NO source code)
3. API enriches the scan with threat intelligence:
   - Known malicious hash lookups
   - Publisher reputation scores
   - Community-reported threats
4. Updated threat signatures are fetched via GET /v1/signatures (delta sync)
5. Signatures are cached locally for offline use
```

## Technology Stack

| Component | Current | Future / Planned |
|-----------|---------|-----------------|
| **CLI** | Bash (`bin/sigil`) | Rust (`cli/`) via clap, walkdir, regex |
| **API** | Python 3.11+ with FastAPI | -- |
| **Dashboard** | Next.js 14, React 18, Tailwind CSS | -- |
| **Database** | PostgreSQL via Supabase | -- |
| **Cache** | Redis | -- |
| **Auth** | JWT (python-jose, passlib/bcrypt) | -- |
| **HTTP Client** | httpx (API), reqwest (Rust CLI) | -- |
| **External Scanners** | semgrep, bandit, trufflehog, safety | npm audit, pip-audit |
| **CI/CD** | GitHub Actions | -- |

### Key Dependencies

**API (`api/requirements.txt`):**
- fastapi, uvicorn -- web framework and ASGI server
- pydantic, pydantic-settings -- configuration and validation
- httpx -- async HTTP client for threat intel queries
- python-jose, passlib, bcrypt -- JWT authentication
- supabase -- database client
- redis -- cache client

**Dashboard (`dashboard/package.json`):**
- next 14.2.5 -- React framework
- react 18.3 -- UI library
- @supabase/supabase-js -- real-time database client
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

All six scan phases run locally without any network calls. This is the default behavior and requires no account or internet connection. The CLI uses built-in pattern matching and any locally installed external scanners.

What works offline:
- All six scan phases with full scoring
- External scanner integration (semgrep, bandit, trufflehog, safety)
- Quarantine management (approve, reject, list)
- Shell aliases and git hooks
- Report generation

What is unavailable offline:
- Threat intelligence lookups (known malicious hashes)
- Publisher reputation scores
- Community threat signatures (delta sync)
- Scan history in the dashboard
- Team management and policies

### Authenticated Mode

After running `sigil login`, the CLI sends scan metadata (never source code) to the Sigil API. This enables:

- **Threat intelligence:** Hash lookups against a database of known malicious packages
- **Publisher reputation:** Trust scores for package authors based on community data
- **Signature updates:** New detection patterns propagated from the community
- **Scan history:** Searchable history of all scans in the web dashboard
- **Team policies:** Configurable auto-approve/reject thresholds per team

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
  |  - CLI fetches on each authenticated scan       |
  +------------------------------------------------+
```

The pipeline ensures that when any user in the community encounters a malicious package, the detection pattern is available to all authenticated users within minutes. No source code is ever transmitted -- only metadata about which scan rules triggered and at what severity.
