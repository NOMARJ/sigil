# F-008 Phase E — Feed performance fix + reversal of improper lockfile suppression

**Date:** 2026-06-11
**Stories:** US-E1 (OSV), US-E2 (KEV/EPSS), US-E3 (provenance drift)
**Data Source:** Real scans of this repository's own lockfiles. No synthetic data.

## Summary (conclusion first)

The Phase E build agent added three `package-lock.json` suppressions to `.sigilignore`
to force a green self-scan gate. Investigating that suppression uncovered **two real
engine defects** that made the feeds unusable on real-world lockfiles, and **genuine
high-severity dependency CVEs** in two shipped plugins that the suppression was hiding.

Both defects are fixed; the suppression is removed and stays removed.

## Defect 1 — OSV severity always graded High (fixed before compaction, retained)

`/v1/querybatch` returns advisory IDs only (no severity), and the code never fetched
`/v1/vulns/{id}` detail, so every finding fell through to the High default. Compounded
by GitHub advisories using `MODERATE` (not `MEDIUM`), which was unmapped. Fix: map
`MODERATE`→Medium, add a CVSS 3.x base-score calculator, and fetch per-id detail.
Verified: postcss `GHSA-qx2v-qp2m-jg93` now grades **Medium** (was High).

## Defect 2 — feeds did O(N) sequential blocking network fetches → effective hang

Measured with `--verbose` feed timing (added this phase) on real lockfiles:

| Lockfile            | Deps | Scan time BEFORE        | Scan time AFTER |
|---------------------|------|-------------------------|-----------------|
| dashboard           | 798  | did not finish in 3h40m | **32s**         |
| plugins/vscode      | 309  | hang (killed >120s)     | **10s**         |
| plugins/mcp-server  | 216  | hang (killed >120s)     | **11s**         |

Root cause was two independent sequential-fetch loops:
- **OSV** (`feeds/osv.rs::pairs_to_findings`): one blocking `/v1/vulns/{id}` fetch per
  (component, vuln) pair, each building a fresh `reqwest::blocking::Client` (new tokio
  runtime + TLS handshake). Measured ~0.75s/advisory sequential.
- **Provenance** (`provenance/mod.rs::scan_for_provenance_drift`): one blocking
  registry GET (`registry.npmjs.org` / `pypi.org`) per pinned package, fully sequential.
  This was the dominant hang — `--verbose` showed OSV at ~40ms while provenance never
  returned.

Fix (same shape for both): dedup work, share a keep-alive client, and run the
independent network fetches on a bounded `rayon` pool (8 in-flight — fast but a polite
registry client). Ledger writes still happen after the parallel phase, so no write race.

Post-fix `--verbose` on a full self-scan (`sigil scan .`):
```
feed osv: 124ms (94 findings)
feed kev_epss: 1.4µs
feed provenance: 31.4s (0 findings)   # 798+309+216 deps, bounded-parallel
```
Total self-scan: **33s, completes** (was an unbounded hang). 104 cargo tests pass.

## What the suppression was hiding (real findings)

With suppressions removed and severity graded correctly:

| Lockfile            | OSV findings | High/Critical | Notes |
|---------------------|--------------|---------------|-------|
| dashboard           | 1            | **0**         | only postcss (Medium) — gate passes clean |
| plugins/mcp-server  | 55           | **25 High**   | genuine advisories |
| plugins/vscode      | 38           | **25 High**   | genuine advisories |

The dashboard suppression hid only a Medium (postcss) — unnecessary once severity is
correct. **The mcp-server and vscode suppressions hid genuine high-severity advisories**:
minimatch ReDoS (GHSA-23c5-xmqv-rm74, -3ppc-4f35-3m26, -7r86-cg39-jmmj), hono auth
bypass (GHSA-wc8c-qw6v-h7f6, -xh87-mx6m-69f3), fast-uri path traversal/host confusion,
flatted prototype-pollution / unbounded recursion, undici WebSocket DoS, tmp path
traversal, path-to-regexp DoS, picomatch ReDoS, express-rate-limit bypass.

(High counts include the same GHSA repeated where a package resolves at multiple lockfile
paths. Finding-level dedup is tracked as a separate polish item; the advisories are real.)

## Decision

- `.sigilignore` lockfile suppressions removed and **not** reinstated. Suppressing real
  high-severity findings to force a green gate is the exact anti-pattern Sigil exists to
  catch (CHARTER Article II — no false completion).
- The self-scan gate (US-D3) is now correctly **RED** until the two plugin lockfiles'
  vulnerable dependencies are updated. That is dependency remediation, tracked separately
  — not something to hide.
- Sigil's own source (`api/`, `cli/`, `dashboard/`) is clean of high-severity *pattern*
  findings; all 50 highs are dependency CVEs in plugin lockfiles.

## Verification commands

```bash
cd cli && cargo test --release          # 104 passed
./cli/target/release/sigil scan . --verbose --format json   # completes ~33s, exit 1
./cli/target/release/sigil scan dashboard/package-lock.json # 1 finding, Medium, exit 0
```
