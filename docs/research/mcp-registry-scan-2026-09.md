# Scanning the MCP registry

**Status:** research note — a measurement of the official Model Context Protocol registry,
kept as the record of how each number was produced
**Date:** 2026-09-03
**Subject:** [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io)
**Reproduce:** `scripts/registry_integrity.py` (§2) and `scripts/registry_scan.py` (§3)

---

## Summary

The MCP registry is a directory that agents install from. This note asks two questions of
it and answers both with real runs, not estimates.

1. **Does the registry point at software that exists?** For 8,127 npm-packaged servers,
   checked against npm: 99 (1.2%) name a package that cannot be installed as listed. All
   44 of the withdrawn ones are *unscoped* names — the kind anyone can claim once they are
   gone. 96 of the 99 are the registry's current listing, not stale history. §2.
2. **What does a scanner find inside the servers that do exist?** A 100-server sample,
   downloaded and scanned as a user would: 55 of 90 execute something at install time and
   58 read credentials. §3 also reports what those numbers say about *Sigil* rather than
   about the registry, because on this measurement they say a great deal. §4.

Nothing here is a claim that any particular server is malicious. Every finding in §3 is a
pattern a scanner matched, and a large share of them are ordinary things an MCP server
does for a living.

---

## 1. What the registry contains

```
Data Source: registry.modelcontextprotocol.io/v0/servers, paged in full
             (891 pages of 100), 2026-09-03
Sample Size: 89,000 listings, 26,575 unique server names
Limitations: One snapshot on one date. The registry lists every published version,
             so listings far exceed names; the figures below count names.
```

| | servers |
|---|---:|
| unique server names | 26,575 |
| ship an npm package | 8,119 |
| ship a PyPI package | 3,532 |
| ship an OCI image | 856 |
| no package at all (remote-only) | 13,850 |

The majority entry is a *remote* server — a URL, nothing to download. Those are outside
the scope of a static scanner and outside this note. The npm-packaged half is what an
agent actually installs onto a developer's machine, and it is what both sections below
measure.

---

## 2. 99 of 8,127 npm listings do not resolve

```
Data Source: every npm-packaged listing in the registry (the version the registry marks
             latest for each name), checked against registry.npmjs.org metadata
Sample Size: 8,127 servers
Limitations: Metadata only — no package was downloaded for this check. npm is the
             authority on its own state and that state changes; the run is dated
             2026-09-03. Counted per server name, not per listing.
```

| state | servers | scoped | unscoped |
|---|---:|---:|---:|
| resolves | 8,028 | | |
| **unpublished** — the versions were withdrawn from npm | 44 | 0 | 44 |
| **missing** — no npm package document at all | 36 | 36 | 0 |
| **version-missing** — package exists, listed version does not | 19 | 9 | 10 |

**96 of the 99 are the listing the registry marks as latest.** These are not historical
rows an agent would skip; they are the current advertised entry. Following one produces an
install failure today.

The split between the two failure modes is the part worth attention, and it is total:

- Every **missing** package is *scoped* (`@owner/name`). A scoped name can only be
  published by the owner of that scope, so a broken scoped listing stays broken. It is a
  dead link.
- Every **unpublished** package is *unscoped* (a bare name). Unscoped names that have been
  fully unpublished do not stay reserved forever — that is npm's documented model, not a
  flaw in it. The consequence here is specific: for 44 names, a public directory that
  agents install from advertises a bare npm name, at a version, that its author has
  withdrawn. Whoever publishes that name next inherits an install path with a standing
  recommendation attached.

The withdrawals are not one incident: 31 distinct publisher namespaces, spread from
2025-09-09 to 2026-08-26. The largest single cluster is 10 packages from one publisher
unpublished on the same day.

This note deliberately does not list the 44 names. The aggregate is the finding; a list
would be a worklist for the exact takeover it describes. Anyone with standing to act on
it — the registry operators first — can regenerate the full set in about ten minutes with
`scripts/registry_integrity.py`, which reads only public metadata and downloads nothing.

The practical lesson for Sigil is narrower and already actionable: a registry listing is
not evidence that a package is the software the listing describes. `sigil npm <pkg>`
resolves and hashes what it actually downloaded, which is the only part of this chain that
can be checked locally.

---

## 3. Scanning a 100-server sample

```
Data Source: the 100 most recently published npm-packaged servers in the registry, each
             downloaded into quarantine and scanned by `sigil npm <pkg> --version <v>`
             exactly as a user would run it
Sample Size: 100 requested, 90 scanned (3,826 files); 10 could not be fetched — those
             10 are part of the unpublished set in §2, which is how that finding surfaced
Limitations: Newest-first, so this is a slice of recent publishing activity, not a random
             sample of the registry's 8,119 npm servers (1.2% of them). Scanned on
             2026-09-03 with the pre-change binary; §4 explains why that matters.
```

### Behaviours

Findings carry behaviour tags, and the tags are more informative than the verdicts:

| behaviour | servers (of 90) |
|---|---:|
| reads credentials | 58 |
| executes something at install time | 55 |
| executes a shell | 30 |
| manifest risk | 23 |
| hard-coded secret shape | 23 |
| publish hygiene | 21 |
| downloads remote content | 19 |
| dynamic import | 17 |
| obfuscation | 13 |
| prompt injection | 9 |

Most-hit rules, by number of servers: `INSTALL-004` (54), `CRED-002` (48), `CODE-007`
(30), `CRED-007` (22), `HYGIENE-001` (20).

**61% of these servers run something at install time.** An MCP server is installed by a
developer, often on the say-so of an agent, and it frequently has a legitimate reason to
build a native module or write a config file in a `postinstall` hook. But install-time
execution is also the single most direct route from "a package was fetched" to "code ran
on this machine", and it is the shape every compromised-package campaign in the Datadog
dataset uses. That it is the norm rather than the exception in this ecosystem is the
finding; whether any individual instance is benign requires reading it.

`reads credentials` at 64% is much weaker evidence. An MCP server whose job is to talk to
an API reads an API key from the environment — that is the design. The rule fires on the
read, not on where the value goes.

### Verdicts, and why they are the weakest thing here

| verdict | servers |
|---|---:|
| CRITICAL RISK | 27 |
| HIGH RISK | 43 |
| MEDIUM RISK | 2 |
| LOW RISK | 18 |

---

## 4. What §3 measures about Sigil

A scanner that returns CRITICAL on 30% of a public registry is not describing the
registry. On the same binary and the same day, Sigil returned CRITICAL on 5 of the 20 most
downloaded packages on npm and PyPI — including `requests` and `urllib3` — and HIGH or
worse on 15 of 20. Against that baseline, "27 of 90 MCP servers are CRITICAL" carries
almost no information about the servers.

This is the honest reading, and it is why the verdict table is last rather than first, and
why this note leads with the behaviour counts and the §2 integrity check: those are
measurements of the registry. The verdict distribution is mostly a measurement of Sigil's
own threshold.

### The same packages, after the precision work

The packages were kept in quarantine and re-scanned with the branch binary, so both
columns below are the same bytes judged by two versions of the same scanner. 89 of the 90
are included: one quarantine directory did not survive to be re-scanned, and the 10
unfetchable servers of §2 are excluded from both columns because there was never anything
to scan.

```
Data Source: the identical quarantined packages from the run above, re-scanned with the
             branch binary (all phases, --no-cache, isolated HOME)
Sample Size: 89 servers, 3,826 files
Limitations: same sample and same date as the run above, so this measures the change in
             the scanner and nothing about the registry. One package's directory was lost
             between runs; it is excluded from both columns rather than counted as clean.
```

| verdict | before | after |
|---|---:|---:|
| CRITICAL RISK | 27 | **17** |
| HIGH RISK | 43 | 46 |
| MEDIUM RISK | 2 | 9 |
| LOW RISK | 17 | 17 |

Fifteen verdicts moved. Ten of the CRITICAL verdicts were withdrawn by the evidence gate:
a single Critical finding from a rule marked `corroborate` — an embedded key shape, a
`setup.py cmdclass` — no longer speaks for a whole package on its own.

One server got *worse*, and it was worth chasing: `@chronary/mcp` gained a High finding
for writing into an agent's configuration directory. The line was
`Edit \`.cursor/mcp.json\` (project-level) or \`~/.cursor/mcp.json\` (user-level):` — the
package's own README, telling a human how to install it, which is what every MCP server's
README says. That rule now stays out of README and INSTALL files, which took it from 25
of these 89 servers to 2 while costing one detection across 204 malicious skill samples.
Re-scanning the same sample is what surfaced it; a fresh sample would have hidden it in
the noise.

17 of 89 still comes back CRITICAL. That is better than 27 and still too high to publish
per-server verdicts from, which is why this note does not.

---

## 5. Method

Both scripts are committed, take no credentials, and execute nothing they download.

- `scripts/registry_integrity.py <out.json>` — pages the registry in full, keeps the
  listing each server name is marked latest at, and asks npm for that package's metadata
  document. Classifies each as resolves / unpublished / missing / version-missing.
- `scripts/registry_scan.py --out <dir> --count 100` — pages the registry, keeps npm-packaged
  servers newest-first, and runs `sigil npm` on each so the package travels the same
  download-and-quarantine path a user's would. Per-server results stay in `<dir>/scans/`;
  the published aggregate is `<dir>/aggregate.json`. `--rescan` re-runs the current binary
  over the retained quarantine, which is what makes a before/after comparison honest.

Per-server grades and verdicts are deliberately not published. The sample was taken to
measure the ecosystem and the scanner, and — as §4 says plainly — the verdicts are not
yet precise enough to name individual projects with.
