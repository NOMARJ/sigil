---
id: ADR-0007
title: "Provenance layer detects drift, never penalizes absence; OSV is the primary advisory feed, NVD enrichment-only"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, provenance, feeds, osv, f-008, d4]
outcome: pending
---

## Context

Adoption reality (researched 2026-06-10): <1% of npm packages carry provenance; PyPI reached 17% of 2025 uploads; crates.io has none; no package manager verifies attestations at install time by default. Both 2026 worm waves (TanStack/Mini Shai-Hulud, AntV) published malware with *valid* SLSA L3/Sigstore attestations via CI OIDC hijack. NVD formally abandoned universal enrichment 2026-04-15; OSV.dev aggregates GHSA + 19 home databases + OpenSSF `MAL-` malicious-package records (226,783 as of 2026-06-10), free, no key.

## Decision

Phase 6 gains: (a) npm/PyPI attestation verification when present; (b) drift findings — provenance downgrade (previously-attested package publishes unattested), publisher-identity change, provenance-repo ≠ manifest-repo mismatch; (c) absence of provenance recorded in SBOM output, never a scored finding. Advisory pipeline: OSV.dev primary (CVEs + `MAL-`), CISA KEV + EPSS prioritization overlay, NVD as best-effort enrichment join only (F-008 US-E1–E3).

## Alternatives rejected

- **Flagging missing provenance** — ~99% false-positive rate at current adoption; pure noise.
- **SLSA-level gating** — almost nobody can comply, and valid L3 was defeated twice in 2026; presence proves attribution, not safety.
- **Building a proprietary advisory feed first** — consume the commons first; *publishing* an OSV-schema MCP/skills feed is a later ecosystem play (after F-008 Phase E).

## Consequences

Provenance becomes an anomaly-detection layer that survives CI-compromise attacks; advisory coverage rides the best-maintained free infrastructure. Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D4, `docs/internal/THREAT-LANDSCAPE-2026-06.md` §3.
