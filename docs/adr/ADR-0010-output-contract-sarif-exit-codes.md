---
id: ADR-0010
title: "Output contract: SARIF 2.1.0 + versioned JSON + human text; exit codes are the CI interface"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, output, sarif, ci, f-008, d7]
outcome: pending
---

## Context

Audit evidence: the bash CLI exits 0 on a CRITICAL/250 verdict — it cannot gate anything. SARIF is the only format GitHub Code Scanning and IDE surfaces ingest without bespoke integration; OSV-Scanner/Trivy demonstrate that CI-nativeness is how open-source scanners actually get adopted.

## Decision

Three output modes: human text (default), `--format json` (stable, versioned schema), `--format sarif` (SARIF 2.1.0). Exit codes: 0 = below threshold, 1 = findings ≥ `--fail-on` (default high), 2 = scan error. A first-party GitHub Action wraps scan + SARIF upload. Sigil's own repo runs `sigil scan .` as a required CI check, with suppressions carrying written rationale (F-008 US-D1–D3).

## Alternatives rejected

- **Custom findings format only** — every CI/IDE integration becomes bespoke work for consumers.
- **Always-zero exit with report parsing** — the current bash behavior; demonstrated unusable as a gate.

## Consequences

Exit-code discipline and schema stability become a compatibility promise. Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D7.
