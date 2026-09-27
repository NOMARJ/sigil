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

## Addendum (2026-09-02): additive keys and document kinds

The JSON contract grew in the prism-scanner review. All changes are additive; nothing
moved or was renamed.

- `summary` gained `grade` (A–F), `recommendation`, `inline_suppressed_count` and
  `platform` — scalars only, as before.
- New top-level keys: `profile` (`behaviors`, `key_risks`) and `inline_suppressed`
  (findings silenced by `sigil:ignore` markers, with attributions). Both sort after
  `findings`, so the findings array is still the first `[` on stdout, which is how
  `scripts/run_eval.py` and `sigil explain` locate it. Any future top-level key must keep
  sorting after `findings`.
- Each finding may carry `title`, `remediation`, `references`, `tags` and `behavior`.
- A finding may carry `evidence` (`"corroborate"`), from the rule field of the same
  name. It is emitted **only** when it is not the default `standalone`, so a finding
  from a rule that says nothing about evidence serializes exactly as before and a
  cached or baseline document written without the key still deserializes. It changes
  no existing key and it does not change `severity`: a corroborating Critical is still
  reported as Critical and still fails `--fail-on critical`. What it changes is
  `summary.verdict`, which reaches `CRITICAL RISK` only on a standalone Critical or on
  Critical findings from two different corroborating rules.
- SARIF: rules carry `fullDescription`, `help` and `properties.tags`; suppressed findings
  are emitted with `suppressions` (`kind: inSource`) rather than dropped.
- `sigil residue` documents are a different kind and are not scan results: they carry
  `"kind": "residue"` / `"residue-plan"` / `"residue-apply"` / `"residue-rollback"` and a
  `residue_schema` version. Consumers dispatch on `kind`; `sigil diff` refuses them as a
  baseline. The first-`[` rule applies to scan documents only.
- `--format html` is a fourth output mode: one self-contained page, no scripts, every
  value escaped. It is a presentation of the JSON document, not a contract of its own.
