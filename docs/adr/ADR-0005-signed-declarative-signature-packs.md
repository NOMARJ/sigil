---
id: ADR-0005
title: "Detection corpus lives in signed, versioned, declarative packs; the rules engine never executes user code"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, corpus, signatures, f-008, d2]
outcome: pending
---

## Context

Audit findings: detection patterns are hardcoded in three codebases; `threat_signatures.json` declares `signature_count: 247` while containing 55 entries; "4,700+ threats" marketing traces to a file's line count (actual entries: 133). Signature updates currently require binary releases. Cisco's open-source MCP scanner — the closest analogue — showed ~78% false positives on its YARA path in independent testing.

## Decision

All detection patterns move to versioned signature packs (JSON; evolved `threat_signatures.json` schema): id, phase, severity, weight, patterns, language scope, context-suppression predicates, provenance (source advisory/CVE/campaign), FP-likelihood, dates. Packs are signed and verified before load; `~/.sigil/` caches for offline use. Counts are always derived from entries, never declared (CI-enforced, US-A1). Custom user rules use the same declarative format. The rules engine executes no user-supplied code — no Lua/Rhai/JS plugins. If declarative matching hits a wall, the only escalation path considered is fuel-metered WASM with zero I/O imports, as a separate future ADR.

## Alternatives rejected

- **YARA** — binary-artifact heritage; independently measured 78% FP on MCP/skill text content.
- **Embedding Semgrep** — Python runtime + license surface + weight, against a single-binary CLI.
- **Plugin scripts** — Sigil flags `eval()` in other tools (CODE-001); an engine that executes arbitrary rule code fails Sigil's own permission test.

## Tradeoff accepted

Declarative rules cannot express taint flows. Accepted: Sigil's verified threat classes (install hooks, instruction poisoning, exfil patterns, inference config) are pattern+context shaped, and the Python FP filters are expressible as suppression predicates.

## Consequences

Signature updates become data-plane (no release needed); the corpus with per-entry provenance becomes the compounding asset. Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D2.
