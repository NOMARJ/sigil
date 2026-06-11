---
id: ADR-0004
title: "One detection engine: Rust cli/ is canonical; Python and bash scanners become consumers, then retire"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, scanner, rust, f-008, d1]
outcome: pending
---

## Context

The 2026-06-10 ground-truth audit found three scanner implementations with disjoint capabilities and no synchronization: AI-specific phases (7 prompt injection, 8 skill security, 10 inference security) exist only in Rust (`cli/src/scanner/phases.rs`); the 13 supply-chain rules, 14 obfuscation-chain rules, and all 4 false-positive context filters exist only in Python (`api/services/scanner.py`); bash (`bin/sigil`) has neither, took ~37 minutes to self-scan this repo, and exits 0 on a CRITICAL verdict. Three pattern sets produce three different verdicts for the same artifact.

## Decision

The Rust CLI is the single detection engine. The Python API invokes it (subprocess `--format json` first; PyO3 later if profiling justifies it). `bin/sigil` is frozen immediately, becomes an install/bootstrap shim, and delegates scan/clone/pip/npm to the Rust binary (F-008 US-G1, US-G2). Python scanner rules are frozen; its rules and filters are ported into the externalized corpus (ADR-0005) with parity tests before `scanner.py` is deleted.

## Alternatives rejected

- **Keep Python as the server-side engine** — preserves the drift mechanism that produced this situation; every rule lands twice or diverges.
- **Port Rust to Python** — loses single-binary distribution (a scanner that needs `pip install` can be attacked through pip — capability-minimal property) and the performance headroom.
- **Feature-for-feature bash rewrite** — the semgrep/trufflehog orchestration moves behind optional Rust-driven integration instead; the bash scan path is not worth preserving.

## Tradeoff accepted

Python's proven FP filters and supply-chain rules must reach parity in the corpus before any Python scan path is removed. Parity is a gate (US-C3), not an aspiration.

## Consequences

Deterministic identical verdicts across CLI, API, CI, and IDE surfaces; one corpus to maintain. Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D1.
