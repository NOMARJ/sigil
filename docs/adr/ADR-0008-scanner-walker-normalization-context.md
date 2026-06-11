---
id: ADR-0008
title: "Scanner mechanics: ignore-aware parallel walker, Unicode normalization before matching, context-aware suppression"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, scanner, performance, unicode, f-008, d5]
outcome: pending
---

## Context

Audit evidence: the Rust scanner walks every file with no exclusions (`cli/src/scanner/mod.rs:164` — node_modules, .git, target all regex-scanned); a full-repo self-scan did not finish in 30 minutes. It flags `eval`/`exec` *type declarations* in `.d.ts` files. Invisible-Unicode payloads (PUA, bidi, zero-width) are standard attacker tradecraft since GlassWorm and the Rules File Backdoor; naive pattern matching misses them entirely. Python's scanner has four proven FP context filters and a 22-domain safe list that exist nowhere else.

## Decision

(a) Walker respects `.gitignore`/`.sigilignore` plus hard default excludes (node_modules, .git, target, dist, .next); vendored trees are scanned in dependency-manifest mode only; rayon-parallel traversal with bounded file sizes. (b) A Unicode normalization pass runs before all pattern matching; invisible characters in instruction files (SKILL.md, CLAUDE.md, .cursorrules, tool descriptions) are themselves a High finding. (c) Python's suppression contexts (declaration files, type stubs, UMD/polyfill/webpack preambles, safe domains) are ported as corpus predicates per ADR-0005, not code (F-008 US-B1–B3, US-C3).

## Alternatives rejected

- **Scanning everything for completeness** — a scanner too slow to self-scan cannot be a CI gate (a stated project constraint), and node_modules content findings are noise without manifest context.
- **Treating FP suppression as post-processing** — context must be available at match time to avoid paying the match cost and to keep pack semantics self-contained.

## Consequences

Self-scan becomes feasible (<60s target), the `.d.ts` FP class dies, and invisible-Unicode attacks become detections instead of blind spots. Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D5.
