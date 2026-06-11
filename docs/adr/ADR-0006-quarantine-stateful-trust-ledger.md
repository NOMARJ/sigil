---
id: ADR-0006
title: "Quarantine approval becomes a stateful trust ledger: hash-pin at approve, diff on every re-encounter"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, quarantine, rug-pull, f-008, d3]
outcome: pending
---

## Context

postmark-mcp (Sept 2025) was benign for 15 versions, then v1.0.16 added a BCC-exfil line — the first in-the-wild malicious MCP server. CVE-2025-54136 (Cursor "MCPoison") showed approval bound to a name, not contents, yields silent RCE. Single-snapshot scanning is structurally blind to artifacts that turn malicious after approval. Sigil already has an approve/reject state machine; no competitor has an approval workflow to anchor pins to.

## Decision

`sigil approve` records content hashes — package version + tarball hash, MCP tool-definition hashes, instruction-file (SKILL.md/CLAUDE.md) hashes — in a local ledger under `~/.sigil/`. Every subsequent scan/run diffs current state against the approval record; drift triggers re-quarantine with a diff-scoped scan and a Critical `RUGPULL-001` finding (F-008 US-F1, US-F2).

## Alternatives rejected

- **Per-session full re-scan** — cost without memory; cannot distinguish *changed* from *always-was*.
- **Cloud-side pinning ledger** — breaks offline use, adds a phone-home dependency to the free tier, fails the permission test.

## Consequences

The quarantine UX feature becomes the rug-pull detection layer — the structural moat. Storage mechanism (SQLite vs JSONL) is an implementation detail. Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D3.
