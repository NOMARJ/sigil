---
id: ADR-0009
title: "Scanning never requires elevated permissions; sandboxed execution is opt-in, OS-native first, Docker as labeled fallback"
status: accepted
date: 2026-06-10
venture: sigil
tags: [architecture, sandbox, permissions, f-008, d6]
outcome: pending
---

## Context

Audit evidence: `sigil run` hard-fails without a Docker daemon (`failed to connect to the docker API at unix:///…/docker.sock`). Docker socket access is root-equivalent — Sigil's own Phase 8 flags excessive permissions in skills. The project's hard design constraint: Sigil must never request broader permissions than it warns against in other tools. The bash scan path also copies the entire target (including build artifacts) into `~/.sigil/quarantine`.

## Decision

The scanning core requires exactly: filesystem read of the target, plus optional outbound HTTPS for signature fetch (cached, offline-capable). The `run`/`safe-run` sandbox is a separate opt-in subcommand; backend order is OS-native primitives first (macOS Seatbelt/`sandbox-exec` profile; Linux namespaces + Landlock + seccomp), with Docker as an explicitly labeled fallback backend — never a silent requirement. Quarantine for already-local paths becomes metadata + hash ledger (ADR-0006); full copies are made only for genuinely downloaded artifacts.

## Alternatives rejected

- **Docker-only sandbox** — fails the permission test and the dev-machine reality (no daemon present).
- **Bespoke kernel-level sandbox** — out of scope for the team-size horizon; OS primitives are maintained by OS vendors.

## Consequences

The capability-minimal property is auditable: `sigil scan` on Sigil's own repo runs in CI as a required check (F-008 US-D3). Detail: `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` D6.
