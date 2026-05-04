# Instinct Lineage

Version-tracked log of every instinct write operation. Each entry records the instinct ID, content version (first 7 chars of SHA-256), the operation type, parent (for derived instincts), trigger context, summary, and ISO 8601 timestamp.

## Entries

- id: inst-20260503-001 | v: 8db2fb0 | op: CAPTURE | parent: null | trigger: session-capture | summary: "NPM scope is @nomarj (with J), not @nomark" | ts: 2026-05-03T20:38:11+1000
- id: inst-20260503-002 | v: 769c130 | op: CAPTURE | parent: null | trigger: session-capture | summary: "Verify agent output against the original brief, not against the agent's self-report" | ts: 2026-05-03T20:38:11+1000
- id: inst-20260503-003 | v: 330593a | op: CAPTURE | parent: null | trigger: session-capture | summary: "Token health check via known-good prior version before real release" | ts: 2026-05-03T20:38:11+1000
- id: inst-20260503-004 | v: c263863 | op: CAPTURE | parent: null | trigger: session-capture | summary: "GitHub Actions reads on:push:tags filter from the tag's commit, not from main" | ts: 2026-05-03T20:38:11+1000
- id: inst-20260503-005 | v: 72523ae | op: CAPTURE | parent: null | trigger: session-capture | summary: "npm version --allow-same-version in release pipelines that bump in a separate PR" | ts: 2026-05-03T20:38:11+1000
