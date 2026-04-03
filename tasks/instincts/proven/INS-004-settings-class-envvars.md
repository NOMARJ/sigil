---
id: INS-004
title: Endpoints must use Settings class, not raw os.getenv()
status: proven
confidence: 0.8
created: 2026-03-13
proven_at: 2026-03-13
source: lesson
tags: [python, fastapi, configuration]
---

Environment variables used by API endpoints must be defined in the Settings class with pydantic-settings prefix handling. Never use raw `os.getenv()` in endpoint code — it bypasses validation and prefix handling.

**Evidence:** Attestation endpoint returning "Public key not configured" despite env var being set — fixed by adding to Settings class.
