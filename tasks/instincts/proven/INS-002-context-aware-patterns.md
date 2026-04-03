---
id: INS-002
title: Context-aware pattern matching for security scanners
status: proven
confidence: 0.9
created: 2026-03-15
proven_at: 2026-03-17
source: lesson
tags: [scanner, false-positives, patterns]
---

Security scanners must distinguish legitimate vs malicious usage through context: file type (docs/tests get reduced severity), string literal detection (eval in quotes is not execution), domain allowlists (Anthropic/OpenAI/GitHub are safe), and method disambiguation (RegExp.exec() is not shell exec).

**Evidence:** False positive rate dropped from 36% to <5% after implementing context-aware pipeline in _scan_content().
