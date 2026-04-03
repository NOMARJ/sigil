---
id: INS-005
title: React hooks must declare all dependencies
status: proven
confidence: 0.8
created: 2026-03-13
proven_at: 2026-03-13
source: lesson
tags: [react, hooks, frontend]
---

Always include function dependencies in useCallback/useEffect dependency arrays. Wrap functions with useCallback before passing them as dependencies. Missing deps cause infinite re-renders or stale closures.

**Evidence:** ESLint warnings and render loops fixed across dashboard components (#75, #76).
