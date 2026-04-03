---
id: INS-001
title: Use char_indices() for Rust string truncation
status: proven
confidence: 0.9
created: 2026-03-15
proven_at: 2026-03-15
source: lesson
tags: [rust, safety, unicode]
---

Never slice Rust strings with byte indices. Use `char_indices()` and `take_while()` for safe truncation. Use `String::from_utf8_lossy()` instead of `read_to_string()` for robust file processing. Check for null bytes to detect binary files before text processing.

**Evidence:** P0 crash fix — `byte index 200 is not a char boundary` panic in phases.rs.
