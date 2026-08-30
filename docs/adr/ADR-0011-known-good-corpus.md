---
id: ADR-0011
title: "Recognise known-good published code, in two tiers, instead of pattern-matching it from scratch"
status: accepted
date: 2026-08-30
venture: sigil
tags: [architecture, corpus, false-positives, supply-chain, ghidra]
outcome: pending
---

## Context

Sigil judges every file solely by whether its text matches a malicious pattern. It has no
notion of code it already knows to be fine. Two consequences follow, and they are the two
biggest open problems in the scanner.

**The false-positive rate is structural.** Clean packages are mostly *well-known* code:
bundled runtimes, vendored libraries, minified dependencies, polyfill preambles. Sigil
re-litigates all of it on every scan. The project's own evaluation is explicit about the
cost:

```
Data Source:  evaluation_results/honest_detection_eval.md — Datadog
              malicious-software-packages-dataset (human-triaged real malware)
              plus a clean control set
Sample Size:  351 malicious, 20 clean
Limitations:  Cold (ledger-empty) run, offline phases only; the clean control set
              is 20 packages, which is small.
Result:       90.31% recall / 70.00% clean-set FP at the High threshold.
```

ADR-0008's answer was better suppression predicates. That helps at the margin, but it is
describing known code rather than recognising it, and the description has to be rewritten
every time a bundler changes its preamble.

**Trojanised dependencies are invisible.** A copy of a popular library with three lines
changed in one file is the `event-stream` / `ua-parser-js` shape. Sigil cannot see it,
because it has nothing to compare against.
[ADR-0006](ADR-0006-quarantine-stateful-trust-ledger.md)'s trust ledger detects drift *from
what this user approved*, which is the right primitive but only covers artifacts the user
has already approved once. Nothing covers "this claims to be lodash 4.17.21 and is not".

Ghidra solved the analogous problem — identifying code in a stripped binary — in two
distinct tiers, with two different data structures, because they answer different
questions. *Function ID* stores exact hashes of known library functions with their
metadata, so an unnamed function can be identified as `memcpy` from a specific glibc
build. *BSim* handles the fuzzy case: a feature vector per function derived from the
decompiler's P-Code, deliberately excluding constants, register names and data types so
that functionally equivalent code produces equal features, indexed with locality-sensitive
hashing and compared by cosine similarity. Exact identification and "this is a modified
copy of something I know" are not the same problem and are not solved by the same index.

## Decision

Sigil gains a **known-good corpus**: a content-addressed index of files as published, in
two tiers mirroring FID and BSim.

**Tier 1 — exact.** SHA-256 per file, keyed to `(ecosystem, package, version, path)`. An
exact match answers "this is `lodash@4.17.21/lodash.js`, unmodified, as published". That
is a suppression signal, and it attacks the FP rate at its root: it *removes* the largest
category of noise rather than describing it.

**Tier 2 — fuzzy.** Minification, bundling and transpilation change bytes without changing
meaning, which is exactly why Ghidra needed BSim on top of FID. The source-code analogue of
BSim's "constants and register names deliberately excluded" is a normalised hash: strip
comments and whitespace, drop string-literal contents, rename locals positionally, then
hash. Indexed with LSH so lookup stays sub-linear.

**Drift is a finding, not a suppression.** When part of a package matches a known release
and part does not, that is the trojanised-dependency shape, and it is reported as Critical
(`KNOWNGOOD-DRIFT-001`) rather than passed over. This is the detection Sigil cannot
currently make at any severity, and it is the reason the corpus is worth building — the FP
reduction alone would not justify it.

Suppression is never silent. A known-good match moves findings into
`suppressed_findings` with attribution, exactly as the trust ledger does, so a report
always shows what was set aside and why.

## Alternatives rejected

- **More suppression predicates (ADR-0008's path alone)** — describes known code instead of
  recognising it, and must be rewritten whenever a bundler changes its output.
- **Trusting `package-lock.json` integrity hashes** — they attest that the bytes match what
  the registry served, not that the registry served what the maintainer wrote, and they say
  nothing about vendored or bundled copies with no lockfile entry.
- **A single fuzzy index with no exact tier** — an exact hash is far cheaper and answers
  most cases; Ghidra keeps both for the same reason.
- **Shipping the index inside the binary** — it is orders of magnitude larger than the
  signature corpus. It loads as data from `~/.sigil/known-good/`, per
  [ADR-0007](ADR-0007-provenance-drift-and-osv-feeds.md)'s offline-tolerant feed model.

## Tradeoff accepted

A known-good index is a *trust* input: an attacker who can write to it can suppress real
findings. It is therefore treated exactly like a signature pack — signature-verified under
the same `SIGIL_PACK_PUBLIC_KEY` policy, and absent-by-default. Absence must never fail
open into false confidence, so a file that is simply unknown is scanned normally and
reported normally; the corpus can only ever *explain* code, never excuse it.

Corpus population across npm and PyPI is separate infrastructure with its own storage and
refresh cost. This ADR covers the mechanism and the on-disk format; the scale-out is not
in scope for the first implementation and the feature is inert until an index is installed.

## Consequences

The compounding asset ADR-0005 identifies in the signature corpus gains a second,
opposite-polarity half: one corpus describing what is bad, one recording what is known
good. The second is the harder to build and the harder to copy.

Implementation status at time of writing: tier 1, drift detection, the on-disk format, and
`sigil known-good` (build an index from a local tree, inspect an installed one) are
implemented. Tier 2's normalisation is specified here and not yet built; nothing in the
format prevents adding it, as entries carry an optional normalised hash field.
