# FP-Adjudication Eval — F-009 US-110 (Honest Measurement)

_Run: 2026-06-12 (JSON `generated_at` 2026-06-11T20:50Z UTC) · Raw verdicts: `evidence/F-009/fp-adjudication-eval.json` · Instrument: `scripts/eval_fp_adjudication.py`_

## Disclosure (mandatory, per CLAUDE.md)

```
Data Source: Real production API calls — 168 claude-fable-5 adjudications (0 fell back to
             claude-opus-4-8; 0 refusals). Findings produced by the real sigil 1.2.0 release
             binary on: (a) the F-008 clean control set — 20 popular npm/PyPI packages
             fetched from the live registries; (b) the Datadog malicious-software-packages-
             dataset (commit 605a7318822117b3b29466747e65db1d582f290c), encrypted sample
             zips extracted for static scanning only.
Sample Size: Control: 20 packages, 2,544 High+ findings total, 89 adjudicated (cap: first 10
             per package, severity-desc/file/line order — deterministic, no random).
             Malicious: first 25 sample zips (sorted) detected at >=High, 79 findings
             adjudicated (cap: 5 per sample), 0 extract failures.
Limitations: Caps bound the package-level "after" numbers conservatively — a capped target
             can never fully clear, so caps can only UNDERSTATE adjudication's benefit on
             clean packages and OVERSTATE retention on malicious ones (measured below: cap
             contributed nothing to malicious retention). Offline static phases only (same
             as F-008 eval). Token figures are ~4 chars/token estimates; thinking tokens
             are billed but not visible. Malicious dataset has GuardDog selection bias
             (Datadog's own disclaimer). Single run; LLM verdicts are not bit-reproducible.
```

## Direction 1 — clean control set (the win)

Finding-level: **89/89 adjudicated High+ findings classified `benign_dual_use`**
(confidence 0.95–0.99, 0 suspicious, 0 malicious, 0 refused, 0 errors).

Package-level FP@High:

| | Flagged at >=High | FP rate |
|---|---|---|
| Before adjudication (F-008 baseline) | 14 / 20 | 70% |
| After adjudication | 6 / 20 | **30%** |

The 8 cleared: axios, chalk, commander, cross-spawn, click, flask, jinja2, rich.
The 6 still flagged (lodash, numpy, packaging, pyyaml, requests, urllib3) are **entirely a
cap artifact**: each has >10 High+ findings, and every one of their adjudicated findings came
back benign. No clean package had a single finding judged non-benign. The 30% residual is the
eval's budget boundary, not a verdict failure — uncapped adjudication would likely clear more,
but that is extrapolation, not measurement, so 30% is the number we report.

Rationale quality (verbatim examples in the JSON): the model identified lodash's
`Function('return this')()` global-object idiom, NumPy's CircleCI deploy-key fingerprint
pattern, and urllib3's dummyserver test-CA key — each grounded in the actual code context.

## Direction 2 — malicious samples (the damage check)

Finding-level on 25 truly-malicious packages: 48 `benign_dual_use`, 26 `suspicious`,
5 `malicious` (confidence 0.55–0.98). The 61% finding-level benign rate is expected —
malicious packages are mostly ordinary code; the question is whether the discriminating
verdict lands on the right finding.

Sample-level recall at >=High:

| | Detected at >=High | Retention |
|---|---|---|
| Before adjudication | 25 / 25 | — |
| After adjudication | 24 / 25 | **96%** |

Retention decomposition (the integrity-critical number): **all 24 retained samples were
retained by an actual suspicious/malicious verdict — 0 were retained only by the cap.**
The conservative cap contributed nothing; the verdicts did the work.

The 1 cleared sample (`@aifabrix/miso-client 4.7.2`): its only two High findings were
NET-006/PROMPT-007 hits on the npm **registry packument JSON** (metadata URLs and integrity
fields), not on code. Both verdicts are individually defensible — the scanner's High
detection of this sample was itself metadata noise; the malicious payload never appeared in
the High+ finding set. It still counts as a recall loss against the F-008 metric and is
reported as such: **sample-level recall cost = 1/25 (4%)**, with the caveat that the
underlying detection signal was FP-shaped.

## Cross-checks

- **Not a rubber stamp:** the same model that judged 89/89 clean findings benign judged
  31/79 malicious-sample findings non-benign. The verdicts discriminate; they don't
  default-benign.
- **Refusals:** 0 in 168 calls — the cyber-classifier concern (security-tooling content
  tripping Fable 5 safety classifiers) did not materialize on this corpus. The
  refusal→Opus-4.8 fallback path was never exercised live; it remains covered by unit tests.
- **F-010 separation:** this measures the adjudication lever only. The trust-ledger lever
  (F-010) reaches warm-FP 0% by operator approval; adjudication reaches 30% (cap-bounded)
  with no operator action and also survives first-contact with unknown packages. The two
  compose: ledger for known-approved content, adjudication for everything else.

## Cost (estimated)

~131K input + ~35K visible output tokens across 168 calls (thinking tokens billed but not
visible; true cost higher). At published Fable 5 pricing this is roughly $3–8 visible +
thinking overhead — within the pre-run estimate of US$15–30.

## Ship / No-ship recommendation

**SHIP.** Evidence: (1) adjudication halves package-level FP@High (70%→30%) with zero
wrong-direction verdicts on clean packages; (2) it costs 4% sample-level recall, and the
single loss case was a metadata-noise detection, not a payload detection; (3) retention on
malicious samples is verdict-driven, not artifact-driven; (4) zero refusals and zero errors
in 168 live calls.

Ship conditions:
1. Keep the conservative product behavior this eval assumed: a finding is cleared **only**
   by an explicit `benign_dual_use` verdict; refusals/errors leave findings flagged.
2. Surface adjudication as per-finding triage (as built in US-107/US-111), not automatic
   bulk suppression — the 61% benign rate on malicious-package findings means bulk
   auto-clear without the sample-level "any non-benign retains the package" rule would be
   unsafe.
3. US-112 ops verification still required before production exposure (env, retention, live
   smoke through the deployed API).
