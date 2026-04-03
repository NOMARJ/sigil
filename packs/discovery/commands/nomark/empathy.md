# /empathy

Quick empathy check — the Suri test against the current Feature or Epic.

## Usage

```
/empathy              # Check current Feature
/empathy EP-001       # Check specific Epic
/empathy F-003        # Check specific Feature
```

## What It Does (5 minutes, no web search required)

1. Read the current Feature's SOLUTION.md entry
2. Read the linked Epic's evidence basis
3. Answer five questions:

```
┌──────────────────────────────────────────────────┐
│ EMPATHY CHECK — Suri Test                        │
├──────────────────────────────────────────────────┤
│ Feature: [F-XXX]  Epic: [EP-XXX]                │
│                                                   │
│ 1. WHO: Can we name the people this serves?      │
│    [Named / Vague / Unknown]                     │
│                                                   │
│ 2. EVIDENCE: Is the need grounded in evidence?   │
│    [HIGH / MED / LOW / HYPOTHESIS]               │
│                                                   │
│ 3. FRESHNESS: Is the evidence current (<90 days)?│
│    [Current / Stale / None]                      │
│                                                   │
│ 4. SILENCE: Do we know who's missing?            │
│    [Audited / Unaudited]                         │
│                                                   │
│ 5. SURI: Would she approve?                      │
│    [Yes / Concerns / No]                         │
├──────────────────────────────────────────────────┤
│ RESULT: ✅ Proceed / 🟡 Note gaps / 🔴 Research │
└──────────────────────────────────────────────────┘
```

4. If all green: proceed with confidence
5. If any yellow: note the gap, proceed with awareness
6. If any red: recommend `/discover` before further build work

## When to Run

- Before starting work on a Feature (routine hygiene)
- When switching context to a different Feature
- When the owner asks "are we building the right thing?"
- When brainstorming produces ideas that feel disconnected from users

## What It Does NOT Do

- Does not run web searches
- Does not construct personas
- Does not conduct synthetic interviews
- Does not produce research artifacts
- For all of that: `/discover`
