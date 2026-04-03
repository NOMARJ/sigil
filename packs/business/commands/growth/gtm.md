# /growth:gtm

Derive or review the GTM strategy for a product.

## Usage

```
/growth:gtm <product>           # derive GTM from scratch
/growth:gtm <product> review    # review and update existing spec
/growth:gtm all                 # status overview of all product GTMs
```

## What it does

Invokes `gtm-architect` (Opus) with:
1. `BUSINESS-CONTEXT.md`
2. The product's existing GTM spec (if any)

Outputs a structured GTM spec to `.nomark/gtm/<product>.md` covering:
- Buyer (specific, not generic)
- Motion (one primary motion)
- Channel (where + why)
- Core message (one sentence, with proof)
- Funnel (awareness → conversion, with the drop-off lever)
- Metrics (3 leading, 1 lagging)
- 90-day plan (week-by-week)
- Anti-patterns (what not to do)

## What it doesn't do

Does not execute anything. GTM is architecture — derive it first, confirm it,
then execute with `/growth:launch`, `/growth:outreach`, `/growth:content`.

## After running

Review the output spec. The architect will ask for your confirmation before
any execution work begins. Adjust the spec if any assumption is wrong —
especially about buyer specificity and motion fit.

## `all` option

Produces a portfolio view:

```
Product        | Motion           | Spec Status | Last Updated
---------------|------------------|-------------|------------
Sigil          | Developer-led    | Active      | 2026-03-15
Operable       | Relationship-led | Active      | 2026-03-10
InstaIndex     | Content-led      | Active      | 2026-03-18
PolicyPA       | Community-led    | Draft       | 2026-02-28
Smart Settle   | Relationship-led | Not started | —
```

Flag any product without an active spec.
