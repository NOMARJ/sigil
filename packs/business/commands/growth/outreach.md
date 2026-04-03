# /growth:outreach

Produce B2B outreach sequences for a product.

## Usage

```
/growth:outreach <product>               # generate sequence for primary ICP
/growth:outreach <product> <segment>     # specific ICP segment
```

## Requires

GTM spec for this product (run `/growth:gtm <product>` first).
ICP doc if available (run `/growth:content <product> icp` to generate).

## What it does

Reads `outreach-engine` skill. Produces:
- 3-touch sequence for the specified ICP segment
- Trigger-aware messaging (references the buyer's specific trigger event)
- Channel-appropriate format (email vs LinkedIn vs community)

## Hard gate

Relationship-led products (Operable, Smart Settle) will not get cold sequences.
The skill will flag this and recommend warm path alternatives.
