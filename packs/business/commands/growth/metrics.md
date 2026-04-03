# /growth:metrics

Review growth metrics for a product or the whole portfolio.

## Usage

```
/growth:metrics <product>        # weekly metrics snapshot
/growth:metrics <product> setup  # set up tracking for this product
/growth:metrics all              # portfolio-wide weekly review
```

## What it does

Reads `growth-metrics` skill.

`setup`: Defines the 3 leading + 1 lagging metrics for this product's motion.
Saves metric definitions to `.nomark/gtm/<product>.md` metrics section.

Weekly review: Compares actuals to thresholds. Produces:
- Status table (✅/⚠️/❌ per metric)
- What's working
- What's not
- One change this week

`all`: Portfolio view across all products with specs.

## Threshold flags

If a metric is ❌ for 3 consecutive weeks → automatically suggests a GTM spec review.
Growth without measurement is guesswork.
