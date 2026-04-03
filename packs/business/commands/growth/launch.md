# /growth:launch

Produce a launch checklist and sequencing plan.

## Usage

```
/growth:launch <product>         # full launch plan
/growth:launch <product> check   # status check against existing launch plan
```

## What it does

Reads `launch-playbook` skill. Produces:
- T-30, T-7, launch day, T+7, T+30 checklist
- Motion-specific distribution plan
- Anti-patterns to avoid
- Success thresholds for launch day and week 1

## Output

Saved to `.nomark/growth/<product>/launch-<date>.md`.
Tracked as `STORY-LAUNCH-<product>` in progress.md.
