# ADR Graph Schema

> How ADRs and Architecture Lessons are tracked in `.nomark/graph.json`.

---

## Node Schema

```json
{
  "ADR-0001": {
    "type": "adr",
    "title": "Use Redis for session caching",
    "status": "proposed | accepted | deprecated | superseded",
    "date": "2026-03-31",
    "venture": "flowmetrics | nomark",
    "level": "1 | 2",
    "tags": ["database", "tier-2"],
    "file": "docs/adr/ADR-0001.md",
    "outcome": "pending | success | partial | failure | reverted",
    "outcome_date": "2026-06-15",
    "outcome_lesson": "AL-001"
  }
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| type | string | Always `"adr"` |
| title | string | Short decision title |
| status | string | `proposed`, `accepted`, `deprecated`, `superseded` |
| date | string | ISO date of creation |
| venture | string | Venture name or `"nomark"` for Level 1 |
| level | string | `"1"` (NOMARK universal) or `"2"` (venture-specific) |
| tags | string[] | Technology, pattern, or domain tags |
| file | string | Relative path to the ADR markdown file |

### Outcome Fields (optional — added after implementation)

| Field | Type | Description |
|-------|------|-------------|
| outcome | string | `pending` (default), `success`, `partial`, `failure`, `reverted` |
| outcome_date | string | ISO date outcome was recorded |
| outcome_lesson | string | Linked architecture lesson ID (e.g., `AL-001`) |

## Architecture Lesson Node

```json
{
  "AL-001": {
    "type": "al",
    "title": "Redis caching — success at current scale",
    "date": "2026-06-15",
    "venture": "flowmetrics",
    "category": "database",
    "outcome": "success",
    "adr": "ADR-0001",
    "tags": ["redis", "caching"],
    "file": "docs/arch-lessons/AL-001.md"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| type | string | Always `"al"` |
| title | string | Short lesson summary |
| date | string | ISO date of capture |
| venture | string | Venture name |
| category | string | Architecture domain |
| outcome | string | `success`, `partial`, `failure`, `reverted` |
| adr | string | Linked ADR ID |
| tags | string[] | Technology and domain tags |
| file | string | Relative path to lesson file |

## Edge Types

| Relationship | From | To | Meaning |
|-------------|------|----|---------|
| `decided_by` | ADR | venture | Which venture made this decision |
| `supersedes` | ADR | ADR | This ADR replaces an older one |
| `adopts_pattern` | ADR | pattern | Decision to adopt a NOMARK pattern |
| `adopts_tech` | ADR | tech | Decision to use a Tier 2 technology |
| `documents_outcome` | AL | ADR | Lesson records outcome of this ADR |
| `learned_by` | AL | venture | Which venture captured this lesson |
| `implemented_by` | AL | commit | Commits that implemented the decision |
| `references` | any | any | General cross-reference |

## Examples

```json
{
  "nodes": {
    "ADR-0001": {
      "type": "adr", "title": "Use Redis for session caching",
      "status": "accepted", "date": "2026-03-31", "venture": "flowmetrics",
      "level": "2", "tags": ["database", "tier-2", "redis"],
      "file": "docs/adr/ADR-0001.md",
      "outcome": "success", "outcome_date": "2026-06-15", "outcome_lesson": "AL-001"
    },
    "AL-001": {
      "type": "al", "title": "Redis caching — success at current scale",
      "date": "2026-06-15", "venture": "flowmetrics", "category": "database",
      "outcome": "success", "adr": "ADR-0001", "tags": ["redis", "caching"],
      "file": "docs/arch-lessons/AL-001.md"
    }
  },
  "edges": [
    { "from": "ADR-0001", "to": "venture:flowmetrics", "rel": "decided_by" },
    { "from": "ADR-0001", "to": "tech:redis", "rel": "adopts_tech" },
    { "from": "AL-001", "to": "ADR-0001", "rel": "documents_outcome" },
    { "from": "AL-001", "to": "venture:flowmetrics", "rel": "learned_by" },
    { "from": "AL-001", "to": "commit:abc1234", "rel": "implemented_by" }
  ]
}
```

## Agent Protocol

1. **On ADR creation:** Add node to graph. Add `decided_by` edge. Add `adopts_tech` or `adopts_pattern` edge if applicable. Set `outcome: "pending"`.
2. **On ADR acceptance:** Update node status to `accepted`.
3. **On ADR deprecation:** Update status to `deprecated`. Verify no active code depends on it.
4. **On supersession:** Update old ADR to `superseded`. Add `supersedes` edge from new to old.
5. **On outcome capture:** Update ADR node with `outcome`, `outcome_date`, `outcome_lesson`. Create AL node. Add `documents_outcome` edge from AL to ADR. Add `implemented_by` edges from AL to relevant commits.
6. **On cross-project query:** Portfolio intelligence can aggregate ADR nodes across ventures to detect patterns (e.g., "3 ventures adopted Redis — consider Tier 1 promotion").

### Outcome Lifecycle

ADR created (pending) → 90 days → agent prompts → owner responds → outcome + lesson created → synced to portfolio. Dismissed prompts re-fire after 30 days.
