---
name: dashboard-patterns
description: >
  Tactical layout and data visualization patterns for building dashboards, analytics views,
  executive summaries, KPI displays, and any data-heavy UI. Use this skill whenever the user
  asks to build a dashboard, analytics page, metrics view, reporting UI, admin panel with data,
  or any interface that displays KPIs, charts, tables, or operational data. Also trigger when
  reviewing or improving an existing dashboard layout, or when the user mentions "dashboard",
  "metrics", "KPIs", "analytics", "data visualization", "charts", "reporting view", or
  "executive summary". Works alongside frontend-design (which handles aesthetics) — this skill
  handles information architecture and data presentation patterns specifically.
---

# Dashboard Patterns

Tactical rules for building dashboards that communicate data clearly. These patterns come from
eye-tracking research, information design principles, and proven UX heuristics. Apply them
before reaching for any styling decisions.

## 1. Scan Path Patterns

Choose your layout based on who's reading and what they need.

### Z Pattern
Eye scans: top-left → top-right → diagonal down → bottom-left → bottom-right.
- **Use for**: Executive dashboards, overview/summary views, status boards.
- **Rule**: Place #1 KPI top-left, #2 KPI top-right. Supporting detail bottom half.
- **Anti-pattern**: Burying the most important metric in the middle or bottom.

### F Pattern
Eye scans: full top row → shorter second row → drops straight down the left edge.
- **Use for**: Analytical dashboards, data-heavy views, list-driven UIs.
- **Rule**: Put #1 metric at the top. Each row below gets progressively less attention.
  Front-load labels and key values on the left side.
- **Anti-pattern**: Placing critical filters or actions on the right side where attention drops off.

### Selection guide
| Audience | Dashboard type | Pattern |
|----------|---------------|---------|
| C-suite / board | Status overview | Z |
| Analysts / ops | Deep-dive, investigation | F |
| Mixed | Summary + drill-down | Z top section, F below fold |

## 2. Layout Composition

### 60/40 Split
Give the primary visual (main chart, map, key table) 60% width. Secondary content gets 40%.
Eyes gravitate to the larger area. Simple rule, big impact on visual balance.

### Golden Ratio Grid
For complex dashboards with 6+ widgets: use a 3-column grid where the left column is ~38%,
middle ~38%, right ~24%. Or 2-column with 62/38 split. Feels balanced without being rigid.

### Card Hierarchy
Not all cards are equal. Signal importance through:
- **Size**: Important metrics get larger cards.
- **Elevation**: Higher shadow = higher importance (use sparingly — max 2 levels).
- **Position**: Top-left is prime real estate. Bottom-right is the graveyard.
- **Border/accent**: A left-border color accent on a card draws the eye without shouting.

### Vertical Rhythm
Maintain consistent spacing between rows of cards. Use a base unit (8px) and multiply:
- Between card groups: 24px (3×)
- Between cards in a group: 16px (2×)
- Internal card padding: 16-24px
- Never mix spacing values randomly. Pick a scale and stick to it.

## 3. Proximity & Grouping

**The rule people always forget.** Related things must be physically close. Don't separate
metrics just to achieve visual symmetry. Random spacing is what makes dashboards look messy
even when the data is solid.

### Grouping principles
- **Contextual clusters**: Revenue + Revenue Change + Revenue Chart = one group.
  Don't scatter them across the page.
- **Section headers**: Use subtle, low-contrast headers to label groups. Not bold banners.
- **White space as separator**: The gap between groups should be noticeably larger than
  the gap between items within a group. This is the single most effective way to create
  visual hierarchy without adding any UI chrome.
- **Alignment rails**: Every element should sit on an invisible grid line. If something
  is 2px off, it looks amateur. Snap everything.

## 4. KPI & Metric Display

### The KPI Card Formula
```
[Label]                    [Trend indicator]
[Big Number]
[Context line: vs prior period, target, or benchmark]
```

- **Big number**: 32-48px, bold. This is what they came for.
- **Label**: 12-14px, muted color. Above the number, not below.
- **Context**: 12-14px, shows direction. "+12% vs last month" or "3% below target."
- **Trend indicator**: Sparkline, arrow, or small inline chart. Not a full chart.
- **Color coding**: Green/red for good/bad ONLY if the metric has a clear direction.
  Don't color-code things that are just "different."

### Number Formatting
- Abbreviate large numbers: 1.2M not 1,200,000. 14.3K not 14,300.
- Consistent decimal places within a group. Don't mix "12.3%" and "8%".
- Right-align numbers in tables. Always. Left-aligned numbers are unreadable for comparison.
- Use tabular/monospace figures for numbers in tables (`font-variant-numeric: tabular-nums`).

## 5. Chart Selection

Don't pick charts by what looks cool. Pick by what the data needs to say.

| What you're showing | Use | Don't use |
|---------------------|-----|-----------|
| Single value + trend | KPI card + sparkline | Pie chart |
| Comparison across categories | Horizontal bar | Pie chart, 3D bar |
| Change over time | Line chart | Vertical bar (unless discrete periods) |
| Part-to-whole | Stacked bar, treemap | Pie chart (>5 slices) |
| Distribution | Histogram, box plot | Bar chart |
| Correlation | Scatter plot | Dual-axis line (misleading) |
| Composition over time | Stacked area | Multiple pie charts |

### Chart rules
- **Never use dual-axis charts** unless both axes share the same unit. They mislead.
- **Start Y-axis at zero** for bar charts. Line charts can have a non-zero baseline
  if the range is narrow and clearly labeled.
- **Limit pie charts to 3-5 slices**. Beyond that, use a horizontal bar.
- **Label directly** on the chart where possible. Legends force the eye to bounce
  back and forth. Inline labels > legend.
- **Mute gridlines**. They should be barely visible — guides, not features.
  Use `rgba(0,0,0,0.06)` or similar.
- **Consistent color mapping**: If "Revenue" is blue in one chart, it's blue everywhere.

## 6. Data Tables

- **Zebra striping**: Use very subtle alternating row colors (`rgba(0,0,0,0.02)`).
  Heavy striping is worse than none.
- **Sticky headers**: Always for tables taller than viewport.
- **Column alignment**: Text left, numbers right, dates center or left.
- **Sortable columns**: Indicate with a subtle chevron. Active sort should be obvious.
- **Row hover**: Subtle highlight on hover. Helps track across wide tables.
- **Truncation**: Long text gets truncated with ellipsis + tooltip. Never let text wrap
  and blow out row height inconsistently.
- **Density control**: Offer compact/comfortable/spacious modes for power users.

## 7. Responsive Dashboard Behavior

- **Don't just stack columns**. A 4-column desktop layout stacked to 1 column is unusable.
  Redesign for mobile: prioritize top 2-3 KPIs, collapse detail into expandable sections.
- **Minimum card width**: 280px. Below this, charts become unreadable.
- **Chart fallbacks**: Complex charts on mobile should simplify to KPI cards or small sparklines.
- **Touch targets**: 44px minimum on mobile. Don't make people precision-tap filters.

## 8. Filters & Controls

- **Position**: Top of the page, above all content. Never in a sidebar that hides data.
- **Active state**: Always show what's currently filtered. "Showing: Last 30 days, AU region"
  as a persistent strip.
- **Date range**: Default to a sensible range (last 30 days). Don't make them pick every time.
- **Filter pills**: Show active filters as removable pills. One click to clear each,
  "Clear all" option visible.
- **Avoid dropdowns for <5 options**: Use segmented controls or toggle buttons instead.
  Faster to scan, faster to click.

## 9. Loading & Empty States

- **Skeleton screens** over spinners. Show the layout shape while data loads.
- **Progressive loading**: Load KPI cards first (fast, small payloads), then charts,
  then tables. Don't block everything on the slowest query.
- **Empty states**: Never show a blank card. Show "No data for this period" with a
  suggestion: "Try expanding the date range."
- **Error states**: Show per-widget, not a full-page error. One failed query shouldn't
  nuke the entire dashboard.

## 10. Color & Accessibility

- **Don't rely on color alone**. Pair color with icons, patterns, or text labels.
  8% of men are color-blind.
- **Contrast ratios**: Text on colored backgrounds must meet WCAG AA (4.5:1 for body,
  3:1 for large text).
- **Sequential palettes**: For magnitude (low→high), use single-hue gradients.
  Not rainbow. Rainbow is unordered and misleading.
- **Diverging palettes**: For above/below a midpoint, use two-hue diverging
  (e.g., blue→white→red). Midpoint must be meaningful.
- **Categorical palettes**: Max 8 distinct colors. Beyond that, humans can't
  distinguish reliably. Group the rest as "Other."

## 11. Information Density

### The density spectrum
- **Executive**: Low density. Big numbers, lots of white space, 4-6 widgets max.
- **Operational**: Medium density. 8-12 widgets, tighter spacing, more context per card.
- **Analytical**: High density. Tables, small multiples, dense charts. Power user territory.

Match density to audience. Don't build an analyst dashboard for a CEO or vice versa.

### Small multiples
When comparing the same metric across many segments (regions, products, teams), use
small multiples: the same chart repeated in a grid, one per segment, all with identical
axes. Far more effective than one chart with 15 overlapping lines.

## Usage Notes

This skill provides layout and data presentation rules. For visual aesthetics (typography,
color themes, animation, creative direction), also consult the `frontend-design` skill.
For accessibility audits, use `web-design-guidelines`.

When building a dashboard:
1. **First**: Decide audience → pick scan pattern (§1) and density level (§11).
2. **Then**: Choose layout composition (§2) and group related metrics (§3).
3. **Then**: Design individual widgets — KPIs (§4), charts (§5), tables (§6).
4. **Then**: Add controls (§8) and states (§9).
5. **Last**: Apply color/accessibility rules (§10) and responsive behavior (§7).
