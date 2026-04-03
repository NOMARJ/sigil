---
name: interactive-dashboard-builder
description: >
  Build self-contained interactive HTML dashboards with Chart.js, dropdown filters,
  and professional styling. Use when someone asks to create a dashboard, build an
  interactive report, generate a shareable HTML file with charts and filters,
  or needs a visual data summary that works without a server.
---

# Interactive Dashboard Builder

Build standalone HTML dashboards that work in any browser — no server, no dependencies beyond CDN-hosted Chart.js.

## When to Use

- User has data (CSV, JSON, SQL results, spreadsheet) and wants a visual overview
- Need a shareable report that works offline
- Quick dashboard without setting up Metabase/Grafana/Tableau
- Prototype before building a production dashboard

## Architecture

Single `.html` file containing:
- **Chart.js** (via CDN) for all visualizations
- **Inline CSS** for professional styling (dark/light theme support)
- **Vanilla JS** for interactivity (filters, tooltips, responsive layout)
- **Embedded data** as JSON within the file (no external API calls)

## Build Process

### Step 1: Understand the Data

- Read the data source (CSV, JSON, database results)
- Profile: row count, column types, date ranges, categorical values
- Identify the key dimensions (what to filter/group by) and measures (what to chart)

### Step 2: Design the Layout

Standard dashboard layout:
```
┌─────────────────────────────────────────────────┐
│ Dashboard Title                    [Filters ▾]  │
├──────────┬──────────┬──────────┬────────────────┤
│  KPI 1   │  KPI 2   │  KPI 3   │    KPI 4      │
├──────────┴──────────┴──────────┴────────────────┤
│                                                  │
│         Primary Chart (line/bar/area)            │
│                                                  │
├─────────────────────┬────────────────────────────┤
│   Secondary Chart   │    Secondary Chart         │
│   (pie/donut)       │    (bar/comparison)        │
├─────────────────────┴────────────────────────────┤
│                  Data Table                       │
└──────────────────────────────────────────────────┘
```

### Step 3: Chart Type Selection

| Data Pattern | Recommended Chart | Chart.js Type |
|-------------|-------------------|---------------|
| Trend over time | Line chart | `line` |
| Category comparison | Horizontal bar | `bar` (indexAxis: 'y') |
| Part of whole | Donut chart | `doughnut` |
| Distribution | Histogram (bar) | `bar` |
| Two variables | Scatter plot | `scatter` |
| Multiple series | Stacked bar or grouped bar | `bar` (stacked) |
| KPI / single number | Big number card | HTML/CSS |

### Step 4: Implement Filters

```javascript
// Dropdown filter pattern
function filterData(dimension, value) {
    const filtered = value === 'All'
        ? rawData
        : rawData.filter(row => row[dimension] === value);
    updateCharts(filtered);
    updateKPIs(filtered);
    updateTable(filtered);
}
```

### Step 5: Styling Principles

- **Font**: System font stack (`-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto`)
- **Colors**: Professional palette, colorblind-safe (use Chart.js built-in palettes)
- **KPI cards**: Large number, small label, optional trend indicator (↑↓)
- **Responsive**: CSS Grid with `minmax()` for card layout
- **Dark mode**: `prefers-color-scheme: dark` media query with CSS variables

### Step 6: Data Embedding

For dashboards < 5MB of data, embed directly:
```html
<script>
const DATA = [/* JSON array */];
</script>
```

For larger datasets: use `fetch()` to load a companion `.json` file.

## Output

Save as `[name]-dashboard.html` in the project workspace. Single file, opens in any browser.

## Integration

- Read data context skill (if exists) for metrics definitions and terminology
- Follow brand voice from BUSINESS-CONTEXT.md for dashboard titles and labels
- Save to workspace for user access
