---
name: audit
description: Perform comprehensive audit of interface quality across accessibility, performance, theming, responsive design, and AI slop detection. Generates detailed report with severity ratings. Does NOT fix — only documents.
args:
  - name: area
    description: The feature or area to audit (optional)
    required: false
user-invokable: true
---

Run systematic quality checks and generate a comprehensive audit report with prioritized issues and actionable recommendations. Don't fix issues - document them for other commands to address.

**First**: Use the frontend-design skill for design principles and anti-patterns.

## Diagnostic Scan

Run comprehensive checks across multiple dimensions:

1. **Accessibility (A11y)** - Check for:
   - **Contrast issues**: Text contrast ratios < 4.5:1 (or 7:1 for AAA)
   - **Missing ARIA**: Interactive elements without proper roles, labels, or states
   - **Keyboard navigation**: Missing focus indicators, illogical tab order, keyboard traps
   - **Semantic HTML**: Improper heading hierarchy, missing landmarks, divs instead of buttons
   - **Alt text**: Missing or poor image descriptions
   - **Form issues**: Inputs without labels, poor error messaging, missing required indicators

2. **Performance** - Check for:
   - **Layout thrashing**: Reading/writing layout properties in loops
   - **Expensive animations**: Animating layout properties (width, height, top, left) instead of transform/opacity
   - **Missing optimization**: Images without lazy loading, unoptimized assets, missing will-change
   - **Bundle size**: Unnecessary imports, unused dependencies
   - **Render performance**: Unnecessary re-renders, missing memoization

3. **Theming** - Check for:
   - **Hard-coded colors**: Colors not using design tokens
   - **Broken dark mode**: Missing dark mode variants, poor contrast in dark theme
   - **Inconsistent tokens**: Using wrong tokens, mixing token types
   - **Theme switching issues**: Values that don't update on theme change

4. **Responsive Design** - Check for:
   - **Fixed widths**: Hard-coded widths that break on mobile
   - **Touch targets**: Interactive elements < 44x44px
   - **Horizontal scroll**: Content overflow on narrow viewports
   - **Text scaling**: Layouts that break when text size increases
   - **Missing breakpoints**: No mobile/tablet variants

5. **Anti-Patterns (CRITICAL)** - Check against ALL anti-patterns below. Look for AI slop tells and general design anti-patterns.

### AI Slop Anti-Patterns Checklist
- [ ] AI color palette: cyan-on-dark, purple-to-blue gradients, neon accents on dark backgrounds
- [ ] Gradient text for "impact" on metrics or headings
- [ ] Dark mode with glowing accents as default
- [ ] Pure black (#000) or pure white (#fff) without tinting
- [ ] Gray text on colored backgrounds
- [ ] Overused fonts: Inter, Roboto, Arial, Open Sans
- [ ] Monospace typography as lazy "tech" signaling
- [ ] Large icons with rounded corners above headings
- [ ] Everything wrapped in cards / nested cards
- [ ] Identical card grids (icon + heading + text repeated)
- [ ] Hero metric layout template (big number, small label, gradient accent)
- [ ] Everything centered
- [ ] Uniform spacing throughout (no rhythm)
- [ ] Glassmorphism everywhere (blur effects, glass cards, glow borders)
- [ ] Rounded elements with thick colored border on one side
- [ ] Decorative sparklines that convey nothing
- [ ] Rounded rectangles with generic drop shadows
- [ ] Bounce/elastic easing
- [ ] Animating layout properties instead of transform/opacity
- [ ] Redundant copy (intros restating headings)
- [ ] Every button styled as primary

**CRITICAL**: This is an audit, not a fix. Document issues thoroughly with clear explanations of impact. Use other commands to fix issues after audit.

## Generate Comprehensive Report

### Anti-Patterns Verdict
**Start here.** Pass/fail: Does this look AI-generated? List specific tells. Be brutally honest.

### Executive Summary
- Total issues found (count by severity)
- Most critical issues (top 3-5)
- Overall quality score (if applicable)
- Recommended next steps

### Detailed Findings by Severity

For each issue, document:
- **Location**: Where the issue occurs (component, file, line)
- **Severity**: Critical / High / Medium / Low
- **Category**: Accessibility / Performance / Theming / Responsive / Anti-Pattern
- **Description**: What the issue is
- **Impact**: How it affects users
- **WCAG/Standard**: Which standard it violates (if applicable)
- **Recommendation**: How to fix it

#### Critical Issues
[Issues that block core functionality or violate WCAG A]

#### High-Severity Issues
[Significant usability/accessibility impact, WCAG AA violations]

#### Medium-Severity Issues
[Quality issues, WCAG AAA violations, performance concerns]

#### Low-Severity Issues
[Minor inconsistencies, optimization opportunities]

### Patterns & Systemic Issues
Identify recurring problems across the codebase.

### Positive Findings
Note what's working well — good practices to maintain.

### Recommendations by Priority
1. **Immediate**: Critical blockers to fix first
2. **Short-term**: High-severity issues (this sprint)
3. **Medium-term**: Quality improvements (next sprint)
4. **Long-term**: Nice-to-haves and optimizations

### Suggested Commands for Fixes
Map issues to available commands. Examples:
- "Use `/quality:refactor-clean` to address N structural issues"
- "Use `/quality:accessibility-audit` for deeper a11y analysis"
- "Use `/quality:polish` to fix N detail/spacing issues"

**NEVER**:
- Report issues without explaining impact
- Mix severity levels inconsistently
- Skip positive findings
- Provide generic recommendations
- Report false positives without verification
