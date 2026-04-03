---
name: polish
description: Final quality pass before shipping. Fixes alignment, spacing, consistency, and detail issues that separate good from great. Checks against AI slop anti-patterns.
args:
  - name: target
    description: The feature or area to polish (optional)
    required: false
user-invokable: true
---

Perform a meticulous final pass to catch all the small details that separate good work from great work.

## Pre-Polish Assessment

1. **Review completeness**:
   - Is it functionally complete?
   - Are there known issues to preserve (mark with TODOs)?
   - What's the quality bar? (MVP vs flagship feature?)

2. **Identify polish areas**:
   - Visual inconsistencies
   - Spacing and alignment issues
   - Interaction state gaps
   - Copy inconsistencies
   - Edge cases and error states
   - Loading and transition smoothness

**CRITICAL**: Polish is the last step, not the first. Don't polish work that's not functionally complete.

## Polish Systematically

### Visual Alignment & Spacing
- Pixel-perfect alignment to grid at all breakpoints
- Consistent spacing using design tokens (no random 13px gaps)
- Optical alignment adjustments for visual weight
- Responsive consistency across viewports

### Typography Refinement
- Hierarchy consistency: same elements use same sizes/weights
- Line length: 45-75 characters for body text
- No widows or orphans
- Font loading: no FOUT/FOIT flashes

### Color & Contrast
- All text meets WCAG contrast standards
- Consistent token usage — no hard-coded colors
- Theme consistency across all variants
- Tinted neutrals — no pure gray or pure black (add subtle chroma 0.01)
- Never gray text on colored backgrounds — use a shade of that color or transparency

### Interaction States
Every interactive element needs ALL states:
- Default, Hover, Focus, Active, Disabled, Loading, Error, Success

### Micro-interactions & Transitions
- Smooth transitions: 150-300ms for state changes
- Consistent easing: ease-out-quart/quint/expo for natural deceleration
- Never bounce or elastic — they feel dated
- 60fps animations, only animate transform and opacity
- For height animations, use grid-template-rows transitions
- Respects `prefers-reduced-motion`

### Content & Copy
- Consistent terminology throughout
- Consistent capitalization (Title Case vs Sentence case)
- No typos, grammar issues
- No redundant copy

### Icons & Images
- Consistent icon style and sizing
- Proper optical alignment with text
- Alt text on all images
- No layout shift on load

### Forms & Inputs
- All inputs properly labeled
- Consistent required indicators
- Helpful, specific error messages
- Logical tab order

### Edge Cases & Error States
- Loading states for all async actions
- Helpful empty states (not just blank space)
- Clear error messages with recovery paths
- Handles long content, missing data gracefully

### Responsiveness
- Test mobile, tablet, desktop
- Touch targets: 44x44px minimum
- No text smaller than 14px on mobile
- No horizontal scroll

### Code Quality
- Remove console logs, commented code, unused imports
- No TypeScript `any` or ignored errors

## Polish Checklist

- [ ] Visual alignment perfect at all breakpoints
- [ ] Spacing uses design tokens consistently
- [ ] Typography hierarchy consistent
- [ ] All interactive states implemented
- [ ] All transitions smooth (60fps)
- [ ] Copy is consistent and polished
- [ ] Icons consistent and properly sized
- [ ] All forms properly labeled and validated
- [ ] Error states are helpful
- [ ] Loading states are clear
- [ ] Empty states are welcoming
- [ ] Touch targets 44x44px minimum
- [ ] Contrast ratios meet WCAG AA
- [ ] Keyboard navigation works
- [ ] Focus indicators visible
- [ ] No console errors or warnings
- [ ] No layout shift on load
- [ ] Respects reduced motion preference
- [ ] Code is clean

**NEVER**:
- Polish before it's functionally complete
- Introduce bugs while polishing
- Ignore systematic issues
- Perfect one thing while leaving others rough

## Final Verification
- **Use it yourself**: Actually interact with the feature
- **Compare to design**: Match intended design
- **Check all states**: Don't just test happy path
