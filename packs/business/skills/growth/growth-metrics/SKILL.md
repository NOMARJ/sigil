---
name: growth-metrics
description: >
  Defines the correct metrics for a product's GTM motion and reviews actuals
  against thresholds. Reads the GTM spec. Produces a weekly metrics snapshot.
  Flags when leading indicators are below threshold. Use for weekly growth reviews.
---

# Growth Metrics

## Pre-requisites

Invoke `business-context` skill. Read GTM spec for this product.

---

## Metrics are motion-specific

Using vanity metrics for the wrong motion is worse than no metrics.
Track what the motion requires.

| Motion | Leading indicators | Lagging |
|---|---|---|
| Developer-led | GitHub stars, forks, issues opened, installs | Paid tier conversions |
| Content-led | Organic impressions, AI search appearances, backlinks | Trial signups |
| Community-led | Community mentions, helpful replies cited, DMs asking for access | Signups from community |
| Relationship-led | Conversations initiated, demos booked, warm intros made | Proposals sent, pipeline value |

---

## Per-product metrics

### Sigil (developer-led)

**Weekly:**
- GitHub stars (target: +10/week after launch)
- GitHub forks (target: +5/week)
- Issues opened (signal of engagement — quality > quantity)
- HN/Reddit mentions

**Monthly:**
- Install count from package manager
- Pull requests from external contributors
- Security community citations

**Threshold for motion pivot:** 3 months post-launch, <100 stars and 0 enterprise inquiries
→ review motion and channel, not just content.

### InstaIndex (content-led)

**Weekly:**
- GSC impressions for target AEO keywords
- Position for "how to get indexed by AI search" variants
- New backlinks (ahrefs/SEMrush)
- Signups from organic

**Monthly:**
- AI search appearance count (perplexity.ai, chatgpt search queries)
- Blog posts published vs plan
- Paid conversion rate from organic

**Threshold for motion pivot:** 6 months, <500 organic monthly visits
→ review AEO targeting and content quality.

### Operable (relationship-led)

**Weekly:**
- LinkedIn post impressions and comments (investment ops specific)
- Warm conversations initiated (email/LinkedIn/in person)
- Demos booked

**Monthly:**
- Pipeline value (deals in consideration)
- Referrals from existing network
- Event attendance + follow-up rate

**Threshold:** 6 months, 0 pipeline conversations → the network path isn't working,
consider whether a different entry point (conference talk, written case study) unlocks it.

### PolicyPA (community-led)

**Weekly:**
- Reddit upvotes and helpful cites
- Media inquiries received
- User signups from community mentions

**Monthly:**
- Press mentions
- Government data citation count (Google News alerts)

---

## Weekly metrics review format

```markdown
## Growth Metrics — <Product> — <Date>

### Leading indicators

| Metric | Target | Actual | Status |
|---|---|---|---|
| [metric 1] | [threshold] | [actual] | ✅/⚠️/❌ |
| [metric 2] | [threshold] | [actual] | ✅/⚠️/❌ |
| [metric 3] | [threshold] | [actual] | ✅/⚠️/❌ |

### What's working
- [observation]

### What's not
- [observation]

### One change this week
- [single specific action to move the needle]
```

Save to `.nomark/growth/<product>/metrics-<date>.md`.
Review trends monthly. If 3 consecutive weeks of ❌ on a metric → flag for GTM review.
