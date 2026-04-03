---
name: launch-playbook
description: >
  Produces a launch checklist and sequencing plan for a product, calibrated to its
  GTM motion. Reads business context and GTM spec. Covers pre-launch, launch day,
  and 30-day post-launch. Use when preparing to ship or announce a product.
---

# Launch Playbook

## Pre-requisites

Invoke `business-context` skill. Read GTM spec for this product.

A launch is a distribution event, not a product event.
The product ships when it ships. The launch is when you tell the right people,
in the right place, in the right way.

---

## Launch checklist generator

For the target product and motion, produce a checklist in this structure:

### T-30 days (pre-launch foundation)

**Content and discovery:**
- [ ] Primary landing page live with clear message and proof point
- [ ] AEO-optimised content published (for content-led products)
- [ ] GitHub README complete (for developer-led products)
- [ ] `llms.txt` deployed at `/llms.txt` (all products — AI discoverability)
- [ ] `robots.txt` not blocking AI crawlers
- [ ] Structured data / schema markup implemented

**Outreach preparation:**
- [ ] ICP list built (for outreach-led launches)
- [ ] Warm paths identified (for relationship-led products — never cold)
- [ ] Community presence established before asking for anything

**Social proof:**
- [ ] One real proof point documented (number, result, customer quote)
- [ ] No fake data, no "beta users said..." without specifics

### T-7 days (pre-launch activation)

- [ ] Teaser content published (what's coming, why it matters)
- [ ] Early access / waitlist open (if applicable)
- [ ] Distribution channels primed (community presence, LinkedIn warm-up)

### Launch day

**Developer-led (Sigil):**
- [ ] GitHub repo public with complete README
- [ ] HN "Show HN" post drafted and ready
- [ ] /r/netsec or security Slack communities post ready
- [ ] Responsible disclosure paper linked
- [ ] One-line install works end-to-end

**Content-led (InstaIndex):**
- [ ] 3+ AEO blog posts live before launch
- [ ] Product Hunt submission scheduled
- [ ] SEO community posts (Twitter/X, Reddit r/SEO)
- [ ] GSC integration docs clear and working

**Community-led (PolicyPA):**
- [ ] Media pitch sent to 3-5 journalists (consumer finance beat)
- [ ] Reddit posts in AusFinance, AusLegal — genuine value first
- [ ] Product Hunt launch

**Relationship-led (Operable, Smart Settle):**
- [ ] Warm email to existing network — personal, specific, not broadcast
- [ ] LinkedIn post targeted to investment operations audience
- [ ] Conference/event presence scheduled (ASFA, ICA)

### T+7 days

- [ ] Reply to every comment/reply — launch is a conversation
- [ ] Capture all feedback in `.nomark/memory/`
- [ ] Iterate on messaging based on what questions people ask
- [ ] Track leading indicators against GTM spec thresholds

### T+30 days

- [ ] Review metrics against spec thresholds
- [ ] Update GTM spec with what's working and what isn't
- [ ] Commit to next growth cycle or pivot decision

---

## Anti-patterns (per motion)

**Developer-led:**
- Don't launch without a working CLI install
- Don't launch without real benchmark data
- Don't over-explain — let the code speak

**Content-led:**
- Don't launch before the first 3 pieces of content are live
- Don't launch with generic SEO content — needs a specific angle

**Relationship-led:**
- Don't blast your LinkedIn network with a press release
- Don't cold email — ever
- Don't launch without a specific person in mind to call

---

## Output

Save launch checklist to `.nomark/growth/<product>/launch-<date>.md`.
Track completion in progress.md as STORY-LAUNCH-<product>.
