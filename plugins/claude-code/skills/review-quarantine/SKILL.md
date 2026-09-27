---
name: review-quarantine
description: Review items in Sigil quarantine and help decide whether to approve or reject them. Use when scan results are available or when managing quarantined code.
allowed-tools: Bash(sigil *)
---

# Quarantine Review

Review and manage quarantined items:

1. List quarantined items: `sigil list`
2. Review findings for each item
3. Explain detected threats and risk levels
4. Guide approval decision:
   - `sigil approve <id>` - Move to working directory
   - `sigil reject <id>` - Permanently delete

**Decision criteria:**
- CLEAN/LOW: Generally safe to approve
- MEDIUM: Review findings, approve with caution
- HIGH: Reject unless specific threat is false positive
- CRITICAL: Always reject

Help the user understand the security implications before approving.
