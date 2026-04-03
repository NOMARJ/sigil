---
name: supply-chain-audit
description: "Audit the supply-chain threat landscape of project dependencies. Part of the Nomark Method Layer 1 security scanning. Use whenever dependency files change (package.json, requirements.txt, go.mod, Cargo.toml), someone adds a new dependency, or someone asks 'are our dependencies safe', 'dependency audit', 'supply chain risk'."
---

# Supply Chain Risk Auditor

Adapted from Trail of Bits' supply-chain-risk-auditor skill. Evaluates the security posture of project dependencies because your app is only as secure as its weakest dependency.

## What You're Auditing

### Known Vulnerabilities
- Check dependencies against known CVE databases
- Run `npm audit`, `pip-audit`, `cargo audit`, `govulncheck` as appropriate
- Flag severity: Critical, High, Medium, Low
- Check if patches are available

### Dependency Health Signals
For each significant dependency, assess:
- **Maintenance status:** Last commit date, release frequency, open issue count
- **Maintainer count:** Single maintainer = bus factor risk
- **Download/usage stats:** Very low usage for a critical function = suspicious
- **License compatibility:** Does the license work with your project?

### Supply Chain Attack Vectors
- **Typosquatting:** Does this package name closely resemble a popular package? (`lodash` vs `l0dash`)
- **Dependency confusion:** Could an internal package name collide with a public one?
- **Compromised maintainer:** Has the package ownership changed recently?
- **Install scripts:** Does the package run code during `npm install` / `pip install`?
- **Excessive permissions:** Does a "color formatting" library need network access?

### Dependency Hygiene
- **Version pinning:** Are versions pinned or floating? (Floating = you auto-adopt compromised releases)
- **Lock file integrity:** Is the lock file committed and up to date?
- **Transitive depth:** How deep is the dependency tree? Each level adds risk.
- **Unused dependencies:** Dependencies that aren't imported but are installed = unnecessary attack surface

## Audit Protocol

```
1. Identify dependency files in the change set
2. Run automated vulnerability scanning (npm audit, pip-audit, etc.)
3. For new/changed dependencies:
   a. Check package registry for health signals
   b. Review install scripts
   c. Check for typosquatting indicators
   d. Assess maintenance status
4. Classify findings by severity
5. Recommend: update, replace, or accept with justification
```

## Output Format

```
SUPPLY CHAIN AUDIT — [timestamp]
Dependencies analyzed: [count]
New/changed: [count]

🔴 CRITICAL — lodash@4.17.20 has known prototype pollution (CVE-2021-23337)
   Fix: Upgrade to lodash@4.17.21+

🟡 WARNING — new-dep@1.0.0 has 1 maintainer, 12 weekly downloads, first published 30 days ago
   Risk: Low adoption, potential typosquat or abandoned package
   Action: Manual review recommended before adopting

🟡 WARNING — package-lock.json not committed
   Risk: Builds may use different dependency versions than tested
   Action: Commit lock file

🟢 [count] dependencies passed all checks
```
