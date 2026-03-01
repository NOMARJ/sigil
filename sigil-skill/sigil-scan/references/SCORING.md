# Risk Scoring Methodology

Sigil calculates risk scores using a weighted formula that accounts for both the severity of each finding and the phase in which it was detected.

## Score Formula

Each finding contributes to the aggregate score:

```
finding_score = severity_base_score * phase_weight
aggregate_score = sum(finding_score for each finding)
```

## Severity Base Scores

| Severity | Base Score |
|----------|-----------|
| Low | 1 |
| Medium | 2 |
| High | 3 |
| Critical | 5 |

## Phase Weights

| Phase | Weight | Rationale |
|-------|--------|-----------|
| Install Hooks | 10x | Code executes automatically during installation, before user review |
| Code Patterns | 5x | Dangerous runtime patterns (eval, exec, pickle) enable arbitrary code execution |
| Obfuscation | 5x | Obfuscated code is specifically designed to evade review |
| Network/Exfil | 3x | Outbound network access can exfiltrate data |
| Credentials | 2x | Credential access enables lateral movement |
| Provenance | 1-3x | Metadata-level signals (varies per finding) |
| Prompt Injection | 10x | Jailbreaks and prompt manipulation directly compromise agent behaviour |
| Skill Security | 5x | Malicious skill definitions can execute arbitrary code via agents |

## Verdict Thresholds

| Verdict | Score Range | Meaning |
|---------|-------------|---------|
| LOW RISK | 0-9 | No significant patterns detected |
| MEDIUM RISK | 10-24 | Suspicious patterns warrant manual review |
| HIGH RISK | 25-49 | Patterns strongly suggest elevated risk |
| CRITICAL RISK | 50+ | Very high concentration of dangerous patterns |

## Immediate Escalation Rule

Any finding with `Critical` severity in the `InstallHooks` phase triggers an immediate `CRITICAL RISK` verdict, regardless of the aggregate score. This is because install hooks execute before the user can review the code.

## Score Examples

**Example 1: Single eval() call**
- Phase: CodePatterns (5x), Severity: High (3) = score 15 → MEDIUM RISK

**Example 2: npm postinstall hook**
- Phase: InstallHooks (10x), Severity: Critical (5) = score 50 → CRITICAL RISK (also escalated by rule)

**Example 3: base64 decode + HTTP request**
- Obfuscation (5x) High (3) = 15
- NetworkExfil (3x) Medium (2) = 6
- Total: 21 → MEDIUM RISK

**Example 4: Full attack chain**
- InstallHooks Critical (5 * 10) = 50
- CodePatterns High (3 * 5) = 15
- NetworkExfil High (3 * 3) = 9
- Obfuscation High (3 * 5) = 15
- Total: 89 → CRITICAL RISK
