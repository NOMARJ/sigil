# Unseen MCP servers (146): main 35c0155 against ws/exfil-port 34eaa0b

_Composed from two runs of `scripts/benchmark_skills.py --tools sigil --workers 2`, one per build._

```
Data Source: Real samples: the 146-server MCP holdout
             (evaluation_results/corpora/mcp_holdout146_manifest.json), not used for tuning.
Sample Size: 146 clean, each scanned once with main 35c0155 and once with ws/exfil-port 34eaa0b.
Limitations: Real samples, static analysis only. 'Clean' means published, not audited.
             One run per build on a 4-core machine (--workers 2); the per-file time
             budget makes large files load-sensitive (PROV-BUDGET-001 is listed below).
             main 35c0155 predates the whole branch (the MCP false-positive pass, #169,
             #170 and this port), so main-vs-branch differences are not all this port's.
```

| Build | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Malicious any | Clean blocked | Clean warned | Clean any | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| main | 0/0 | 0/0 | 0/0 | 80/146 | 135/146 | 144/146 | 0 |
| branch | 0/0 | 0/0 | 0/0 | 66/146 | 114/146 | 144/146 | 0 |

Chains (samples each fires on): main {'DROPPER-CHAIN-001': 2}; branch none.

## Level changes (34)

| Sample | Label | main | branch | High/Critical rules removed | High/Critical rules added | Rules below the old level after (rescan) | Budget hit |
|---|---|---|---|---|---|---|---|
| `corpora/mcp_holdout/au.com.ato-mcp__ato-mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/com.githits__githits` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002 | no |
| `corpora/mcp_holdout/com.shipstatic__mcp` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/com.tokportal__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.171county__modwrench` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.AgentPhone-AI__agentphone` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.AlgoVaultFi__crypto-quant-signal-mcp` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002 | no |
| `corpora/mcp_holdout/io.github.MatanYemini__bitbucket-mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.StuMason__coolify` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.akutishevsky__lunchmoney-mcp` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.b1ff__atlassian-dc-mcp-confluence` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.b1ff__atlassian-dc-mcp-jira` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.bgauryy__octocode-mcp` | clean | CRITICAL | MEDIUM | SUPPLY-011, SUPPLY-013, SUPPLY-016 | - | SUPPLY-011, SUPPLY-013, SUPPLY-016 | no |
| `corpora/mcp_holdout/io.github.cablate__google-map` | clean | HIGH | LOW | INFER-004, INFER-005 | - | INFER-004, INFER-005 | no |
| `corpora/mcp_holdout/io.github.discourse__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.domdomegg__airtable-mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.esaio__esa` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.fluttersdk__ai` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.giancarloerra__socraticode` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.grossiweb__toolroute` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.hypothesi__mcp-server-tauri` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.iseppo__e-arveldaja-mcp` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.karanb192__reddit-mcp-buddy` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.kitepon-rgb__aiterm-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.letoribo__mcp-graphql-enhanced` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_holdout/io.github.neat-technologies__neat` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.nteract__semiotic` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.planetabhi__figma-mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.screenpipe__screenpipe-mcp` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002 | no |
| `corpora/mcp_holdout/io.github.shinpr__mcp-local-rag` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.t8y2__dbx` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_holdout/io.github.tosin2013__mcp-adr-analysis-server` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.yamadashy__repomix` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_holdout/io.github.yokingma__time-mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |

## Correlation-chain changes (2)

| Sample | Label | Chains main | Chains branch | Levels |
|---|---|---|---|---|
| `corpora/mcp_holdout/com.vibgrate__ai-context` | clean | DROPPER-CHAIN-001 | - | CRITICAL → CRITICAL |
| `corpora/mcp_holdout/dev.jasonpearson__auto-mobile` | clean | DROPPER-CHAIN-001 | - | CRITICAL → CRITICAL |

Samples whose rule set or finding count changed at the same level: 71 (listed in the JSON). Samples where either build hit the per-file time budget (PROV-BUDGET-001): 0.
