# Unseen MCP servers (146): main 35c0155 against ws/lifecycle-shadow ad57eff

_Composed from two runs of `scripts/benchmark_skills.py --tools sigil --workers 2`, one per build._

```
Data Source: Real samples: the 146-server MCP holdout (evaluation_results/corpora/mcp_holdout146_manifest.json), not used for tuning.
Sample Size: 146 clean, each scanned once with main 35c0155 and once with
             the final lifecycle-shadow build ad57eff.
Limitations: Real samples, static analysis only. 'Clean' means published, not audited.
             One run per build on a 4-core machine (--workers 2); the per-file time
             budget makes large files load-sensitive (no run reported PROV-BUDGET-001).
             main 35c0155 predates the whole branch, so main-vs-branch differences
             are not all from the lifecycle rewrites.
```

| Build | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Malicious any | Clean blocked | Clean warned | Clean any | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| main | 0/0 | 0/0 | 0/0 | 80/146 | 135/146 | 144/146 | 0 |
| branch | 0/0 | 0/0 | 0/0 | 69/146 | 115/146 | 144/146 | 0 |

## Level changes (30)

| Sample | Label | main | branch | High/Critical rules removed | High/Critical rules added | Rules removed | Rules added | Budget hit |
|---|---|---|---|---|---|---|---|---|
| `corpora/mcp_holdout/au.com.ato-mcp__ato-mcp` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/com.githits__githits` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002 | INSTALL-009 | no |
| `corpora/mcp_holdout/com.shipstatic__mcp` | clean | HIGH | MEDIUM | - | - | - | - | no |
| `corpora/mcp_holdout/com.tokportal__mcp` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.171county__modwrench` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.AgentPhone-AI__agentphone` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.AlgoVaultFi__crypto-quant-signal-mcp` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002, INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.MatanYemini__bitbucket-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.akutishevsky__lunchmoney-mcp` | clean | HIGH | MEDIUM | - | - | - | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.b1ff__atlassian-dc-mcp-confluence` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.b1ff__atlassian-dc-mcp-jira` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.bgauryy__octocode-mcp` | clean | CRITICAL | MEDIUM | SUPPLY-011, SUPPLY-013, SUPPLY-016 | - | CODE-003, INSTALL-004, OBFUSC-CHAIN-009, SUPPLY-011, SUPPLY-013, SUPPLY-016 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.cablate__google-map` | clean | HIGH | LOW | INFER-004, INFER-005 | - | INFER-004, INFER-005, INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.discourse__mcp` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.domdomegg__airtable-mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.esaio__esa` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.fluttersdk__ai` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.giancarloerra__socraticode` | clean | HIGH | MEDIUM | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.grossiweb__toolroute` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.hypothesi__mcp-server-tauri` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.iseppo__e-arveldaja-mcp` | clean | HIGH | MEDIUM | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.karanb192__reddit-mcp-buddy` | clean | HIGH | MEDIUM | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.kitepon-rgb__aiterm-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.letoribo__mcp-graphql-enhanced` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_holdout/io.github.neat-technologies__neat` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.nteract__semiotic` | clean | HIGH | MEDIUM | - | - | CODE-003, INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.planetabhi__figma-mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.screenpipe__screenpipe-mcp` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002, CODE-003, INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.t8y2__dbx` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_holdout/io.github.yokingma__time-mcp` | clean | MEDIUM | LOW | - | - | - | - | no |

Samples whose rule set or finding count changed at the same level: 68.

The branch's prior build 34eaa0b blocked 66 and warned 114 of these 146; the fail-closed rewrites moved 4 servers up a level (0 down) to the figures above. No `package.json` outside `node_modules` in this corpus uses `directories.bin` or ships a `.npmrc` / `.yarnrc` / `.pnpmfile.cjs`, so those additions changed nothing here.
