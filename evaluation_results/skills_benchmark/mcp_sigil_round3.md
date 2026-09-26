# Clean MCP servers (169): main 35c0155 against ws/lifecycle-shadow ad57eff

_Composed from two runs of `scripts/benchmark_skills.py --tools sigil --workers 2`, one per build._

```
Data Source: Real samples: 169 clean MCP servers (evaluation_results/corpora/mcp_clean_manifest.json).
Sample Size: 169 clean, each scanned once with main 35c0155 and once with
             the final lifecycle-shadow build ad57eff.
Limitations: Real samples, static analysis only. 'Clean' means published, not audited.
             One run per build on a 4-core machine (--workers 2); the per-file time
             budget makes large files load-sensitive (no run reported PROV-BUDGET-001).
             main 35c0155 predates the whole branch, so main-vs-branch differences
             are not all from the lifecycle rewrites.
```

| Build | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Malicious any | Clean blocked | Clean warned | Clean any | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| main | 0/0 | 0/0 | 0/0 | 39/169 | 125/169 | 163/169 | 0 |
| branch | 0/0 | 0/0 | 0/0 | 28/169 | 89/169 | 163/169 | 0 |

## Level changes (46)

| Sample | Label | main | branch | High/Critical rules removed | High/Critical rules added | Rules removed | Rules added | Budget hit |
|---|---|---|---|---|---|---|---|---|
| `corpora/mcp_clean/ai.dimensions__analytics-mcp` | clean | CRITICAL | MEDIUM | - | - | - | - | no |
| `corpora/mcp_clean/ai.elfa__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/ai.reka__mcp` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | - | no |
| `corpora/mcp_clean/ai.wavespeed__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.aave__mcp` | clean | HIGH | MEDIUM | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.apideck__mcp` | clean | HIGH | MEDIUM | CRED-007, CRED-008, SUPPLY-008 | - | CRED-007, CRED-008, INSTALL-004, SUPPLY-008 | INSTALL-009 | no |
| `corpora/mcp_clean/com.audioeye__testing-sdk-mcp` | clean | HIGH | MEDIUM | CODE-009 | - | - | - | no |
| `corpora/mcp_clean/com.blindpay__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.cosmicjs__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.eclipsesource__review-guard` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_clean/com.eztexting__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.geekflare__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.growsurf__growsurf` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.ismalicious__mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.letta__memory-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.pdfgate__mcp-server` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_clean/com.proabono__mcp-installation` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.pulsemcp__appsignal` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.pulsemcp__dynamodb` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.pulsemcp__fly-io` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.pulsemcp__gcs` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.pulsemcp__remote-filesystem` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.synder__gl-importer-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.tracklution__server-side-tracking` | clean | HIGH | LOW | CRED-011 | - | CRED-011 | - | no |
| `corpora/mcp_clean/com.vaiz__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/com.zype.mcp__server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/dev.edgegap__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/dev.openfeature__mcp` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_clean/io.aiven__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.frase__mcp-server` | clean | HIGH | MEDIUM | - | - | CODE-003, INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.gainium__gainium-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.github.ChromeDevTools__chrome-devtools-mcp` | clean | CRITICAL | MEDIUM | CODE-009, OBFUSC-CHAIN-011 | - | CODE-003, OBFUSC-CHAIN-011 | - | no |
| `corpora/mcp_clean/io.github.CrowdStrike__falcon-mcp` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | - | no |
| `corpora/mcp_clean/io.github.Decodo__mcp-server` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_clean/io.github.PrefectHQ__prefect-mcp-server` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | - | no |
| `corpora/mcp_clean/io.github.cloudinary__asset-management-mcp` | clean | HIGH | MEDIUM | SUPPLY-008 | - | INSTALL-004, SUPPLY-008 | INSTALL-009 | no |
| `corpora/mcp_clean/io.github.firebase__firebase-mcp` | clean | HIGH | MEDIUM | CRED-008 | - | CODE-003, CRED-008 | - | no |
| `corpora/mcp_clean/io.github.mapbox__mcp-docs-server` | clean | MEDIUM | LOW | - | - | - | - | no |
| `corpora/mcp_clean/io.github.mozilla__firefox-devtools-mcp` | clean | HIGH | MEDIUM | - | - | CODE-003, INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-aura-manager` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | - | no |
| `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-cypher` | clean | MEDIUM | LOW | CRED-008 | - | CRED-008 | - | no |
| `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-memory` | clean | MEDIUM | LOW | CRED-008 | - | CRED-008 | - | no |
| `corpora/mcp_clean/io.github.questdb__mcp-server-questdb` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.github.timescale__pg-aiguide` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.prospeo__prospeo-mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | INSTALL-009 | no |
| `corpora/mcp_clean/io.qase__mcp-server` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002 | - | no |

Samples whose rule set or finding count changed at the same level: 35.

The branch's prior build 34eaa0b (the code of #172's head 1ae5cbe, before the lifecycle rewrites were made to fail closed) blocked 24 and warned 76 of these 169. Making the rewrites fail closed on runners, dependencies, `directories.bin` and install-config side channels moved 16 servers up a level (0 down) to the figures above; every one of them installs, or its script's runner could be shadowed by, more than the tools the script names.
