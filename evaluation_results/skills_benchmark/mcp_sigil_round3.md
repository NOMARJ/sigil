# Clean MCP servers (169): main 35c0155 against ws/exfil-port 34eaa0b

_Composed from two runs of `scripts/benchmark_skills.py --tools sigil --workers 2`, one per build._

```
Data Source: Real samples: 169 clean MCP servers (evaluation_results/corpora/mcp_clean_manifest.json).
Sample Size: 169 clean, each scanned once with main 35c0155, once with e45efc5 and once with
             ws/exfil-port 34eaa0b.
Limitations: Real samples, static analysis only. 'Clean' means published, not audited.
             One run per build on a 4-core machine (--workers 2); the per-file time
             budget makes large files load-sensitive (PROV-BUDGET-001 is listed below).
             main 35c0155 predates the whole branch (the MCP false-positive pass, #169,
             #170 and this port), so main-vs-branch differences are not all this port's.
             In-sample: the MCP false-positive pass was tuned on this corpus.
```

| Build | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Malicious any | Clean blocked | Clean warned | Clean any | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| main | 0/0 | 0/0 | 0/0 | 39/169 | 125/169 | 163/169 | 0 |
| branch | 0/0 | 0/0 | 0/0 | 24/169 | 76/169 | 163/169 | 0 |

Chains (samples each fires on): main none; branch none.

## Level changes (62)

| Sample | Label | main | branch | High/Critical rules removed | High/Critical rules added | Rules below the old level after (rescan) | Budget hit |
|---|---|---|---|---|---|---|---|
| `corpora/mcp_clean/ai.dimensions__analytics-mcp` | clean | CRITICAL | MEDIUM | - | - | - | no |
| `corpora/mcp_clean/ai.elfa__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/ai.perplexity__mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/ai.reka__mcp` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | no |
| `corpora/mcp_clean/ai.wavespeed__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.aave__mcp` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_clean/com.apideck__mcp` | clean | HIGH | MEDIUM | CRED-007, CRED-008, SUPPLY-008 | - | CRED-007, CRED-008, SUPPLY-008 | no |
| `corpora/mcp_clean/com.audioeye__testing-sdk-mcp` | clean | HIGH | MEDIUM | CODE-009 | - | CODE-009 | no |
| `corpora/mcp_clean/com.blackduck__mcp-server` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.blindpay__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.cosmicjs__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.eclipsesource__review-guard` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_clean/com.eztexting__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.geekflare__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.growsurf__growsurf` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.ismalicious__mcp-server` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.kudosity__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.letta__memory-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.microsoft__azure` | clean | CRITICAL | MEDIUM | CODE-014, INSTALL-003, SKILL-006 | - | CODE-014, INSTALL-003, SKILL-006 | no |
| `corpora/mcp_clean/com.microsoft__microsoft-fabric` | clean | CRITICAL | MEDIUM | CODE-014, INSTALL-003, SKILL-006 | - | CODE-014, INSTALL-003, SKILL-006 | no |
| `corpora/mcp_clean/com.microsoft__template-server-name` | clean | CRITICAL | MEDIUM | CODE-014, INSTALL-003, SKILL-006 | - | CODE-014, INSTALL-003, SKILL-006 | no |
| `corpora/mcp_clean/com.pdfgate__mcp-server` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_clean/com.postman__postman-mcp-server` | clean | CRITICAL | LOW | INSTALL-003, SKILL-006 | - | INSTALL-003, SKILL-006 | no |
| `corpora/mcp_clean/com.proabono__mcp-installation` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.pulsemcp__appsignal` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.pulsemcp__dynamodb` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.pulsemcp__fly-io` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.pulsemcp__gcs` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.pulsemcp__remote-filesystem` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/com.synder__gl-importer-mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.tracklution__server-side-tracking` | clean | HIGH | LOW | CRED-011 | - | CRED-011 | no |
| `corpora/mcp_clean/com.vaiz__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/com.zype.mcp__server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/dev.edgegap__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/dev.openfeature__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_clean/io.aiven__mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/io.capawesome__capacitor-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.capawesome__ionic-framework-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.capawesome__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.frase__mcp-server` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_clean/io.gainium__gainium-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.github.Automattic__simplenote-mcp` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/io.github.ChromeDevTools__chrome-devtools-mcp` | clean | CRITICAL | MEDIUM | CODE-009, OBFUSC-CHAIN-011 | - | CODE-009, OBFUSC-CHAIN-011 | no |
| `corpora/mcp_clean/io.github.CrowdStrike__falcon-mcp` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | no |
| `corpora/mcp_clean/io.github.Decodo__mcp-server` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_clean/io.github.GoogleCloudPlatform__gemini-cloud-assist-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.github.PrefectHQ__prefect-mcp-server` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | no |
| `corpora/mcp_clean/io.github.ZenRows__zenrows-mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.github.cloudinary__asset-management-mcp` | clean | HIGH | MEDIUM | SUPPLY-008 | - | SUPPLY-008 | no |
| `corpora/mcp_clean/io.github.firebase__firebase-mcp` | clean | HIGH | MEDIUM | CRED-008 | - | CRED-008 | no |
| `corpora/mcp_clean/io.github.mapbox__mcp-docs-server` | clean | MEDIUM | LOW | - | - | HYGIENE-001 | no |
| `corpora/mcp_clean/io.github.mozilla__firefox-devtools-mcp` | clean | HIGH | MEDIUM | - | - | - | no |
| `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-aura-manager` | clean | MEDIUM | LOW | CRED-007 | - | CRED-007 | no |
| `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-cypher` | clean | MEDIUM | LOW | CRED-008 | - | CRED-008 | no |
| `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-memory` | clean | MEDIUM | LOW | CRED-008 | - | CRED-008 | no |
| `corpora/mcp_clean/io.github.perplexityai__mcp-server` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.github.questdb__mcp-server-questdb` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.github.timescale__pg-aiguide` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/io.github.timescale__tiger-skills` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/io.mailtrap__mcp` | clean | MEDIUM | LOW | - | - | INSTALL-004 | no |
| `corpora/mcp_clean/io.prospeo__prospeo-mcp-server` | clean | MEDIUM | LOW | - | - | HYGIENE-001, INSTALL-004 | no |
| `corpora/mcp_clean/io.qase__mcp-server` | clean | HIGH | MEDIUM | CODE-002 | - | CODE-002 | no |

## Correlation-chain changes (0)

None.

Samples whose rule set or finding count changed at the same level: 27 (listed in the JSON). Samples where either build hit the per-file time budget (PROV-BUDGET-001): 0.

## The port's own effect: e45efc5 against 34eaa0b

e45efc5 (the branch before the port: the MCP false-positive pass, #169 and #170) blocks 24/169, warns 76/169 and flags 163/169; level changes against 34eaa0b: 0; correlation-chain changes: 0; other rule-set or finding-count changes: 0. So every level change above comes from the rest of the branch, not from the port.
