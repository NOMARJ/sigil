# Skill scanner head-to-head

_Generated 2026-09-24T10:13:58+00:00 by `scripts/benchmark_skills.py`._

```
Data Source: Real samples. Malicious: 
             Clean: mcp_clean
Sample Size: 0 malicious, 169 clean (per-corpus counts below)
Limitations: Static analysis only for every tool (SkillSpector --no-llm, Sigil offline
             phases). 'Clean' means published by a reputable vendor catalog, not audited;
             a vendor skill that legitimately shells out or reads credentials can be a
             correct finding, so the FP column is an upper bound on true false positives.
```

| Corpus | Samples |
|---|---:|
| clean:mcp_clean | 169 |

## Results

| Tool | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Clean blocked (FP) | Clean warned (FP) | Errors | Scan time |
|---|---:|---:|---:|---:|---:|---:|
| skillspector | 0/0 (n/a) | 0/0 (n/a) | 100/156 (64.1%) | 127/156 (81.4%) | 13 | 7877s |

## Clean samples blocked

- skillspector: `corpora/mcp_clean/ai.elfa__mcp` — CRITICAL ['EA2', 'P2', 'PE3', 'RP1', 'SC1', 'SC4', 'YR4'] (High/Critical: ['P2', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/ai.reka__mcp` — CRITICAL ['EA4', 'PE3', 'RP1', 'SC4'] (High/Critical: ['PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/aws.api.us-east-1.ecs-mcp__server` — CRITICAL ['AST7', 'EA4', 'P9', 'PE3', 'RP1', 'SC4', 'TM3'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/aws.api.us-east-1.eks-mcp__server` — CRITICAL ['AST7', 'EA4', 'P9', 'PE3', 'RP1', 'SC4', 'TM3'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/com.aave__mcp` — CRITICAL ['AR2', 'AS1', 'AS2', 'E1', 'EA1', 'EA2', 'SC1', 'SC4'] (High/Critical: ['AR2', 'AS1', 'AS2'])
- skillspector: `corpora/mcp_clean/com.adbutler__mcp-server` — HIGH ['E1', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/com.allstacks__allstacks-mcp` — CRITICAL ['E1', 'PE3', 'SC4', 'TM1'] (High/Critical: ['PE3', 'TM1'])
- skillspector: `corpora/mcp_clean/com.altmetric.mcp__altmetric-mcp` — HIGH ['PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/com.appfigures__mcp` — CRITICAL ['AE4', 'EA2', 'MP2', 'P2', 'P9', 'PE1', 'PE3', 'RA2'] (High/Critical: ['P2', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/com.audioeye__testing-sdk-mcp` — CRITICAL ['AR2', 'AS1', 'EA2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC3'] (High/Critical: ['AR2', 'AS1', 'PE3', 'SC3', 'YR4'])
- skillspector: `corpora/mcp_clean/com.auth0__mcp` — CRITICAL ['EA1', 'EA2', 'P1', 'P6', 'P9', 'PE1', 'PE2', 'PE3'] (High/Critical: ['P1', 'P6', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/com.automox__automox-mcp` — CRITICAL ['AST7', 'EA2', 'MP2', 'OH3', 'P1', 'PE2', 'PE3', 'RP1'] (High/Critical: ['P1', 'PE3', 'SSRF1', 'TM1', 'YR4'])
- skillspector: `corpora/mcp_clean/com.blackduck__mcp-server` — CRITICAL ['EA2', 'EA3', 'MP2', 'P9', 'PE3', 'RP1', 'SC4'] (High/Critical: ['PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/com.blindpay__mcp` — CRITICAL ['AS1', 'E1', 'MP2', 'PE2', 'PE3', 'RA2', 'RP1', 'SC1'] (High/Critical: ['AS1', 'PE3'])
- skillspector: `corpora/mcp_clean/com.browser-use__browser-use` — CRITICAL ['AE4', 'AR1', 'AR2', 'AS3', 'AST1', 'AST4', 'AST7', 'E1'] (High/Critical: ['AR1', 'AR2', 'AST1', 'E2', 'MP3', 'P3', 'PE3', 'RA1', 'SC2', 'SC4'])
- skillspector: `corpora/mcp_clean/com.clicksend__clicksend-mcp-server` — CRITICAL ['P3', 'PE2', 'SC1', 'SC4', 'SC5', 'YR4'] (High/Critical: ['P3', 'SC4', 'YR4'])
- skillspector: `corpora/mcp_clean/com.docfork__docfork-mcp` — CRITICAL ['E1', 'PE2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/com.easyship__mcp` — CRITICAL ['AS1', 'AST7', 'E1', 'PE3', 'RA2', 'RP1', 'SC4', 'TM1'] (High/Critical: ['AS1', 'PE3', 'SC4', 'TM1', 'YR4'])
- skillspector: `corpora/mcp_clean/com.eclipsesource__review-guard` — HIGH ['AS1', 'EA2', 'P9', 'PE2', 'PE3', 'RA2', 'SC1', 'SC4'] (High/Critical: ['AS1', 'PE3'])
- skillspector: `corpora/mcp_clean/com.growsurf__growsurf` — CRITICAL ['AS1', 'AS2', 'E1', 'EA2', 'PE3', 'RA2', 'RP1', 'SC1'] (High/Critical: ['AS1', 'AS2', 'PE3'])
- skillspector: `corpora/mcp_clean/com.hasdata__duckduckgo` — HIGH ['AS1', 'AS2', 'SC1', 'SC4'] (High/Critical: ['AS1', 'AS2'])
- skillspector: `corpora/mcp_clean/com.keboola__mcp` — CRITICAL ['AST7', 'E1', 'EA2', 'EA3', 'PE2', 'PE3', 'RA1', 'RA2'] (High/Critical: ['PE3', 'RA1', 'TM1'])
- skillspector: `corpora/mcp_clean/com.letta__memory-mcp` — HIGH ['P2', 'P4', 'PE2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['P2'])
- skillspector: `corpora/mcp_clean/com.microsoft__azure` — HIGH ['AR1', 'AS1', 'RP1'] (High/Critical: ['AR1', 'AS1'])
- skillspector: `corpora/mcp_clean/com.microsoft__powerbi-modeling-mcp` — HIGH ['AR1', 'EA3', 'RP1'] (High/Critical: ['AR1'])
- skillspector: `corpora/mcp_clean/com.mux__mcp` — CRITICAL ['MP2', 'PE3', 'SC1', 'SC4', 'YR4'] (High/Critical: ['PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/com.opensolr__opensolr-mcp` — HIGH ['AR2', 'E1', 'RP1', 'SC4', 'TM3'] (High/Critical: ['AR2'])
- skillspector: `corpora/mcp_clean/com.opsmill__infrahub-mcp` — CRITICAL ['AST7', 'EA4', 'P2', 'PE3', 'SC1', 'SC4', 'SC9', 'TM1'] (High/Critical: ['P2', 'PE3', 'SC4', 'SC9', 'TM1'])
- skillspector: `corpora/mcp_clean/com.proabono__mcp-installation` — HIGH ['AS2', 'EA2', 'PE1', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS2'])
- skillspector: `corpora/mcp_clean/com.pulsemcp__appsignal` — HIGH ['EA2', 'PE3', 'RA2', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/com.pulsemcp__fly-io` — CRITICAL ['MP3', 'P9', 'PE3', 'RA2', 'SC1', 'SC4'] (High/Critical: ['MP3', 'PE3'])
- skillspector: `corpora/mcp_clean/com.rootly__mcp-server` — CRITICAL ['AR2', 'AS3', 'AST7', 'E1', 'E2', 'EA2', 'P1', 'PE3'] (High/Critical: ['AR2', 'E2', 'P1', 'PE3', 'SC4', 'SC9', 'TM1', 'TM2', 'YR1', 'YR4'])
- skillspector: `corpora/mcp_clean/com.smartbear__smartbear-mcp` — CRITICAL ['AR2', 'E1', 'EA2', 'OH3', 'P4', 'PE3', 'RA2', 'SC1'] (High/Critical: ['AR2', 'PE3', 'TM1'])
- skillspector: `corpora/mcp_clean/com.stackhawk__stackhawk` — CRITICAL ['P6', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['P6', 'PE3'])
- skillspector: `corpora/mcp_clean/com.streamkap__tools` — CRITICAL ['EA2', 'PE2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4', 'SSRF1'] (High/Critical: ['PE3', 'SSRF1'])
- skillspector: `corpora/mcp_clean/com.supabase__mcp` — CRITICAL ['EA1', 'EA2', 'MP2', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/com.tracklution__server-side-tracking` — CRITICAL ['AS1', 'AS2', 'E1', 'P2', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'AS2', 'P2'])
- skillspector: `corpora/mcp_clean/com.zeroheight__zeroheight` — HIGH ['E2', 'PE2', 'PE3', 'SC1', 'SC4'] (High/Critical: ['E2', 'PE3'])
- skillspector: `corpora/mcp_clean/dev.openfeature__mcp` — HIGH ['AS1', 'P2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'P2'])
- skillspector: `corpora/mcp_clean/dev.rivet__mcp` — CRITICAL ['AE4', 'MP2', 'P2', 'PE1', 'PE3', 'SC1', 'SC3', 'SC4'] (High/Critical: ['P2', 'PE3', 'SC3', 'TM1', 'YR4'])
- skillspector: `corpora/mcp_clean/dev.tinify__mcp` — CRITICAL ['AS1', 'E1', 'EA2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'PE3'])
- skillspector: `corpora/mcp_clean/io.aiven__mcp` — CRITICAL ['E1', 'E2', 'EA2', 'MP2', 'OH3', 'P6', 'PE1', 'PE3'] (High/Critical: ['E2', 'P6', 'PE3', 'TM1', 'TM2', 'YR4'])
- skillspector: `corpora/mcp_clean/io.carbone__carbone-mcp` — CRITICAL ['E2', 'EA2', 'EA3', 'PE3', 'RP1', 'SC4', 'SSRF1', 'TM1'] (High/Critical: ['E2', 'PE3', 'SSRF1', 'TM1'])
- skillspector: `corpora/mcp_clean/io.form__formio-mcp` — CRITICAL ['E1', 'EA2', 'PE1', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.form__formio-uag` — CRITICAL ['EA3', 'EA4', 'P6', 'PE3', 'RP1', 'SC1', 'SC4', 'TM3'] (High/Critical: ['P6', 'PE3'])
- skillspector: `corpora/mcp_clean/io.frase__mcp-server` — CRITICAL ['EA1', 'EA2', 'P6', 'PE3', 'RP1', 'SC1', 'SC4', 'YR4'] (High/Critical: ['P6', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/io.fusionauth__mcp-api` — HIGH ['MP2', 'PE1', 'PE2', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.gainium__gainium-mcp` — HIGH ['PE3', 'SC1', 'SC4', 'TM1'] (High/Critical: ['PE3', 'TM1'])
- skillspector: `corpora/mcp_clean/io.getunleash__unleash-mcp` — CRITICAL ['P6', 'PE3', 'RA1', 'RP1', 'SC1', 'SC4', 'TM1'] (High/Critical: ['P6', 'PE3', 'RA1', 'TM1'])
- skillspector: `corpora/mcp_clean/io.github.Automattic__simplenote-mcp` — HIGH ['AS1', 'E1', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1'])
- skillspector: `corpora/mcp_clean/io.github.Azure__containerization-assist` — CRITICAL ['AR2', 'E1', 'E3', 'EA1', 'EA2', 'OH3', 'P6', 'PE2'] (High/Critical: ['AR2', 'P6', 'PE3', 'PE4', 'SC9', 'TM1', 'TM2', 'TM4', 'YR1'])
- skillspector: `corpora/mcp_clean/io.github.ClickHouse__mcp-clickhouse` — CRITICAL ['AST3', 'AST4', 'AST7', 'E2', 'EA4', 'P9', 'PE3', 'RP1'] (High/Critical: ['E2', 'PE3', 'SC4', 'SC6'])
- skillspector: `corpora/mcp_clean/io.github.CrowdStrike__falcon-mcp` — CRITICAL ['AS2', 'AST7', 'P6', 'PE3', 'RP1', 'SC4', 'YR1', 'YR4'] (High/Critical: ['AS2', 'P6', 'PE3', 'YR1', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.GoogleCloudPlatform__gemini-cloud-assist-mcp` — HIGH ['AS1', 'EA3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1'])
- skillspector: `corpora/mcp_clean/io.github.PrefectHQ__prefect-mcp-server` — CRITICAL ['AS1', 'AST4', 'E1', 'E2', 'PE2', 'PE3', 'RA1', 'RA2'] (High/Critical: ['AS1', 'E2', 'PE3', 'RA1', 'SC4', 'SC6'])
- skillspector: `corpora/mcp_clean/io.github.Snowflake-Labs__mcp` — CRITICAL ['AS1', 'AST7', 'E1', 'PE2', 'PE3', 'RP1', 'SC4', 'TM2'] (High/Critical: ['AS1', 'PE3', 'SC4', 'TM2'])
- skillspector: `corpora/mcp_clean/io.github.ZenRows__zenrows-mcp` — HIGH ['E1', 'MP2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.github.appwrite__mcp-for-api` — CRITICAL ['AS2', 'EA3', 'PE3', 'RP1', 'SC2', 'SC4', 'TM2'] (High/Critical: ['AS2', 'PE3', 'SC4', 'TM2'])
- skillspector: `corpora/mcp_clean/io.github.aws__aws-mcp` — CRITICAL ['AST7', 'EA4', 'P9', 'PE3', 'RP1', 'SC4', 'TM3'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.github.aws__mcp-proxy-for-aws` — CRITICAL ['AST7', 'EA4', 'P9', 'PE3', 'RP1', 'SC4', 'TM3'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.github.awslabs__mcp-server-for-oscal` — CRITICAL ['AST3', 'AST4', 'AST7', 'E1', 'E2', 'E4', 'EA1', 'EA2'] (High/Critical: ['E2', 'E4', 'P2', 'PE3', 'RA1', 'SC4', 'SC6', 'TM1', 'TM2', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.brightdata__brightdata-mcp` — CRITICAL ['AS1', 'E1', 'EA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'SC4'])
- skillspector: `corpora/mcp_clean/io.github.browserstack__mcp-server` — CRITICAL ['E1', 'EA2', 'EA3', 'P6', 'PE2', 'RA2', 'RP1', 'SC1'] (High/Critical: ['P6'])
- skillspector: `corpora/mcp_clean/io.github.bytedance__mcp-server-filesystem` — CRITICAL ['AR2', 'RA1', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AR2', 'RA1'])
- skillspector: `corpora/mcp_clean/io.github.comet-ml__opik-mcp` — CRITICAL ['E2', 'E4', 'P1', 'P3', 'PE3', 'RA2', 'RP1', 'SC1'] (High/Critical: ['E2', 'E4', 'P1', 'P3', 'PE3'])
- skillspector: `corpora/mcp_clean/io.github.containers__kubernetes-mcp-server` — CRITICAL ['MP2', 'P2', 'P9', 'PE3', 'RP1'] (High/Critical: ['P2', 'PE3'])
- skillspector: `corpora/mcp_clean/io.github.couchbase__mcp-server-couchbase` — CRITICAL ['AST4', 'E1', 'E2', 'EA1', 'EA2', 'MP3', 'P2', 'P9'] (High/Critical: ['E2', 'MP3', 'P2', 'PE3', 'PE5', 'SC2', 'SC4', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.dynatrace-oss__dynatrace-managed-mcp` — HIGH ['AS1', 'E1', 'P9', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'PE3'])
- skillspector: `corpora/mcp_clean/io.github.firebase__firebase-mcp` — CRITICAL ['EA2', 'EA4', 'MP3', 'OH1', 'P2', 'P3', 'P6', 'P9'] (High/Critical: ['MP3', 'OH1', 'P2', 'P3', 'P6', 'PE3', 'SC2', 'SC6', 'TM2'])
- skillspector: `corpora/mcp_clean/io.github.firecrawl__firecrawl-mcp-server` — CRITICAL ['EA2', 'MP2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC2', 'SC4'] (High/Critical: ['PE3', 'SC2'])
- skillspector: `corpora/mcp_clean/io.github.getsentry__sentry-mcp` — CRITICAL ['AS2', 'E1', 'EA2', 'EA3', 'MP2', 'P6', 'PE3', 'RP1'] (High/Critical: ['AS2', 'P6', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.growthbook__growthbook-mcp` — CRITICAL ['AR2', 'E1', 'EA2', 'EA4', 'MP1', 'P9', 'PE2', 'PE3'] (High/Critical: ['AR2', 'PE3', 'RA1', 'TM1'])
- skillspector: `corpora/mcp_clean/io.github.localstack__localstack-mcp-server` — CRITICAL ['E1', 'EA2', 'MP2', 'P9', 'PE3', 'PE4', 'RP1', 'SC1'] (High/Critical: ['PE3', 'PE4', 'TM1'])
- skillspector: `corpora/mcp_clean/io.github.mapbox__mcp-devkit-server` — CRITICAL ['AS3', 'E1', 'EA2', 'MP2', 'P6', 'PE3', 'RA2', 'RP1'] (High/Critical: ['P6', 'PE3'])
- skillspector: `corpora/mcp_clean/io.github.mapbox__mcp-docs-server` — HIGH ['MP2', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.github.mapbox__mcp-server` — CRITICAL ['E1', 'MP2', 'P6', 'PE3', 'RP1', 'SC1', 'SC4', 'YR4'] (High/Critical: ['P6', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.microsoft__playwright-mcp` — CRITICAL ['AS1', 'EA1', 'P2', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'P2'])
- skillspector: `corpora/mcp_clean/io.github.motherduckdb__mcp-server-motherduck` — CRITICAL ['AS1', 'AST4', 'E2', 'OH3', 'PE3', 'RA2', 'RP1', 'SC4'] (High/Critical: ['AS1', 'E2', 'PE3', 'SC4', 'TM1'])
- skillspector: `corpora/mcp_clean/io.github.mozilla__firefox-devtools-mcp` — CRITICAL ['AS1', 'EA1', 'EA3', 'MP2', 'OH3', 'P6', 'PE3', 'RA2'] (High/Critical: ['AS1', 'P6', 'PE3', 'TM4', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.neo4j-contrib__gds-agent` — CRITICAL ['AST4', 'AST7', 'E2', 'OH3', 'PE3', 'RA2', 'SC4'] (High/Critical: ['E2', 'PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-aura-manager` — CRITICAL ['E1', 'EA2', 'PE3', 'RP1', 'SC4', 'SSRF2', 'TM3'] (High/Critical: ['PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-cypher` — CRITICAL ['AR2', 'E2', 'EA2', 'EA4', 'MP2', 'OH3', 'PE3', 'RP1'] (High/Critical: ['AR2', 'E2', 'PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-data-modeling` — CRITICAL ['EA2', 'P6', 'PE3', 'RP1', 'SC4', 'SSRF2', 'TM1'] (High/Critical: ['P6', 'PE3', 'SC4', 'TM1'])
- skillspector: `corpora/mcp_clean/io.github.neo4j-contrib__mcp-neo4j-memory` — CRITICAL ['AR2', 'PE3', 'RP1', 'SC4', 'SSRF2', 'TM3'] (High/Critical: ['AR2', 'PE3', 'SC4'])
- skillspector: `corpora/mcp_clean/io.github.neo4j-labs__neo4j-mcp-canary` — CRITICAL ['AST4', 'E1', 'EA3', 'P9', 'RP1', 'SC9', 'YR4'] (High/Critical: ['SC9', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.paypal__paypal-mcp-server` — HIGH ['E1', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.github.questdb__mcp-server-questdb` — HIGH ['AS1', 'EA2', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1'])
- skillspector: `corpora/mcp_clean/io.github.saucelabs__sauce-api-mcp` — CRITICAL ['AS1', 'E1', 'EA2', 'EA3', 'P2', 'P6', 'P9', 'PE3'] (High/Critical: ['AS1', 'P2', 'P6', 'PE3', 'TT3'])
- skillspector: `corpora/mcp_clean/io.github.snyk__saw-mcp` — CRITICAL ['AS3', 'AST7', 'E1', 'PE3', 'RP1', 'SC4'] (High/Critical: ['PE3'])
- skillspector: `corpora/mcp_clean/io.github.tavily-ai__tavily-mcp` — CRITICAL ['E1', 'EA3', 'PE2', 'PE3', 'RP1', 'SC1', 'SC4', 'TM1'] (High/Critical: ['PE3', 'SC4', 'TM1', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.team-telnyx__telnyx` — CRITICAL ['AS2', 'E1', 'E2', 'EA2', 'EA3', 'EA4', 'MP2', 'OH1'] (High/Critical: ['AS2', 'E2', 'OH1', 'P2', 'P3', 'PE3'])
- skillspector: `corpora/mcp_clean/io.github.upstash__context7` — CRITICAL ['AE4', 'AS1', 'EA2', 'PE2', 'PE3', 'RA2', 'RP1', 'SC1'] (High/Critical: ['AS1', 'PE3', 'TM1', 'TM2'])
- skillspector: `corpora/mcp_clean/io.github.upstash__mcp-server` — CRITICAL ['AS1', 'AS2', 'MP2', 'OH3', 'P1', 'P3', 'PE3', 'RA2'] (High/Critical: ['AS1', 'AS2', 'P1', 'P3', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/io.github.upstash__redis-mcp` — HIGH ['AS1', 'P9', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'PE3'])
- skillspector: `corpora/mcp_clean/io.github.vercel__next-devtools-mcp` — CRITICAL ['AR2', 'AR3', 'E1', 'P6', 'PE3', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AR2', 'AR3', 'P6', 'PE3', 'SC4', 'TM1'])
- skillspector: `corpora/mcp_clean/io.mailtrap__mcp` — CRITICAL ['P3', 'RA2', 'RP1', 'SC1', 'SC4', 'YR4'] (High/Critical: ['P3', 'YR4'])
- skillspector: `corpora/mcp_clean/io.oxylabs__oxylabs-mcp` — CRITICAL ['P9', 'PE2', 'PE3', 'RP1', 'SC2', 'SC4', 'TM2'] (High/Critical: ['PE3', 'SC4', 'TM2'])
- skillspector: `corpora/mcp_clean/io.qase__mcp-server` — CRITICAL ['AS1', 'E1', 'EA2', 'PE3', 'RA2', 'RP1', 'SC1', 'SC4'] (High/Critical: ['AS1', 'PE3', 'TM1'])
- skillspector: `corpora/mcp_clean/io.scrapfly.mcp__mcp` — CRITICAL ['AS1', 'EA4', 'P6', 'PE3', 'RA2', 'YR4'] (High/Critical: ['AS1', 'P6', 'PE3', 'YR4'])
- skillspector: `corpora/mcp_clean/io.slingdata__sling-cli` — CRITICAL ['AST4', 'E1', 'E2', 'EA2', 'RA2', 'TM1', 'TT3'] (High/Critical: ['E2', 'TM1', 'TT3'])
