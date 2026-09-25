# Insecure transport rules (TLS)

The `insecure_transport.json` pack (`cli/packs/core/v1/`, meta id
`sigil-core-insecure-transport`) reports code, configuration and instructions
that turn off TLS certificate verification. With verification off the
connection is still encrypted, but to whoever answered: anyone on the network
path (a hostile Wi-Fi network, a compromised proxy, a cloud neighbour) can
present their own certificate, read the traffic and change the response. It is
the class Bandit B501/B323, gosec G402 and semgrep's insecure-transport rules
cover, and one of the gaps in the
[SkillSpector comparison](../comparison/skillspector.md).

This is configuration hygiene rather than an attack shape, and the severities
say so:

- Each line rule is **Medium** (weight 2): on its own it makes a package
  MEDIUM RISK (warn, review before approving) and never HIGH. The one
  exception is TLS-003, which is a **Low** observation.
- **TLS-CHAIN-001** is **High**: a credential, read from the environment or
  written into the code, is used in the request or connection whose
  verification is off. Whoever intercepts that connection gets the key.

## Rules

| Rule | Severity | Catches |
|---|---|---|
| `TLS-001` | Medium | Python HTTP clients: `verify=False` on requests / httpx calls and clients, `session.verify = False`, `{"verify": False}`, aiohttp `ssl=False` on a connector or request |
| `TLS-002` | Medium | Python `ssl`: `verify_mode = ssl.CERT_NONE`, `cert_reqs=CERT_NONE`, `check_hostname = False`, `ssl._create_unverified_context` |
| `TLS-003` | Low | urllib3's `InsecureRequestWarning` silenced (`disable_warnings(...)`, `filterwarnings`/`simplefilter`): the warning `verify=False` triggers. An observation that points at the TLS-001 it hides |
| `TLS-004` | Medium | Node.js: `rejectUnauthorized: false` (https.Agent, tls.connect, WebSocket, undici `connect`), request's `strictSSL: false`, a no-op `checkServerIdentity` |
| `TLS-005` | Medium | Verification off for the whole process: `NODE_TLS_REJECT_UNAUTHORIZED=0` and `PYTHONHTTPSVERIFY=0` set in code (`process.env`, `os.environ`), a shell, a Dockerfile, a `.env` file, an MCP server's `env` block or a docker `-e` argument; an empty `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` in Python |
| `TLS-006` | Medium | Other languages: Go `InsecureSkipVerify: true`, Rust reqwest `danger_accept_invalid_certs(true)`, Ruby `VERIFY_NONE` and Faraday `ssl: { verify: false }`, PHP / C / pycurl `CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST` 0 and Guzzle `'verify' => false`, .NET `DangerousAcceptAnyServerCertificateValidator` or a validation callback returning `true`, Apache HttpClient `NoopHostnameVerifier` / `TrustAllStrategy` and hostname-verifier lambdas returning `true` |
| `TLS-007` | Medium | Commands: `curl -k` / `--insecure` (also combined flags such as `-sSLk`, and `["curl", "-k", ...]` argument lists), `wget --no-check-certificate`, PowerShell `-SkipCertificateCheck`, `kubectl`/`helm --insecure-skip-tls-verify`, `deno --unsafely-ignore-certificate-errors`, in scripts and in instructions an agent follows (SKILL.md, AGENTS.md, MCP setup steps) |
| `TLS-008` | Medium | git: `git -c http.sslVerify=false`, `git config http.sslVerify false`, `GIT_SSL_NO_VERIFY=1` |
| `TLS-009` | Medium | Package managers, as commands or environment: `pip install --trusted-host`, `pip config set global.trusted-host`, `PIP_TRUSTED_HOST`, `uv --allow-insecure-host` / `UV_INSECURE_HOST`, `npm`/`yarn`/`pnpm` `strict-ssl false` or `--no-strict-ssl`, `npm_config_strict_ssl=false`, `echo "strict-ssl=false" >> ~/.npmrc`, `conda config --set ssl_verify false`, a poetry certificate set to `false`, `maven.wagon.http.ssl.insecure=true` |
| `TLS-010` | Medium | A configuration key named for verification set to off, in code, YAML, JSON or TOML: `verify_ssl` / `ssl_verify` / `verify_certs` / `tls_verify` = false; `insecure_skip_verify` / `insecureSkipVerify` / `insecure-skip-tls-verify` / `tls_insecure` = true; httplib2 `disable_ssl_certificate_validation=True` |
| `TLS-CHAIN-001` | High | A credential (CRED-001/002 secret-named environment reads, CRED-MCP-001, or a hardcoded key or token rule) whose bound name appears in the arguments around a TLS-001, 002, 004, 005, 006, 007 or 010 finding, within 60 lines |

Shipped package-manager configuration files (`.npmrc`, `pip.conf`,
`requirements.txt`, `Pipfile`, `pyproject.toml`) are parsed by
[`DEPSRC-004`](structural-checks.md), which reports the same TLS-off settings
there; TLS-009 and TLS-010 leave those files alone so nothing is reported
twice.

### What is not reported

- **Comments.** A match on a line that starts with `#`, `//`, `/*` or a ` * `
  block-comment continuation, or that comes after `#` or `//` on the line, is
  not reported (`://` in a URL does not count as a comment). A top-level
  Markdown bullet (`* `) is still read.
- **Test files and data files.** Paths containing `tests/`, `/test/`,
  `__tests__/`, `/spec/`, `fixtures/`, `testdata/`, `/test_`, `conftest.py`,
  and files ending `_test.go`, `_test.py`, `.test.js`/`.ts`/`.mjs`,
  `.spec.js`/`.ts` or `.jsonl`. Test suites turn verification off against
  their own fake servers on purpose.
- **Verification that is on, or pointed at a CA:** `verify=True`,
  `verify=ca_bundle`, `rejectUnauthorized: true`, `InsecureSkipVerify:
  cfg.Insecure`, `CERT_REQUIRED`.
- **Comparisons, not assignments:** `process.env.NODE_TLS_REJECT_UNAUTHORIZED
  === "0"`, `if session.verify == False`.
- **Messages that name a setting.** A key or variable that opens a string it
  never closes (`"SSL_VERIFY=false is only allowed for loopback endpoints"`),
  or a bare value followed by a closing quote (`"Pipfile verify_ssl = false"`),
  is text about the setting, not the setting. Markdown inline code (a
  backtick) is an instruction and is reported.
- **Loopback.** `curl -k https://localhost:8443/health`, a pip
  `--trusted-host localhost`, and a TLS-010 setting whose line confines it to
  loopback or localhost. Nobody sits between a client and a server on the same
  machine. `NODE_TLS_REJECT_UNAUTHORIZED=0` is reported whatever the line says:
  it applies to every connection the process makes.
- **Database drivers' `ssl=False`** (asyncpg, redis): it means plaintext to a
  local server, not a skipped certificate check, and is outside this pack.
  TLS-001 reads `ssl=False` only on aiohttp's connector and request methods.

### Not covered

Rules match one line at a time, so a keyword argument split across lines
(`client(verify=` on one line, `False)` two lines later) is missed; two of
SkillSpector's five TLS examples are that shape. Browser automation flags
(`--ignore-certificate-errors`, Puppeteer `ignoreHTTPSErrors`, WebDriver
`acceptInsecureCerts`), Docker's `--insecure-registry` / `insecure-registries`,
Java `X509TrustManager` implementations with empty `checkServerTrusted`
bodies, and `.wgetrc` / `.curlrc` settings are not covered.

## The credential chain (TLS-CHAIN-001)

The chain is a correlation rule (see `CONTRIBUTING.md`): a credential
finding's source line binds a name (`token = os.getenv("GITHUB_TOKEN")`), and
that name must appear in the argument window of the TLS finding. The window is
the TLS line, the four lines after it, and the five lines above it
(`sink_window_before`), because a formatter puts `verify=False,` on its own
line at the end of a call whose headers are above it:

```python
token = os.getenv("GITHUB_TOKEN")          # CRED-001 binds `token`

resp = requests.get(
    url,
    headers={"Authorization": f"Bearer {token}"},
    timeout=30,
    verify=False,                           # TLS-001, and TLS-CHAIN-001 (High)
)
```

The source line is left out of the text the link is read from, so a credential
read three lines above an unrelated `requests.get(health_url, verify=False)`
does not link by repeating its own name. Unlike the exfiltration chain,
`Authorization` and `headers=` do not disqualify the link: an auth header is
exactly where the credential is exposed.

A High finding in the code a package runs is attack-shaped evidence to the
verdict, so TLS-CHAIN-001 can make a small package HIGH RISK. In the
measurements below it fired on no clean sample.

## Measurements

The rules were written and calibrated against the corpora below, so every
figure here is in-sample.

### Clean MCP servers and skills

```
Data Source: Real samples. Clean MCP servers: 169 packages from the official MCP
             registry (evaluation_results/corpora/mcp_clean_manifest.json).
             Skills: Datadog malicious-software-packages-dataset ai-skills bucket
             (204 malicious); anthropics, NVIDIA, openai and vercel-labs skill
             catalogs (455 clean).
Sample Size: 169 MCP servers; 204 malicious and 455 clean skills.
Limitations: In-sample. "Clean" means published by a vendor or in the registry,
             not audited. No malicious sample in these corpora disables TLS
             verification, so this measures false positives and coverage of
             clean code, not recall on attacks.
```

`scripts/benchmark_skills.py --tools sigil` (blocked = HIGH or CRITICAL RISK,
warned = MEDIUM RISK or above), compared per sample with the published runs of
the previous build (`sigil_7826ea1`, `mcp_sigil_7826ea1`). This run's
per-sample outcomes are `sigil_tls` and `mcp_sigil_tls` in
[`evaluation_results/skills_benchmark/`](../../evaluation_results/skills_benchmark/).
A same-day run of the previous build's binary on the 169 MCP servers differs
from this pack's run only in `io.form/formio-uag` (no finding, then LOW) and in
the TLS rules themselves.

| | Before | With this pack |
|---|---:|---:|
| MCP servers blocked | 39/169 (23.1%) | 39/169 (23.1%) |
| MCP servers warned | 125/169 (74.0%) | 125/169 (74.0%) |
| MCP servers CRITICAL | 17 | 17 |
| Malicious skills blocked | 173/204 (84.8%) | 173/204 (84.8%) |
| Malicious skills warned | 184/204 (90.2%) | 184/204 (90.2%) |
| Clean skills blocked | 7/455 (1.5%) | 7/455 (1.5%) |
| Clean skills warned | 71/455 (15.6%) | 71/455 (15.6%) |

No sample changed between blocked, warned and not warned. One MCP server
moved from no findings to LOW (`io.form/formio-uag`: a README line, see
below). TLS-CHAIN-001 fired on no sample.

Every TLS finding on a clean sample, read one by one (9 MCP servers with 16
findings, 3 skills with 4 findings):

| Sample | Rule | Where | What it is |
|---|---|---|---|
| MCP `com.zeroheight/zeroheight` | TLS-005 ×3 | `dist/api/api.js`, `dist/stdio.js` | Sets `NODE_TLS_REJECT_UNAUTHORIZED = "0"` when `NODE_ENV === "dev"`. Genuine |
| MCP `io.form/formio-mcp` | TLS-005 | `dist/formio-client.js` | Sets it when the user opts in with `FORMIO_INSECURE_TLS`. Genuine |
| MCP `io.form/formio-uag` | TLS-005 | `README.md` | Troubleshooting table tells the user to set `NODE_TLS_REJECT_UNAUTHORIZED=0` for a self-signed server. Genuine documentation; a README is a secondary path, so the server stays LOW |
| MCP `io.github.SAP-samples/hana-cli` | TLS-005, TLS-004 | `docs/…/environments.md`; `@sap/cds` kafka messaging inside the bundled `.vsix` | `export NODE_TLS_REJECT_UNAUTHORIZED=0` in the docs (genuine); `rejectUnauthorized: false` in a bundled dependency's development configuration, whose Kafka brokers are on `127.0.0.1` a few lines away (genuine setting, loopback target) |
| MCP `io.github.SAP/fiori-mcp-server` | TLS-005 ×2 | `README.md` | Line 279 is an MCP config with `"NODE_TLS_REJECT_UNAUTHORIZED": "0"` (genuine). Line 268 is the security warning that precedes it ("Setting … disables all SSL certificate validation"): a mention, reported because it names the setting in inline code |
| MCP `io.github.browserstack/mcp-server` | TLS-004 ×2 | `dist/lib/apiClient.js` | `rejectUnauthorized: false` on the proxy and CA agents, even when a CA certificate is configured. Genuine |
| MCP `io.github.vercel/next-devtools-mcp` | TLS-004 | `dist/_internal/nextjs-runtime-manager.js` | An undici agent with `rejectUnauthorized: false`, used when the environment already disables verification. Genuine |
| MCP `io.slingdata/sling-cli` | TLS-002 ×2 | `sling/bin.py` | On an SSL error, retries the download of the sling binary from GitHub with `check_hostname = False` and `CERT_NONE`, then extracts it. Genuine, and the riskiest of the set: the executable itself comes over the unverified connection |
| MCP `io.snyk/mcp` | TLS-004 ×2 | `dist/cli/index.js` | Bundled HTTP code that sets `rejectUnauthorized = false` in its insecure / ignore-unknown-CA modes. Genuine |
| Skill NVIDIA `vss-generate-video-calibration` | TLS-010 ×2 | `references/rtsp.md` | The capture request body the skill documents sends `"ssl_verify": false`. Genuine |
| Skill openai `render-deploy` | TLS-004 | `references/configuration-guide.md` | A Postgres pool with `ssl: production ? { rejectUnauthorized: false } : false`. Genuine |
| Skill openai `security-best-practices` | TLS-006 | `references/golang-general-backend-security.md` | A review checklist lists `` `InsecureSkipVerify: true` `` as something to look for. A mention, not an instance |

So 18 of the 20 findings are code or instructions that really turn
verification off (one of them, in hana-cli's bundled Kafka client, for brokers
on 127.0.0.1); 2 are documentation that names the setting (the SAP warning
line and the security checklist). Neither of those changes a verdict: both are
in reference documentation, and both samples are MEDIUM or above for other
reasons.

Two false positives were found and fixed during calibration, before the
figures above, both in NVIDIA's `amc-run-rtsp-calibration` skill: a script's
error message (`"SSL_VERIFY=false is only allowed for loopback AMC
endpoints…"`) and the SKILL.md sentence confining `SSL_VERIFY=false` to
loopback testing. Each moved the skill from LOW to MEDIUM until it was fixed.
The quote rule and the loopback rule under "What is not reported" come from
them.

### SkillSpector's own examples

`scripts/skillspector_parity.py run` over the 1,796 examples SkillSpector's
test suite constructs (results: `parity_sigil_tls` in
`evaluation_results/skills_benchmark/`). The insecure-transport examples are
20 of them: 14 `curl -k` / `curl --insecure` lines in TM1 (tool misuse), 5 TLS
lines in TM3 (insecure configuration: `verify = False`, `ssl_verify = False`,
`NODE_TLS_REJECT_UNAUTHORIZED = "0"`, and a `verify=` / `False` call split
across a blank line, twice), and SC7's `docker pull --insecure-registry`.

```
Data Source: SkillSpector's test suite (every finding its tests construct, de-duplicated),
             the corpus scripts/skillspector_parity.py capture builds from it.
Sample Size: 20 insecure-transport examples of 1,796.
Limitations: SkillSpector's examples, not a malicious corpus. Several are single
             lines written to exercise a regex (`verify = False` alone in http.py).
```

| | Before (published run, `7826ea1`) | With this pack |
|---|---:|---:|
| Insecure-transport examples flagged, any severity | 14/20 | 17/20 |
| … flagged by a TLS rule | 0/20 | 17/20 |
| … flagged at High or above | 0/20 | 0/20 |
| All 1,796 examples, any severity | 623 (34.7%) | 626 (34.9%) |
| All 1,796 examples, High or above | 385 (21.4%) | 385 (21.4%) |

Per example:

- The 14 `curl -k` / `--insecure` examples were already flagged before, by
  NET-012 (a download command, Low), not for the missing verification. They
  now also carry TLS-007 at Medium.
- TM3's `verify = False`, `ssl_verify = False` and
  `NODE_TLS_REJECT_UNAUTHORIZED = "0"` are newly flagged (TLS-001, TLS-010,
  TLS-005). These three are the whole change in the totals row.
- TM3's two split-line examples (`client(verify=`, a blank line, then
  `False)`, as a Python file and inside a SKILL.md code fence) are not
  flagged: the rules read one line at a time.
- SC7's `docker pull --insecure-registry` is not flagged (see "Not covered").

None of the 20 reaches High: the pack is Medium by design, and SkillSpector's
examples carry no credential for TLS-CHAIN-001 to link.

### Malicious npm and PyPI packages

`scripts/run_eval.py --dataset datadog --limit 204` (844 samples, the same
selection as the published report) gives the same recall with and without the
pack: 785 at any severity (93.01%), 761 at Medium or above (90.17%), 752 at
High or above (89.10%), 561 at Critical (66.47%). The report does not record
which rules fired, so how many of those packages carry a TLS finding was not
measured.

### Cost

CPU time (user + system) of a full scan of `io.github.SAP-samples/hana-cli`
(3,829 files, the slowest of the eight large MCP servers timed), three
alternating runs of the previous build's binary and of this one: median
39.08 s before and 39.41 s with the pack (+0.8%), fastest run 36.93 s and
37.18 s. Other work was running on the 4-core machine at the time, so treat
the difference as approximate.

## Choosing the severity

Medium is the severity of "suspicious in context, review before approving"
(see `scoring.rs`). Turning verification off is a real weakness, and most of
the clean instances above are an opt-in or development mode that a reviewer
should see and decide on, which is what MEDIUM RISK asks for. It is not
evidence that the package attacks the machine it runs on, so it is not High:
a High line rule would be attack evidence to the verdict, and could block a
small clean package for an opt-in development switch.
The chain is High because a credential sent over an unverified connection is
a concrete loss, not a configuration choice.
