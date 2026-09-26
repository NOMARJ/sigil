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
| `TLS-002` | Medium | Python `ssl`: `verify_mode = ssl.CERT_NONE` (or `ssl.VerifyMode.CERT_NONE`), `cert_reqs=CERT_NONE`, `check_hostname = False`, `ssl._create_unverified_context` |
| `TLS-003` | Low | urllib3's `InsecureRequestWarning` silenced (`disable_warnings(...)`, `filterwarnings`/`simplefilter`): the warning `verify=False` triggers. An observation that points at the TLS-001 it hides |
| `TLS-004` | Medium | Node.js: `rejectUnauthorized: false` (https.Agent, tls.connect, WebSocket, undici `connect`), request's `strictSSL: false`, a no-op `checkServerIdentity`; also the minified forms a bundled `dist/` file carries (`rejectUnauthorized:!1`, `() => void 0`) |
| `TLS-005` | Medium | Verification off for the whole process: `NODE_TLS_REJECT_UNAUTHORIZED=0` and `PYTHONHTTPSVERIFY=0` set in code (`process.env`, `os.environ`), a shell, a Dockerfile, a `.env` file, an MCP server's `env` block or a docker `-e` argument; an empty `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` in Python |
| `TLS-006` | Medium | Other languages: Go `InsecureSkipVerify: true`, Rust reqwest `danger_accept_invalid_certs(true)`, Ruby `VERIFY_NONE` and Faraday `ssl: { verify: false }`, PHP / C / pycurl `CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST` 0 and Guzzle `'verify' => false`, .NET `DangerousAcceptAnyServerCertificateValidator` or a validation callback returning `true`, Apache HttpClient `NoopHostnameVerifier` / `TrustAllStrategy` and hostname-verifier lambdas returning `true` |
| `TLS-007` | Medium | Commands: `curl -k` / `--insecure` (also combined flags such as `-sSLk`, and `["curl", "-k", ...]` argument lists), `wget --no-check-certificate`, PowerShell `-SkipCertificateCheck`, `kubectl`/`helm --insecure-skip-tls-verify`, `deno --unsafely-ignore-certificate-errors`, in scripts and in instructions an agent follows (SKILL.md, AGENTS.md, MCP setup steps) |
| `TLS-008` | Medium | git: `git -c http.sslVerify=false`, `git config http.sslVerify false`, `GIT_SSL_NO_VERIFY=1` |
| `TLS-009` | Medium | Package managers, as commands or environment: `pip install --trusted-host`, `pip config set global.trusted-host`, `PIP_TRUSTED_HOST`, `uv --allow-insecure-host` / `UV_INSECURE_HOST`, `npm`/`yarn`/`pnpm` `strict-ssl false` or `--no-strict-ssl`, `npm_config_strict_ssl=false`, `echo "strict-ssl=false" >> ~/.npmrc`, `conda config --set ssl_verify false`, a poetry certificate set to `false`, `maven.wagon.http.ssl.insecure=true` |
| `TLS-010` | Medium | A configuration key named for verification set to off, in code, YAML, JSON or TOML: `verify_ssl` / `ssl_verify` / `verify_certs` / `tls_verify` = false; `insecure_skip_verify` / `insecureSkipVerify` / `insecure-skip-tls-verify` / `tls_insecure` = true; httplib2 `disable_ssl_certificate_validation=True` |
| `TLS-CHAIN-001` | High | A credential (CRED-001/002 secret-named environment reads, CRED-MCP-001, or a hardcoded key or token rule) that is part of the call or literal a TLS-001, 002, 004, 005, 006, 007 or 010 finding belongs to, or whose bound name that statement (or the set-up and use lines next to it) uses as a value, within 60 lines; see [the chain](#the-credential-chain-tls-chain-001) |

Shipped package-manager configuration files (`.npmrc`, `.yarnrc`,
`.yarnrc.yml`, `pip.conf`, `pip.ini`, `requirements.txt`, `Pipfile`,
`pyproject.toml`, `pdm.toml`, `uv.toml`) are parsed by
[`DEPSRC-004`](structural-checks.md), which reports the TLS-off settings of a
package source there. TLS-009 matches commands and environment variables, not
those files' own option lines, and TLS-010 skips `.npmrc`, `.yarnrc`,
`.yarnrc.yml`, `pip.conf`, `pip.ini`, `Pipfile`, `pyproject.toml` and
`pdm.toml`, so a package source's `verify_ssl = false` is reported once. The
cost: an application's own `verify_ssl = false` under some other `[tool.*]`
table of a `pyproject.toml` is reported by neither rule.

### What is not reported

- **Comments.** A match on a line that starts with `#`, `//`, `/*` or a ` * `
  block-comment continuation is not reported, and neither is one that comes
  after `//` or after a `#` that follows whitespace (`x = 1  # verify=False`).
  `://` in a URL is not a comment, and neither is a `#` glued to the character
  before it: a `"#"` string, a shell `$#`, a URL fragment, a JavaScript
  `this.#field`. A top-level Markdown bullet (`* `) is read; an indented one is
  not (see "Not covered").
- **JWT signature switches.** `jwt.decode(token, verify=False)` (PyJWT 1.x)
  and python-jose's `jws.verify(..., verify=False)` skip a token signature
  check, not a certificate check, so TLS-001 leaves a line that contains
  `jwt.decode(` or `jws.verify(` alone.
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
  machine. The check reads the line's text, not the target: TLS-007 and TLS-009
  skip any line containing `://localhost`, `://127.0.0.1`, `://0.0.0.0`,
  `://[::1]` or `://host.docker.internal` (TLS-009 also `--trusted-host
  localhost` / `127.0.0.1`), and TLS-010 any line containing `localhost`,
  `127.0.0.1`, `loopback` or `Loopback`. So a remote `curl -k` whose line also
  mentions a localhost URL, in a comment for example, is not reported.
  `NODE_TLS_REJECT_UNAUTHORIZED=0` is reported whatever the line says: it
  applies to every connection the process makes.
- **Database drivers' `ssl=False`** (asyncpg, redis): it means plaintext to a
  local server, not a skipped certificate check, and is outside this pack.
  TLS-001 reads `ssl=False` only on aiohttp's connector and request methods.

### Not covered

Rules match one line at a time, so a keyword argument split across lines
(`client(verify=` on one line, `False)` two lines later) is missed; two of
SkillSpector's five TLS examples are that shape. For the same reason:

- A Kubernetes `env:` entry that names `NODE_TLS_REJECT_UNAUTHORIZED` on one
  line and sets `value: "0"` on the next is missed (the one-line forms of
  Docker Compose, GitHub Actions and `.env` files are reported).
- A multi-line `jwt.decode(` call whose `verify=False,` sits on its own line is
  reported as TLS-001, because the suppression only sees the line it is on.
- A loopback host on another line of the same object (`host: '127.0.0.1'`
  above `verifySsl: false`) does not suppress TLS-010.

The chain has blind spots of its own:

- Only Python and JavaScript environment reads (CRED-001, CRED-002), the MCP
  credential names (CRED-MCP-001) and hardcoded keys are credentials to it. A
  shell `curl -k -H "Authorization: Bearer $GITHUB_TOKEN" ...`, or a Go
  `os.Getenv("TOKEN")` beside `InsecureSkipVerify: true`, is reported as the
  TLS finding alone.
- A credential used *after* the statement that builds the insecure object
  (`socket.write(process.env.REDIS_PASSWORD)` below `tls.connect({...,
  rejectUnauthorized: false })`) is not linked: the lines below the statement
  are read only for a name bound above it.
- Sibling literals of one options object are not linked (got's
  `https: { rejectUnauthorized: false }` beside `headers: {...}`; see
  "What a second review changed").
- A line longer than 500 bytes is not linked, so a long trailing comment on
  the TLS line hides the chain (the TLS finding is still reported).
- In Markdown prose, a sentence line that ends with a comma continues into
  the next line like an argument list does, so a credential named in the
  sentence that leads into a TLS instruction links.

The comment and command-span rules trade some shapes for others:

- An indented Markdown bullet that starts with `*` (`  * run curl -k ...`)
  is read as a block-comment continuation and skipped; `-` bullets and
  top-level `*` bullets are read.
- A JavaScript private field declared at the start of a line (`#agent = new
  https.Agent({ rejectUnauthorized: false })`) is read as a comment;
  `this.#agent = ...` is reported.
- The command rules stop at a backtick between the command and its flag, so
  prose such as "run `curl` with `-k`" is not reported, while
  `` `curl -k https://...` `` in one code span is.
- A `#` after whitespace, or a `//`, starts a comment even inside a string, so
  `requests.get("https://host/page #top", verify=False)` is not reported.
- The test-path suppression matches substrings: `tests/` also matches a
  `contests/` directory, and `/test_` a `test_utils/` module.

Browser automation flags (`--ignore-certificate-errors`, Puppeteer
`ignoreHTTPSErrors`, WebDriver `acceptInsecureCerts`), Docker's
`--insecure-registry` / `insecure-registries`, Java `X509TrustManager`
implementations with empty `checkServerTrusted` bodies, and `.wgetrc` /
`.curlrc` settings are not covered.

## The credential chain (TLS-CHAIN-001)

The chain is a correlation rule (see `CONTRIBUTING.md`) that reads the
*statement* the TLS finding belongs to, not a fixed band of lines around it
(`sink_window_before: 10`, `max_line_length: 500`, `name_uses: value`). A
credential finding (CRED-001 `token = os.getenv("GITHUB_TOKEN")`, a hardcoded
key) links to the TLS finding when, within 60 lines:

1. **It is in the same call or literal.** The statement is the TLS line, the
   lines above it that continue into it (the call's opening line and earlier
   arguments, each ending with `(`, `[`, `,`, `\` or an object literal's `{`;
   at most 10), and the lines below it that its call continues onto. A
   credential read inline in the headers argument of the call whose last
   argument is `verify=False,` is in that call, and so is a
   `connectionString: process.env.DATABASE_URL` beside the `ssl: {
   rejectUnauthorized: false }` of the same `new Pool({...})`. Brackets
   decide what belongs together: the credential's line and the TLS line must
   start in the same bracket group, or one inside the other. Two sibling
   literals of one statement are not one call: an `openai: {...}` entry with
   an API key and a `db: { ssl: {...} }` entry beside it in one exported
   configuration are two services. A line that is one key and a literal it
   opens and closes (`"metrics": {"url": u, "verify_ssl": False},`) counts as
   a literal of its own.
2. **Or the name it binds is used there, as a value.** The name must appear in
   the statement, or in the lines next to it that work with the same object:
   above, a line that assigns to or calls a method on a local name the
   statement uses (`headers = {"Authorization": ...}` above `get(url,
   headers=headers, verify=False)`, `session.headers.update(...)` above
   `session.get(url, verify=False)`); below, within four lines, a line that
   uses the name the statement assigns (`fetch(url, { agent, ... })` after
   `const agent = new https.Agent({ rejectUnauthorized: false })`). "Local"
   means assigned in the window, or an attribute of `self` / `this`, so an
   imported module (`requests.post(...)` above `requests.get(...,
   verify=False)`) does not connect two unrelated calls. A keyword-argument
   name or an object key is not a use: `headers={"Accept": "json"}` does not
   use a `headers` dict built from the token elsewhere, and
   `hvac.Client(token=role_token)` does not use a `token` variable; the
   value side (`headers=headers`, `{ auth: token }`, `f"Bearer {token}"`)
   is. The statement is read as code, as every chain with `name_uses: value`
   reads it ([correlation-chains.md](correlation-chains.md)): a word inside
   a string or a comment, an attribute of another object, a destructuring
   target or a count is not a use, and a credential finding that matched
   only a line's comment does not put that line in the call.

```python
token = os.getenv("GITHUB_TOKEN")          # CRED-001 binds `token`

resp = requests.get(
    url,
    headers={"Authorization": f"Bearer {token}"},
    timeout=30,
    verify=False,                           # TLS-001, and TLS-CHAIN-001 (High)
)
```

Any other line near the TLS finding is a different statement and is not read.
A key used by `client = OpenAI(api_key=api_key)` on the line above
`status = requests.get(STATUS_URL, verify=False)` goes to its own vendor over
a verified connection; it is not linked. Unlike the exfiltration chain,
`Authorization` and `headers=` do not disqualify the link: an auth header is
exactly where the credential is exposed.

A TLS finding or credential on a line longer than 500 bytes is not linked: on
a minified bundle one line holds a whole program, and two matches on it say
nothing about each other. A shorter line holding both still links, including
a short single-line bundle.

A High finding in the code a package runs is attack-shaped evidence to the
verdict, so TLS-CHAIN-001 can make a small package HIGH RISK. In the
measurements below it fired on one clean sample, a genuine instance in
reference documentation that did not change the verdict.

### What an adversarial review changed

The first version of the chain read the five lines above the TLS finding and
the four below it, whatever statements they were, and linked any credential
and TLS match that shared a line, however long. A review built the
cases below (synthetic, one file each, scanned with `sigil scan`) and changed
the chain and the rules to the behaviour described above. Each case is a unit
test in `cli/src/corpus/insecure_transport_tests.rs` or
`cli/src/scanner/correlate.rs`.

```
Data Source: Synthetic test cases written for the review (not real packages).
Sample Size: 16 cases (one file each, two for the bundle): the 12 below that
             changed, and 4 set-up shapes that must still link. Each was scanned
             with the first version and with this one.
Limitations: Constructed to probe the rules, so they show which shapes change,
             not how often each occurs in real code.
```

| Case | First version | This version |
|---|---|---|
| Key used by `OpenAI(api_key=...)` on the line above an unrelated `requests.get(..., verify=False)` | TLS-CHAIN-001, HIGH RISK | TLS-001 only, MEDIUM RISK |
| `const gh = new Octokit({ auth: token })` on the line below an unrelated insecure agent | TLS-CHAIN-001, HIGH RISK | TLS-004 only, MEDIUM RISK |
| `requests.post(api, headers={... token})` above an unrelated `requests.get(..., verify=False)` | TLS-CHAIN-001, HIGH RISK | TLS-001 only, MEDIUM RISK |
| `jwt.decode(token, verify=False)` after reading the token from the environment | TLS-001 and TLS-CHAIN-001, HIGH RISK | nothing from this pack, LOW RISK |
| A 714-byte bundle line with a `GITHUB_TOKEN` read in one function and `rejectUnauthorized:false` in another | TLS-CHAIN-001, HIGH RISK | TLS-004 only, MEDIUM RISK |
| `os.environ["TOKEN"]` read inline in the headers argument above `verify=False,` | TLS-001 only | TLS-001 and TLS-CHAIN-001 |
| The same, with the headers argument below `verify=False,` | TLS-001 only | TLS-001 and TLS-CHAIN-001 |
| `requests.get(URL, headers={"Accept": "#"}, verify=False)` | not reported | TLS-001 |
| `this.#agent = new https.Agent({ rejectUnauthorized: false })` | not reported | TLS-004 |
| `[ $# -gt 0 ] && curl -k "$1" -o out.bin` | not reported | TLS-007 |
| "Fetch the file with curl, then sort it with `sort -k 2`." in a SKILL.md | TLS-007 | not reported |
| A `[[tool.pdm.source]]` with `verify_ssl = false` in `pyproject.toml` | DEPSRC-004 and TLS-010 | DEPSRC-004 |

Four set-up shapes the first version linked only because they were near the
TLS line still link: a `headers` dict built from the token above the call, a
`requests.Session()` configured with the token above `session.get(...,
verify=False)`, `self.session` configured in `__init__`, and an agent used
with the token on the next line.

### What a second review changed

A second adversarial review of the reviewed chain built 29 more one-file
cases. The statement window still linked through the *name* of a parameter
and across sibling literals, and six clean files went from LOW to HIGH RISK
on TLS-CHAIN-001 alone. Three disabling forms were not reported. Each row is
a unit test in `cli/src/corpus/insecure_transport_tests.rs` or
`cli/src/scanner/correlate.rs`.

```
Data Source: Synthetic test cases written for the second review (not real packages).
Sample Size: 29 probe files (one file each), scanned with the first review's
             build and with this one. 11 changed: the 10 rows below, and the
             got-style options described after the table (a lost chain). 18 did
             not, 5 of them genuine chains that still link: a token passed as
             auth=(user, token), as headers=headers, as params={"token": token},
             in a headers literal above verify=False, and in an aiohttp
             session's headers above its insecure connector.
Limitations: Constructed to probe the rules, so they show which shapes change,
             not how often each occurs in real code.
```

| Case | First review | This version |
|---|---|---|
| `headers = {"Authorization": ... os.environ[...]}` at module level; an unrelated `requests.get(..., headers={"Accept": ...}, verify=False)` | TLS-CHAIN-001, HIGH RISK | TLS-001 only, MEDIUM RISK |
| `token = os.environ["GITHUB_TOKEN"]` used by `Github(token)`; `hvac.Client(url=..., token=role_token, verify=False)` | TLS-CHAIN-001, HIGH RISK | TLS-001 only, MEDIUM RISK |
| `const token = process.env.GITHUB_TOKEN` used by Octokit; `new https.Agent({ token: "public", rejectUnauthorized: false })` | TLS-CHAIN-001, HIGH RISK | TLS-004 only, MEDIUM RISK |
| `self.headers` built from `self.api_key`; `requests.head(host, headers={"User-Agent": ...}, verify=False)` in another method | TLS-CHAIN-001, HIGH RISK | TLS-001 only, MEDIUM RISK |
| `url = os.environ["DATABASE_URL"]`; `requests.get(url=base + "/ping", verify=False)` | TLS-CHAIN-001; CRITICAL RISK from EXFIL-CHAIN-001, which predates this pack and reads names the old way | TLS-001 only; still CRITICAL RISK from EXFIL-CHAIN-001 |
| `module.exports = { openai: { apiKey: process.env.OPENAI_API_KEY }, db: { ssl: { rejectUnauthorized: false } } }`, one key per line | TLS-CHAIN-001, HIGH RISK | TLS-004 only, MEDIUM RISK |
| A `SERVICES` dict with one line per service: `"openai": {"api_key": os.environ[...]}` above `"metrics": {..., "verify_ssl": False}` | TLS-CHAIN-001, HIGH RISK | TLS-010 only, MEDIUM RISK |
| A minified bundle's `new a.Agent({keepAlive:!0,rejectUnauthorized:!1})` | not reported, LOW RISK | TLS-004, MEDIUM RISK |
| `checkServerIdentity: () => void 0` (esbuild's `undefined`) | not reported | TLS-004 |
| `ctx.verify_mode = ssl.VerifyMode.CERT_NONE` | not reported | TLS-002 |

The `DATABASE_URL` row is the TLS lane's result. EXFIL-CHAIN-001 has since
been switched to read names as values too (`"name_uses": "value"`, see
[correlation-chains.md](correlation-chains.md)), and that file is now MEDIUM
RISK on TLS-001 alone.

The sibling rule has a cost: got's options, written with the headers and the
TLS switch as sibling literals (`headers: { Authorization: ... }` beside
`https: { rejectUnauthorized: false }`), are one request, and that chain is
no longer linked (TLS-004 still reports the switch, and the package is still
MEDIUM RISK). The rule prefers missing that High to raising a configuration
file with two services to HIGH RISK.

## Measurements

The rules were written and calibrated against the corpora below, so every
figure here is in-sample, except the second set of MCP servers ("Out of
sample"), which the first review added.

Three builds of the pack were measured: its first commit, the first review's
build and the second review's (the final build). The published per-sample
files are the final build's runs; the earlier builds' runs are in the commits
that published them. Compared sample by sample, every clean MCP server, every
skill and every SkillSpector example has the same verdict level (and, for
the examples, the same rule set) with all three builds. The second review's
changes to the chain and to TLS-002 / TLS-004 moved no sample in these
corpora.

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
the previous build (`sigil_7826ea1`, `mcp_sigil_7826ea1`). The per-sample
outcomes are `sigil_tls` and `mcp_sigil_tls` in
[`evaluation_results/skills_benchmark/`](../../evaluation_results/skills_benchmark/),
from the final build. A same-day run of the previous build's binary on the
169 MCP servers differs from this pack's first build only in
`io.form/formio-uag` (no finding, then LOW) and in the TLS rules themselves.
Between the first build and the reviewed builds, one skill gained a
TLS-CHAIN-001 finding (`render-deploy`, below). In the first review's MCP run,
one server, `io.github.SAP/fiori-mcp-server`, swapped `CRED-008` for
`PROV-BUDGET-001`: a file ran out of scan time on the loaded machine. The
final build's run has `CRED-008` again, as the first build's did. That is not
a TLS rule, and the server is HIGH RISK in all three runs.

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
below). TLS-CHAIN-001 fired on one clean skill (`render-deploy`, in reference
documentation, which stays MEDIUM) and on no MCP server or malicious skill.

Every TLS finding on a clean sample, read one by one (9 MCP servers with 16
findings; 3 skills with 4 line findings and 1 chain finding):

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
| Skill openai `render-deploy` | TLS-004, TLS-CHAIN-001 | `references/configuration-guide.md` | A Postgres pool with `ssl: production ? { rejectUnauthorized: false } : false`. Genuine. The chain: the line above, in the same `new Pool({...})` options, is `connectionString: process.env.DATABASE_URL` (CRED-002), so the database credentials travel on the unverified connection. The first build missed it (an object key binds no name); the final build links a source inside the same literal. A reference document is a secondary path, so the skill stays MEDIUM |
| Skill openai `security-best-practices` | TLS-006 | `references/golang-general-backend-security.md` | A review checklist lists `` `InsecureSkipVerify: true` `` as something to look for. A mention, not an instance |

So 18 of the 20 line findings are code or instructions that really turn
verification off (one of them, in hana-cli's bundled Kafka client, for brokers
on 127.0.0.1); 2 are documentation that names the setting (the SAP warning
line and the security checklist). Neither of those changes a verdict: both are
in reference documentation, and both samples are MEDIUM or above for other
reasons. The one chain finding is a genuine instance of the chain's pattern,
in documentation.

Two false positives were found and fixed during calibration, before the
figures above, both in NVIDIA's `amc-run-rtsp-calibration` skill: a script's
error message (`"SSL_VERIFY=false is only allowed for loopback AMC
endpoints…"`) and the SKILL.md sentence confining `SSL_VERIFY=false` to
loopback testing. Each moved the skill from LOW to MEDIUM until it was fixed.
The quote rule and the loopback rule under "What is not reported" come from
them.

### Out of sample: 146 more MCP servers

The first review ran the pack on MCP servers it was not calibrated on: a second
registry selection of popular npm-published servers that excludes every server
in the 169 above. Run with `scripts/benchmark_skills.py --tools sigil --clean
<holdout> --clean-sample-depth 1`.

```
Data Source: Real samples. 146 MCP servers from the official MCP registry: latest,
             active, published on npm with at least 5,000 downloads in the 30 days
             to 2026-09-21, at least 90 days old, at most 3 per namespace, none of
             the 169 in-sample servers and none on Datadog's malicious npm list
             (148 selected, 2 failed to download).
Sample Size: 146 MCP servers.
Limitations: "Clean" means popular and registry-listed, not audited. The selection
             manifest was not published with this change.
```

The selection manifest has since been published as
`evaluation_results/corpora/mcp_holdout146_manifest.json`; it rebuilds this
146-server corpus with `fetch_mcp_clean.py --from-manifest`.

| | main (no TLS rules) | First build of the pack | First review | Final build |
|---|---:|---:|---:|---:|
| Servers blocked (HIGH or CRITICAL RISK) | 80/146 (54.8%) | 80/146 | 80/146 | 80/146 |
| Servers warned (MEDIUM or above) | 135/146 (92.5%) | 135/146 | 135/146 | 135/146 |
| Servers CRITICAL | 46 | 46 | 46 | 46 |
| Servers with a TLS finding | 0 | 11 | 11 | 11 |
| TLS findings | 0 | 27 | 28 | 29 |
| TLS-CHAIN-001 | 0 | 0 | 0 | 0 |

No server changed level: every server the TLS rules touch was already MEDIUM
or above. (The 54.8% blocked is the existing rules' false-positive rate on
this selection, not something this pack adds.) Of the final build's 29
findings, read one by one:

- 22 turn verification off. 20 are shipped code: Postgres, MySQL and MariaDB
  drivers' `ssl: { rejectUnauthorized: false }` for "require without verify"
  modes (`YawLabs/postgres-mcp` ×6, `bytebase/dbhub` ×5), dbhub's
  `checkServerIdentity = () => void 0` for `sslmode=verify-ca` (the CA is
  checked, the host name is not), opt-in
  insecure-TLS switches in GitLab, Obsidian, WordPress and agent clients, and
  `verifySsl: false` in an email client's preset for a local mail bridge
  (genuine setting, but the host, `127.0.0.1`, is on another line of the
  object, so the loopback check does not see it). The other 2 are a
  README telling the user to set `NODE_TLS_REJECT_UNAUTHORIZED=0` for SSL
  errors, and a Prometheus example with `insecure_skip_verify: true`.
- 7 are changelog or README text that describes the setting rather than
  making it: 5 lines of `obsidian-mcp-server` changelogs, one of
  `respira-wordpress`, and one README sentence in `mcp-postgres-server` that
  says `rejectUnauthorized` is pinned on *so that* an inherited
  `NODE_TLS_REJECT_UNAUTHORIZED=0` cannot disable it. All are in secondary
  paths and change no verdict.

The finding the first review adds is one of those 7 (`obsidian-mcp-server`
`changelog/3.5.x/3.5.4.md:31`). The first build skipped it only because a
Markdown issue link, `[#131](...)`, came earlier on the line, and it read any
`#` as the start of a comment. The finding the final build adds is dbhub's
`checkServerIdentity = () => void 0` (bundled output of `() => undefined`,
which the earlier builds already read). Rescanned one by one with the first
review's binary and with the final one, the 11 servers with a TLS finding
differ in that line only; the final build's run of all 146 servers has the
same figures as the first review's in every other row.

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
examples carry no credential for TLS-CHAIN-001 to link. All three builds give
the same result, maximum severity and rule set, for every one of the 1,796
examples; their published files differ only in the label of the binary.

### Malicious npm and PyPI packages

```
Data Source: Real samples. DataDog malicious-software-packages-dataset, npm and
             PyPI, selected by scripts/run_eval.py --limit 204.
Sample Size: 844 malicious packages; no clean control in this run.
Limitations: Recall only. The dataset is mostly GuardDog-identified (selection
             bias, per Datadog). Offline static phases only.
```

`scripts/run_eval.py --dataset datadog --limit 204` (844 samples, the same
selection as the published report) gives the same recall with each of the
pack's three builds (all run for this change) as the published report of the
previous build (`evaluation_results/
honest_detection_eval_7826ea1.md`): 785 at any severity (93.01%),
761 at Medium or above (90.17%), 752 at High or above (89.10%), 561 at
Critical (66.47%). The report does not record which rules fired, so how many
of those packages carry a TLS finding was not measured.

### Cost

CPU time (user + system) of a full scan of `io.github.SAP-samples/hana-cli`
(3,829 files, the slowest of the eight large MCP servers timed), three
alternating runs per binary. Three sessions, each on a shared 4-core machine
with other work running, so treat the differences as approximate:

| Session | Without the pack | First build | First review | Final build |
|---|---:|---:|---:|---:|
| Pack author, median (fastest) | 39.08 s (36.93 s) | 39.41 s (37.18 s), +0.8% | not built yet | not built yet |
| First review, median (fastest) | 40.74 s (38.43 s) | 42.58 s (41.47 s), +4.5% | 41.99 s (41.90 s), +3.1% | not built yet |
| Second review, median (fastest) | 42.96 s (40.20 s) | not run | 42.89 s (41.77 s), -0.2% | 42.59 s (42.59 s), -0.9% |

The reviews' runs had load averages between 2 and 7 while they ran; their
spread (38.4 to 41.3 s, and 40.2 to 43.1 s, for the same binary without the
pack) is as large as the differences between binaries. The second review's
bracket and keyword checks run only in a file that has both a credential
finding and a TLS finding.

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
