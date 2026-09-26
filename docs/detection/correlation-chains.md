# Correlation chains

A correlation chain is a rule over *findings* rather than over file content
(`correlation_rules` in `cli/packs/core/v1/*.json`, applied by
`cli/src/scanner/correlate.rs`). It fires when a source finding and a sink
finding sit in the same file, the source first and within the rule's window,
and what the source line produced reaches the sink. It is the one place a pack
can say "line 9 feeds line 10" without the engine executing anything: the
link is a text check, not taint analysis. `CONTRIBUTING.md` ("Correlation
rules") has the schema; this page lists the built-in chains, what each links
through, how a bound name is read, the probes behind each part of that
reading, what it still gets wrong, and what changed on real samples.

## The built-in chains

| Chain | Severity | Source | Sink | Links through |
|---|---|---|---|---|
| `EXFIL-CHAIN-001` | Critical | any `CRED-*` finding | an outbound send: `NET-001`..`009`, `NET-012`, `NET-014`, `NET-UPLOAD-001` | the name the source line assigns, the handle of a file it opens for reading (`with open(<key file>) as keyfile`), or a file it writes, sent in the sink's call. `sink_excludes`: `headers`, `Authorization`, `authorization`, `Bearer`, `bearer`, `x-api-key`, `X-Api-Key`, `auth=` in the sink line or the four lines after it disqualify the link (an auth header is where a key legitimately goes) |
| `DROPPER-CHAIN-001` | High | a download: `NET-001`..`005`, `NET-012`, `NET-EXE-001`, `NET-RAWIP-001`, `AGENTSC-004` | `CODE-RUNFILE-001`, a launch of a program named by a variable | only a file the source line *wrote* (`open(PATH, 'wb')`, `urlretrieve(url, PATH)`, `curl -o "$OUT"`, `-OutFile`, a literal path such as `"/tmp/x.pyz"`), and only when the launch *runs* it: the program operand `CODE-RUNFILE-001` matched, not a data file handed to that program |
| `AGENTSC-CHAIN-001` | Critical | `AGENTSC-010`, a secret-named environment sweep (`env \| grep TOKEN`) | an outbound send: `NET-001`..`009`, `NET-012`, `NET-014`, `SKILL-017`, `AGENTSC-012`, `AGENTSC-020` | the name the sweep is assigned to (`SECRETS=$(env \| grep ...)`), sent in the sink's call |
| `AGENTSC-CHAIN-002` | High | `AGENTSC-011`, a project archive built without excluding `.env` | an upload: `NET-UPLOAD-001`, `AGENTSC-012`, `NET-001`..`005`, `NET-012` | the archive path `tar -c…f` writes (`"$TARBALL"`), sent in the sink's call |
| `DESER-CHAIN-001` | High | `CODE-MODEL-001`, a pickle-format file resolved inside the package's own directory | `CODE-DESER-001`, `torch.load(..., weights_only=False)` | the name the path is assigned to (`model_path = os.path.join(os.path.dirname(__file__), "model.pt")`), loaded in the sink's call |
| `TLS-CHAIN-001` | High | a credential read or hardcoded key | a TLS-verification switch (`TLS-001`, `002`, `004`..`007`, `010`) | the sink's statement (`sink_window_before: 10`); see [insecure-transport.md](insecure-transport.md#the-credential-chain-tls-chain-001) |

A source and a sink on the same line link without a name, unless one of them
matched only the line's comment. Every other link goes through a name the
source line binds.

## How a bound name is read (`name_uses: "value"`)

Every built-in chain sets `"name_uses": "value"`: the link needs the sink to
*send* the bound value, not only to mention its name.

1. **Code, not text.** The window is read with its comments and the contents
   of its string literals blanked, by the sink file's extension (Python;
   shell, PowerShell, Ruby, YAML and TOML; JavaScript, TypeScript and the C
   family; PHP; Markdown and text, whose code blocks may be any of these). A
   JavaScript regular-expression literal is text too. What a string
   interpolates is kept: a Python f-string's `{expr}` whatever
   follows it (`{token:>40}`, `{token:s}`, `{token!r}`, `{token=}`), `${...}`
   and `$(...)` in any string, `$NAME`, and, when the text formats with
   `locals()`, `vars()` or `globals()`, a plain string's `{name}` and
   `%(name)s`. A token endpoint's path (`"https://oauth2.example.com/token"`),
   an OAuth grant type, an escaped JSON body and a `# no token needed` note are
   not the token.
2. **Values, not names.** An occurrence that only names something is skipped:
   a keyword argument's name or an assignment target (`name=`, not `==`); an
   object key (`name:` after `{`, `,`, `(`, `;` or at the start of a line, bare
   or quoted); a TypeScript member (`token?: string`, `token!: T`,
   `private token: string`); an attribute of another object (`r.url`;
   `self.token`, `this.token` and the receiver the source line assigned
   through, `cfg.token`, are the value); a destructuring or tuple target
   (`const { token } = await res.json()`, `status, token = pair`); an export
   list (`export { token }`, `module.exports = { token, health }`); a count
   (`len(secrets)`, `secrets.split("\n").length`, `.size`, `.count(...)`: a
   number, not the secret). A variable reference is a use whatever follows it
   (`${TOKEN:-}`, `${TOKEN:?}`, `${TOKEN:0:64}`, `${TOKEN=x}`, `"$TOKEN=1"`),
   and so is a Python dict key, which is an expression (`{token: "host"}`
   sends the token), and a ternary operand after a line ending in `?`.
3. **The sink's own call.** Outside the statement mode the window is the sink
   line and the lines its call continues onto (an open bracket, a trailing
   `,` or `\`), at most five lines. The next function, a docstring, a log line
   or a query after the send is something else. A sink that names a
   destination without sending anything itself (a webhook, callback or tunnel
   URL, an HTTP connection, a socket) adds the lines below that use the name
   it assigns: `url = "https://hook.example/c"`, then `Request(url,
   data=body)`.
4. **The bound value, not a parameter.** In the body of a function declared
   after the source line whose parameter list declares the same name
   (`def ping(url):`, `lambda url: ...`, `function send(token) {`,
   `(token: string) =>`, a method `verify(token) {`), the name is that
   parameter. A Python body is the lines indented under the `def`; a
   C-family body is the braces after the header, or an arrow's expression.
   A function called with the bound value, or a name assigned from it,
   within the rule's window (`send(token)`, `send(t)` after `t = token`)
   passes it on, and does not shadow it; neither does a parameter whose
   default is the bound value (`def ping(url=url):`).
5. **One more hop, where the word reading linked.** A name assigned from the
   bound one between the source and the send (`encoded =
   urlencode(data)`, `payload = JSON.stringify({ v: body })`) is followed when
   the word reading's window (the sink line and the four lines after it)
   names the bound name in its code. That keeps the exfiltration whose send
   repeats the source's name as a keyword or key (`data = dict(os.environ)`
   … `Request(url, data=encoded_data)`), and makes no link the word reading
   did not make: the same flow with the variable called `env` was never
   linked and is not now. Following every derived name would be the taint
   propagation ADR-0005 keeps out of the engine, and would link every client
   built with a key (`client = Client(token)`).
6. **A same-line link is code.** A source and a sink on one line (or, in the
   statement mode, a source on a line of the same call) link unless the
   source or the sink matched only the line's comment, checked against the
   rule's own pattern with the comment blanked:
   `curl -fsS https://status.example.com/health   # MCP_TOKEN is only for the local server`
   is a request with a note beside it.
7. **Source maps are not linked.** A `.map` file holds other files' source
   as JSON string data, one line of it megabytes long, and none of it runs.

`DROPPER-CHAIN-001` links only through a file the download wrote, and reads
the launch line for the program it runs (`launched_operands`, the same
shapes as `CODE-RUNFILE-001`: the first element after the interpreter in
`subprocess.run([sys.executable, PATH])`, the `Start-Process` or
`os.startfile` operand, `execFile`'s first argument, the variable after
`bash`/`sh`/`python`/`node`). A downloaded CSV handed to a converter, a path
in `cwd=` or `--input`, a `[ -s "$FILE" ]` guard and a comment are not the
program. A launch shape the operand reading does not know is read by value
on its whole line; a test keeps the two in step.

| Sink, with the name bound on an earlier line | Links? |
|---|---|
| `url` bound; `requests.get(url=base + "/ping")` | no: the call sends `base + "/ping"` |
| `token` bound; `requests.post(u, json={"token": "x"})` or `{ token: "anonymous" }` in JavaScript | no |
| `token` bound; `requests.post("https://oauth2.example.com/token", data={"grant_type": "client_credentials"})` | no: a word in a string |
| `url` bound; `def ping(url):` / `    return requests.get(url + "/ping")` | no: the parameter |
| `url` bound; `r = requests.get(page)` / `log.debug("fetched %s", r.url)` | no: another object's attribute, on a line after the call |
| `PATH` written by the download; `subprocess.run([sys.executable, build_script], env={"PATH": "/usr/bin"})` | no: the launch runs `build_script` |
| `csv_path` written by the download; `subprocess.run([sys.executable, convert_script, csv_path])` | no: `csv_path` is the converter's input |
| `secrets` swept; `json={"count": len(secrets.splitlines())}` | no: a count |
| `api_key` bound; `requests.post(u, json={"k": api_key})` | yes |
| `token` bound; `data=token`, `f"...{token}"`, `f"...{token:>40}"`, `f"{token=}"`, `requests.post(u, token)`, `token=token`, `params={"token": token}`, `json={token: 1}` | yes |
| `TOKEN` bound; `curl -d "k=${TOKEN:-}" ...` | yes |
| `token` bound; `fetch(u, { body: token })`, `axios.post(u, { token })` | yes |
| `data = dict(os.environ)`; `encoded = urlencode(data)`; `requests.post(u, data=encoded)` | yes (one hop, the keyword repeats `data`) |
| `token` bound; `def send(token): requests.post(u, data=token)` and later `send(token)` | yes |
| `token` bound; `headers={"Authorization": token}` | the name is used, and `AGENTSC-CHAIN-001` (no `sink_excludes`) links it; `EXFIL-CHAIN-001` does not, because of its `sink_excludes`, as before |

`"name_uses": "word"` links on any whole-word occurrence in the sink line and
the four lines after it, keyword names, strings and comments included. That
is how `EXFIL-CHAIN-001`, `DROPPER-CHAIN-001`, `AGENTSC-CHAIN-001`,
`AGENTSC-CHAIN-002` and `DESER-CHAIN-001` linked before the field existed;
`TLS-CHAIN-001` already read names as values in its statement window. A rule
that leaves the field out keeps the behaviour it had: `"value"` with
`sink_window_before`, `"word"` without it, so a custom pack links as it did.
The corpus digest (`sigil scan --format json` reports it as
`scanner.corpus_digest`, and the scan cache is keyed on it) includes each
chain's `name_uses`, so a scan cached under one reading is not served under
another.

### Custom packs

Any `name_uses` value other than `value` or `word` refuses the pack. An
unknown key on a correlation rule or on its `source` or `sink` selector (a
`notes` field for the owning team, a misspelt `name_use` or `rule_idz`), and a
selector that names no rule, do **not**: earlier versions accepted any key on
a correlation rule, and a signed pack cannot be edited without re-signing it.
A scan loads the pack, ignores the key and prints a warning on stderr,
whatever the output format:

```
warning: rule pack acme.json: correlation_rules[0] (ACME-CHAIN-001): unknown key 'notes' (known keys: ...) — ignored; `sigil rules validate` rejects it
```

`sigil rules validate`, `sigil config --validate` (for the packs a policy
names) and `sigil rules sign` reject it, with a "did you mean" hint for a
near-miss. That is the line the other unknown keys follow: an unknown key on
a content rule or at a pack's top level was already an error everywhere, and
still is.

### What the value reading still gets wrong

These are known and measured only on the probes below (synthetic inputs):

- **Misses it shares with the word reading.** A secret forwarded under
  another name before the send (`t = token`, then `data=t`), a walrus or a
  destructuring on the source line (`if (token := ...)`, `const {
  SERVICE_TOKEN: token } = process.env`), a `headers` or `**kw` dict built
  above the send, two hops where the send does not repeat the source's name,
  and a template-literal URL the network rules do not match. None of these
  linked with cff3fa2 either.
- **`sink_excludes` still read the five-line window.** An `Authorization`
  header on a line after the send still keeps `EXFIL-CHAIN-001` quiet, as it
  did with cff3fa2. Reading the excludes over the sink's call alone would add
  links cff3fa2 did not make, which this change does not do.
- **Heuristics that fall back to linking.** A function header the shadowing
  check does not recognise (a Java or Go method, a parameter list over
  several lines), a Python docstring line indented less than its `def`, and a
  launch shape the operand reading does not know all leave the name read as
  the bound value, as before.
- **Heuristics that can hide a use.** A function whose parameter shares the
  bound name is treated as shadowing it unless it is called, within the
  rule's window of the source, with the bound value or a name assigned from
  it (`t = token`, `send(t)`); a call further away or through two aliases is
  not seen. A JavaScript regular-expression literal is recognised where a
  value is expected and when it closes within 256 bytes on its line; one
  after `return`, or longer, is read as code, and a quote inside it then
  opens a string to the end of the line. A one-hop follow needs the word
  reading's coincidence (see 5 above).
- **Counts are not values.** A count of a secret's lines is not reported as
  exfiltration; its length is still information about it.

## The attack probes

The first cut of the value reading (commit 8f77c2d) read names as values in
the old window: the sink line and the four lines after it, strings and
comments included. Two review lenses then attacked it, one for true links it
had lost and one for false links it had kept, and reported 20 findings. Every
probe they wrote was scanned again with the release build of cff3fa2 (before
any value reading), and with the final build of this change; the 8f77c2d
column is the earlier run of the same probes with the same harness.

```
Data Source: Synthetic test. Hand-written probe files: 144 from the recall
             lens, 119 from the false-positive lens, 23 written for this
             change (the edges of its fixes); 2 custom packs; 8 long-line
             timing files. Every probe is scanned as a directory with
             `sigil --format json scan <dir> --no-cache` and an empty HOME.
Sample Size: 286 probe trees: 203 where the chain is the right answer, 83
             where it is not.
Limitations: Synthetic: the probes show which shapes each build links, not
             how often those shapes occur in real code. The lenses wrote them
             against the first cut, so they concentrate on its edges. The
             8f77c2d column has no result for this change's own 23 probes.
             "Right" means the probe's target chain fires on a true probe and
             does not fire on a clean one; the verdict can still be HIGH or
             CRITICAL on other rules.
```

The findings, and how many of each finding's probes each build gets right
(a probe can count under more than one finding; the last row counts each
once):

| Lens | # | Finding | Probes (true + clean) | cff3fa2 right | 8f77c2d right | final right |
|---|---|---|---|---:|---:|---:|
| recall | 0 | f-string / str.format field with a spec, a conversion or `=` | 17 (17 + 0) | 17/17 | 3/17 | 17/17 |
| recall | 1 | shell parameter expansion with a modifier (`${VAR:-}`, `${VAR:?}`, `${VAR:0:N}`, `${VAR=x}`, `$VAR=`) | 15 (15 + 0) | 15/15 | 2/15 | 15/15 |
| recall | 2 | two hops, where the send's keyword or key repeats the source's name | 12 (11 + 1) | 10/12 | 0/9 | 10/12 |
| recall | 3 | a Python dict whose key is the variable | 3 (3 + 0) | 3/3 | 0/3 | 3/3 |
| recall | 4 | a JS ternary operand after a line that ends in `?` | 2 (2 + 0) | 2/2 | 1/2 | 2/2 |
| false positive | 0 | the window ran past the sink's call (the next function, a docstring, a log line, a query) | 23 (0 + 23) | 0/23 | 0/23 | 23/23 |
| false positive | 1 | a word inside a string literal (a token endpoint, an OAuth grant, escaped JSON, a format placeholder) | 14 (0 + 14) | 0/14 | 0/14 | 14/14 |
| false positive | 2 | DROPPER-CHAIN-001 on a data file, `cwd=`, a guard or a comment on the launch line | 9 (2 + 7) | 2/9 | 2/9 | 9/9 |
| false positive | 3 | a comment on the sink line | 12 (2 + 10) | 2/12 | 0/8 | 12/12 |
| false positive | 4 | an attribute of another object (`r.url`) | 3 (1 + 2) | 1/3 | 1/3 | 3/3 |
| false positive | 5 | a function parameter of the same name | 16 (9 + 7) | 9/16 | 1/5 | 16/16 |
| false positive | 6 | a destructuring target or an export list | 5 (1 + 4) | 1/5 | 0/3 | 5/5 |
| false positive | 7 | TypeScript member syntax (`token?:`, `private token:`, a member after `;`) | 4 (0 + 4) | 0/4 | 0/4 | 4/4 |
| false positive | 8 | a shell default expansion on a real send (true) | 4 (4 + 0) | 4/4 | 1/4 | 4/4 |
| false positive | 9 | a Python dict with a variable key (true) | 1 (1 + 0) | 1/1 | 0/1 | 1/1 |
| all | | every probe | 286 (203 + 83) | 198/286 | 152/263 | 279/286 |

With the final build every true probe keeps the verdict it had with cff3fa2
and every chain it had; no probe gains a chain; 79 of the 83 clean probes
drop a level (58 from CRITICAL to LOW RISK). The four that do not: two never
linked (`fp/py14_argparse_dest_after_sink`, `xv/th_client_receiver`), and two
lose the chain but keep their level on other rules (`fp/py29_keyfile_handle_comment`
reads `~/.ssh/id_rsa`, CRED-005 Critical on its own; `fp/dr08_js_execfile_data_arg`
is HIGH on CODE-007 and CODE-014).

Seven true probes link with none of the three builds; they are the misses
listed under "What the value reading still gets wrong": a headers dict built
above the send (`sink_excludes`), a secret forwarded under another name
(`t = token`), a walrus and a destructuring on the source line, a `**kw` dict
built above the send, a two-hop flow whose send does not repeat the source's
name, and a template-literal URL NET-004 does not match.

The findings that are not probe shapes:

| Lens | # | Finding | cff3fa2 | 8f77c2d | Final |
|---|---|---|---|---|---|
| recall | 5 | An unknown key on a custom pack's correlation rule refuses the pack | loads, key ignored silently | refused: the scan exits 2 with no report | loads; the scan warns on stderr and ignores the key; `sigil rules validate`, `sigil config --validate` and `sigil rules sign` reject it (tested in `tests/customisation.rs`) |
| recall | 6 | The docs and a test said "two f-string forms" were the only cost | n/a | the lost set was a class (specs, shell expansions, dict keys, ternaries, two-hop coincidences) | fixed in code; the test now asserts the links (`format_fields_send_the_value`), and this page lists what is still missed |
| false positive | 10 | DROPPER-CHAIN-001 same-line links on one-line `.js.map` source maps (two unseen MCP servers) | fires | fires | not linked: a `.map` file is not read by value (measured below) |
| false positive | 11 | The headline overstated the fix; a misspelt selector key (`rule_idz`) leaves the chain silently empty | n/a | silent | docs scoped to what is implemented; a selector key is checked like a rule key, and a selector that names no rule is reported (warning in a scan, error in validation) |
| false positive | 12 | A blank line broke the results table in `evaluation_results/skills_benchmark/README.md` | n/a | broken | fixed |

The two custom-pack probes (a pack whose correlation rule carries a `notes`
key, and the same pack without it), scanned against the reported file:

| Pack | cff3fa2 | Final |
|---|---|---|
| with `notes` | loads; CRITICAL RISK (`ACME-CHAIN-001`, `EXFIL-CHAIN-001`); `rules validate` exit 0 | loads with a warning naming the key; HIGH RISK (`ACME-CHAIN-001` alone: the custom chain leaves `name_uses` out and links by word, as it did); `rules validate` exit 1 |
| without | loads; CRITICAL RISK (`ACME-CHAIN-002`, `EXFIL-CHAIN-001`) | loads; HIGH RISK (`ACME-CHAIN-002`) |

### Long lines

The value reading looks at every occurrence of the bound name that is not a
use, so a line that repeats the name thousands of times in such a shape is
its worst case. The interrupted work-in-progress commit (5f3fef0) re-read the
line, or the text before the occurrence, for each one: on a 20,000-repetition
line (about 200 KB) a Python key after `(` took 2.01 s against 0.55 s for
cff3fa2, and a destructuring target 5.64 s against 0.60 s, growing with the
square of the length. Correlation runs after the per-file time budget, so
nothing would have cut it short. The final build works out the open bracket
and each line's facts once, caps how far it reads back over a receiver, a
member chain or a regular expression, and is covered by a timing test
(`long_lines_stay_linear`, profile-aware limits).

```
Data Source: Synthetic test: 8 generated one-file trees, each a credential
             read and one long sink line (or 100,000 sink lines).
Sample Size: 8 files, each scanned once per build (wall time).
Limitations: One run each on a machine shared with another workflow; the
             times are indicative. The 5f3fef0 figures are from the smaller
             20,000-repetition files.
```

| Line (one file each) | cff3fa2 | Final |
|---|---:|---:|
| Python, `token: 1, ` 500,000 times inside `(...)` (5 MB) | 1.55 s | 1.52 s |
| Python, `r.token, ` 500,000 times (4.5 MB) | 1.39 s | 1.45 s |
| JavaScript destructuring target, `token, ` 500,000 times (3.5 MB) | 1.17 s | 1.34 s |
| JavaScript export list after the send, `token, ` 500,000 times (3.5 MB) | 1.13 s | 1.23 s |
| JavaScript object keys, `token: 1, ` 500,000 times (5 MB) | 1.46 s | 1.50 s |
| `token`, 1,000 blanks, `: 1,`, 5,000 times (5 MB) | 1.31 s | 1.42 s |
| `(/[` 500,000 times, patterns that never close (1.5 MB) | 0.83 s | 1.31 s |
| 100,000 sink lines, each `fetch(..., { token: 1 })` | 2.84 s | 2.95 s |

Every file but the `(/[` one is CRITICAL RISK with cff3fa2 (the keys and
names link) and LOW RISK with the final build.

### Every probe

The verdict of every probe with each build; ", chain" means the probe's
target chain fired. The probe files are not reproduced here.

<details>
<summary>286 probes</summary>

| Probe | Expected | Chain | cff3fa2 | 8f77c2d | final |
|---|---|---|---|---|---|
| `recall/p00_reported_fp` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `recall/py01_kw_same_name` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py02_apikey_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py03_data_data` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py04_kw_same_spaced` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py05_fstr_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py06_fstr_spec_s` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py07_fstr_conv_r` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py08_fstr_empty_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py09_fstr_trunc_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py10_fstr_selfdoc` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py11_fstr_nested_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py12_fstr_conv_and_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py13_fstr_body_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py14_percent` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py15_percent_dict` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py16_format_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py17_format_positional` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py18_dict_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py19_kwargs_splat` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py20_dict_spread` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py21_dict_var_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py22_dict_var_key_multiline` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/py23_self_attr` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py24_subscript` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py25_attr_of_bound` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py26_headers_prev_line` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `recall/py27_forward_one_hop` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `recall/py28_multiline_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py29_multiline_value_next_line` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py30_multiline_dict_value_next` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py31_lambda` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py32_comprehension` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py33_conditional` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py34_slice` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py35_annotated_source` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py36_annotated_source_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py37_walrus_source` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `recall/py38_two_hop_data_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | CRITICAL, chain |
| `recall/py39_two_hop_json_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | CRITICAL, chain |
| `recall/py40_two_hop_params_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | CRITICAL, chain |
| `recall/py41_two_hop_files_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/py42_b64` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py43_json_same_key_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py44_keyword_url_real` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py45_ne_compare` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py46_template` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py47_template_locals` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py48_fstr_spec_multi` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/js01_shorthand` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js02_key_same_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js03_template` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js04_template_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js05_spread` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js06_computed_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js07_ternary` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js08_ts_typed_source` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js09_multiline_value_next` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js10_multiline_ternary` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js11_stringify_shorthand` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js12_fetch_body_var_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js13_fetch_body_key_same_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js14_urlsearchparams` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js15_or_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js16_destructure_source` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `recall/js17_arrow_param_shadow` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js18_object_assign` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js19_body_key_same_name_two_hop` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/sh01_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh02_braced` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh03_default_expansion` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/sh04_substring_expansion` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/sh05_error_expansion` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/sh06_kv` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh07_same_name_kv` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh08_json_escaped` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh09_default_expansion_url` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/sh10_dollar_then_eq` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/ag01_py_data` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag02_py_kw_same` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag03_py_fstr_spec` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/ag04_sh_default_expansion` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/ag05_sh_plain` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag06_js_shorthand` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag07_py_two_hop_data_kw` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/ag21_sh_form` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag22_sh_form_default_exp` | true | AGENTSC-CHAIN-002 | HIGH, chain | MEDIUM | HIGH, chain |
| `recall/ag23_py_open` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag24_py_key_same_value` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag25_py_tuple` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag26_py_data_kw_same` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr01_py_basic` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr02_py_same_name_env_key_and_positional` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr03_py_fstring` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr04_sh_basic` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr05_sh_braced` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr06_ps_start_process` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr07_py_urlretrieve_kw` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr08_startfile` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr09_execfile_js` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de01_basic` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de02_kw_f` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de03_kw_same_name` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de04_fstring_spec` | true | DESER-CHAIN-001 | HIGH, chain | LOW | HIGH, chain |
| `recall/de05_open_handle` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de06_pathlib` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de07_multiline` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/s3_sh_mcp_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/s3_sh_mcp_error` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/s3_sh_mcp_substr` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/s3_sh_mcp_assign_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `recall/s3_sh_mcp_alt` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_nocolon_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_set_u_idiom` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_js_ternary_trailing` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_py_fstr_selfdoc_conv` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_py_fstr_table` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_py_format_locals_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_py_format_locals_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_fstr_space_colon` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_py_dict_var_key_after_comma` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/s3_py_walrus_in_sink` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_urlopen_encode` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_httpclient_body` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_socket_send` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_json_dumps_same_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_kwargs_prev_line` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `recall/s3_js_template_url_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_js_multiline_shorthand` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_js_key_same_multiline_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_dr_popen_kw_same` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/s3_dr_run_list_env_key_same` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/b4_sh_export_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `recall/b4_py_kw_value_next_line` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_conv_then_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_js_quoted_key_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_de_conditional` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/b4_py_discord_embed` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_fstr_in_embed_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `recall/b4_py_percent_named_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_env_copy_kw_json` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_env_two_hop_body` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | CRITICAL, chain |
| `recall/b4_py_env_two_hop_var_named_body` | true | EXFIL-CHAIN-001 | MEDIUM | MEDIUM | MEDIUM |
| `fp/py01_reported_example` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/py02_login_fallback_subscript` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py03_login_fallback_get` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py04_attribute_access` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py05_next_function_header` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py06_shadowing_parameter` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py07_comment_on_sink_line` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py08_docstring_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py09_oauth_password_grant_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py10_token_endpoint_path` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py11_str_format_placeholder` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py12_percent_mapping` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py13_escaped_json_body` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py14_argparse_dest_after_sink` | clean | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `fp/py15_pydantic_alias_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py16_dataclass_field_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/py17_logging_string_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py18_orm_filter_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py19_response_type_token_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py20_decorator_route_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py21_self_attr_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/py22_value_true_control` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/js01_destructure_response` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js02_destructured_param_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/ts01_optional_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/ts02_class_field_modifier` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/ts03_interface_semicolons` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js03_token_endpoint_path` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js04_searchparams_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js05_axios_type_token_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js06_line_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js07_computed_key_control` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/js08_block_comment_key` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js09_ternary_key` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/js10_yaml_list_in_template` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/dr01_data_file_arg_py` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/dr02_shell_check_then_run` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/dr03_literal_data_path` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/dr04_cwd_kw_value` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/dr05_comment_on_launch` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/dr06_true_control` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/de01_bundled_labels_after_sink` | clean | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/de02_comment_on_sink` | clean | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/de03_true_control` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/ag01_shell_escaped_json_key` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH |
| `fp/ag02_shell_after_sink` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH |
| `fp/ag03_shell_comment` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH |
| `fp/ag04_py_inline_count` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH |
| `fp/ag05_shell_default_expansion_true` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `fp/ac01_cleanup_after_upload` | clean | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | MEDIUM |
| `fp/ac02_echo_after_upload` | clean | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | MEDIUM |
| `fp/ac03_true_control` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/sh01_mcp_token_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/sh02_mcp_token_default_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/py14b_argparse_dest_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py23_all_exports_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py24_lambda_shadow` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py25_fstring_log_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py26_toml_in_string_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/py27_nested_kw_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/py28_multiline_then_use` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py29_keyfile_handle_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL |
| `fp/py30_value_multi_line_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/js11_module_exports_shorthand` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js12_export_list` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js13_ts_arrow_param_annot_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/js14_jsx_prop_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/js15_template_literal_true` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW |
| `fp/js16_body_json_stringify_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/ts04_type_alias_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/dr07_env_key_fixed` | clean | DROPPER-CHAIN-001 | HIGH, chain | LOW | LOW |
| `fp/dr08_js_execfile_data_arg` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH |
| `fp/dr09_shell_true_control` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/dr10_py_log_kw_value` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/ag06_py_after_sink_len` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH |
| `fp/ag07_py_key_fixed` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH |
| `fp/ag08_shell_default_colon_q_true` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain |
| `fp/ac04_upload_other_same_dir` | clean | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | MEDIUM |
| `fp/de04_log_after_sink` | clean | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW |
| `fp/de05_kw_fixed` | clean | DESER-CHAIN-001 | HIGH, chain | LOW | LOW |
| `fp/md01_skill_prose_after_curl` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py31_graphql_field` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py32_getattr_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py33_def_param_on_sink_line` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/py34_django_filter_kw_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW |
| `fp/js17_url_obj_property` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW |
| `fp/sh03_env_key_prefix_fixed` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH |
| `fp/lt01_py_dict_variable_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | CRITICAL, chain |
| `fp/lt02_shell_cred_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL, chain |
| `fp/lt03_js_ts_non_null` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py00` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py01` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py02` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py03` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py04` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py05` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py06` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py07` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py08` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py09` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py10` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js00` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js01` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js02` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js03` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js04` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_keyfile` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_one_hop_webhook` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_httpclient_conn` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_socket` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_shell_curl_d` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_shell_curl_continued` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_tar_upload` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_tar_upload_py` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_py_open` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_literal` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_ps_fstring` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_shell` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_deser_kw` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain |
| `xv/sh_def_called_with_token` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_def_ended_module_send` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_lambda_after_real_use` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_default_is_bound` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_js_function_called` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_js_arrow_called` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_js_function_ended` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_def_called_with_forwarded` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/rx_js_regex_quote_then_send` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/sh_class_method_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/sh_js_callback_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/sh_ts_arrow_typed_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/cm_py_source_in_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/cm_py_sink_in_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/cm_py_same_line_real` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/cm_sh_same_line_real` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/ct_positional_continuation` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/ct_tuple_assignment_target` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/th_data_encoded_plain_host` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/th_json_payload` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |
| `xv/th_client_receiver` | clean | EXFIL-CHAIN-001 | LOW | - | LOW |
| `xv/rp_reported_example` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | - | LOW |
| `xv/rp_reported_value_twin` | true | EXFIL-CHAIN-001 | CRITICAL, chain | - | CRITICAL, chain |

</details>

## Measurements

Every corpus was scanned sample by sample with the release build of cff3fa2
(the base, before any value reading) and with the final release build of
this change (d89c600), and compared in both directions: every level change,
every change of rule set or finding count, every chain that moved.

```
Data Source: Real samples. Clean MCP servers: 169 packages from the official
             MCP registry (evaluation_results/corpora/mcp_clean_manifest.json),
             and 146 other popular registry servers not used for calibration
             (the holdout corpus; its manifest is on the ws/holdout branch).
             Skills: Datadog malicious-software-packages-dataset ai-skills
             bucket (204 malicious); anthropics, NVIDIA, openai and
             vercel-labs skill catalogs (455 clean). Datadog: run_eval.py's
             selection of the malicious-software-packages-dataset (--limit
             204). SkillSpector's own test suite (the parity corpus).
Sample Size: 169 + 146 MCP servers; 204 malicious and 455 clean skills;
             844 Datadog malicious packages; 1,796 SkillSpector test
             examples.
Limitations: The MCP (169) and skills corpora are in-sample for the rules
             around the chains. Only a handful of samples in any corpus
             carry a chain, so these corpora show what moved on real code,
             not how often each probe shape occurs. "Clean" means published
             by a vendor or in the registry, not audited. Datadog is
             malicious packages only, scanned with run_eval.py's six detection
             phases; its per-sample comparison is a script that imports
             run_eval.py's selection, extraction and reduction and runs its
             scan command with each build and an empty HOME. The machine was
             shared with another workflow; the first run of the final build
             on the two MCP corpora had two files cut short by the 30 s
             per-file budget (see below), and those corpora were run again.
```

| Corpus | cff3fa2 | Final | Level changes, either direction | Chains that moved |
|---|---|---|---|---|
| Clean MCP servers (169) | 39 blocked, 125 warned, 163 with any finding | the same | none | none; no chain fires with either build |
| Unseen MCP servers (146) | 80 blocked, 135 warned, 144 with any finding | the same | none | DROPPER-CHAIN-001 no longer fires on 2 servers (below); every other finding is the same |
| Malicious skills (204) | 173 blocked, 184 warned, 190 with any finding | the same | none | none: EXFIL-CHAIN-001 on 4 and AGENTSC-CHAIN-002 on 4 with both builds, at the same file and line |
| Clean skills (455) | 7 blocked, 71 warned, 224 with any finding | the same | none | none: TLS-CHAIN-001 on 1 (openai `render-deploy`) with both |
| Datadog malicious packages (844) | detected at any severity 785, ≥ Medium 761, ≥ High 752, ≥ Critical 561 | the same | none (no highest severity changes) | none: every package has the same rules, finding count and chain findings (rule, file, line); EXFIL-CHAIN-001 on 40, DROPPER-CHAIN-001 on 7, DESER-CHAIN-001 on 16, AGENTSC-CHAIN-002 on 4, TLS-CHAIN-001 on 1 with both |
| SkillSpector's test examples (1,796) | 626 flagged at any severity, 385 at High or above | the same | none | none: every example has the same rule set; EXFIL-CHAIN-001 on 9 with both |

Blocked is HIGH or CRITICAL RISK, warned MEDIUM RISK or above.
`scripts/run_eval.py --dataset datadog --limit 204` itself, run with the
final build and an empty HOME (dataset commit 1dbcfc5), gives the same figures: 844 scanned, no
extraction failure or scan error, 785 / 761 / 752 / 561 at any / Medium /
High / Critical.
The final build's per-sample outputs are in
`evaluation_results/skills_benchmark/` (`*_exfilchain*`, and
`datadog_exfilchain_diff.json` for the Datadog comparison) and
`evaluation_results/honest_detection_eval_exfilchain.{md,json}`.

### What moved

**Two DROPPER-CHAIN-001 findings on the unseen MCP servers, removed: false
positives.** `com.vibgrate__ai-context` (`package/dist/cli.js.map`, one line of
2.7 MB) and `dev.jasonpearson__auto-mobile` (`package/dist/src/index.js.map`,
one line of 13.4 MB) each carried `NET-012 (@L1) reaches CODE-RUNFILE-001
(@L1)`: a same-line link inside a source map, whose `sourcesContent` embeds
the source of many modules as JSON string data, so a `curl` in one module and
a launch in another sit on the same "line". Nothing in a source map runs.
Both servers stay CRITICAL RISK on other rules, with one finding fewer each.

**Nothing else.** The first cut of the value reading lost EXFIL-CHAIN-001 on
17 Datadog packages (artifact-lab-3-package and twelve renamed copies, which
encode `dict(os.environ)` into `encoded_data` before `Request(url,
data=encoded_data)`); the one-hop follow restores all 17, at the same line. No
clean MCP server, clean skill or SkillSpector example carried a chain that the
probes' false-positive shapes describe, so the real corpora show that the
value reading costs nothing measurable, not how often those shapes occur; the
reported file and the probes above are that evidence.

**A run that was redone.** The first run of the final build on the two MCP
corpora ran beside a debug build of the test suite, and two large files hit
the 30 s per-file budget (`io.github.SAP__fiori-mcp-server`, 106 findings
with cff3fa2 and 92 plus PROV-BUDGET-001 in that run;
`dev.jasonpearson__auto-mobile`, 95 and 36 plus PROV-BUDGET-001). Neither
changed level. Both corpora were run again with the final build on a quieter
machine; that run has no truncation and is the one compared above and
published. No cff3fa2 run, skills run, parity run or Datadog scan was
truncated.
