# Correlation chains, source maps and one-line programs

A correlation chain links a source finding to a sink finding in the same file
(`cli/src/scanner/correlate.rs`). When both sit on the *same line* the link
needs no shared name, because on ordinary code one line is one statement.
That stops being true where one line holds a whole program. `TLS-CHAIN-001`
therefore sets `max_line_length: 500`. The five older chains (`EXFIL-CHAIN-001`
and `DROPPER-CHAIN-001` in `network_exfil.json`, `AGENTSC-CHAIN-001/002` in
`agent_supply_chain.json`, `DESER-CHAIN-001` in `code_patterns.json`) set no
cap.

This note records why they still set none, and why source maps are now left
out of correlation altogether. Every number below comes from a command that
was run; the commands are at the end.

```
Data Source: Real samples.
             Clean MCP servers: the 169 of evaluation_results/corpora/mcp_clean_manifest.json
                    (rebuilt from the manifest, 169/169 archives sha256-verified).
             Unseen MCP servers: a reconstruction of the 146-server holdout in
                    docs/detection/insecure-transport.md, rebuilt to its documented
                    selection (see "The holdout reconstruction"): 157 servers,
                    evaluation_results/corpora/mcp_holdout_manifest.json.
             Skills: 204 malicious (Datadog ai-skills bucket, dataset commit 0f6b305b)
                    and 455 vendor skills (anthropics/skills 34040c9, NVIDIA/skills
                    0f72c29b, openai/skills 49f948f, vercel-labs/agent-skills 063bee9).
             Malicious packages: Datadog malicious-software-packages-dataset at
                    0f6b305b, run_eval.py selection (--limit 204 per bucket).
Sample Size: 169 + 157 MCP servers; 204 + 455 skills; 844 malicious packages.
Limitations: "Clean" means published by a vendor or popular in the registry, not
             audited. The holdout is a reconstruction, not the original 146
             (their manifest was never published): same recipe, a registry
             snapshot four days later, 157 servers. Static analysis only. The
             benchmark runs ran one at a time; the three Datadog runs ran side
             by side. The before and after Datadog results are identical sample
             by sample, so load moved nothing there.
```

## What was seen

On the unseen MCP servers, two clean servers carried `DROPPER-CHAIN-001` at
High, each as a same-line link on a one-line source map:

| Server | File | Line length | "Download" (`NET-012`) | "Launch" (`CODE-RUNFILE-001`) |
|---|---|---:|---|---|
| `com.vibgrate/ai-context` | `dist/cli.js.map:1` | 2,671,547 B | a code comment, `curl when available; avoid hard dependency on fetch…`, at byte 1,671,657 | `execFile(file, args, { timeout: … })` at byte 2,590,681 |
| `dev.jasonpearson/auto-mobile` | `dist/src/index.js.map:1` | 13,438,312 B | a log message, `curl unavailable, falling back to wget`, at byte 897,826 | an `execFile(file, args, options, callback)` wrapper at byte 357,071 |

Neither is a download that is then run: in the original sources the two ends
are in different functions, hundreds of kilobytes apart, and share no name.
A source map stores each original file as one JSON string in
`sourcesContent`, so every line of the program is "line 1". Both servers are
CRITICAL RISK on other rules, so neither verdict moved, but each chain was a
false High.

## The probe

A matrix of hand-built packages, scanned with the build of the #168 branch head
(`ef0b95f`). `DROPPER-CHAIN-001` findings per case:

| Case | Line | Before | Source maps skipped | + cap of 500 |
|---|---:|---:|---:|---:|
| One-line map of a shell script: `curl … -o "$X"`, then `bash "$X"` | 207 B | 0 | 0 | 0 |
| The same shell script as a file | 47 B | 0 | 0 | 0 |
| One-line map of a download and a `; bash '$X';` launch | 318 B | 1 | **0** | 0 |
| The same map with a realistic `mappings` string | 2,318 B | 1 | **0** | 0 |
| The same code minified onto one short `.js` line | 196 B | 1 | 1 | 1 |
| The same code on one long `.js` line | 916 B | 1 | 1 | **0** |
| The real FP shape (a `curl … https://` help string, and `execFileSync(adbPath, …)` 150 lines later) as a map | 4,032 B | 1 | **0** | 0 |
| The same, as the original multi-line `.ts` | 86 B | 0 | 0 | 0 |
| The same, minified onto one `.js` line | 3,764 B | 1 | 1 | **0** |

The first case is the one the question named, and it does not chain at all. In
JSON, `bash "$X"` is written `bash \"$X\"`, and `\n` is two characters rather
than a line start, so the launch rule's shell form (an interpreter at the start
of a line or after `;`, `&`, `|`, `(`, `then` or `do`, then a variable) cannot match
inside a map. The plain script does not chain either: one-letter names are
never bound (they collide with the `f`/`r`/`b` string prefixes; see
`push_binding`). The launch shapes that do survive JSON escaping are a
`;`-separated, single-quoted shell launch and `execFile(<name>, …)`, and
`execFile(<name>, …)` is ordinary JavaScript. That shape is what fired in both
real maps.

A short one-line map (318 bytes) still links under a 500-byte cap: a cap does
not describe what a source map is.

## Where the chains sit

Every correlation chain the #168 build reports on these corpora, with the
length of its source and sink lines:

| Corpus | Chains | On a line over 500 B | In a `.map` |
|---|---|---|---|
| Clean MCP (169) | none | — | — |
| Unseen MCP (157) | `DROPPER-CHAIN-001` ×2 (2 servers) | 2 | 2 |
| Skills (204 + 455) | `AGENTSC-CHAIN-002` ×4, `EXFIL-CHAIN-001` ×4 (malicious); `TLS-CHAIN-001` ×1 (clean) | 0 | 0 |
| Datadog (844) | `EXFIL-CHAIN-001` ×49 (40 samples), `DESER-CHAIN-001` ×17 (16), `DROPPER-CHAIN-001` ×15 (7), `AGENTSC-CHAIN-002` ×4 (4), `TLS-CHAIN-001` ×3 (1) | 15, all `EXFIL-CHAIN-001`, in 9 samples | 0 |

Outside the two maps, every chain sits either on a line of at most 114 bytes
or on one of at least 7,101 bytes, so any cap from 115 to 7,100 bytes removes
exactly the same chains as the 500 measured below.

**The droppers the chain was written for** are all short-line, cross-line
links: guardrails-ai 0.10.1 (79 → 37 bytes), durabletask 1.4.1, 1.4.2 and
1.4.3 (96 → 114), and the antibyfron, artindex and automsg
`Start-Process "{output_file}"` droppers (106 → 73). A cap of 500 keeps all
15 findings in all 7 samples.

**The long-line `EXFIL-CHAIN-001` links** are all in malicious packages, and
in all 9 samples every EXFIL chain is on a long line, so a cap removes the
chain from each:

- `asyncmodules` 2.3.5, `assaulthimars` 1.3.5, `assulthimars` 1.3.5 (PyPI):
  line 134 is `exec(invoke('<7 KB of base64>').decode())`. The scanner decodes
  the blob (a Telegram session stealer) and reports every decoded finding on
  the line that holds it. The chain, a hardcoded Telegram bot token (CRED-026)
  reaching `requests.post` (NET-001), is real. It is "same-line" because a
  decoded payload always is.
- Six compromised `@automagik/genie` releases (npm): `dist/genie.js:3119`
  (19,796 B) and `plugins/genie/scripts/genie.cjs:183` (11,071 B) are
  minified. The "credential read" is `env: {...process.env, FORCE_COLOR: "1"}`
  handed to a child process (CRED-ENV-001), and the "send" is a `console.log`
  reinstall hint, `curl -fsSL https://…/install.sh | bash` (NET-012), 4,200
  to 13,000 bytes further along the line. That is the same coincidence as the
  source maps, inside a malicious package.

## Decision

1. **Source maps are not correlated.** It applies to every chain, including
   `TLS-CHAIN-001`. Nothing in a source map runs, and the compiled file it
   describes is scanned and correlated on its own. A file qualifies only when
   it is named `*.map` and its whole content is one JSON object with
   `mappings` (or `sections`, for an index map), optionally after the
   `)]}'` guard line the format allows. A script given the extension
   (`node lib/x.map`, `python3 x.map`, or a real map followed by code) is not
   JSON as a whole and is correlated like any other file. A map over the 10 MB
   whole-file limit reaches correlation as its first 2 MB, which never closes
   the JSON, so for such a file the check streams the whole file from disk.
   `auto-mobile`'s 13.4 MB map is that case. A map inside an archive in the
   tree is read up to the 4 MB member cap and no further, so there is no
   file to go back to. There, the part that was read is judged: it must be
   one JSON object, complete or still open where the cut falls. Nothing
   after the cut is scanned, and everything before it is inside that object,
   which is data both as JavaScript and as Python. The line findings in a map are
   still reported; `.map` was already a secondary path for the verdict's
   first-party score.
2. **The legacy chains keep no `max_line_length`.** On the droppers a cap is
   neutral, but it removes a real credential-theft chain from three decoded
   stealers, which lowers Datadog recall at Critical from 561 to 558 of 844
   (measured below). It removes nothing on a clean sample that the
   source-map rule does not already remove. It would also be cheap to evade:
   500 bytes of padding on a `curl … -o "$P" && bash "$P"` line turn a High
   chain into two Low observations.

## Re-measurement

Three builds, each run with the same commands on the same inputs:
**before** (#168 head, `ef0b95f`), **source maps skipped** (this change), and
**+ cap** (this change plus `max_line_length: 500` on the five legacy chains,
built only to measure the alternative and not committed).

| | Before | Source maps skipped | + cap |
|---|---:|---:|---:|
| Clean MCP blocked (HIGH or CRITICAL RISK) | 39/169 (23.1%) | 39/169 | 39/169 |
| Clean MCP warned (MEDIUM or above) | 125/169 (74.0%) | 125/169 | 125/169 |
| Clean MCP CRITICAL | 17 | 17 | 17 |
| Unseen MCP blocked | 88/157 (56.1%) | 88/157 | 88/157 |
| Unseen MCP warned | 146/157 (93.0%) | 146/157 | 146/157 |
| Unseen MCP CRITICAL | 52 | 52 | 52 |
| Unseen MCP servers with `DROPPER-CHAIN-001` | 2 | **0** | 0 |
| Malicious skills blocked | 173/204 (84.8%) | 173/204 | 173/204 |
| Malicious skills warned | 184/204 (90.2%) | 184/204 | 184/204 |
| Clean skills blocked | 7/455 (1.5%) | 7/455 | 7/455 |
| Clean skills warned | 71/455 (15.6%) | 71/455 | 71/455 |
| Datadog recall, any finding | 785/844 (93.01%) | 785/844 | 785/844 |
| Datadog recall, ≥ Medium | 761/844 (90.17%) | 761/844 | 761/844 |
| Datadog recall, ≥ High | 752/844 (89.10%) | 752/844 | 752/844 |
| Datadog recall, Critical | 561/844 (66.47%) | 561/844 | **558/844 (66.11%)** |

**Level changes, in both directions:**

- Source maps skipped, against before: none, in any corpus.
- + cap, against before: three, all down, all in the Datadog set:
  `asyncmodules` 2.3.5, `assaulthimars` 1.3.5 and `assulthimars` 1.3.5 go
  from Critical to High. Their real `EXFIL-CHAIN-001` (the decoded Telegram
  stealer above) was their only Critical finding.

**Rule changes at the same level:**

- Source maps skipped, against before: `DROPPER-CHAIN-001` left
  `com.vibgrate/ai-context` and `dev.jasonpearson/auto-mobile`; both stay
  CRITICAL RISK. Nothing else changed in the clean MCP, unseen MCP or skills
  runs (compared sample by sample, rule by rule). The 844
  Datadog samples have identical maximum severity and finding count.
- + cap, against before: the same two removals on the unseen servers; on the
  Datadog set, besides the three level changes, the six `@automagik/genie`
  releases each lose their two coincidental `EXFIL-CHAIN-001` findings and
  stay Critical. Nothing else changed.

The "before" runs match the committed #168 runs sample for sample: every
verdict level and rule set in `mcp_sigil_tls.json` and `sigil_tls.json`
(`evaluation_results/skills_benchmark/`). The Datadog recall equals the
figures in `CHANGELOG.md` and `honest_detection_eval_7826ea1.md`.

## What this does not fix

- **A minified bundle is still one line.** The same coincidence on a long
  minified `.js` line still links (the probe's 3,764-byte case), and it did
  so in the six compromised `@automagik/genie` releases. No clean sample in
  these corpora has it, and the cap that would remove it also removes the
  decoded stealers' chains. A real fix needs match positions, so that two
  matches on one line link only when they are close; findings do not carry
  a column today.
- **A one-letter shell variable does not link** (`curl -o "$X" …` then
  `bash "$X"`), by the existing rule that drops one-character names.

## The holdout reconstruction

`insecure-transport.md` describes the unseen servers as: latest and active in
the official MCP registry, published on npm with at least 5,000 downloads in
the 30 days to 2026-09-21, at least 90 days old, at most 3 per namespace, none
of the 169 in-sample servers and none on Datadog's malicious npm list (148
selected, 146 fetched). Its manifest was not published. Rebuilt to that
recipe from a registry snapshot of 2026-09-25:

- 9,746 active latest entries with an npm package, 9,614 of them not in the
  169;
- 204 with at least 5,000 downloads over 2026-08-22..2026-09-21;
- 163 created on or before 2026-06-23;
- 162 after the Datadog list (`io.github.antvis/mcp-server-chart`: its
  package name is on the list);
- 160 after the per-namespace cap. 157 were fetched; 3 archives are over the
  30 MB download cap.

Both servers named above qualify on the recipe. The count differs from 148:
nine npm packages are registered under two server names each, "30 days to
2026-09-21" is read here as 31 days counting both ends (on the 30-day reading
two more servers drop out), and the registry moved in four days. Every
figure above is on this set of 157. Its manifest
(`evaluation_results/corpora/mcp_holdout_manifest.json`: name, npm package,
version, archive URL and SHA-256 of each server) rebuilds it byte for byte
with `fetch_mcp_clean.py --from-manifest`.

## Reproducing

```bash
# Corpora
python3 evaluation_results/corpora/fetch_mcp_clean.py --out <mcp_clean> \
    --from-manifest evaluation_results/corpora/mcp_clean_manifest.json
python3 evaluation_results/corpora/fetch_mcp_clean.py --out <mcp_holdout> \
    --from-manifest evaluation_results/corpora/mcp_holdout_manifest.json
git clone https://github.com/DataDog/malicious-software-packages-dataset <dd>   # at 0f6b305b
# skills: anthropics/skills, NVIDIA/skills, openai/skills, vercel-labs/agent-skills
# at the commits in the disclosure block; the Datadog ai-skills zips extracted
# one per directory (unzip -P infected) under <mal_skills>/malicious_intent/.

(cd cli && cargo build --release)

SIGIL_BIN=cli/target/release/sigil python3 scripts/benchmark_skills.py --tools sigil \
    --clean <mcp_clean> --clean-sample-depth 1 --workers 3 --out <out>/mcp_clean
SIGIL_BIN=cli/target/release/sigil python3 scripts/benchmark_skills.py --tools sigil \
    --clean <mcp_holdout> --clean-sample-depth 1 --workers 3 --out <out>/mcp_holdout
SIGIL_BIN=cli/target/release/sigil python3 scripts/benchmark_skills.py --tools sigil \
    --malicious <mal_skills> --sample-depth 2 \
    --clean <anthropics_skills> --clean <NVIDIA_skills> \
    --clean <openai_skills> --clean <vercel-labs_agent-skills> --workers 3 --out <out>/skills
SIGIL_BIN=cli/target/release/sigil python3 scripts/run_eval.py --dataset datadog \
    --dataset-path <dd> --out <out>/dd --limit 204
```

The "before" column is the same commands with a build of `ef0b95f`. The
per-sample Datadog comparison comes from the same `run_eval.py` runs: its
`main()` was called through a wrapper that also saved what `evaluate_set`
returned for each sample (maximum severity and finding count), since the
report keeps only the totals.
