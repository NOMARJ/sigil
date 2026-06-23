# corpus-gen — LOLBin / reverse-shell signature pack generator

Generates three Sigil signature packs from upstream living-off-the-land
corpora, so detection content stays sourced from the community references rather
than hand-maintained guesses:

| Pack | Output | Upstream source | License | Distribution |
| --- | --- | --- | --- | --- |
| `lolbin_unix.json` | `packs/lolbin/v1/` | [GTFOBins](https://gtfobins.github.io/) | GPL-3.0 | **Optional bundle** (runtime) |
| `lolbin_windows.json` | `packs/lolbin/v1/` | [LOLBAS](https://lolbas-project.github.io/) | GPL-3.0 | **Optional bundle** (runtime) |
| `reverse_shells.json` | `packs/core/v1/` | [reverse-shell-generator](https://www.revshells.com/) | MIT | Embedded in binary |

> **Licensing split (deliberate).** Sigil is Apache-2.0. GTFOBins and LOLBAS are
> **GPL-3.0**, so their derived packs are **not** compiled into the binary — they
> ship as the optional, separately-licensed bundle in `packs/lolbin/v1/`
> (GPL-3.0, see its `LICENSE` + `NOTICE.md`) that users opt into by installing
> into `~/.sigil/packs/`. Only the MIT-derived reverse-shell pack is embedded.
> See the "Licensing" section below.

## Pipeline

Two deterministic steps, split so pack regeneration is reproducible and offline:

```
fetch.py     # network: download pinned upstream, distill -> vendor/*.json (+ provenance)
generate.py  # offline: vendor/*.json -> packs/core/v1/reverse_shells.json (embedded, MIT)
             #                        -> packs/lolbin/v1/lolbin_{unix,windows}.json (bundle, GPL-3.0)
```

```bash
python3 tools/corpus-gen/fetch.py        # refresh vendored snapshots from upstream
python3 tools/corpus-gen/generate.py     # rebuild the packs
cargo test -p sigil-cli corpus::          # all_embedded_rule_patterns_compile + detection tests
```

After regenerating, the new pack content is embedded into the binary at compile
time via `include_str!` in `cli/src/corpus/loader.rs`.

## Provenance & no-fake-data

`vendor/{gtfobins,lolbas,revshells}.json` each carry a `source` block recording
the upstream repo, ref, commit SHA, retrieval date, tarball SHA-256, and
license. Every rule is derived verbatim from that pinned upstream — there is no
synthetic or hand-invented signal (see `CLAUDE.md`, "No Fake Data").

## How patterns are built (precision)

* **Binary + abuse shape, never the bare name.** Each GTFOBins/LOLBAS rule is
  one consolidated regex per binary, anchored on the binary name *and* requiring
  one of its documented argument shapes on the same line. `tar` alone never
  matches; `tar ... --checkpoint-action=exec=` does. This keeps false positives
  low and the rule count ≈ the binary count (the engine compiles each rule's
  regex per scanned file).
* **Generic interpreters excluded.** `python`, `bash`, `perl`, … are dropped
  from the LOLBin packs — their "run arbitrary code" vector is already covered
  by the core code-pattern rules, and the reverse-shell pack carries their full
  payloads. Flagging bare `python -c` would be pure noise.
* **Reverse/bind shells use full-payload regexes** (placeholders abstracted to
  `\S+` / `\d+`), so the whole payload structure must be present to match.

Each rule supports an opt-out review marker: add `sigil-reviewed-lolbin` (LOLBin
packs) or `sigil-reviewed-revshell` (reverse-shell pack) on the matched line.

## Licensing — resolution

Sigil is **Apache-2.0**. **GTFOBins and LOLBAS are GPL-3.0** (verified: each
upstream repo has a single repo-wide GPL-3.0 `LICENSE`, no separate data
carve-out); reverse-shell-generator is **MIT**. GPL-3.0 is copyleft and is not
one-way compatible with Apache-2.0, so GPL-derived material cannot be
redistributed as part of the Apache-2.0 binary.

**Resolution adopted (the "split"):**

* **MIT → embedded.** `reverse_shells.json` is compiled into the Apache-2.0
  binary via `include_str!` (`packs/core/v1/`).
* **GPL-3.0 → optional runtime bundle.** `lolbin_unix.json` and
  `lolbin_windows.json` are **not** embedded. They ship as the standalone
  GPL-3.0 bundle in `packs/lolbin/v1/` (with its own `LICENSE` + `NOTICE.md`)
  and are loaded at runtime as data when the user installs them into
  `~/.sigil/packs/`. This keeps the binary free of statically-combined GPL
  material and treats the packs as opt-in data rather than linked code — the
  more defensible "not a derivative work / mere aggregation" posture.

Whether regex signatures distilled from the GPL corpora are a derivative work is
still a fact-specific legal question; the conservative split above does not
require resolving it to ship safely, but **commercial redistributors should
confirm with counsel**. The `vendor/*.json` provenance blocks record the exact
upstream repo, commit, and license.
