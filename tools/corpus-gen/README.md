# corpus-gen — LOLBin / reverse-shell signature pack generator

Generates three Sigil signature packs from upstream living-off-the-land
corpora, so detection content stays sourced from the community references rather
than hand-maintained guesses:

| Pack (`packs/core/v1/`) | Upstream source | Detects |
| --- | --- | --- |
| `lolbin_unix.json` | [GTFOBins](https://gtfobins.github.io/) | Abuse of legit **Unix** binaries (shell breakout, file read/write, exfil) |
| `lolbin_windows.json` | [LOLBAS](https://lolbas-project.github.io/) | Abuse of native **Windows** binaries (execute, download, AWL bypass) |
| `reverse_shells.json` | [reverse-shell-generator](https://www.revshells.com/) | Reverse / bind shell payloads (interactive C2) |

## Pipeline

Two deterministic steps, split so pack regeneration is reproducible and offline:

```
fetch.py     # network: download pinned upstream, distill -> vendor/*.json (+ provenance)
generate.py  # offline: vendor/*.json -> packs/core/v1/{lolbin_unix,lolbin_windows,reverse_shells}.json
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

## ⚠️ Licensing — needs maintainer review

Sigil is **Apache-2.0**. **GTFOBins and LOLBAS are GPL-3.0**;
reverse-shell-generator is MIT. The generated regexes are *derived from* the
GPL-licensed command corpora. Whether signature regexes distilled from GPL data
constitute a derivative work is a genuine licensing question that a maintainer
(not this tooling) must resolve before release — e.g. relicensing the generated
packs, isolating them, or seeking upstream clarification. The provenance blocks
in `vendor/` record the exact upstream and license for that review.
