# Sigil LOLBin Pack Bundle — Attribution & Licensing

This bundle (`packs/lolbin/v1/`) is an **optional**, separately-distributed
add-on for Sigil. It is **GPL-3.0-licensed** — see the `LICENSE` file in this
directory — and is **NOT** compiled into the Apache-2.0 Sigil binary. Install it
at runtime by copying the pack files into `~/.sigil/packs/` (see below).

## Why this is separate from the rest of Sigil

Sigil's source is licensed under Apache-2.0. The detection rules in this bundle
are generated from upstream corpora that are licensed under **GPL-3.0**:

| Pack | Derived from | Upstream license |
| --- | --- | --- |
| `lolbin_unix.json` | [GTFOBins](https://gtfobins.github.io/) — `GTFOBins/GTFOBins.github.io` | GPL-3.0 |
| `lolbin_windows.json` | [LOLBAS](https://lolbas-project.github.io/) — `LOLBAS-Project/LOLBAS` | GPL-3.0 |

GPL-3.0 is a copyleft license and is not one-way compatible with Apache-2.0. To
keep the Apache-2.0 binary free of GPL-derived material, these packs are kept
out of the compiled binary and shipped as this clearly-separated, GPL-3.0
bundle that the user opts into and loads as runtime data. The reverse/bind-shell
pack (`packs/core/v1/reverse_shells.json`) is derived from the MIT-licensed
reverse-shell-generator and therefore *is* embedded in the binary.

> Note: whether regex signatures distilled from these corpora are a derivative
> work of the GPL-3.0 originals is a fact-specific legal question. This bundle
> takes the conservative position (treat as GPL-3.0, distribute separately).
> Projects redistributing Sigil commercially should confirm with counsel.

## Provenance

Generated from pinned upstream commits (see `tools/corpus-gen/vendor/*.json`
for the full provenance block — repo, ref, commit, retrieval date, tarball
SHA-256, license):

- GTFOBins `GTFOBins/GTFOBins.github.io@master` `acd5246` (retrieved 2026-06-22)
- LOLBAS `LOLBAS-Project/LOLBAS@master` `f06df10` (retrieved 2026-06-22)

Regenerate with `python3 tools/corpus-gen/generate.py`.

## Installing the bundle (opt-in)

```bash
mkdir -p ~/.sigil/packs
cp packs/lolbin/v1/lolbin_unix.json    ~/.sigil/packs/
cp packs/lolbin/v1/lolbin_windows.json ~/.sigil/packs/
```

Sigil loads `~/.sigil/packs/*.json` automatically on the next scan. Remove the
files to disable the bundle. (If `SIGIL_PACK_PUBLIC_KEY` is configured, the
packs must be signed; see `cli/src/corpus/signing.rs`.)
