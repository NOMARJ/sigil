# Known-good corpus

> Design rationale: [ADR-0011](./adr/ADR-0011-known-good-corpus.md).
> Related: [ADR-0005](./adr/ADR-0005-signed-declarative-signature-packs.md) (signature packs),
> [ADR-0006](./adr/ADR-0006-quarantine-stateful-trust-ledger.md) (trust ledger).

Sigil normally judges a file only by whether its text matches a malicious pattern. It has
no memory of code it already knows to be fine, so it re-litigates bundled runtimes,
vendored libraries and minified dependencies on every scan. That is where most of the
clean-set false positives come from.

The known-good corpus is the other half: a content-addressed index of files **as
published**. A file whose SHA-256 matches an indexed release file is recognised rather
than re-judged, and — more importantly — a file that *should* belong to a recognised
release and does not match it is reported as drift, which is the trojanised-dependency
shape Sigil could not previously see at any severity.

Two rules never bend:

- **Suppression is never silent.** Recognised findings move into `suppressed_findings`
  with an attribution string; they are never dropped. `sigil scan -f json` always shows
  what was set aside and why.
- **Absence never fails open.** A file the corpus does not know is scanned and reported
  exactly as before. The corpus can *explain* code, never *excuse* it.

---

## Quick start

```bash
# What is installed right now?
sigil known-good status

# Install an index
sigil known-good install top-packages-2026-09.json

# Remove it again
sigil known-good remove top-packages-2026-09.json
```

Indexes live in `~/.sigil/known-good/*.json`. Nothing is installed by default; the feature
is inert until you install one.

---

## What the shipped index contains

| | |
|---|---|
| Name | `top-packages-2026-09` |
| Releases | 300 (150 npm, 150 PyPI) |
| Files | 75,905 |
| Size | 11,243,329 bytes (10.72 MB minified) |
| SHA-256 | `259d50728b29db340aacb47b2d4d9fd9d80c67bbf21c5fa6c0399f67f50219ce` |
| Corpus snapshot | 2026-09-03 |
| Selection | top-download packages on each registry at the snapshot date, one release each |

The index itself is **not committed to this repository** — 10.72 MB of hashes is release
payload, not source. What is committed is the *index manifest*,
[`cli/packs/known-good/v1/top-packages-2026-09.manifest.json`](../cli/packs/known-good/v1/top-packages-2026-09.manifest.json),
which records the index's SHA-256, its size, its release and file counts, the exact command
that rebuilds it, and — per release — the registry URL and archive SHA-256 the hashes were
taken from. That is enough to verify that an index you were handed is the one this project
published, and to rebuild it from scratch if you would rather not trust the handoff.

The index is attached to the release as `top-packages-2026-09.json`.

### Provenance

Every release entry carries its origin:

```json
{
  "ecosystem": "npm",
  "name": "lodash",
  "version": "4.18.1",
  "source_url": "https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz",
  "archive_sha256": "…",
  "files": [{ "path": "package/lodash.js", "sha256": "…" }]
}
```

An index is a **trust input**: anyone who can write to it can suppress real findings. That
is why the origin of every hash is written down — "trust these 75,905 hashes" is only a
reviewable claim if each one can be traced back to a specific published archive and checked
against it.

### Indexed paths are archive-internal

`path` is the path *inside the published archive* — `package/lodash.js` for an npm tarball,
`requests-2.34.2/requests/api.py` for a PyPI sdist. Drift detection locates a release in a
scanned tree by stripping the indexed path off the scanned path, so archive-internal paths
are what let a vendored copy be recognised wherever it sits in a tree.

---

## Building an index

`scripts/build_known_good.py` builds a merged index from a corpus manifest — a JSON file
listing, per package, its `ecosystem`, `name`, `version`, `url`, `sha256` and the `dir` the
archive was unpacked into:

```bash
python3 scripts/build_known_good.py \
    --bin target/release/sigil \
    --manifest /path/to/corpus/manifest.json \
    --out top-packages-2026-09.json \
    --name top-packages-2026-09 \
    --index-manifest cli/packs/known-good/v1/top-packages-2026-09.manifest.json
```

The script is an orchestrator only. All hashing, merging and validation happen in the
engine (`sigil known-good build`, then `sigil known-good merge`), so there is exactly one
implementation of the on-disk format and it is the one `cargo test` covers.

**It is deterministic.** No randomness, no clock: releases and files are sorted by the
engine and the recorded build date comes from the corpus manifest, so the same inputs
reproduce the same bytes and therefore the same SHA-256.

Single releases can also be indexed by hand:

```bash
sigil known-good build ./unpacked-tarball \
    --ecosystem npm --name lodash --version 4.18.1 \
    --source-url https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz \
    --archive-sha256 <digest> \
    --out lodash.json

sigil known-good merge lodash.json axios.json \
    --name my-corpus --generated 2026-09-03 --out my-corpus.json
```

`merge` collapses identical duplicates and **fails** on two different definitions of the
same `ecosystem:name@version` — an ambiguous release is exactly what drift detection
cannot tolerate.

---

## Installing and removing

`sigil known-good install <file.json>` validates before it copies. It refuses:

- anything that is not JSON, or is JSON but not an index;
- `format` other than `sigil-known-good/v1` (a signature pack, for instance);
- an index with no releases, or a release with no files or a blank coordinate;
- a digest that is not 64 lowercase hex characters — the lookup table is keyed on
  lowercase hex, so any other shape would install cleanly and then recognise nothing;
- a file path that escapes the release root (`../…`, absolute);
- the same `ecosystem:name@version` twice;
- a file name that does not end in `.json`, since installed indexes are loaded by
  extension.

The file is copied byte-for-byte rather than re-serialised, so a `meta.signature` survives
installation.

**Signature policy is unchanged.** An index is verified on exactly the same policy as a
signature pack: when `SIGIL_PACK_PUBLIC_KEY` is set, an index that fails verification is a
fatal error at scan time. `install` runs the same check, so an index that would break every
later scan is refused now instead.

`sigil known-good remove <file-name>` deletes one index. Deleting the file from
`~/.sigil/known-good/` by hand is equally supported — the directory is plain JSON with no
side state — but the command scopes the deletion: a name containing a path separator or
`..` is refused rather than resolved.

---

## What a scan looks like with an index installed

Recognised files:

```
suppressed_by: "known-good: 24 file(s) matched 1 published release(s) unmodified"
```

and every finding in those files appears under `suppressed_findings` in the JSON report,
never silently discarded.

Drift:

```
KNOWNGOOD-DRIFT-001  (Critical, provenance phase)
  Modified copy of a published release: 23 sibling file(s) match npm:minimist@1.2.8
  exactly, but this file differs from the published bytes. A library that is mostly a
  known release with local modifications is the trojanised-dependency shape.
```

Drift needs at least two exactly-matching sibling files before it will call a tree a copy
of a release, so a single coincidental match (an empty file, a shared `LICENSE`) is not
enough to anchor it.

---

## Measured effect

```
Data Source:  Real runs of the release binary built from this branch, executed for
              this change. Clean sets: 20 popular packages and the 300 top-download
              packages the index was built from (150 npm, 150 PyPI). Malicious set:
              the first 30 npm samples of the Datadog malicious-software-packages
              dataset (npm/malicious_intent, sorted order, human-triaged real
              malware). No synthetic data, no estimates.
Sample Size:  300 clean packages (also 20 as a separate set), 30 malicious samples,
              1 tampered package. Each scanned twice — with and without the index.
Limitations:  READ THIS FIRST — the index was built FROM the same 300 packages it is
              measured on. The clean-set numbers below therefore demonstrate that the
              mechanism works; they say NOTHING about how it generalises to packages
              or versions the corpus has never seen. On an unindexed package the
              corpus does nothing at all, by design. Every clean package here is also
              the exact version indexed; a different version of the same package is
              not recognised. Single sequential run on a 4-CPU machine shared with
              other work, so timings are indicative, not benchmarks. Verdicts come
              from the current scoring model; the underlying finding counts are the
              more stable figure.
```

Commands (`$BIN` is `target/release/sigil`, `$HOME_WITH` has the index installed,
`$HOME_WITHOUT` is empty):

```bash
HOME=$HOME_WITH    $BIN scan <pkg> --no-cache -f json
HOME=$HOME_WITHOUT $BIN scan <pkg> --no-cache -f json
```

### 20 popular packages

| | without index | with index |
|---|---|---|
| Verdicts | 6 CRITICAL, 12 HIGH, 1 MEDIUM, 1 LOW | 20 LOW |
| Findings | 2,910 | 0 (all 2,910 moved to `suppressed_findings`) |
| Total scan time | 21.9 s (1.10 s/pkg) | 25.2 s (1.26 s/pkg) |

19 of 20 verdicts dropped. The twentieth, `npm-debug`, was already LOW with zero
findings. Worst single case: `pypi-idna` fell from 1,913 findings to 0.

### 300 top-download packages

| | without index | with index |
|---|---|---|
| Verdicts | 62 CRITICAL, 148 HIGH, 37 MEDIUM, 53 LOW | 11 HIGH, 2 MEDIUM, 287 LOW |
| Findings | 138,660 | 128 (−99.9%) |
| Total scan time | 856.3 s (2.85 s/pkg) | 899.2 s (3.00 s/pkg, +5%) |

- **239 of 300 verdicts dropped** — 100 of 150 npm, 139 of 150 PyPI. 61 unchanged (53 of
  those were already LOW). **None worsened.**
- 138,532 findings moved into `suppressed_findings` with attribution rather than being
  discarded.
- **No false drift, on these versions.** `KNOWNGOOD-DRIFT-001` fired zero times across
  all 300 unmodified packages. Read that narrowly: drift is unreachable by construction
  on the exact releases the index was built from, because every file matches. The
  adjacent case — a *different* version of an indexed package — is the one that matters,
  and it is covered by the coordinate check described under Limits.
- The 128 findings that remain, in 13 packages, are **entirely advisory-feed matches**
  (GHSA / PYSEC / RUSTSEC) derived from lockfiles and manifests. The corpus deliberately
  does not touch them: recognising a file as authentically published says nothing about
  whether the version it belongs to has a known vulnerability, and suppressing a CVE
  because the bytes are genuine would be exactly the wrong trade.

Again: this index was built from these packages. The right way to read the table is
"recognition removes essentially all pattern-matching noise from code it knows", not
"Sigil's false-positive rate is now 0.1%".

### Drift on a tampered copy

`package/index.js` of `npm:minimist@1.2.8` copied and one line changed
(`'use strict';` → `'use strict';  // patched by a third party`), everything else
untouched:

| | without index | with index |
|---|---|---|
| Verdict | HIGH RISK | **CRITICAL RISK** |
| Findings | 4 (ordinary pattern matches) | 1 |
| `KNOWNGOOD-DRIFT-001` | 0 | 1, on `package/index.js` |

```json
{
  "rule": "KNOWNGOOD-DRIFT-001",
  "severity": "Critical",
  "phase": "Provenance",
  "behavior": "modified_known_release",
  "file": "package/index.js",
  "locator": "npm:minimist@1.2.8|file://package/index.js",
  "title": "Modified copy of a published release",
  "snippet": "Modified copy of a published release: 22 sibling file(s) match npm:minimist@1.2.8 exactly, but this file differs from the published bytes. A library that is mostly a known release with local modifications is the trojanised-dependency shape.",
  "weight": 10
}
```

Note the direction: the index makes this package look **worse**, not better. Without it,
one changed line in a library is invisible.

### Nothing malicious is suppressed

30 npm samples from the Datadog malicious dataset, scanned with and without the index:

- verdicts identical on all 30 (23 CRITICAL, 3 HIGH, 1 MEDIUM, 3 LOW);
- finding counts and scores identical on all 30;
- **0 findings suppressed** by the corpus across the whole set.

That is the expected result and the one that matters: malware is not published code, so
nothing in it hashes to anything in the index.

---

## Limits

- **Tier 1 only.** Exact SHA-256 matching. Minification, transpilation and re-packing
  change bytes without changing meaning, and those copies are not recognised. ADR-0011's
  tier 2 (normalised hashing with LSH) is specified and not built; the on-disk format
  already reserves a `normalized` field per file.
- **One version per package.** The index holds a single release per package, so a
  project on any other version gets no suppression from it. It also gets no *drift*
  finding: a release is only compared against the index when the tree says it is that
  release, by name and version, in the manifest the ecosystem puts beside its files
  (`package.json` for npm, `PKG-INFO` or `METADATA` for Python). That check is load
  bearing rather than cosmetic. Anchoring on matching files alone is exactly what a
  neighbouring version looks like — most of its files never changed — and without the
  check, scanning the genuine, registry-signed `semver` 7.7.2 tarball against an index
  built from 7.8.5 reported eleven of its files as a trojanised release and returned
  CRITICAL RISK. With it, that scan is byte-for-byte identical to the same scan with no
  index installed, while a copy of 7.8.5 with one line added to `index.js` still raises
  `KNOWNGOOD-DRIFT-001` against 52 matching siblings.
- **A tree with no manifest is never compared.** The coordinate check needs a manifest to
  read, so an unpacked release stripped of its `package.json` is neither recognised nor
  reported as drift.
- **Coverage is the whole game.** 300 packages is a demonstration of the mechanism, not
  coverage of npm and PyPI. Populating a corpus at registry scale is separate
  infrastructure with its own storage and refresh cost (ADR-0011).
- **Cost.** The index is parsed on every scan. See the timing figures above.
