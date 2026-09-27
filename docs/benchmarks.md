# Benchmarks — how Sigil measures itself

Sigil publishes its detection numbers, including the unflattering ones. This
page describes how they are produced, so anyone can reproduce them or argue
with the method.

- Latest results: [`evaluation_results/honest_detection_eval.md`](../evaluation_results/honest_detection_eval.md)
- Every published measurement, in one table: [`evaluation_results/HISTORY.md`](../evaluation_results/HISTORY.md)
- Release-time procedure: [`docs/RELEASING.md`](RELEASING.md)

## Running it

```bash
make cli-build                      # measure the binary you think you are measuring
make benchmark \
    SIGIL_EVAL_DATASET=/path/to/malicious-software-packages-dataset \
    SIGIL_EVAL_CONTROL=/path/to/clean-control-packages
```

`make benchmark-quick` runs the same thing with `--limit 30` for iteration. Both
write `honest_detection_eval.json` and `honest_detection_eval.md` into
`SIGIL_EVAL_OUT` (default `evaluation_results/`), so a quick run overwrites the
published report — point `SIGIL_EVAL_OUT` at a scratch directory when that
matters.

Neither dataset is vendored here. The malicious corpus is
[DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
— thousands of password-protected real malware samples; committing them into a
security tool's own repository would be reckless. The clean control set is a
directory whose immediate subdirectories are extracted, legitimate packages
fetched from the live npm and PyPI registries.

The scanner is resolved in this order: `$SIGIL_BIN`, then
`cli/target/release/sigil`, then `sigil` on `PATH`. The repo build deliberately
outranks `PATH` — a stale system install silently measures the wrong code.

## What `scripts/run_eval.py` does

1. **Selects samples deterministically.** Sample zips are sorted and taken with a
   fixed per-bucket cap (`--limit`, or all of them). There is no sampling
   randomness anywhere in the script; a second run on the same dataset revision
   selects the same files.
2. **Fingerprints the input.** The report records the dataset's git commit when
   it can read one, plus a SHA-256 fingerprint over the selected sample list, so
   two reports can be compared on whether they measured the same thing.
3. **Extracts and scans, never executes.** Samples are unpacked into a temporary
   directory with the dataset's own published archive phrase and scanned
   statically. Nothing from a sample is ever run.
4. **Runs offline phases only.** The measured phase set is
   `install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection`.
   OSV and provenance feeds are excluded on purpose: they make network calls
   (non-reproducible) and grade dependency CVEs rather than package
   maliciousness, which is what this measures.
5. **Scans cold.** Every scan is invoked with `--no-cache`, so no previous scan's
   result is reused. That is what makes the clean-set false-positive number a
   real first-scan number. One caveat worth knowing: only the optional
   ledger-warm pass builds a hermetic `HOME`; the cold pass uses the caller's, so
   run the benchmark from an account whose trust ledger has not already approved
   anything in the corpus, or the FP rate will read lower than it is.
6. **Scans the clean control set the same way** and reports the false-positive
   rate. Without `--control-path` the script reports recall only and says so —
   it never invents a precision figure.
7. **Reports at four thresholds** — any severity, ≥ Medium, ≥ High, ≥ Critical —
   for both recall and clean-set FP, and counts extract failures and scan errors
   separately rather than folding them into the denominator silently.

### Optional: the ledger-warm pass

`--ledger-warm` adds a second pass that approves the clean control set into a
hermetic trust ledger with the real `sigil approve`, then re-scans both sets. It
measures two things: how much the allowlisting workflow suppresses (warm FP) and
whether that suppression leaks to content nobody approved (`recall_delta`, which
must be 0).

Read the warm FP rate for what it is. Exact-digest suppression of
operator-approved content suppresses those findings **by definition**, so the
warm number measures the workflow, not the detector. The cold FP rate is the
detector metric.

## Reading the numbers

- **Cold FP rate, not precision.** Precision on these runs is computed over
  hundreds of malicious samples against 20 clean ones. With that imbalance
  precision stays high even when most clean packages are flagged, so it says
  nothing useful about real-world noise. The clean-set FP rate does.
- **Recall thresholds matter more than the headline.** "Detected at any
  severity" and "detected at ≥ Critical" are very different claims about whether
  a scan would have stopped anyone.
- **Rows in HISTORY.md are not a trend line.** Between the two published runs
  both the sample size and the sample composition changed. Two measurements over
  different corpora are two measurements.

## What is not measured

Being explicit about this is the point of the page.

- **No synthetic data, no simulation, no extrapolation.** Every published number
  came from actually scanning real files. Nothing in the evaluation path uses
  `random`, and no result is scaled up from a smaller run. (See `CLAUDE.md` for
  why this rule exists in this repository specifically.)
- **One public dataset.** Results describe Sigil's behaviour on the Datadog
  corpus and a small clean control set, and nothing else. That corpus carries
  Datadog's own documented selection bias — it is largely GuardDog-identified
  malware, which is not a uniform sample of what exists.
- **No claim about unseen malware.** These are static signature and heuristic
  phases. A recall figure on a known corpus is not a detection rate for novel or
  targeted attacks, and nothing here should be read as one. Malware written
  after, or specifically against, this rule set is not represented.
- **A small clean control set.** Twenty popular packages is enough to show the
  false-positive rate is high; it is not enough to characterise it precisely, and
  it says nothing about false positives on private or unusual codebases.
- **Not a per-rule measurement.** The report grades whole samples. It does not
  tell you which rule earned a detection or which one caused a false positive.
- **Not a performance benchmark.** Scan wall-clock time is not part of these
  numbers.
- **Offline phases only.** Provenance and OSV results, and anything the Pro
  adjudication path changes, are outside the published recall/FP figures. Where
  a number for those appears elsewhere in the repository, HISTORY.md says where
  it came from.
