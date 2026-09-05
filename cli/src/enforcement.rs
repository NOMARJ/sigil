//! What Sigil is allowed to *do* with a tree, as opposed to what it *says* about it.
//!
//! [`Verdict`](crate::scanner::Verdict) is a report label. It is written to JSON,
//! SARIF, HTML and the terminal, read back from `.sigil/cache`, read back from a
//! diff baseline in [`crate::diff::parse_baseline`], and rewritten in-process at
//! four sites. Anything that is displayed, cached and rewritten will eventually be
//! adjusted for presentation reasons.
//!
//! That is not hypothetical here. A proposal to demote HIGH to MEDIUM when a
//! release's findings were unchanged from its predecessor reached review before
//! anyone noticed it also removed the only human confirmation prompt in
//! `sigil safe-run`. Nothing in the type system and no test said so.
//!
//! [`EnforcementLevel`] is a second, *ordered* scale that the execution consumers
//! key on instead — `sandbox::safe_run` (blocking and the confirmation prompt) and
//! `policy::generate` (which sandbox preset the container is built from). It is the
//! **maximum** of two independent readings:
//!
//! - [`from_verdict`] — the label, entering as a *floor*;
//! - [`from_findings`] — the same verdict recomputed from `result.findings`.
//!
//! Taking the max is the whole safety argument, and it is one-directional in both
//! useful senses. A future rule that *lowers* the label cannot lower a gate, because
//! the evidence term is untouched by a write to the field. A future rule that
//! *raises* the label still raises the gate, because the label is a floor. Neither
//! direction requires anyone to remember this module exists.
//!
//! **It is a no-op today, deliberately.** This is a barrier, not a recalibration.
//! `scanner::run_scan` computes the score and then the verdict over the same
//! `findings` vector it stores, so on any freshly computed result the two readings
//! are equal and the max is the identity. Divergence becomes possible only when
//! something writes the verdict from a source other than the findings — which is
//! exactly when a floor is wanted.
//!
//! **What this does not cover.** [`from_findings`] reads `result.findings` and
//! nothing else. A demotion implemented by *moving findings out* of that vector —
//! the idiom the trust ledger already uses for approved content — is invisible here,
//! and correctly so for the ledger, because a human approved that content. An
//! automated demotion written the same way would bypass this module entirely. Gate
//! it here, not in the scorer. See `suppression_still_reaches_open`.
//!
//! Deliberately **not** on this scale:
//!
//! - `acquisition_exit_code` — reports whether the tree is clean; ADR-0010 fixes it
//!   to 0 or 1, and routing it through here would break that contract.
//! - the `--auto-approve` quarantine gate — approves storage, executes nothing.
//! - `exit_code_for` — already keys on finding severities, not on the verdict.
//!
//! Those answer "how bad is it". This scale answers "may we run it".

use crate::scanner::{scoring, ScanResult, Verdict};

/// How much Sigil may do with a tree. Ordered; [`Open`](Self::Open) is weakest.
///
/// `Ord` is load-bearing: [`level_for`] is a `max` over it, and the no-loosening
/// property is written as `>=`. `Verdict` deliberately does *not* derive `Ord`, so
/// no such comparison is possible on the report label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnforcementLevel {
    /// Run without ceremony.
    Open,
    /// Run, but build the sandbox from the stricter preset.
    Restricted,
    /// Ask a human first, unless they passed `--auto-approve`.
    Confirm,
    /// Refuse. `--auto-approve` cannot override this.
    Blocked,
}

/// What the caller should do, once a level has been resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Carry on.
    Proceed,
    /// Prompt for confirmation.
    Confirm,
    /// Stop.
    Block,
}

/// The report label read as a floor.
pub fn from_verdict(verdict: Verdict) -> EnforcementLevel {
    match verdict {
        Verdict::LowRisk => EnforcementLevel::Open,
        Verdict::MediumRisk => EnforcementLevel::Restricted,
        Verdict::HighRisk => EnforcementLevel::Confirm,
        Verdict::CriticalRisk => EnforcementLevel::Blocked,
    }
}

/// The evidence read independently of the label: the verdict this result's own
/// findings compute to, whatever the stored `verdict` field happens to say.
pub fn from_findings(result: &ScanResult) -> EnforcementLevel {
    let score = scoring::calculate_score(&result.findings);
    from_verdict(scoring::determine_verdict_with_size(
        &result.findings,
        score,
        result.files_scanned,
    ))
}

/// The level an execution consumer must key on: the label as a floor, raised by the
/// evidence. Never below [`from_verdict`], by definition of `max`.
pub fn level_for(result: &ScanResult) -> EnforcementLevel {
    from_verdict(result.verdict).max(from_findings(result))
}

/// What to do at a level. Monotone: a higher level never yields a weaker gate, and
/// `auto_approve` waives the confirmation but never the block.
pub fn gate(level: EnforcementLevel, auto_approve: bool) -> Gate {
    match level {
        EnforcementLevel::Blocked => Gate::Block,
        EnforcementLevel::Confirm if !auto_approve => Gate::Confirm,
        _ => Gate::Proceed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, Phase, ScanResult, Severity};

    fn finding(rule: &str, file: &str, severity: Severity, weight: u32) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: file.to_string(),
            line: Some(1),
            snippet: format!("// {rule}"),
            weight,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        }
    }

    fn result(findings: Vec<Finding>, files_scanned: usize) -> ScanResult {
        let score = scoring::calculate_score(&findings);
        let verdict = scoring::determine_verdict_with_size(&findings, score, files_scanned);
        ScanResult {
            findings,
            score,
            verdict,
            files_scanned,
            duration_ms: 0,
            suppressed_findings: Vec::new(),
            suppressed_by: None,
            scanner: None,
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            platform: String::new(),
        }
    }

    /// A result whose findings genuinely compute the verdict it claims. Guarding the
    /// inputs matters: if a scoring recalibration moves these between levels, this
    /// fails first and names the scorer, rather than the table below failing for the
    /// wrong reason and being "fixed" by editing the expected gate.
    fn sample_reaching(want: Verdict) -> ScanResult {
        let r = match want {
            Verdict::LowRisk => result(vec![], 10),
            // Three Medium findings at weight 2 are 12 points: over the 10 that
            // MEDIUM needs, well under the 50 the action term needs, and far too
            // sparse across 40 files for the density term to fire.
            Verdict::MediumRisk => result(
                vec![
                    finding("CODE-001", "a.py", Severity::Medium, 2),
                    finding("CODE-002", "b.py", Severity::Medium, 2),
                    finding("CODE-003", "c.py", Severity::Medium, 2),
                ],
                40,
            ),
            Verdict::HighRisk => result(
                vec![
                    finding("CODE-014", "a.py", Severity::High, 5),
                    finding("CODE-015", "b.py", Severity::High, 5),
                    finding("CODE-006", "c.py", Severity::High, 5),
                ],
                6,
            ),
            Verdict::CriticalRisk => result(
                vec![finding("INSTALL-004", "setup.py", Severity::Critical, 10)],
                10,
            ),
        };
        assert_eq!(r.verdict, want, "fixture does not compute {want:?}");
        r
    }

    #[test]
    fn the_samples_actually_compute_the_verdict_they_claim() {
        for v in [
            Verdict::LowRisk,
            Verdict::MediumRisk,
            Verdict::HighRisk,
            Verdict::CriticalRisk,
        ] {
            let _ = sample_reaching(v);
        }
    }

    /// Every consumer that changes what Sigil DOES, side by side. This is the
    /// artefact whose absence let a proposed HIGH→MEDIUM demotion reach review
    /// without anyone noticing it removed the confirmation prompt. If you are
    /// changing how a verdict is assigned, read it row by row.
    ///
    /// Columns: verdict | level | gate | gate under --auto-approve.
    const ENFORCEMENT_TABLE: [(Verdict, EnforcementLevel, Gate, Gate); 4] = [
        (
            Verdict::LowRisk,
            EnforcementLevel::Open,
            Gate::Proceed,
            Gate::Proceed,
        ),
        (
            Verdict::MediumRisk,
            EnforcementLevel::Restricted,
            Gate::Proceed,
            Gate::Proceed,
        ),
        (
            Verdict::HighRisk,
            EnforcementLevel::Confirm,
            Gate::Confirm,
            Gate::Proceed,
        ),
        (
            Verdict::CriticalRisk,
            EnforcementLevel::Blocked,
            Gate::Block,
            Gate::Block,
        ),
    ];

    #[test]
    fn enforcement_table_is_the_whole_contract() {
        for (verdict, want_level, want_gate, want_gate_auto) in ENFORCEMENT_TABLE {
            let scan = sample_reaching(verdict);
            assert_eq!(level_for(&scan), want_level, "{verdict:?}");
            assert_eq!(gate(level_for(&scan), false), want_gate, "{verdict:?}");
            assert_eq!(gate(level_for(&scan), true), want_gate_auto, "{verdict:?}");
        }
    }

    /// THE INCIDENT AS A TEST. The findings compute HighRisk; the label is demoted
    /// to MediumRisk, which is exactly the change that was proposed and rejected.
    /// The confirmation must survive the demotion.
    #[test]
    fn a_demoted_verdict_does_not_remove_the_confirmation() {
        let mut scan = sample_reaching(Verdict::HighRisk);
        scan.verdict = Verdict::MediumRisk; // the demotion
        assert_eq!(from_verdict(scan.verdict), EnforcementLevel::Restricted);
        assert_eq!(from_findings(&scan), EnforcementLevel::Confirm);
        assert_eq!(level_for(&scan), EnforcementLevel::Confirm);
        assert_eq!(gate(level_for(&scan), false), Gate::Confirm);
    }

    #[test]
    fn a_demoted_critical_still_blocks() {
        let mut scan = sample_reaching(Verdict::CriticalRisk);
        scan.verdict = Verdict::LowRisk;
        assert_eq!(level_for(&scan), EnforcementLevel::Blocked);
        assert_eq!(gate(level_for(&scan), false), Gate::Block);
        // --auto-approve waives a confirmation; it must never waive a block.
        assert_eq!(gate(level_for(&scan), true), Gate::Block);
    }

    /// The safety property, over every (reported, computed) pair rather than the
    /// four diagonal ones: the level is never below what the label alone would give.
    #[test]
    fn union_is_never_below_the_verdict_alone() {
        let all = [
            Verdict::LowRisk,
            Verdict::MediumRisk,
            Verdict::HighRisk,
            Verdict::CriticalRisk,
        ];
        for computed in all {
            for reported in all {
                let mut scan = sample_reaching(computed);
                scan.verdict = reported;
                assert!(
                    level_for(&scan) >= from_verdict(reported),
                    "computed {computed:?} reported {reported:?} loosened the gate"
                );
                assert!(
                    level_for(&scan) >= from_verdict(computed),
                    "computed {computed:?} reported {reported:?} ignored the evidence"
                );
            }
        }
    }

    #[test]
    fn the_gate_is_monotone_in_the_level() {
        let rungs = [
            EnforcementLevel::Open,
            EnforcementLevel::Restricted,
            EnforcementLevel::Confirm,
            EnforcementLevel::Blocked,
        ];
        let strength = |g: Gate| match g {
            Gate::Proceed => 0,
            Gate::Confirm => 1,
            Gate::Block => 2,
        };
        for auto in [false, true] {
            for pair in rungs.windows(2) {
                assert!(
                    strength(gate(pair[1], auto)) >= strength(gate(pair[0], auto)),
                    "{:?} -> {:?} weakened the gate (auto_approve={auto})",
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    /// The deliberate exclusion. Acquisition exit codes stay on the report label
    /// (ADR-0010 fixes them to 0 or 1); routing them through this scale would break
    /// that contract. This pins the decision so a later "tidy-up" has to argue with
    /// it rather than silently make the change.
    #[test]
    fn enforcement_stays_out_of_the_exit_codes() {
        let src = include_str!("main.rs");
        let f = src
            .find("fn acquisition_exit_code")
            .expect("acquisition_exit_code moved; re-point this test");
        let body = &src[f..f + 400];
        assert!(
            !body.contains("enforcement::"),
            "acquisition_exit_code now routes through the enforcement scale, \
             which changes the CI contract described in ADR-0010"
        );
    }

    /// Source-text tripwire. No *enforcement* decision may name a `Verdict` variant.
    ///
    /// `policy::generate::verdict_label` is exempt by name: it renders the label
    /// into the generated policy's `name` field, which is exactly what a report
    /// label is for.
    ///
    /// LIMITS, stated so nobody over-trusts this: it greps for `Verdict::`. A gate
    /// written as `if a.verdict == b.verdict`, or one that calls a helper in a third
    /// file, slips through, and a new enforcement consumer has to be added to this
    /// list by hand.
    #[test]
    fn the_enforcement_path_does_not_match_on_the_report_label() {
        for (name, src) in [
            ("sandbox/safe_run.rs", include_str!("sandbox/safe_run.rs")),
            ("policy/generate.rs", include_str!("policy/generate.rs")),
        ] {
            let mut in_label_fn = false;
            for (i, line) in src.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("fn verdict_label") || t.starts_with("pub fn verdict_label") {
                    in_label_fn = true;
                }
                if in_label_fn && t == "}" {
                    in_label_fn = false;
                    continue;
                }
                if t.starts_with("//") || t.starts_with("///") || in_label_fn {
                    continue;
                }
                assert!(
                    !line.contains("Verdict::"),
                    "{name}:{} makes an enforcement decision on the report label: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// Ledger suppression moves findings OUT of `findings` rather than rewriting the
    /// verdict, so it is invisible to `from_findings` — correctly, because a human
    /// approved that content. Pinned so the limitation is a decision, not a surprise.
    #[test]
    fn suppression_still_reaches_open() {
        let mut scan = sample_reaching(Verdict::HighRisk);
        scan.suppressed_findings = std::mem::take(&mut scan.findings);
        scan.suppressed_by = Some("ledger:example@1.0.0#abcd1234".into());
        scan.score = 0;
        scan.verdict = Verdict::LowRisk;
        assert_eq!(level_for(&scan), EnforcementLevel::Open);
    }
}
