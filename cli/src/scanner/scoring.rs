use std::collections::{HashMap, HashSet};

use super::{Evidence, Finding, Phase, Severity, Verdict};

/// Phase weight multipliers matching the Sigil scan specification:
///
/// - InstallHooks:  10x (Critical)
/// - CodePatterns:   5x (High)
/// - NetworkExfil:   3x (High)
/// - Credentials:    2x (Medium)
/// - Obfuscation:    5x (High)
/// - Provenance:   1-3x (Low, varies per finding)
#[allow(dead_code)]
pub fn phase_weight(phase: Phase) -> u32 {
    phase.default_weight()
}

/// How many findings from the same `(rule, file)` pair may contribute to the
/// aggregate score.
///
/// The score is a sum, so before this cap a single file could dominate the
/// verdict by repetition alone: `idna`'s UTS-46 conformance table
/// (`tests/test_idna_uts46.py`) matched `OBFUSC-CHAIN-008` 1,680 times, which
/// is 16,800 of the 19,140 points that made the package HIGH RISK — on a
/// package whose only sin is shipping the IDNA data it exists to implement.
/// The 1,681st combining mark in one file is not new evidence about whether to
/// trust the package; it is the same observation restated.
///
/// ```text
/// Data Source: real scan of the pypi-idna control package (idna 3.19,
///              fetched from PyPI by scripts/fetch_control_set.py) with the
///              binary built at c7771d2, --no-cache, all phases
/// Sample Size: one package, 1,913 findings, of which 1,718 are
///              OBFUSC-CHAIN-008 across four files
/// Limitations: one package on one date; the figures below for the cap's
///              effect come from the 20-package control set, which is small,
///              and the pack changes that shipped beside the cap contribute
///              to the after numbers.
/// ```
///
/// Three is where restating stops adding information. On the 20-package clean
/// control set the cap (with the pack changes that shipped beside it) takes
/// `idna` from 19,140 to 155 and `urllib3` from 4,448 to 547. Replaying the
/// recorded findings of those same scans at caps of 1, 2, 3 and 5 gives the
/// same verdict for every package at 2, 3 and 5; only a cap of 1 moves any
/// package, and replaying 60 recorded malicious `ai-skills` scans the same way
/// shows a cap of 1 dropping two of them below the HIGH score threshold. Three
/// keeps the volume gradient a reader expects while removing the runaway.
///
/// Every finding is still reported and still counted in `findings_count` —
/// only its contribution to the score saturates.
pub const PER_RULE_FILE_SCORE_CAP: usize = 3;

/// Severity base score: used in combination with phase weight.
fn severity_score(severity: Severity) -> u32 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 5,
    }
}

/// Calculate the aggregate risk score from a list of findings.
///
/// Each finding contributes `severity_score * finding.weight`, except that at
/// most [`PER_RULE_FILE_SCORE_CAP`] findings from the same `(rule, file)` pair
/// are counted — see that constant for why.
///
/// The weight on each finding already reflects the phase multiplier
/// (set at creation time in the phases module).
///
/// This is the *reported* score and it includes Low observations, so a result
/// with nothing but observations still reads as grade B rather than A. The
/// verdict does not use it directly: see [`signal_score`].
pub fn calculate_score(findings: &[Finding]) -> u32 {
    capped_score(findings, |_| true)
}

/// Sum `severity_score * weight` over the findings `keep` accepts, with the
/// per-`(rule, file)` cap applied among the kept findings.
fn capped_score(findings: &[Finding], keep: impl Fn(&Finding) -> bool) -> u32 {
    let mut counted: HashMap<(&str, &str), usize> = HashMap::new();
    let mut score = 0u32;
    for f in findings.iter().filter(|f| keep(f)) {
        let seen = counted
            .entry((f.rule.as_str(), f.file.as_str()))
            .or_insert(0);
        *seen += 1;
        if *seen <= PER_RULE_FILE_SCORE_CAP {
            score = score.saturating_add(severity_score(f.severity) * f.weight);
        }
    }
    score
}

/// Whether a finding is allowed to move the verdict at all.
///
/// Low is the severity of a *capability*: a network client, a subprocess
/// call with an argument list, an API key read from the environment, an
/// unrestricted Bash grant in a skill header. Legitimate skills are made of
/// these, so the corpus reports them as observations and the verdict ignores
/// them — otherwise a pile of observations becomes a verdict by volume, which
/// is exactly how a two-file skill with one `subprocess.run([...])` used to
/// come back HIGH RISK.
///
/// Measured on the 455 clean vendor skills and 204 malicious skills (see
/// docs/detection/fp-calibration.md), before the rule changes that moved
/// routine idioms to Low: excluding Low alone moved 6 clean skills out of
/// HIGH and 3 malicious ones.
fn is_signal(f: &Finding) -> bool {
    f.severity >= Severity::Medium
}

/// The part of the score the verdict reads: [`calculate_score`] without the
/// Low observations.
pub fn signal_score(findings: &[Finding]) -> u32 {
    capped_score(findings, is_signal)
}

/// Whether a finding sits outside the code the package runs: a secondary
/// path (tests, docs, examples, vendored trees — see [`is_secondary_path`]) or
/// a code capability matched inside reference documentation (see
/// [`super::context::is_documented_example`]).
fn is_secondary(f: &Finding) -> bool {
    is_secondary_path(&f.file) || super::context::is_documented_example(f.phase, &f.file)
}

/// Paths whose findings describe content a package ships *around* its code:
/// its own tests, docs and examples, a vendored third-party tree, or a build
/// product that is a copy of code counted elsewhere.
///
/// This is not a suppression — every finding is still reported, and a payload
/// hidden in a test directory is still a payload. It only decides which
/// findings count toward `first_party_score`, the "how much of this is in the
/// code the package actually runs" half of the HIGH gate. Markdown is
/// deliberately *not* secondary: for an agent skill, `SKILL.md` is the payload.
fn is_secondary_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".map") || lower.ends_with(".min.js") || lower.ends_with(".min.css") {
        return true;
    }
    const DIRS: &[&str] = &[
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "doc",
        "docs",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "benchmark",
        "benchmarks",
        // A skill's own evaluation suite (`evals/evals.json`, `evals/files/`),
        // the convention Anthropic's skill-creator and NVIDIA's skills share.
        // It is the skill's test directory by another name, and it holds
        // deliberately hostile inputs: nvflare-convert-pytorch ships a
        // prompt-injection requirements.txt under evals/files/ to prove the
        // skill resists it.
        "evals",
        "vendor",
        "node_modules",
        "third_party",
        "site-packages",
    ];
    lower.split('/').any(|seg| DIRS.contains(&seg))
}

/// The part of the verdict score that comes from code the package actually
/// ships to run.
///
/// Same per-`(rule, file)` cap as [`calculate_score`]; findings that are not
/// [signal](is_signal) or that are [secondary](is_secondary) do not
/// contribute.
pub fn first_party_score(findings: &[Finding]) -> u32 {
    capped_score(findings, |f| is_signal(f) && !is_secondary(f))
}

/// Whether the code the package ships carries at least one attack-shaped
/// finding: a High or Critical rule, in a first-party path.
///
/// High and Critical are reserved for attack shapes (a download piped into a
/// shell, a credential file read and sent, an instruction to hide an action
/// from the user); routine capabilities are Low and context-dependent ones
/// Medium. So this is the question "is there anything here that looks like an
/// attack?", and HIGH RISK requires a yes. A lone Medium — or a pile of them —
/// can raise the verdict to MEDIUM, never to HIGH.
fn has_attack_evidence(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.severity >= Severity::High && !is_secondary(f))
}

/// Behaviours that describe an action taken on the host or the network, as
/// opposed to a capability a library legitimately has. Reading an environment
/// variable or opening a socket is what an API client does for a living;
/// running at install time, shipping an exfiltration endpoint, installing
/// persistence or building code at runtime is a decision about what the
/// package does to the machine it lands on.
const ACTION_BEHAVIOURS: &[&str] = &[
    "install_time_execution",
    "exfiltration_endpoint",
    "installs_persistence",
    "dynamic_execution",
];

/// Whether any finding in a *first-party* path carries an action behaviour.
///
/// The path test matches `first_party_score`, deliberately: both halves of the
/// action term have to agree about what counts as this package's own code. A
/// `postinstall` documented in `docs/` or exercised in `tests/` is the project
/// describing itself, not the project doing it — `pypi-click` reached HIGH on
/// four matches in `docs/shell-completion.md` and nothing else.
fn has_action_behaviour(findings: &[Finding]) -> bool {
    findings
        .iter()
        .filter(|f| is_signal(f) && !is_secondary(f))
        .any(|f| {
            crate::scanner::profile::behavior_for(&f.rule)
                .is_some_and(|b| ACTION_BEHAVIOURS.contains(&b))
        })
}

/// First-party evidence that reaches HIGH on its own.
const HIGH_FIRST_PARTY: u32 = 200;
/// First-party score per scanned file that reaches HIGH on its own — the
/// small-package case, where the absolute score is low because there is barely
/// any code.
///
/// Expressed as a fraction because the measured threshold is 3.5, and the
/// arithmetic stays in integers: `2 * first_party >= 7 * files`.
const HIGH_DENSITY_NUM: u32 = 7;
const HIGH_DENSITY_DEN: u32 = 2;
/// First-party evidence required to corroborate an action behaviour.
const HIGH_ACTION_FIRST_PARTY: u32 = 50;
/// One scanned file in this many carrying attack-shaped evidence reaches HIGH
/// on its own — the concentration term.
///
/// The point terms above weigh a finding by its phase, and the phase weights
/// were set for packages: a High credential finding is worth 3 × 2 = 6 points,
/// so a two-file skill whose one script dumps `os.environ` never reached the
/// 3.5-per-file density bar without a routine network call beside it to push
/// it over. Counting *files* instead asks the question the density term was
/// standing in for — is the attack-shaped code a real part of this package,
/// or one line lost in a large one — without depending on which phase caught
/// it. See docs/detection/fp-calibration.md for the measurement behind 8.
const HIGH_EVIDENCE_FILE_RATIO: usize = 8;

pub fn determine_verdict(findings: &[Finding], score: u32) -> Verdict {
    determine_verdict_with_size(findings, score, 0)
}

/// Determine the overall risk classification, given the number of files the
/// scan actually walked.
///
/// Each level is a claim about evidence, and severity is what carries it:
///
/// - **CriticalRisk**: a Critical rule fired — one `standalone` Critical, or
///   two *different* `corroborate` Criticals (see below).
/// - **HighRisk**: attack-shaped evidence — a High or Critical finding — in
///   the code the package runs (not tests, docs, vendored trees or
///   documentation examples), *and* that evidence is a real part of the
///   package: first-party signal ≥ 200, or ≥ 3.5 points per scanned file, or
///   one scanned file in [`HIGH_EVIDENCE_FILE_RATIO`] carries it, or it
///   co-occurs with an action behaviour at ≥ 50 points.
/// - **MediumRisk**: any Medium-or-above finding in the code the package runs
///   (which includes attack-shaped evidence too diluted to reach HIGH), or a
///   signal score ≥ 10 overall (Medium and above; Low observations do not
///   count).
/// - **LowRisk**: everything else, including any number of Low observations.
///
/// Critical is evidence-gated, not score-only. A large pile of medium/low
/// heuristics can raise the aggregate risk, but it must not claim "almost
/// certainly malicious" unless at least one rule actually emitted Critical.
///
/// Not every Critical rule earns that claim by itself. A rule marked
/// `"evidence": "corroborate"` in its pack (see
/// [`crate::corpus::schema::Evidence`]) reports at Critical and contributes
/// its full weight to the score, but only gates the verdict when a *second,
/// different* corroborating rule also fired: `requests` ships expired test
/// certificates and `dotenv` documents a private key in its README, and one
/// `CRED-006` line in either is not evidence that the package is malicious.
/// Two independent corroborating Criticals is a different claim from one.
///
/// `files_scanned` of 0 means "unknown"; the density and concentration terms
/// are then skipped rather than dividing by a guess. `score` is the reported
/// score ([`calculate_score`]); the verdict reads [`signal_score`] instead.
pub fn determine_verdict_with_size(
    findings: &[Finding],
    score: u32,
    files_scanned: usize,
) -> Verdict {
    let mut standalone_critical = false;
    let mut corroborating: HashSet<&str> = HashSet::new();
    for f in findings.iter().filter(|f| f.severity == Severity::Critical) {
        match f.evidence {
            Evidence::Standalone => standalone_critical = true,
            Evidence::Corroborate => {
                corroborating.insert(f.rule.as_str());
            }
        }
    }

    if standalone_critical || corroborating.len() >= 2 {
        return Verdict::CriticalRisk;
    }

    // HIGH first needs something that looks like an attack: a High or Critical
    // finding in the code the package runs. Without one, no amount of Medium
    // evidence reaches HIGH — a pile of "suspicious in context" findings is a
    // reason to review, not to block. Before this gate a two-file skill with a
    // single Medium `subprocess.run([...])` was HIGH RISK on the density term
    // alone.
    let attack = has_attack_evidence(findings);

    // ...and then the evidence must be a real part of the package rather than
    // one line lost in a large one. That is three questions, not one sum. The
    // sum alone does not separate the populations: measured over 844 malicious
    // samples and 450 clean packages, clean packages sit at median 70 and p75
    // 295 while malicious sit at median 148 — overlapping almost entirely,
    // because a large clean package accumulates score by being large.
    let first_party = first_party_score(findings);
    // Density over FIRST-PARTY score, not total score. Dividing the total by
    // the file count mixed two different populations: the numerator counted
    // findings in tests/, docs/ and vendor/, which `first_party_score` exists
    // to discount, while the denominator counted those files too. A package
    // with a large test suite had its density inflated by its own tests.
    // Measured over 844 malicious samples and 450 clean packages, the
    // first-party form strictly dominates the total-score form: it catches
    // more malicious samples (84.6% vs 84.0%) on fewer clean ones (28.9% vs
    // 32.0%).
    let dense = files_scanned > 0
        && HIGH_DENSITY_DEN * first_party >= HIGH_DENSITY_NUM * files_scanned as u32;
    let concentrated = files_scanned > 0
        && attack_evidence_files(findings) * HIGH_EVIDENCE_FILE_RATIO >= files_scanned;
    if attack
        && (first_party >= HIGH_FIRST_PARTY
            || dense
            || concentrated
            || (first_party >= HIGH_ACTION_FIRST_PARTY && has_action_behaviour(findings)))
    {
        return Verdict::HighRisk;
    }

    // MEDIUM is "suspicious in context, review before approving", which is
    // what a Medium finding says. So any Medium-or-above finding in the code
    // the package runs is at least MEDIUM, and findings around it (tests,
    // docs) reach MEDIUM by the signal score. Low observations never count
    // (see [`is_signal`]): a skill made only of routine capabilities is LOW
    // however many of them it has. The reported `score` still includes them —
    // it is what the grade and the report show — which is why it is not the
    // number compared here.
    let _ = score;
    if signal_score(findings) >= 10 || has_first_party_signal(findings) {
        return Verdict::MediumRisk;
    }

    Verdict::LowRisk
}

/// Whether any Medium-or-above finding sits in the code the package runs.
fn has_first_party_signal(findings: &[Finding]) -> bool {
    findings.iter().any(|f| is_signal(f) && !is_secondary(f))
}

/// Number of distinct first-party files carrying a High or Critical finding.
fn attack_evidence_files(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter(|f| f.severity >= Severity::High && !is_secondary(f))
        .map(|f| f.file.as_str())
        .collect::<HashSet<&str>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rule: &str, file: &str, severity: Severity, weight: u32) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: file.to_string(),
            line: Some(1),
            snippet: "x".to_string(),
            weight,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Evidence::Standalone,
        }
    }

    #[test]
    fn secondary_paths_are_the_package_around_the_code() {
        for p in [
            "package/test/a.js",
            "pkg/tests/b.py",
            "src/__tests__/c.ts",
            "docs/guide.rst",
            "examples/demo.py",
            "vendor/left-pad/index.js",
            "node_modules/x/index.js",
            "dist/bundle.min.js",
            "dist/bundle.js.map",
        ] {
            assert!(is_secondary_path(p), "{p} should be secondary");
        }
        for p in [
            "package/index.js",
            "setup.py",
            "SKILL.md",
            "src/lib/auth.ts",
            "latest.js",
            "protester/main.py",
        ] {
            assert!(!is_secondary_path(p), "{p} should be first-party");
        }
    }

    #[test]
    fn markdown_is_first_party_because_a_skill_is_markdown() {
        // The ai-skills bucket is 204 real malicious skills whose payload is
        // the instruction text. Treating .md as secondary scored them at zero.
        assert!(!is_secondary_path("SKILL.md"));
        assert!(!is_secondary_path("skills/exfil/SKILL.md"));
        // ...but a doc directory is still a doc directory.
        assert!(is_secondary_path("docs/SKILL.md"));
    }

    #[test]
    fn first_party_score_excludes_the_package_scaffolding() {
        let findings = vec![
            at("CODE-001", "src/index.js", Severity::High, 5),
            at("CODE-001", "test/index.test.js", Severity::High, 5),
            at("CODE-002", "docs/usage.md", Severity::High, 5),
        ];
        // 3 × 5 = 15 for the one first-party finding; the whole score counts all three.
        assert_eq!(first_party_score(&findings), 15);
        assert_eq!(calculate_score(&findings), 45);
    }

    #[test]
    fn a_large_clean_package_does_not_reach_high_by_being_large() {
        // 40 findings spread over 40 files of tests: high total score, no
        // first-party evidence, low density.
        let findings: Vec<Finding> = (0..40)
            .map(|i| at("CODE-001", &format!("tests/t{i}.js"), Severity::High, 5))
            .collect();
        assert_eq!(calculate_score(&findings), 600);
        assert_eq!(first_party_score(&findings), 0);
        assert_eq!(
            determine_verdict_with_size(&findings, 600, 400),
            Verdict::MediumRisk
        );
    }

    #[test]
    fn a_small_package_reaches_high_by_density() {
        // Two findings in the only two files it ships: absolute score is low,
        // but there is nothing else in the package.
        let findings = vec![
            at("CODE-001", "index.js", Severity::High, 5),
            at("CODE-002", "install.js", Severity::High, 5),
        ];
        assert_eq!(calculate_score(&findings), 30);
        assert_eq!(
            determine_verdict_with_size(&findings, 30, 2),
            Verdict::HighRisk
        );
    }

    #[test]
    fn a_test_suite_does_not_inflate_density() {
        // The density term divides FIRST-PARTY score by the file count. Before
        // that, it divided the total: a package whose findings lived in its own
        // tests/ directory had its density inflated by the very paths
        // `first_party_score` exists to discount, while those files were also
        // counted in the denominator. Both halves of the ratio now agree.
        let in_tests = vec![
            at("CODE-001", "tests/test_exec.py", Severity::High, 5),
            at("CODE-002", "tests/test_eval.py", Severity::High, 5),
            at("CODE-007", "tests/fixtures/payload.py", Severity::High, 5),
        ];
        assert_eq!(first_party_score(&in_tests), 0);
        // 45 points over 4 files would have been 11.25 per file under the old
        // total-score density, comfortably over the bar. It contributes nothing.
        assert_ne!(
            determine_verdict_with_size(&in_tests, 45, 4),
            Verdict::HighRisk
        );

        // The same findings in the code the package actually ships still gate.
        let shipped = vec![
            at("CODE-001", "src/exec.py", Severity::High, 5),
            at("CODE-002", "src/eval.py", Severity::High, 5),
            at("CODE-007", "src/run.py", Severity::High, 5),
        ];
        assert_eq!(first_party_score(&shipped), 45);
        assert_eq!(
            determine_verdict_with_size(&shipped, 45, 4),
            Verdict::HighRisk
        );
    }

    #[test]
    fn unknown_file_count_skips_the_density_term() {
        let findings = vec![at("CODE-001", "index.js", Severity::High, 2)];
        // files_scanned = 0 means "unknown": density and concentration must not
        // divide by a guess. One file holding a 6-point High finding would be
        // dense and concentrated at 1 file; unknown, it is only MEDIUM.
        assert_eq!(
            determine_verdict_with_size(&findings, 6, 0),
            Verdict::MediumRisk
        );
        assert_eq!(
            determine_verdict_with_size(&findings, 6, 1),
            Verdict::HighRisk
        );
    }

    #[test]
    fn an_action_behaviour_needs_corroboration() {
        // INSTALL- rules carry install_time_execution. One alone, with almost
        // no other first-party evidence, is not HIGH; npm postinstall hooks are
        // ordinary. 111 of 450 clean packages carry this behaviour.
        // It is a Medium finding in shipped code, so the result is MEDIUM:
        // reported for review, never HIGH on its own.
        let one = vec![at("INSTALL-004", "package.json", Severity::Medium, 2)];
        assert_eq!(
            determine_verdict_with_size(&one, 4, 30),
            Verdict::MediumRisk
        );

        // Two install-hook findings in the code the package ships reach the
        // corroboration threshold, and the install behaviour then gates HIGH
        // in a package far too large for the density term to fire.
        let corroborated = vec![
            at("INSTALL-004", "package.json", Severity::High, 10),
            at("INSTALL-003", "scripts/setup.js", Severity::High, 10),
        ];
        assert!(first_party_score(&corroborated) >= HIGH_ACTION_FIRST_PARTY);
        assert_eq!(
            determine_verdict_with_size(&corroborated, 60, 500),
            Verdict::HighRisk
        );
    }

    #[test]
    fn an_action_behaviour_in_a_secondary_path_does_not_gate_high() {
        // Both halves of the action term have to agree about what is this
        // package's own code. `pypi-click` reached HIGH on four
        // installs_persistence matches in `docs/shell-completion.md` — the
        // project documenting its own install steps — while contributing
        // nothing to first_party_score. Documentation is not an action.
        //
        // The documented finding is PERSIST-005 (a startup file *written*,
        // High) rather than the Low PERSIST-004 reference the original report
        // was about, because a Low finding no longer carries an action
        // behaviour into the verdict at all (see
        // `a_low_action_behaviour_does_not_gate_high`); the path rule under
        // test here is independent of that.
        let documented = vec![
            at(
                "PERSIST-005",
                "click/docs/shell-completion.md",
                Severity::High,
                5,
            ),
            at("CODE-013", "click/core.py", Severity::High, 5),
            at("CODE-011", "click/parser.py", Severity::High, 5),
            at("CODE-004", "click/utils.py", Severity::High, 5),
            at("CRED-002", "click/termui.py", Severity::High, 5),
        ];
        assert!(first_party_score(&documented) >= HIGH_ACTION_FIRST_PARTY);
        assert!(!has_action_behaviour(&documented));
        assert_ne!(
            determine_verdict_with_size(&documented, 100, 112),
            Verdict::HighRisk
        );

        // The same behaviour in the code the package actually ships still gates.
        let mut shipped = documented.clone();
        shipped[0].file = "click/_shell_completion.py".to_string();
        assert!(has_action_behaviour(&shipped));
        assert_eq!(
            determine_verdict_with_size(&shipped, 100, 112),
            Verdict::HighRisk
        );
    }

    #[test]
    fn a_low_action_behaviour_does_not_gate_high() {
        // PERSIST-004 only *references* a shell startup file (Low). Before the
        // Low-observation rule it carried installs_persistence into the action
        // term and let 50 points of unrelated evidence reach HIGH.
        let findings = vec![
            at(
                "PERSIST-004",
                "click/_shell_completion.py",
                Severity::Low,
                5,
            ),
            at("CODE-013", "click/core.py", Severity::High, 5),
            at("CODE-011", "click/parser.py", Severity::High, 5),
            at("CODE-004", "click/utils.py", Severity::High, 5),
            at("CRED-002", "click/termui.py", Severity::High, 5),
        ];
        assert!(!has_action_behaviour(&findings));
        assert_eq!(
            determine_verdict_with_size(&findings, 65, 112),
            Verdict::MediumRisk
        );
    }

    #[test]
    fn critical_gating_is_unchanged_by_the_recalibration() {
        let mut f = at("CRED-006", "key.pem", Severity::Critical, 5);
        f.evidence = Evidence::Corroborate;
        // One corroborating Critical still does not gate CRITICAL...
        assert_ne!(
            determine_verdict_with_size(std::slice::from_ref(&f), 25, 100),
            Verdict::CriticalRisk
        );
        // ...two different ones do.
        let mut g = at("INSTALL-001", "setup.py", Severity::Critical, 10);
        g.evidence = Evidence::Corroborate;
        assert_eq!(
            determine_verdict_with_size(&[f, g], 75, 100),
            Verdict::CriticalRisk
        );
    }

    fn dummy_finding(phase: Phase, severity: Severity, weight: u32) -> Finding {
        finding_in(phase, severity, weight, "TEST-000", "test.py")
    }

    fn finding_in(
        phase: Phase,
        severity: Severity,
        weight: u32,
        rule: &str,
        file: &str,
    ) -> Finding {
        Finding {
            phase,
            rule: rule.to_string(),
            severity,
            file: file.to_string(),
            line: Some(1),
            snippet: "test".to_string(),
            weight,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Evidence::Standalone,
        }
    }

    fn corroborating(rule: &str, file: &str) -> Finding {
        let mut f = finding_in(Phase::Credentials, Severity::Critical, 2, rule, file);
        f.evidence = Evidence::Corroborate;
        f
    }

    #[test]
    fn test_low_risk_no_findings() {
        let findings: Vec<Finding> = vec![];
        let score = calculate_score(&findings);
        assert_eq!(score, 0);
        assert_eq!(determine_verdict(&findings, score), Verdict::LowRisk);
    }

    #[test]
    fn test_low_risk_verdict() {
        let findings = vec![
            finding_in(Phase::Provenance, Severity::Low, 1, "PROV-001", "a.py"),
            finding_in(Phase::Provenance, Severity::Low, 1, "PROV-001", "b.py"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(score, 2);
        assert_eq!(determine_verdict(&findings, score), Verdict::LowRisk);
    }

    #[test]
    fn test_medium_risk_verdict() {
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::High, 5),
            finding_in(Phase::NetworkExfil, Severity::Medium, 3, "NET-001", "n.py"),
        ];
        let score = calculate_score(&findings);
        // 3*5 + 2*3 = 15 + 6 = 21
        assert_eq!(score, 21);
        assert_eq!(determine_verdict(&findings, score), Verdict::MediumRisk);
    }

    #[test]
    fn a_score_of_25_from_scattered_dual_use_findings_is_no_longer_high() {
        // This used to be the whole HIGH gate: score >= 25. Three unrelated
        // dual-use findings — a code pattern, an outbound request, an
        // environment read — reach 25 in any ordinary package, which is why
        // 16 of 20 popular packages came back HIGH RISK.
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::High, 5),
            finding_in(Phase::NetworkExfil, Severity::Medium, 3, "NET-001", "n.py"),
            finding_in(Phase::Credentials, Severity::Medium, 2, "CRED-001", "c.py"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(score, 25, "3*5 + 2*3 + 2*2");
        // Spread over a package of any size, this is now MEDIUM: it is
        // evidence worth reading, not a reason to fail a build.
        assert_eq!(
            determine_verdict_with_size(&findings, score, 200),
            Verdict::MediumRisk
        );
    }

    #[test]
    fn the_same_findings_in_a_three_file_package_are_high() {
        // ...and the same evidence in a package that ships almost nothing else
        // still reaches HIGH, through the density term rather than the sum.
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::High, 5),
            finding_in(Phase::NetworkExfil, Severity::Medium, 3, "NET-001", "n.py"),
            finding_in(Phase::Credentials, Severity::Medium, 2, "CRED-001", "c.py"),
        ];
        assert_eq!(
            determine_verdict_with_size(&findings, 25, 3),
            Verdict::HighRisk
        );
    }

    #[test]
    fn test_critical_risk_install_hook_escalation() {
        let findings = vec![dummy_finding(Phase::InstallHooks, Severity::Critical, 10)];
        let score = calculate_score(&findings);
        // Critical install hook always escalates to CriticalRisk
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn test_critical_risk_by_score() {
        // Two standalone Criticals: still CriticalRisk, and the score is the
        // plain sum because they come from different rules and files.
        let findings = vec![
            finding_in(
                Phase::CodePatterns,
                Severity::Critical,
                5,
                "CODE-001",
                "a.js",
            ),
            finding_in(
                Phase::Obfuscation,
                Severity::Critical,
                5,
                "OBFUSC-001",
                "b.js",
            ),
        ];
        let score = calculate_score(&findings);
        // 5*5 + 5*5 = 25+25 = 50
        assert_eq!(score, 50);
        assert!(score >= 50);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn test_medium_low_volume_does_not_become_critical() {
        // Spread over distinct files so the per-(rule, file) cap does not
        // apply: this test is about volume never *escalating* to Critical.
        let findings: Vec<Finding> = (0..20)
            .map(|i| {
                finding_in(
                    Phase::NetworkExfil,
                    Severity::Medium,
                    3,
                    "NET-001",
                    &format!("n{i}.py"),
                )
            })
            .chain((0..20).map(|i| {
                finding_in(
                    Phase::Provenance,
                    Severity::Low,
                    1,
                    "PROV-001",
                    &format!("p{i}.py"),
                )
            }))
            .collect();
        let score = calculate_score(&findings);
        assert_eq!(score, 140);
        // The point of this test: volume alone never reaches CRITICAL.
        assert_ne!(
            determine_verdict_with_size(&findings, score, 20),
            Verdict::CriticalRisk
        );
        // Nor HIGH: 120 signal points in a 20-file package is dense, but every
        // one of them is Medium, and a pile of "suspicious in context" findings
        // is a reason to review, not to block...
        assert_eq!(
            determine_verdict_with_size(&findings, score, 20),
            Verdict::MediumRisk
        );
        // ...and the same holds spread through a large package.
        assert_eq!(
            determine_verdict_with_size(&findings, score, 400),
            Verdict::MediumRisk
        );
    }

    // -- the evidence gate --------------------------------------------------

    #[test]
    fn a_lone_medium_in_a_two_file_skill_is_not_high() {
        // SkillSpector's clean fixture tests/fixtures/mcp_clean_skill: one
        // subprocess.run with an argument list in a two-file skill. At Medium,
        // 10 points over 2 files cleared the 3.5-per-file density bar and the
        // skill was HIGH RISK. Density still fires; the evidence gate does not.
        let findings = vec![at("CODE-013", "scripts/format.py", Severity::Medium, 5)];
        assert!(2 * first_party_score(&findings) >= 7 * 2);
        assert_eq!(
            determine_verdict_with_size(&findings, 10, 2),
            Verdict::MediumRisk
        );
        // Several Medium findings from different rules are still not HIGH.
        let many = vec![
            at("CODE-013", "scripts/a.py", Severity::Medium, 5),
            at("CODE-004", "scripts/a.py", Severity::Medium, 5),
            at("MANIP-008", "SKILL.md", Severity::Medium, 10),
        ];
        assert_eq!(
            determine_verdict_with_size(&many, 40, 2),
            Verdict::MediumRisk
        );
    }

    #[test]
    fn low_observations_never_move_the_verdict() {
        // A skill made only of routine capabilities: network clients, an API
        // key read from the environment, subprocess calls, a Bash grant.
        let findings: Vec<Finding> = (0..30)
            .map(|i| at("NET-001", &format!("scripts/c{i}.py"), Severity::Low, 3))
            .chain((0..30).map(|i| at("CRED-001", &format!("scripts/c{i}.py"), Severity::Low, 2)))
            .chain(std::iter::once(at(
                "SKILL-008",
                "SKILL.md",
                Severity::Low,
                5,
            )))
            .collect();
        let score = calculate_score(&findings);
        assert_eq!(score, 30 * 3 + 30 * 2 + 5, "the reported score keeps them");
        assert_eq!(signal_score(&findings), 0);
        assert_eq!(first_party_score(&findings), 0);
        assert_eq!(
            determine_verdict_with_size(&findings, score, 31),
            Verdict::LowRisk
        );
    }

    #[test]
    fn one_high_finding_in_a_small_skill_is_high_by_concentration() {
        // SkillSpector's malicious fixture: a two-file skill whose helper
        // iterates os.environ (CRED-033, High, weight 2). 6 points over 2 files
        // is under the density bar, which is tuned to phase weights; the
        // concentration term asks whether the attack-shaped code is a real
        // part of the package instead.
        let findings = vec![
            at("CRED-033", "scripts/helper.py", Severity::High, 2),
            at("NET-001", "scripts/helper.py", Severity::Low, 3),
        ];
        assert!(2 * first_party_score(&findings) < 7 * 2);
        assert_eq!(
            determine_verdict_with_size(&findings, 12, 2),
            Verdict::HighRisk
        );
        // The same finding in one file of a 40-file package is diluted: it is
        // reported and it raises the verdict to MEDIUM, but it does not block.
        assert_eq!(
            determine_verdict_with_size(&findings, 12, 40),
            Verdict::MediumRisk
        );
        // With the file count unknown the concentration term is skipped.
        assert_eq!(
            determine_verdict_with_size(&findings, 12, 0),
            Verdict::MediumRisk
        );
    }

    #[test]
    fn attack_evidence_outside_the_shipped_code_does_not_gate_high() {
        // A High finding in tests/ or in a reference document's code example
        // is reported, and counts toward the total, but it is not evidence
        // about what the package does when it runs.
        for file in ["tests/test_exfil.py", "references/api.md", "docs/setup.md"] {
            let f = Finding {
                phase: Phase::NetworkExfil,
                ..at("NET-RCE-001", file, Severity::High, 3)
            };
            assert!(!has_attack_evidence(std::slice::from_ref(&f)), "{file}");
        }
        // The same finding in the skill's entry point is the payload.
        let payload = Finding {
            phase: Phase::NetworkExfil,
            ..at("NET-RCE-001", "SKILL.md", Severity::High, 3)
        };
        assert!(has_attack_evidence(std::slice::from_ref(&payload)));
        assert_eq!(
            determine_verdict_with_size(std::slice::from_ref(&payload), 9, 2),
            Verdict::HighRisk
        );
        // An instruction in a reference file is still an instruction: only the
        // code phases are discounted there.
        let instruction = Finding {
            phase: Phase::PromptInjection,
            ..at("PROMPT-010", "references/setup.md", Severity::High, 10)
        };
        assert!(has_attack_evidence(std::slice::from_ref(&instruction)));
    }

    #[test]
    fn a_skills_evals_directory_is_secondary() {
        // nvflare-convert-pytorch ships a hostile requirements.txt under
        // evals/files/ to prove the skill resists it.
        assert!(is_secondary_path(
            "evals/files/injection-pt/requirements.txt"
        ));
        assert!(is_secondary_path("skill/evals/evals.json"));
        // A code directory merely named eval is not.
        assert!(!is_secondary_path("scripts/eval/run.py"));
    }

    // -- per-(rule, file) contribution cap ---------------------------------

    #[test]
    fn score_saturates_after_three_hits_of_one_rule_in_one_file() {
        let many: Vec<Finding> = (0..1723)
            .map(|_| {
                finding_in(
                    Phase::Obfuscation,
                    Severity::Medium,
                    5,
                    "OBFUSC-X",
                    "data.py",
                )
            })
            .collect();
        // 3 counted * (2 * 5) rather than 1723 * 10.
        assert_eq!(calculate_score(&many), 30);
        assert_eq!(many.len(), 1723, "every finding is still reported");
    }

    #[test]
    fn cap_is_per_file_not_per_rule() {
        let spread: Vec<Finding> = (0..4)
            .map(|i| {
                finding_in(
                    Phase::Obfuscation,
                    Severity::Medium,
                    5,
                    "OBFUSC-X",
                    &format!("f{i}.py"),
                )
            })
            .collect();
        // Four distinct files, all under the cap: 4 * 10.
        assert_eq!(calculate_score(&spread), 40);
    }

    #[test]
    fn cap_is_per_rule_not_per_file() {
        let mixed = vec![
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-Y", "f.py"),
        ];
        // OBFUSC-X capped at 3, OBFUSC-Y counted once: (3 + 1) * 10.
        assert_eq!(calculate_score(&mixed), 40);
    }

    #[test]
    fn capped_findings_are_still_reported_and_still_gate_critical() {
        let mut f = finding_in(
            Phase::InstallHooks,
            Severity::Critical,
            10,
            "INSTALL-003",
            "s.py",
        );
        f.evidence = Evidence::Standalone;
        let findings: Vec<Finding> = (0..10).map(|_| f.clone()).collect();
        let score = calculate_score(&findings);
        assert_eq!(score, 3 * 50);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    // -- evidence-gated Critical -------------------------------------------

    #[test]
    fn one_standalone_critical_gates_the_verdict() {
        let findings = vec![finding_in(
            Phase::InstallHooks,
            Severity::Critical,
            10,
            "INSTALL-003",
            "setup.py",
        )];
        let score = calculate_score(&findings);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn two_corroborating_criticals_from_the_same_rule_do_not_gate() {
        // `requests` ships four test certificates: four CRED-006 hits, one
        // rule. That is one observation repeated, not two independent ones.
        let findings = vec![
            corroborating("CRED-006", "tests/certs/a.key"),
            corroborating("CRED-006", "tests/certs/b.key"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(
            determine_verdict(&findings, score),
            Verdict::MediumRisk,
            "score 20 falls through to the score thresholds"
        );
    }

    #[test]
    fn two_corroborating_criticals_from_different_rules_gate() {
        let findings = vec![
            corroborating("CRED-006", "a.key"),
            corroborating("INSTALL-001", "setup.py"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn corroborate_only_criticals_still_raise_the_score() {
        let one = vec![corroborating("CRED-006", "a.key")];
        // 5 * 2 = 10, which is MediumRisk on its own.
        assert_eq!(calculate_score(&one), 10);
        assert_eq!(
            determine_verdict(&one, calculate_score(&one)),
            Verdict::MediumRisk
        );

        // And a corroborating Critical pushes an otherwise-High set no higher.
        let mut mixed = vec![
            finding_in(Phase::CodePatterns, Severity::High, 5, "CODE-001", "a.js"),
            finding_in(Phase::CodePatterns, Severity::High, 5, "CODE-002", "b.js"),
        ];
        mixed.push(corroborating("CRED-006", "a.key"));
        let score = calculate_score(&mixed);
        assert_eq!(score, 15 + 15 + 10);
        // Three findings in a three-file package: HIGH on density, and the
        // corroborating Critical does not push it to CRITICAL.
        assert_eq!(
            determine_verdict_with_size(&mixed, score, 3),
            Verdict::HighRisk
        );
    }

    #[test]
    fn a_standalone_critical_beside_a_corroborating_one_still_gates() {
        let findings = vec![
            corroborating("CRED-006", "a.key"),
            finding_in(
                Phase::InstallHooks,
                Severity::Critical,
                10,
                "INSTALL-003",
                "s.py",
            ),
        ];
        let score = calculate_score(&findings);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }
}
