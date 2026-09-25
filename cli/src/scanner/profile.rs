//! Scan profile: the letter grade, recommendation, behaviour profile and key
//! risks derived from a finished result.
//!
//! Most of this module is a *presentation* of the score and verdict that
//! `scoring.rs` already computed: the grade is a one-character rendering of
//! the verdict thresholds documented in the README, and the key risks are the
//! top findings by severity. A reader who only sees the grade and the profile
//! should be able to answer "what does this thing *do*?" without reading every
//! finding — that is the whole point.
//!
//! [`behavior_for`] is the exception, and it is load-bearing. Since the
//! verdict recalibration in #160 it is read by
//! `scoring.rs::has_action_behaviour`, which gates the HIGH verdict: one
//! first-party finding whose behaviour is `install_time_execution`,
//! `exfiltration_endpoint`, `installs_persistence`, `dynamic_execution` or
//! `drive_by_install` lets a first-party score of 50 reach HIGH, where 200
//! would otherwise be required — and the verdict becomes the process exit
//! code. A rule with no specific arm inherits its family's behaviour from its
//! id prefix alone, so editing the specific-id arms or the family-prefix
//! table below changes verdicts and exit codes, not just display text.
//! Re-measure against the corpus before changing either.

use super::{Finding, ScanResult, Severity, Verdict};

/// Everything the summary layer says about a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProfile {
    /// `A` through `F`. See [`grade`] for the mapping.
    pub grade: &'static str,
    /// The one-line recommendation for this grade.
    pub recommendation: &'static str,
    /// Sorted, de-duplicated capabilities the findings evidence, e.g.
    /// `executes_shell`, `network_outbound`, `installs_persistence`.
    pub behaviors: Vec<String>,
    /// The top findings by severity, one line each, de-duplicated by rule.
    pub key_risks: Vec<String>,
}

/// Maximum number of key risks reported.
pub const KEY_RISK_LIMIT: usize = 5;

/// Letter grade for a verdict.
///
/// The grade never disagrees with the verdict; it only splits `LOW RISK` into
/// `A` (no findings at all) and `B` (low-severity observations only), which
/// is the distinction a badge or a registry listing wants to make:
///
/// | Grade | Verdict | Meaning |
/// |---|---|---|
/// | A | LOW RISK, score 0 | no findings |
/// | B | LOW RISK, score 1–9 | low-severity observations only |
/// | C | MEDIUM RISK | suspicious patterns, review before approving |
/// | D | HIGH RISK | dangerous patterns, sandbox until reviewed |
/// | F | CRITICAL RISK | strong malicious indicators |
pub fn grade(verdict: Verdict, score: u32) -> &'static str {
    match verdict {
        Verdict::CriticalRisk => "F",
        Verdict::HighRisk => "D",
        Verdict::MediumRisk => "C",
        Verdict::LowRisk if score == 0 => "A",
        Verdict::LowRisk => "B",
    }
}

/// The recommendation that goes with a grade.
///
/// Phrased in Sigil's terms: a clean scan is a reason to *approve*, not a
/// guarantee of safety, which is the line the README and the disclaimer
/// already hold.
pub fn recommendation(grade: &str) -> &'static str {
    match grade {
        "A" => "No known malicious patterns detected — review, then approve.",
        "B" => "Low-severity observations only — review them, then approve.",
        "C" => "Suspicious patterns — review each finding before approving.",
        "D" => "Dangerous patterns — do not run outside a sandbox until reviewed.",
        _ => "Strong malicious indicators — do not install or execute this code.",
    }
}

/// The capability a rule evidences, from its id.
///
/// Rule ids are prefixed by family (`CODE-`, `NET-`, `CRED-`, ...) with a
/// handful of ids inside a family that mean something more specific than the
/// family default (`CODE-004` is deserialization, not dynamic execution).
/// Findings the corpus did not produce — OSV advisories, ledger drift — are
/// mapped by their own id shapes.
pub fn behavior_for(rule_id: &str) -> Option<&'static str> {
    // Specific ids first, so a family default cannot shadow them.
    let specific = match rule_id {
        "CODE-004" | "CODE-005" | "CODE-006" => Some("unsafe_deserialization"),
        "CODE-007" | "CODE-013" | "CODE-014" | "CODE-015" => Some("executes_shell"),
        "CODE-010" | "CODE-011" | "CODE-012" => Some("dynamic_import"),
        "NET-006" | "NET-007" => Some("exfiltration_endpoint"),
        "NET-008" | "NET-009" => Some("raw_sockets"),
        "NET-010" => Some("dns_lookup"),
        "NET-011" => Some("encodes_before_send"),
        "NET-012" | "NET-RCE-001" => Some("downloads_remote_content"),
        "NET-013" => Some("targets_metadata_endpoint"),
        "NET-014" => Some("c2_tunnel_host"),
        "NET-015" => Some("suspicious_domain"),
        "NET-017" => Some("cryptomining"),
        "NET-018" => Some("dns_exfiltration"),
        "CRED-004" | "CRED-006" | "CRED-007" | "CRED-008" | "CRED-009" | "CRED-010"
        | "CRED-011" | "CRED-013" | "CRED-014" | "CRED-015" | "CRED-016" | "CRED-017"
        | "CRED-018" | "CRED-019" | "CRED-020" | "CRED-021" | "CRED-022" | "CRED-023"
        | "CRED-024" | "CRED-025" | "CRED-026" | "CRED-027" | "CRED-028" | "CRED-029" => {
            Some("hardcoded_secrets")
        }
        "CRED-030" | "CRED-031" | "CRED-032" | "CRED-033" | "CRED-040" | "CRED-041"
        | "CRED-042" | "CRED-043" => Some("harvests_credentials"),
        "PROV-DOWNGRADE" | "PROV-IDENTITY-CHANGE" | "PROV-REPO-MISMATCH" => {
            Some("provenance_drift")
        }
        // `^\.(PHONY|ONESHELL).*install` matches a Makefile *declaration*, and
        // neither `pip install` nor `npm install` ever invokes make — a Make
        // target runs only when a human types `make install`. The rule's own
        // remediation says it "runs nothing by itself". Without this arm the
        // "INSTALL-" family default below would call it install_time_execution,
        // an ACTION behaviour that gates HIGH, which is simply not true of a
        // declaration line. Measured over 844 malicious samples and 450 clean
        // packages, correcting it flips no verdict in either population: this
        // is a correctness fix, not a tuning change.
        //
        // Contrast INSTALL-008 (`backend-path =`), which stays an action: a
        // PEP 517 in-tree backend really is executed by pip, and an attacker
        // who publishes an sdist-only package forces that path on a plain
        // `pip install <name>`.
        "INSTALL-006" => Some("build_configuration"),
        // `prepublishOnly` runs on `npm publish` and nowhere else: not on a
        // registry install, a git-dependency install or a bare `npm install`
        // in a checkout. The "INSTALL-" family default would make it
        // `install_time_execution`, an action that lowers the HIGH bar, for a
        // script that cannot run on the installer's machine.
        "INSTALL-009" => Some("publish_time_script"),
        // Lifecycle findings rewritten by scanner::lifecycle. An inert
        // postinstall still runs on install (an action); a package-manager
        // guard, a build-only `prepare` and a launcher that installs its own
        // platform package are not actions, and each needs its arm because
        // the "INSTALL-" and "CODE-" family defaults are.
        "INSTALL-010" => Some("install_time_execution"),
        "INSTALL-011" => Some("install_time_guard"),
        "INSTALL-012" => Some("build_step"),
        "CODE-016" => Some("executes_shell"),
        // Concealment from the user is manipulation of the agent, not an
        // instruction override: same split as MANIP-007 vs PROMPT-001.
        "INTL-003" => Some("manipulates_agent"),
        "REF-001" => Some("downloads_executable"),
        "REF-002" => Some("unscanned_reference"),
        // Agent supply chain pack (agent_supply_chain.json). The ACTION arms
        // were chosen for what the rule proves, not for the verdict it buys:
        // AGENTSC-004 is code that fetches a script from an anonymous
        // file-drop host to run it (dynamic execution in the plainest sense),
        // AGENTSC-030 and AGENTSC-034 are a skill naming, and telling the
        // agent to write itself into, the agent's global instruction file
        // (persistence), and the fake-prerequisite rules (AGENTSC-001..005)
        // are an instruction to fetch and run an installer, labelled
        // `drive_by_install` — an action since the reconciliation pass (see
        // ACTION_BEHAVIOURS in scoring.rs for the measurement).
        "AGENTSC-001" | "AGENTSC-002" | "AGENTSC-003" | "AGENTSC-005" => Some("drive_by_install"),
        "AGENTSC-004" => Some("dynamic_execution"),
        "AGENTSC-010" | "AGENTSC-013" | "AGENTSC-015" => Some("harvests_credentials"),
        "AGENTSC-011" | "AGENTSC-012" | "AGENTSC-032" | "AGENTSC-CHAIN-001"
        | "AGENTSC-CHAIN-002" => Some("exfiltrates_data"),
        "AGENTSC-014" => Some("hardcoded_secrets"),
        "AGENTSC-020" => Some("c2_tunnel_host"),
        "AGENTSC-030" | "AGENTSC-034" => Some("installs_persistence"),
        "AGENTSC-031" | "AGENTSC-033" => Some("manipulates_agent"),
        "AGENTSC-040" => Some("hijacks_browser_session"),
        "AGENTSC-041" => Some("active_content_payload"),
        // Agent-instruction pack (agent_instructions.json). None of these is an
        // ACTION behaviour: they describe what a skill tells the agent to do,
        // and gate the verdict through severity alone. INSTR-014 writes the
        // user's global agent memory file, which is persistence in spirit, but
        // it is deliberately not mapped to `installs_persistence` without a
        // corpus re-measurement (a clean NVIDIA setup skill does it on purpose).
        // INSTR-032 is a Low observation ("from now on, always …") split out of
        // INSTR-011 so a project's own instruction file is not read as memory
        // poisoning; INSTR-033 is a skill that hides itself or sabotages code.
        "INSTR-032" => Some("standing_directive"),
        "INSTR-033" => Some("deceives_user"),
        "INSTR-001" | "INSTR-002" => Some("disables_safety_guardrails"),
        "INSTR-003" | "INSTR-004" => Some("suppresses_warnings"),
        "INSTR-005" => Some("exfiltrates_conversation"),
        "INSTR-006" | "INSTR-007" => Some("manipulates_user"),
        "INSTR-008" => Some("harmful_content"),
        "INSTR-009" | "INSTR-010" => Some("leaks_system_prompt"),
        "INSTR-011" | "INSTR-012" | "INSTR-013" | "INSTR-014" | "INSTR-015" => {
            Some("poisons_agent_memory")
        }
        "INSTR-016" | "INSTR-017" | "INSTR-018" | "INSTR-019" | "INSTR-020" => {
            Some("excessive_agency")
        }
        "INSTR-021" => Some("unbounded_consumption"),
        "INSTR-022" | "INSTR-023" => Some("selects_model"),
        "INSTR-024" | "INSTR-025" | "INSTR-026" => Some("snoops_agent_config"),
        "INSTR-027" => Some("self_modifies"),
        "INSTR-028" => Some("disables_signature_check"),
        "INSTR-029" => Some("hidden_instruction"),
        "INSTR-030" => Some("trigger_abuse"),
        "INSTR-031" => Some("uses_obfuscation"),
        // Reconciliation rules (docs/detection/fp-calibration.md,
        // "Reconciliation"). The Low observations get specific, non-action
        // labels so the CODE- family default (`dynamic_execution`, an action)
        // cannot attach to a routine launch or model load; the chains carry
        // what the link proves. A downloaded file that is then run is dynamic
        // execution; a bundled pickle that is loaded is deserialization.
        "CODE-RUNFILE-001" => Some("executes_program"),
        "CODE-DESER-001" | "DESER-CHAIN-001" => Some("unsafe_deserialization"),
        "CODE-MODEL-001" => Some("bundled_pickle_file"),
        "DROPPER-CHAIN-001" => Some("dynamic_execution"),
        "NET-EXE-001" => Some("downloads_executable"),
        "NET-UPLOAD-001" => Some("uploads_local_file"),
        "NET-RAWIP-001" => Some("raw_ip_endpoint"),
        // Structural checks (scanner::bytecode / artifacts). None of these is
        // an ACTION behaviour: ARTIFACT-002 gates CRITICAL on its own, and the
        // rest describe what was shipped, not something the package did.
        "ARTIFACT-001" | "ARTIFACT-012" => Some("ships_bytecode"),
        "ARTIFACT-002" | "ARTIFACT-003" => Some("bytecode_source_mismatch"),
        "ARTIFACT-004" | "ARTIFACT-006" | "ARTIFACT-011" => Some("concealed_executable"),
        "ARTIFACT-005" | "ARTIFACT-009" => Some("concealed_artifact"),
        "ARTIFACT-010" => Some("archive_path_traversal"),
        "PAD-003" => Some("whitespace_padding"),
        _ => None,
    };
    if specific.is_some() {
        return specific;
    }

    // The scan budget finding says the analyser ran out of time on a file.
    // That is a fact about the scan, not a behaviour of the package, and the
    // behaviour profile is read as a description of the package — so it
    // contributes none. Returning early matters: the "PROV-" family below
    // would otherwise assert a provenance anomaly nobody observed.
    // The same holds for the partial-read finding (scanner::coverage): an
    // unreadable or partly read file says nothing about what the package does.
    if rule_id == crate::scanner::budget::BUDGET_RULE_ID
        || rule_id == crate::scanner::coverage::RULE_PARTIAL
    {
        return None;
    }

    let families: &[(&str, &str)] = &[
        ("CODE-MCP-", "mcp_tooling"),
        ("CODE-", "dynamic_execution"),
        ("NET-SSRF-", "targets_internal_network"),
        ("NET-MCP-", "mcp_transport"),
        ("NET-", "network_outbound"),
        ("CRED-", "reads_credentials"),
        ("OBFUSC-", "uses_obfuscation"),
        ("UNICODE-", "invisible_unicode"),
        ("INSTALL-MCP-", "mcp_registration"),
        ("INSTALL-", "install_time_execution"),
        ("PROMPT-", "prompt_injection"),
        ("INTL-", "prompt_injection"),
        ("MANIP-", "manipulates_agent"),
        ("INSTR-", "agent_instruction_abuse"),
        ("SKILL-", "manifest_risk"),
        ("INFER-", "inference_tampering"),
        ("RSHELL-", "reverse_shell"),
        ("SUPPLY-", "supply_chain_manipulation"),
        ("PERSIST-", "installs_persistence"),
        ("AGENTSC-", "agent_supply_chain"),
        ("EXFIL-", "exfiltrates_data"),
        ("TYPOSQUAT-", "typosquat_dependency"),
        ("HYGIENE-", "publish_hygiene"),
        ("PROV-", "provenance_anomaly"),
        ("KNOWNGOOD-DRIFT", "modified_known_release"),
        ("RUGPULL-", "post_approval_drift"),
        ("ARCHIVE-BOMB", "decompression_bomb"),
        ("AGENTCFG-", "agent_config_risk"),
        ("ARTIFACT-", "bundled_archive"),
        ("DEPSRC-", "dependency_source_redirect"),
        ("PAD-", "hides_text_with_padding"),
        ("LPRIV-", "privilege_mismatch"),
        // OSV advisory ids.
        ("MAL-", "known_malicious_package"),
        ("GHSA-", "known_vulnerable_dependency"),
        ("CVE-", "known_vulnerable_dependency"),
        ("PYSEC-", "known_vulnerable_dependency"),
        ("RUSTSEC-", "known_vulnerable_dependency"),
        ("OSV-", "known_vulnerable_dependency"),
        ("GO-", "known_vulnerable_dependency"),
    ];
    families
        .iter()
        .find(|(prefix, _)| rule_id.starts_with(prefix))
        .map(|(_, behavior)| *behavior)
}

/// Sorted, de-duplicated behaviours across a finding set.
pub fn behaviors(findings: &[Finding]) -> Vec<String> {
    let mut out: Vec<String> = findings
        .iter()
        .filter_map(|f| behavior_for(&f.rule))
        .map(str::to_string)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The title of a finding: the rule description that prefixes every
/// corpus-produced snippet, or the whole snippet when there is no prefix
/// (an OSV advisory summary, say).
pub fn title_of(finding: &Finding) -> String {
    if let Some(meta) = crate::corpus::compiled::corpus().rule_meta(&finding.rule) {
        return meta.title.clone();
    }
    builtin_title(&finding.rule)
        .map(str::to_string)
        .unwrap_or_else(|| finding.snippet.clone())
}

/// Titles for findings produced by Rust code rather than a pack.
fn builtin_title(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "RUGPULL-001" => Some("Approved content changed after approval (rug-pull)"),
        "KNOWNGOOD-DRIFT-001" => Some("Modified copy of a published release"),
        "ARCHIVE-BOMB-001" => Some("Archive expansion exceeded the extraction cap"),
        "UNICODE-001" => Some("Bidirectional override characters in source"),
        "UNICODE-002" => Some("Zero-width characters in source"),
        "UNICODE-003" => Some("Invisible characters inside an identifier or token"),
        "PROV-DOWNGRADE" => Some("Package version downgraded against the ledger baseline"),
        "PROV-IDENTITY-CHANGE" => Some("Package publisher identity changed"),
        "PROV-REPO-MISMATCH" => Some("Package repository does not match the registry record"),
        "EXFIL-CHAIN-001" => Some("Credential read flows into an outbound network send"),
        "TYPOSQUAT-001" => Some("Dependency name is one edit away from a top package (typosquat)"),
        id if id.starts_with("AGENTCFG-") => crate::inventory::title(id),
        _ => None,
    }
}

/// The top findings by severity then weight, one per rule, at most
/// [`KEY_RISK_LIMIT`].
pub fn key_risks(findings: &[Finding]) -> Vec<String> {
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.weight.cmp(&a.weight))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });

    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for f in ranked {
        if f.severity < Severity::Medium {
            break;
        }
        if seen.contains(&f.rule.as_str()) {
            continue;
        }
        seen.push(&f.rule);
        let location = match f.line {
            Some(line) => format!("{}:{}", f.file, line),
            None => f.file.clone(),
        };
        out.push(format!(
            "{}: {} ({}) — {}",
            f.severity,
            title_of(f),
            f.rule,
            location
        ));
        if out.len() >= KEY_RISK_LIMIT {
            break;
        }
    }
    out
}

/// Build the profile for a result. Suppressed findings do not contribute:
/// they are excluded from score and verdict, so they are excluded here too.
pub fn build(result: &ScanResult) -> ScanProfile {
    let grade = grade(result.verdict, result.score);
    ScanProfile {
        grade,
        recommendation: recommendation(grade),
        behaviors: behaviors(&result.findings),
        key_risks: key_risks(&result.findings),
    }
}

#[cfg(test)]
mod tests {
    /// These two rules sit either side of the same question — does this rule
    /// mean the package *runs something at install time*? — and the answer
    /// decides whether one finding can carry a package to HIGH. Both are
    /// pinned because neither is guarded by anything else: `behavior_for`
    /// falls back to the "INSTALL-" family prefix, so deleting either arm
    /// silently changes verdicts and exit codes rather than failing to build.
    #[test]
    fn backend_path_stays_an_action_behaviour() {
        // INSTALL-008 (`backend-path =`) declares a PEP 517 in-tree build
        // backend. pip really does import and run it — not from a wheel, but
        // an attacker publishing an sdist-only package forces the build path
        // on a plain `pip install <name>`, and the hooks run with the
        // victim's environment in scope. A trojaned in-tree backend can also
        // be written to evade the network and exfil-chain rules, leaving this
        // as the only action evidence. It is a true action; it must stay one.
        assert_eq!(behavior_for("INSTALL-008"), Some("install_time_execution"));
    }

    #[test]
    fn a_makefile_install_declaration_is_not_an_action_behaviour() {
        // INSTALL-006 matches `.PHONY:`/`.ONESHELL` lines in a Makefile.
        // Neither `pip install` nor `npm install` invokes make, so nothing
        // here runs at install time; the finding points a reader at the
        // recipe, which is a build-configuration fact, not an action.
        assert_eq!(behavior_for("INSTALL-006"), Some("build_configuration"));
        assert_ne!(behavior_for("INSTALL-006"), Some("install_time_execution"));
    }

    use super::*;
    use crate::scanner::Phase;

    fn f(rule: &str, severity: Severity, weight: u32) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: "a.py".to_string(),
            line: Some(3),
            snippet: format!("{} title: matched line", rule),
            weight,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        }
    }

    #[test]
    fn grade_follows_the_verdict_thresholds() {
        assert_eq!(grade(Verdict::LowRisk, 0), "A");
        assert_eq!(grade(Verdict::LowRisk, 1), "B");
        assert_eq!(grade(Verdict::LowRisk, 9), "B");
        assert_eq!(grade(Verdict::MediumRisk, 10), "C");
        assert_eq!(grade(Verdict::HighRisk, 25), "D");
        assert_eq!(grade(Verdict::CriticalRisk, 5), "F");
    }

    #[test]
    fn every_grade_has_a_recommendation() {
        for g in ["A", "B", "C", "D", "F"] {
            assert!(!recommendation(g).is_empty());
        }
    }

    #[test]
    fn specific_ids_beat_family_defaults() {
        assert_eq!(behavior_for("CODE-001"), Some("dynamic_execution"));
        assert_eq!(behavior_for("CODE-004"), Some("unsafe_deserialization"));
        assert_eq!(behavior_for("CODE-014"), Some("executes_shell"));
        assert_eq!(behavior_for("CODE-MCP-001"), Some("mcp_tooling"));
        assert_eq!(behavior_for("NET-001"), Some("network_outbound"));
        assert_eq!(behavior_for("NET-007"), Some("exfiltration_endpoint"));
        assert_eq!(behavior_for("CRED-001"), Some("reads_credentials"));
        assert_eq!(behavior_for("CRED-004"), Some("hardcoded_secrets"));
        assert_eq!(behavior_for("CRED-021"), Some("hardcoded_secrets"));
        assert_eq!(behavior_for("CRED-040"), Some("harvests_credentials"));
        assert_eq!(
            behavior_for("GHSA-1234-abcd-ef56"),
            Some("known_vulnerable_dependency")
        );
        assert_eq!(behavior_for("MAL-2024-1"), Some("known_malicious_package"));
        assert_eq!(behavior_for("PROV-001"), Some("provenance_anomaly"));
        // A truncated scan is a fact about the scan, not a behaviour of the
        // package: it must not be reported as a provenance anomaly.
        assert_eq!(behavior_for(crate::scanner::budget::BUDGET_RULE_ID), None);
        assert_eq!(behavior_for(crate::scanner::coverage::RULE_PARTIAL), None);
        assert_eq!(behavior_for("PROV-DOWNGRADE"), Some("provenance_drift"));
        assert_eq!(behavior_for("TOTALLY-UNKNOWN"), None);
    }

    /// Every rule the corpus can emit must map to a behaviour, or the
    /// profile silently under-reports the moment a pack adds a family.
    #[test]
    fn every_corpus_rule_maps_to_a_behavior() {
        // Coverage findings are facts about the scan, not behaviours of the
        // package, and deliberately map to none.
        let unmapped: Vec<String> = crate::corpus::compiled::corpus()
            .rule_ids()
            .into_iter()
            .filter(|id| behavior_for(id).is_none())
            .filter(|id| {
                id != crate::scanner::budget::BUDGET_RULE_ID
                    && id != crate::scanner::coverage::RULE_PARTIAL
            })
            .collect();
        assert!(
            unmapped.is_empty(),
            "rules without a behaviour: {unmapped:?}"
        );
    }

    /// INSTR-* findings gate the verdict through their severity alone. None
    /// may borrow the lower HIGH threshold that an action behaviour unlocks
    /// in `scoring::has_action_behaviour` without a corpus re-measurement.
    #[test]
    fn agent_instruction_rules_are_not_action_behaviours() {
        const ACTIONS: &[&str] = &[
            "install_time_execution",
            "exfiltration_endpoint",
            "installs_persistence",
            "dynamic_execution",
        ];
        let ids: Vec<String> = crate::corpus::compiled::corpus()
            .rule_ids()
            .into_iter()
            .filter(|id| id.starts_with("INSTR-"))
            .collect();
        assert!(
            ids.len() >= 30,
            "agent_instructions pack not loaded: {ids:?}"
        );
        for id in &ids {
            let b = behavior_for(id).unwrap_or_else(|| panic!("{id} has no behaviour"));
            assert!(!ACTIONS.contains(&b), "{id} maps to action behaviour {b}");
        }
        assert_eq!(behavior_for("INSTR-014"), Some("poisons_agent_memory"));
        assert_eq!(behavior_for("INSTR-099"), Some("agent_instruction_abuse"));
    }

    /// Lifecycle findings that cannot run on the installer's machine, or that
    /// the lifecycle classifier found inert, must not borrow the lowered HIGH
    /// bar an action behaviour unlocks. Each needs its own arm: the
    /// "INSTALL-" and "CODE-" family defaults are both actions.
    #[test]
    fn non_executing_lifecycle_rules_are_not_action_behaviours() {
        use crate::scanner::scoring::ACTION_BEHAVIOURS;
        for (id, expected) in [
            ("INSTALL-009", "publish_time_script"),
            ("INSTALL-011", "install_time_guard"),
            ("INSTALL-012", "build_step"),
            ("CODE-016", "executes_shell"),
        ] {
            let b = behavior_for(id).unwrap_or_else(|| panic!("{id} has no behaviour"));
            assert_eq!(b, expected, "{id}");
            assert!(
                !ACTION_BEHAVIOURS.contains(&b),
                "{id} maps to action behaviour {b}"
            );
        }
        // INSTALL-004 (prepare/prepublish) still runs on a git-dependency
        // install and stays an action, and so does an inert postinstall
        // (INSTALL-010): it still runs on every install.
        assert!(ACTION_BEHAVIOURS.contains(&behavior_for("INSTALL-004").unwrap()));
        assert_eq!(behavior_for("INSTALL-010"), Some("install_time_execution"));
    }

    #[test]
    fn behaviors_are_sorted_and_unique() {
        let findings = vec![
            f("NET-001", Severity::Medium, 3),
            f("NET-004", Severity::Medium, 3),
            f("CODE-014", Severity::High, 5),
            f("CRED-004", Severity::Critical, 2),
        ];
        assert_eq!(
            behaviors(&findings),
            vec!["executes_shell", "hardcoded_secrets", "network_outbound"]
        );
    }

    #[test]
    fn key_risks_rank_by_severity_dedupe_by_rule_and_cap() {
        let mut findings = vec![
            f("NET-001", Severity::Medium, 3),
            f("NET-001", Severity::Medium, 3),
            f("CODE-001", Severity::High, 5),
            f("CRED-004", Severity::Critical, 2),
            f("PROV-001", Severity::Low, 1),
        ];
        for i in 0..10 {
            findings.push(f(&format!("X-{i}"), Severity::High, 5));
        }
        let risks = key_risks(&findings);
        assert_eq!(risks.len(), KEY_RISK_LIMIT);
        assert!(risks[0].starts_with("CRITICAL: "), "{:?}", risks);
        assert!(risks[0].contains("(CRED-004)"));
        // Low findings never make the list, and duplicates collapse.
        assert!(risks.iter().all(|r| !r.contains("PROV-001")));
        assert_eq!(risks.iter().filter(|r| r.contains("(NET-001)")).count(), 0);
    }

    #[test]
    fn title_falls_back_to_the_snippet_for_unknown_rules() {
        let fnd = f("GHSA-zzzz", Severity::High, 1);
        assert_eq!(title_of(&fnd), fnd.snippet);
        let known = f("CODE-001", Severity::High, 5);
        assert_eq!(title_of(&known), "eval() call — arbitrary code execution"); // sigil:ignore CODE-001 -- rule title in a test expectation
    }

    #[test]
    fn build_uses_only_active_findings() {
        let result = ScanResult {
            findings: vec![f("CODE-014", Severity::High, 5)],
            score: 15,
            verdict: Verdict::MediumRisk,
            files_scanned: 1,
            duration_ms: 1,
            suppressed_findings: vec![f("NET-001", Severity::Medium, 3)],
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            suppressed_by: Some("ledger".to_string()),
            scanner: None,
            platform: String::new(),
        };
        let p = build(&result);
        assert_eq!(p.grade, "C");
        assert_eq!(p.behaviors, vec!["executes_shell"]);
        assert_eq!(p.key_risks.len(), 1);
    }
}
