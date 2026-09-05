use super::schema::*;
use crate::enforcement::{self, EnforcementLevel};
use crate::scanner::{Finding, Phase, ScanResult, Verdict};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

/// Generate a SigilPolicy from scan results.
pub fn generate_from_scan(scan: &ScanResult) -> SigilPolicy {
    // Start from a base preset depending on how much we may DO with this tree.
    //
    // Keyed on `enforcement::level_for`, not on `scan.verdict`. The verdict is a
    // report label that is cached, serialized and rewritten; the level is the max
    // of that label and the verdict recomputed from `scan.findings`, so demoting
    // the label alone cannot pick a weaker preset. See `crate::enforcement`.
    let mut policy = match enforcement::level_for(scan) {
        EnforcementLevel::Open | EnforcementLevel::Restricted => {
            SigilPolicy::preset("standard").unwrap()
        }
        EnforcementLevel::Confirm | EnforcementLevel::Blocked => {
            SigilPolicy::preset("strict").unwrap()
        }
    };

    // Rename to indicate this is auto-generated
    policy.name = format!("auto-generated-{}", verdict_label(scan.verdict));
    policy.description = Some(format!(
        "Auto-generated policy from scan (score: {}, verdict: {})",
        scan.score, scan.verdict
    ));

    let has_phase = |phase: Phase| scan.findings.iter().any(|f| f.phase == phase);

    // --- Phase 1: InstallHooks → restrict filesystem ---
    if has_phase(Phase::InstallHooks) {
        policy.filesystem.read_write = vec!["/tmp".into()];
        policy.filesystem.include_workdir = false;
    }

    // --- Phase 3: NetworkExfil → deny all network if findings exist ---
    if has_phase(Phase::NetworkExfil) {
        policy.network.default_action = "deny".into();
        policy.network.rules = vec![]; // block everything
    } else if enforcement::level_for(scan) == EnforcementLevel::Open {
        // No network findings and nothing to enforce: allow standard endpoints.
        // Keyed on the enforcement level rather than the label, so demoting a
        // result's verdict to LowRisk cannot hand it these endpoints.
        policy.network = NetworkPolicy {
            default_action: "deny".into(),
            rules: vec![
                NetworkRule {
                    name: "pypi".into(),
                    host: "pypi.org".into(),
                    port: 443,
                    access: "read-only".into(),
                    enforcement: "enforce".into(),
                },
                NetworkRule {
                    name: "npm".into(),
                    host: "registry.npmjs.org".into(),
                    port: 443,
                    access: "read-only".into(),
                    enforcement: "enforce".into(),
                },
                NetworkRule {
                    name: "github".into(),
                    host: "api.github.com".into(),
                    port: 443,
                    access: "read-write".into(),
                    enforcement: "enforce".into(),
                },
            ],
        };
    }

    // --- Phase 4: Credentials → populate denied_env ---
    let cred_findings: Vec<&Finding> = scan
        .findings
        .iter()
        .filter(|f| f.phase == Phase::Credentials)
        .collect();
    if !cred_findings.is_empty() {
        let mut denied: BTreeSet<String> = BTreeSet::new();
        let env_re = Regex::new(r"[A-Z][A-Z0-9_]{2,}").unwrap();
        for finding in &cred_findings {
            for cap in env_re.find_iter(&finding.snippet) {
                let name = cap.as_str().to_string();
                // Skip common non-env-var uppercase words
                if !["THE", "AND", "FOR", "NOT", "BUT", "ARE", "THIS", "THAT"]
                    .contains(&name.as_str())
                {
                    denied.insert(name);
                }
            }
        }
        policy.credentials.denied_env = denied.into_iter().collect();
        policy.credentials.allowed_env = vec!["PATH".into(), "HOME".into(), "TERM".into()];
    }

    // --- Phase 5: Obfuscation → deny dangerous syscall categories ---
    if has_phase(Phase::Obfuscation) {
        let cats = &mut policy.process.deny_syscall_categories;
        for cat in &["privilege_escalation", "dangerous_io"] {
            let s = cat.to_string();
            if !cats.contains(&s) {
                cats.push(s);
            }
        }
    }

    // --- Phase 7: PromptInjection → add prompt_isolation ---
    if has_phase(Phase::PromptInjection) {
        let cats = &mut policy.process.deny_syscall_categories;
        let s = "prompt_isolation".to_string();
        if !cats.contains(&s) {
            cats.push(s);
        }
    }

    // --- Blocked: deny everything ---
    // Keyed on the enforcement level rather than the label, so demoting a result's
    // verdict cannot strip these restrictions from something whose findings still
    // compute CriticalRisk.
    if enforcement::level_for(scan) == EnforcementLevel::Blocked {
        policy.network.default_action = "deny".into();
        policy.network.rules = vec![];
        policy.credentials.denied_env = vec!["*".into()];
        policy.credentials.allowed_env = vec![];
        policy.filesystem.read_write = vec!["/tmp".into()];
        policy.filesystem.include_workdir = false;
    }

    policy
}

/// Scan a path and generate a policy.
pub fn generate_for_path(
    path: &Path,
) -> Result<(SigilPolicy, ScanResult), Box<dyn std::error::Error>> {
    let scan = crate::scanner::run_scan(path, None, None);
    let policy = generate_from_scan(&scan);
    Ok((policy, scan))
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::LowRisk => "low-risk",
        Verdict::MediumRisk => "medium-risk",
        Verdict::HighRisk => "high-risk",
        Verdict::CriticalRisk => "critical-risk",
    }
}
