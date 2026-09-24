//! Context classification that suppresses findings code cannot act on.
//! First slice of the Python scanner's proven FP filters (ADR-0008); the
//! remainder (UMD/polyfill/webpack preambles, safe domains) ports with the
//! corpus work in US-C3.
//!
//! Everything here is derived from a finding's own fields (its path and its
//! phase), never from side tables built during the scan. That matters because
//! the verdict is recomputed from findings in several places — the ledger, the
//! enforcement gate, `sigil diff` against a stored report — and a context flag
//! that only existed inside one scan would make those recomputations disagree
//! with the scan that produced the findings.

use super::Phase;

/// Type-declaration files describe APIs; nothing in them executes. `eval(` in
/// a `.d.ts` is a signature, not a call — the audit showed 4 of 7 test-repo
/// findings were this false-positive class.
pub fn is_declaration_file(rel_path: &str) -> bool {
    let lower = rel_path.to_lowercase();
    lower.ends_with(".d.ts")
        || lower.ends_with(".d.mts")
        || lower.ends_with(".d.cts")
        || lower.ends_with(".pyi")
}

/// Files an agent loads *as instructions*: a skill's entry point and the
/// repository-level agent files every host reads on startup.
///
/// These are the payload of a malicious skill — prose, fenced examples and
/// all — so nothing in them is ever discounted as documentation.
pub fn is_agent_instruction_file(rel_path: &str) -> bool {
    let name = rel_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "skill.md"
            | "agents.md"
            | "claude.md"
            | "gemini.md"
            | "copilot-instructions.md"
            | ".cursorrules"
            | ".windsurfrules"
            | ".clinerules"
    )
}

/// Reference documentation: a markdown or reStructuredText file that is not an
/// agent entry point (`references/api.md`, `docs/setup.rst`, a README).
pub fn is_reference_doc(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    let is_doc = [".md", ".mdx", ".markdown", ".rst"]
        .iter()
        .any(|ext| lower.ends_with(ext));
    is_doc && !is_agent_instruction_file(rel_path)
}

/// Whether a finding is a *code capability* matched inside reference
/// documentation — an API example in `references/python.md`, a `curl` in an
/// install guide — rather than code the package runs or text the agent is
/// told to follow.
///
/// Only the four code phases qualify. Prompt-injection, agent-manipulation
/// and skill-manifest findings describe instructions, and an instruction in a
/// reference file the agent is sent to read is still an instruction, so those
/// phases are never discounted here. Neither is anything in an agent
/// instruction file (see [`is_agent_instruction_file`]).
///
/// Nor is a rule in [`INSTRUCTION_SHAPED_RULES`]: those sit in a code phase
/// for weighting, but what they match is a command an agent carries out when
/// it follows the document, so a skill's `references/setup.md` saying
/// `curl … | bash` is the payload, not an example of one.
///
/// This is a verdict input, not a suppression: the finding is still reported
/// at its own severity. `scoring` treats it like a finding under `docs/` —
/// counted in the total score, not in the first-party score that gates HIGH.
pub fn is_documented_example(phase: Phase, rule: &str, rel_path: &str) -> bool {
    matches!(
        phase,
        Phase::CodePatterns | Phase::NetworkExfil | Phase::Credentials | Phase::Obfuscation
    ) && !INSTRUCTION_SHAPED_RULES.contains(&rule)
        && is_reference_doc(rel_path)
}

/// Code-phase rules whose match is an *action for the reader to take* rather
/// than an API example: download-and-execute, running and deleting a script,
/// uploading a local file, reading another application's credential store or
/// a hidden credential file, auto-answering a confirmation prompt, and reading
/// agent state into a command substitution.
///
/// A skill's reference documents are loaded into the agent's context and
/// followed, so moving one of these lines out of `SKILL.md` into
/// `references/install.md` must not take it out of the HIGH gate. Measured on
/// the 455 clean vendor skills and 204 malicious skills: exempting these rules
/// from the documentation context changed no verdict in either set (the
/// documentation context still keeps 6 clean skills out of HIGH through the
/// API examples it was written for); it closes the evasion for skills that
/// place the payload in a reference file, as the malicious syncause-debugger
/// sample does with `curl … install_probe.sh | bash` in
/// `references/install/nodejs.md`.
pub const INSTRUCTION_SHAPED_RULES: &[&str] = &[
    "NET-RCE-001",
    "SKILL-011",
    "SKILL-016",
    "SKILL-017",
    "SKILL-018",
    "SKILL-020",
    "SKILL-021",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_declaration_files() {
        assert!(is_declaration_file("types.d.ts"));
        assert!(is_declaration_file("lib/index.d.mts"));
        assert!(is_declaration_file("stubs/requests.pyi"));
        assert!(!is_declaration_file("malicious.js"));
        assert!(!is_declaration_file("setup.py"));
        // A directory named like a decl file must not suppress its children.
        assert!(!is_declaration_file("evil.d.ts/payload.js"));
    }

    #[test]
    fn agent_instruction_files_are_never_reference_docs() {
        for p in [
            "SKILL.md",
            "skills/exfil/SKILL.md",
            "AGENTS.md",
            "CLAUDE.md",
            ".github/copilot-instructions.md",
            "repo/.cursorrules",
        ] {
            assert!(is_agent_instruction_file(p), "{p}");
            assert!(!is_reference_doc(p), "{p}");
        }
    }

    #[test]
    fn reference_docs_are_non_entry_point_markdown() {
        for p in [
            "references/python.md",
            "docs/install.rst",
            "README.md",
            "curl/examples.MD",
        ] {
            assert!(is_reference_doc(p), "{p}");
        }
        for p in ["scripts/run.py", "SKILL.md", "notes.txt", "config.json"] {
            assert!(!is_reference_doc(p), "{p}");
        }
    }

    #[test]
    fn only_code_phases_in_reference_docs_are_documented_examples() {
        // An API example in a reference file documents code.
        assert!(is_documented_example(
            Phase::NetworkExfil,
            "NET-001",
            "references/api.md"
        ));
        assert!(is_documented_example(
            Phase::CodePatterns,
            "CODE-001",
            "docs/usage.md"
        ));
        // The same code in the skill's entry point is the payload.
        assert!(!is_documented_example(
            Phase::NetworkExfil,
            "NET-001",
            "SKILL.md"
        ));
        // ...and in a script it is code the skill runs.
        assert!(!is_documented_example(
            Phase::CodePatterns,
            "CODE-001",
            "scripts/run.py"
        ));
        // An instruction in a reference file is still an instruction.
        assert!(!is_documented_example(
            Phase::PromptInjection,
            "PROMPT-010",
            "references/setup.md"
        ));
        assert!(!is_documented_example(
            Phase::SkillSecurity,
            "SKILL-024",
            "references/setup.md"
        ));
    }

    #[test]
    fn instruction_shaped_code_rules_are_never_documentation() {
        // `curl … | bash` in a skill's reference file is a step the agent is
        // told to run: moving it out of SKILL.md must not discount it.
        for rule in INSTRUCTION_SHAPED_RULES {
            assert!(
                !is_documented_example(Phase::NetworkExfil, rule, "references/install/nodejs.md"),
                "{rule}"
            );
            assert!(
                !is_documented_example(Phase::Credentials, rule, "README.md"),
                "{rule}"
            );
        }
        // A code example of the same phase in the same file still is one.
        assert!(is_documented_example(
            Phase::NetworkExfil,
            "NET-012",
            "references/install/nodejs.md"
        ));
    }
}
