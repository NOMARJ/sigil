use super::{Finding, Phase, Severity};
use std::borrow::Cow;

/// Bidirectional control characters (Trojan Source / CVE-2021-42574 class).
const BIDI_CONTROLS: &[char] = &[
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // LRE RLE PDF LRO RLO
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // LRI RLI FSI PDI
    '\u{200E}', '\u{200F}', '\u{061C}', // LRM RLM ALM
];

/// Zero-width characters that are suspicious anywhere in code or instructions.
/// U+200C/U+200D are handled separately: they are legitimate inside emoji and
/// complex-script sequences, so they only flag when embedded between ASCII.
const ZERO_WIDTH_ALWAYS: &[char] = &['\u{200B}', '\u{2060}', '\u{180E}'];

fn is_pua(c: char) -> bool {
    matches!(c,
        '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}')
}

fn is_joiner(c: char) -> bool {
    c == '\u{200C}' || c == '\u{200D}'
}

/// Files whose contents steer AI agents: invisible characters here are an
/// active attack technique (Rules File Backdoor, GlassWorm), not a curiosity.
pub fn is_instruction_file(rel_path: &str) -> bool {
    let lower = rel_path.to_lowercase();
    let filename = lower.rsplit('/').next().unwrap_or(&lower);
    matches!(
        filename,
        "claude.md" | "agents.md" | "skill.md" | "gemini.md" | "copilot-instructions.md"
    ) || filename.ends_with(".cursorrules")
        || filename.ends_with(".windsurfrules")
        || lower.contains(".claude/")
        || lower.contains(".cursor/")
        || lower.contains(".github/instructions/")
}

/// Detect invisible/cloaking Unicode. Returns findings; severity is High in
/// instruction files, Medium elsewhere.
pub fn inspect_invisible(rel_path: &str, contents: &str) -> Vec<Finding> {
    let mut pua_line = None;
    let mut bidi_line = None;
    let mut zw_line = None;

    for (idx, line) in contents.lines().enumerate() {
        let lineno = idx + 1;
        if pua_line.is_none() && line.chars().any(is_pua) {
            pua_line = Some(lineno);
        }
        if bidi_line.is_none() && line.chars().any(|c| BIDI_CONTROLS.contains(&c)) {
            bidi_line = Some(lineno);
        }
        if zw_line.is_none() {
            let chars: Vec<char> = line.chars().collect();
            let suspicious = chars.iter().enumerate().any(|(i, &c)| {
                if ZERO_WIDTH_ALWAYS.contains(&c) {
                    return true;
                }
                // Embedded BOM (not at file start) is a cloaking signal.
                if c == '\u{FEFF}' && !(idx == 0 && i == 0) {
                    return true;
                }
                // ZWJ/ZWNJ between two ASCII chars: cloaking inside code or
                // prose, never a legitimate emoji/script sequence.
                if is_joiner(c) {
                    let prev_ascii = i > 0 && chars[i - 1].is_ascii();
                    let next_ascii = i + 1 < chars.len() && chars[i + 1].is_ascii();
                    return prev_ascii && next_ascii;
                }
                false
            });
            if suspicious {
                zw_line = Some(lineno);
            }
        }
    }

    let severity = if is_instruction_file(rel_path) {
        Severity::High
    } else {
        Severity::Medium
    };
    let weight = if severity == Severity::High { 5 } else { 2 };

    let mut findings = Vec::new();
    let mut push = |rule: &str, line: Option<usize>, desc: &str| {
        findings.push(Finding {
            phase: Phase::Obfuscation,
            rule: rule.to_string(),
            severity,
            file: rel_path.to_string(),
            line,
            snippet: desc.to_string(),
            weight,
        });
    };

    if let Some(l) = pua_line {
        push(
            "UNICODE-001",
            Some(l),
            "Private Use Area characters — invisible payload channel (GlassWorm tradecraft)",
        );
    }
    if let Some(l) = bidi_line {
        push(
            "UNICODE-002",
            Some(l),
            "Bidirectional control characters — Trojan Source text reordering",
        );
    }
    if let Some(l) = zw_line {
        push(
            "UNICODE-003",
            Some(l),
            "Zero-width characters embedded in text — invisible instruction cloaking",
        );
    }
    findings
}

/// Strip cloaking characters so downstream pattern matching sees the text a
/// reviewer cannot: patterns match the de-cloaked form. Emoji-internal
/// joiners are preserved (non-ASCII neighbors).
pub fn normalize_for_matching(contents: &str) -> Cow<'_, str> {
    let needs_work = contents.chars().any(|c| {
        BIDI_CONTROLS.contains(&c)
            || ZERO_WIDTH_ALWAYS.contains(&c)
            || c == '\u{FEFF}'
            || is_joiner(c)
    });
    if !needs_work {
        return Cow::Borrowed(contents);
    }

    let chars: Vec<char> = contents.chars().collect();
    let mut out = String::with_capacity(contents.len());
    for (i, &c) in chars.iter().enumerate() {
        if BIDI_CONTROLS.contains(&c) || ZERO_WIDTH_ALWAYS.contains(&c) || c == '\u{FEFF}' {
            continue;
        }
        if is_joiner(c) {
            let prev_ascii = i > 0 && chars[i - 1].is_ascii();
            let next_ascii = i + 1 < chars.len() && chars[i + 1].is_ascii();
            if prev_ascii && next_ascii {
                continue;
            }
        }
        out.push(c);
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/unicode");

    fn read_fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/{}", FIXTURES, name))
            .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    #[test]
    fn unicode_pua_payload_detected() {
        let content = read_fixture("pua_payload.SKILL.md");
        let findings = inspect_invisible("skills/evil/SKILL.md", &content);
        assert!(findings.iter().any(|f| f.rule == "UNICODE-001"));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn unicode_bidi_detected() {
        let content = read_fixture("bidi_reorder.rs.txt");
        let findings = inspect_invisible("src/lib.rs", &content);
        assert!(findings.iter().any(|f| f.rule == "UNICODE-002"));
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn unicode_zwj_cloaking_detected_in_instruction_file() {
        let content = read_fixture("zwj_cloaked.cursorrules");
        let findings = inspect_invisible(".cursorrules", &content);
        assert!(findings.iter().any(|f| f.rule == "UNICODE-003"));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn unicode_clean_cjk_emoji_no_findings() {
        let content = read_fixture("clean_cjk_emoji.md");
        let findings = inspect_invisible("README.md", &content);
        assert!(
            findings.is_empty(),
            "clean CJK/emoji file produced findings: {:?}",
            findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unicode_normalize_decloaks_for_matching() {
        // "ev<ZWJ>al(" must become "eval(" so phase regexes can see it.
        let cloaked = "ev\u{200D}al(user_input)";
        let normalized = normalize_for_matching(cloaked);
        assert_eq!(normalized, "eval(user_input)");
        // Emoji ZWJ sequences survive normalization.
        let family = "👨\u{200D}👩\u{200D}👧 fine";
        assert_eq!(normalize_for_matching(family), family);
    }

    #[test]
    fn unicode_instruction_file_classifier() {
        assert!(is_instruction_file("CLAUDE.md"));
        assert!(is_instruction_file("skills/x/SKILL.md"));
        assert!(is_instruction_file(".cursorrules"));
        assert!(is_instruction_file(".claude/settings.json"));
        assert!(!is_instruction_file("src/main.rs"));
        assert!(!is_instruction_file("README.md"));
    }
}
