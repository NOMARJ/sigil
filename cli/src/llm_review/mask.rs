//! What is removed from scanned content before any of it leaves the machine.
//!
//! Every string the LLM stage sends that came from the scanned tree — the
//! matched line, the lines around it, the file path, a title that fell back
//! to the snippet — goes through [`Masker::mask_lines`] or
//! [`Masker::mask_text`] first. Four passes, in order:
//!
//! 1. Private-key blocks (`-----BEGIN ... PRIVATE KEY-----` to `-----END`):
//!    every line of the block is replaced.
//! 2. Every match of a secret rule in the active corpus: all rules in the
//!    Credentials phase, and any rule tagged `hardcoded-secret`,
//!    `secret-in-prompt`, `api-key` or `credentials`, whatever its phase.
//! 3. Built-in secret shapes, so a secret is masked even where no rule fires:
//!    well-known token prefixes, `Authorization:` header values, passwords in
//!    URLs, and quoted values assigned to names like `api_key`, `secret`,
//!    `token`, `password`.
//! 4. Any remaining high-entropy token (see [`looks_random`]).
//!
//! Masked text is replaced by `[REDACTED:<why>]`. The masking errs towards
//! removing too much: a masked environment-variable read costs the reviewer
//! some context, an unmasked key costs the key.

use std::sync::OnceLock;

use regex::Regex;

use crate::scanner::Phase;

/// Tags that mark a rule whose matches may be secret values.
const SECRET_TAGS: &[&str] = &[
    "hardcoded-secret",
    "secret-in-prompt",
    "api-key",
    "credentials",
];

/// Shortest token the entropy test considers.
const ENTROPY_MIN_LEN: usize = 20;

/// Masks secrets out of scanned content. Build once per scan.
pub struct Masker {
    rules: Vec<(String, Regex)>,
}

/// Built-in secret shapes: (label, pattern, replacement). A replacement of
/// `None` masks the whole match; `Some` rewrites it, keeping the non-secret
/// prefix captured as group 1.
fn builtin() -> &'static [(&'static str, Regex, Option<&'static str>)] {
    static B: OnceLock<Vec<(&'static str, Regex, Option<&'static str>)>> = OnceLock::new();
    B.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("builtin masking pattern");
        vec![
            (
                "token",
                r(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b"),
                None,
            ),
            ("token", r(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), None),
            ("token", r(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), None),
            ("token", r(r"\bglpat-[A-Za-z0-9_\-]{20,}"), None),
            ("token", r(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"), None),
            ("token", r(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"), None),
            ("token", r(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}"), None),
            ("token", r(r"\bAIza[0-9A-Za-z_\-]{35}"), None),
            ("token", r(r"\bnpm_[A-Za-z0-9]{36}"), None),
            ("token", r(r"\bhf_[A-Za-z0-9]{30,}"), None),
            (
                "token",
                r(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
                None,
            ),
            (
                "auth-header",
                r(r#"(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*["']?\s*(?:bearer|basic|token|bot)\s+)[^\s"',;]+"#),
                Some("${1}[REDACTED:auth-header]"),
            ),
            (
                "url-password",
                r(r#"(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@"'`]*:)[^/\s@"'`]+@"#),
                Some("${1}[REDACTED:url-password]@"),
            ),
            (
                "assignment",
                r(r#"(?i)((?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|pwd|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?)[a-z0-9_\-]*["']?\s*(?:=|:|=>|:=)\s*["'`])[^"'`\s]{4,}"#),
                Some("${1}[REDACTED:assignment]"),
            ),
            (
                "assignment",
                r(r#"(?i)^(\s*(?:export\s+)?[a-z0-9_]*(?:key|secret|token|password|passwd|pwd|credentials?)[a-z0-9_]*\s*=\s*)[^\s"'#]{4,}"#),
                Some("${1}[REDACTED:assignment]"),
            ),
        ]
    })
}

fn token_re() -> &'static Regex {
    static T: OnceLock<Regex> = OnceLock::new();
    T.get_or_init(|| Regex::new(r"[A-Za-z0-9+/=_\-]{20,}").expect("token regex"))
}

/// Replace every non-empty match of `re` in `s` with `with`. A corpus rule
/// whose pattern can match the empty string must not splice a label between
/// every character.
fn replace_nonempty(re: &Regex, s: &str, with: &str) -> (String, usize) {
    let mut out = String::with_capacity(s.len());
    let mut last = 0usize;
    let mut n = 0usize;
    for m in re.find_iter(s) {
        if m.as_str().is_empty() {
            continue;
        }
        out.push_str(&s[last..m.start()]);
        out.push_str(with);
        last = m.end();
        n += 1;
    }
    out.push_str(&s[last..]);
    (out, n)
}

/// Shannon entropy of `s`, in bits per character.
fn shannon(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let bytes = s.as_bytes();
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Does this token look like a random string (a key, a token, a hash)?
///
/// Hex strings of 24+ characters with some spread are hashes or keys. Other
/// tokens must contain a digit and a letter and come close to the entropy a
/// random string of that length would have: at least 85% of `log2(len)`
/// (capped at the 64-symbol base64 alphabet). Identifiers and paths made of
/// words fall well short of that.
pub fn looks_random(tok: &str) -> bool {
    let len = tok.len();
    if len < ENTROPY_MIN_LEN {
        return false;
    }
    let e = shannon(tok);
    if tok.chars().all(|c| c.is_ascii_hexdigit()) {
        return len >= 24 && e >= 3.0;
    }
    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let has_alpha = tok.chars().any(|c| c.is_ascii_alphabetic());
    let ceiling = (len.min(64) as f64).log2();
    has_digit && has_alpha && e >= 0.85 * ceiling
}

impl Masker {
    /// A masker over the secret rules of the active corpus.
    pub fn from_corpus() -> Self {
        let corpus = crate::corpus::compiled::corpus();
        let rules = corpus
            .content_rules_sorted()
            .into_iter()
            .filter(|r| {
                r.phase == Phase::Credentials
                    || corpus
                        .rule_meta(&r.id)
                        .is_some_and(|m| m.tags.iter().any(|t| SECRET_TAGS.contains(&t.as_str())))
            })
            .map(|r| (r.id.clone(), r.regex.clone()))
            .collect();
        Masker { rules }
    }

    /// Number of secret rules this masker applies.
    #[cfg(test)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Mask one piece of text. Returns the masked text and how many values
    /// were masked.
    pub fn mask_text(&self, text: &str) -> (String, usize) {
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        let (masked, n) = self.mask_lines(&lines);
        (masked.join("\n"), n)
    }

    /// Mask consecutive lines of a file, tracking private-key blocks that
    /// span lines.
    pub fn mask_lines(&self, lines: &[String]) -> (Vec<String>, usize) {
        let mut count = 0usize;
        let mut in_key = false;
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            let upper = line.to_ascii_uppercase();
            if upper.contains("-----BEGIN") && upper.contains("PRIVATE KEY") {
                in_key = true;
            }
            if in_key {
                if upper.contains("-----END") {
                    in_key = false;
                }
                out.push("[REDACTED:private-key]".to_string());
                count += 1;
                continue;
            }
            let (masked, n) = self.mask_line(line);
            count += n;
            out.push(masked);
        }
        (out, count)
    }

    fn mask_line(&self, line: &str) -> (String, usize) {
        let mut s = line.to_string();
        let mut count = 0usize;
        for (id, re) in &self.rules {
            let (masked, n) = replace_nonempty(re, &s, &format!("[REDACTED:{id}]"));
            if n > 0 {
                count += n;
                s = masked;
            }
        }
        for (label, re, replacement) in builtin() {
            let n = re.find_iter(&s).count();
            if n == 0 {
                continue;
            }
            count += n;
            s = match replacement {
                Some(rep) => re.replace_all(&s, *rep).into_owned(),
                None => re
                    .replace_all(&s, format!("[REDACTED:{label}]").as_str())
                    .into_owned(),
            };
        }
        let mut entropy_hits = 0usize;
        let s = token_re()
            .replace_all(&s, |caps: &regex::Captures| {
                let tok = &caps[0];
                if looks_random(tok) {
                    entropy_hits += 1;
                    format!("[REDACTED:high-entropy:{}]", tok.len())
                } else {
                    tok.to_string()
                }
            })
            .into_owned();
        (s, count + entropy_hits)
    }
}

#[cfg(test)]
impl Masker {
    /// A masker with no corpus rules: only the built-in shapes and entropy.
    pub fn builtin_only() -> Self {
        Masker { rules: Vec::new() }
    }
}
