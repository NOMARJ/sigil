//! What is removed from scanned content before any of it leaves the machine.
//!
//! Every string the LLM stage sends that came from the scanned tree — the
//! matched line, the lines around it, the file path, a title that fell back
//! to the snippet — goes through [`Masker::mask_lines`],
//! [`Masker::mask_line`] or [`Masker::mask_text`] first. Invisible
//! characters are made visible before that ([`reveal_invisible`]). Then four
//! passes, in order:
//!
//! 1. Private-key blocks (`-----BEGIN ... PRIVATE KEY-----` to `-----END`):
//!    every line of the block is replaced. The block is tracked from the top
//!    of the file ([`KeyBlock`]), so a window that starts inside a key is
//!    still masked even though its `BEGIN` line is not in the window.
//! 2. Every match of a secret rule in the active corpus: all rules in the
//!    Credentials phase, and any rule tagged `hardcoded-secret`,
//!    `secret-in-prompt`, `api-key` or `credentials`, whatever its phase.
//! 3. Built-in secret shapes, so a secret is masked even where no rule fires:
//!    well-known token prefixes, `Authorization:` header values, passwords in
//!    URLs, the whole quoted value assigned to names like `api_key`,
//!    `secret`, `token`, `password` or `passphrase`, and the unquoted value
//!    of such a name in `NAME=value` and `name: value` lines (env, INI, YAML,
//!    TOML).
//! 4. Any remaining high-entropy token (see [`looks_random`]).
//!
//! Masked text is replaced by `[REDACTED:<why>]`. The masking errs towards
//! removing too much: a masked environment-variable read costs the reviewer
//! some context, an unmasked key costs the key.

use std::borrow::Cow;
use std::sync::OnceLock;

use regex::Regex;

use crate::scanner::Phase;

/// What a line of a private-key block is replaced with.
pub const PRIVATE_KEY_MASK: &str = "[REDACTED:private-key]";

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
            // A quoted value assigned to a secret-named key: the whole value
            // up to the closing quote, spaces included (a passphrase is
            // several words). One pattern per quote character, since the
            // regex crate has no backreferences.
            (
                "assignment",
                r(&format!(r#"(?i)({SECRET_NAME}[a-z0-9_\-]*["']?\s*(?:=|:|=>|:=)\s*")[^"\n]{{4,}}"#)),
                Some("${1}[REDACTED:assignment]"),
            ),
            (
                "assignment",
                r(&format!(r#"(?i)({SECRET_NAME}[a-z0-9_\-]*["']?\s*(?:=|:|=>|:=)\s*')[^'\n]{{4,}}"#)),
                Some("${1}[REDACTED:assignment]"),
            ),
            (
                "assignment",
                r(&format!(r#"(?i)({SECRET_NAME}[a-z0-9_\-]*["']?\s*(?:=|:|=>|:=)\s*`)[^`\n]{{4,}}"#)),
                Some("${1}[REDACTED:assignment]"),
            ),
            // An unquoted value on a line that assigns a secret-named key:
            // `NAME=value` (env, shell, INI) and `name: value` (YAML, TOML
            // with `=`), optionally a YAML list item or `export`.
            (
                "assignment",
                r(r#"(?i)^(\s*(?:-\s+)?(?:export\s+)?["']?[a-z0-9_.\-]*(?:key|secret|token|passw(?:or)?d|passwd|passphrase|passcode|pwd|credentials?)[a-z0-9_.\-]*["']?\s*[:=]\s*)[^\s"'`#][^\s#]{3,}"#),
                Some("${1}[REDACTED:assignment]"),
            ),
        ]
    })
}

/// Key names whose value is a secret, for the quoted-assignment shapes.
const SECRET_NAME: &str = r"(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|passphrase|passcode|pwd|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?)";

/// Tracks private-key blocks across the consecutive lines of one file.
///
/// Feed it every line from the top of the file, in order; it says which lines
/// belong to a `-----BEGIN ... PRIVATE KEY-----` ... `-----END` block. A
/// window read from the middle of a file needs this: the base64 body of a key
/// carries no marker of its own, and some of its lines fall below the
/// entropy test's threshold (6 of the 26 body lines of one freshly generated
/// 2048-bit RSA key).
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyBlock {
    in_key: bool,
}

impl KeyBlock {
    /// Feed the next line. True when the line is part of a private-key block.
    pub fn feed(&mut self, line: &str) -> bool {
        let upper = line.to_ascii_uppercase();
        if upper.contains("-----BEGIN") && upper.contains("PRIVATE KEY") {
            self.in_key = true;
        }
        if self.in_key {
            if upper.contains("-----END") {
                self.in_key = false;
            }
            return true;
        }
        false
    }
}

/// Is `c` a character a reader does not see: bidirectional controls,
/// zero-width characters, the soft hyphen, the Mongolian vowel separator, the
/// byte-order mark inside text, and the variation-selector supplement?
/// (Unicode tag characters are handled separately: they carry text.)
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{E0100}'..='\u{E01EF}')
}

/// Is `c` a Unicode tag character (U+E0000 to U+E007F)? Tags U+E0020 to
/// U+E007E mirror printable ASCII and are invisible in most editors, but a
/// language model can read them: "ASCII smuggling".
fn is_tag(c: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&c)
}

/// The ASCII character a tag character mirrors, if any.
fn tag_ascii(c: char) -> Option<char> {
    let v = c as u32;
    (0xE0020..=0xE007E)
        .contains(&v)
        .then(|| char::from_u32(v - 0xE0000))
        .flatten()
}

/// Make invisible characters visible, so the model sees what a reader of the
/// file would miss and nothing more:
///
/// - a run of Unicode tag characters becomes `[hidden-text:"..."]` with the
///   ASCII it spells;
/// - a run of other invisible characters (zero-width, bidirectional
///   controls, ...) becomes `[invisible:N]`.
///
/// Returns the text and whether it held tag characters that spell something
/// other than an emoji tag sequence (lowercase letters and digits, as in the
/// flag of a country subdivision).
pub fn reveal_invisible(s: &str) -> (Cow<'_, str>, bool) {
    if !s.chars().any(|c| is_tag(c) || is_invisible(c)) {
        return (Cow::Borrowed(s), false);
    }
    let mut out = String::with_capacity(s.len() + 16);
    let mut hidden_text = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if is_tag(c) {
            let mut decoded = String::new();
            decoded.extend(tag_ascii(c));
            while let Some(&n) = chars.peek().filter(|n| is_tag(**n)) {
                decoded.extend(tag_ascii(n));
                chars.next();
            }
            if decoded
                .chars()
                .any(|d| !(d.is_ascii_lowercase() || d.is_ascii_digit()))
            {
                hidden_text = true;
            }
            out.push_str(&format!("[hidden-text:{decoded:?}]"));
        } else if is_invisible(c) {
            let mut n = 1usize;
            while chars.peek().is_some_and(|n| is_invisible(*n)) {
                n += 1;
                chars.next();
            }
            out.push_str(&format!("[invisible:{n}]"));
        } else {
            out.push(c);
        }
    }
    (Cow::Owned(out), hidden_text)
}

/// The text a pattern check should see: invisible characters removed and
/// tag characters read as the ASCII they spell, so a note split with
/// zero-width spaces or written in tag characters reads as plain words.
pub fn plain_for_checks(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| is_tag(c) || is_invisible(c)) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .filter_map(|c| {
                if is_tag(c) {
                    tag_ascii(c)
                } else if is_invisible(c) {
                    None
                } else {
                    Some(c)
                }
            })
            .collect(),
    )
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
    /// span lines. The lines are taken to start outside a key block; a
    /// caller that reads from the middle of a file tracks blocks itself with
    /// [`KeyBlock`] and masks line by line.
    pub fn mask_lines(&self, lines: &[String]) -> (Vec<String>, usize) {
        let mut count = 0usize;
        let mut block = KeyBlock::default();
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            if block.feed(line) {
                out.push(PRIVATE_KEY_MASK.to_string());
                count += 1;
                continue;
            }
            let (masked, n) = self.mask_line(line);
            count += n;
            out.push(masked);
        }
        (out, count)
    }

    /// Mask one line that is known not to be part of a private-key block.
    /// Invisible characters are made visible first ([`reveal_invisible`]),
    /// so a secret spelled in tag characters is masked like any other.
    pub fn mask_line(&self, line: &str) -> (String, usize) {
        let mut s = reveal_invisible(line).0.into_owned();
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
