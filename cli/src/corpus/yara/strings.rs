//! YARA strings compiled to byte-level automata.
//!
//! Every string — text, hex or regular expression — becomes one or more
//! `regex-automata` meta regexes over raw bytes (Unicode off, UTF-8 off):
//! the engine the `regex` crate itself runs on, already in the build. It
//! guarantees linear-time search, so no string can backtrack
//! catastrophically, whatever the scanned bytes are.
//!
//! - text: each byte as `\xHH`; `nocase` makes ASCII letters a two-byte
//!   class; `wide` interleaves `\x00`; `ascii` + `wide` is two automata, so
//!   `fullword` can check the boundary the way the matched form needs.
//! - hex: `??` is any byte, `4?`/`?4` are sixteen-byte classes, `[n-m]` is a
//!   lazy bounded repeat, `[n-]` a lazy unbounded one, `( A | B )` an
//!   alternation.
//! - regex: compiled as written, with YARA's `i` and `s` flags (and the
//!   `nocase` modifier) mapped to case-insensitive and dot-matches-newline.

use std::fmt::Write as _;

use regex_automata::meta;
use regex_automata::nfa::thompson::WhichCaptures;
use regex_automata::util::syntax;
use regex_syntax::hir::{Hir, HirKind};

use super::parse::{HexToken, StringAst, StringValue};

/// Automaton size limit per string. Generous for any realistic signature;
/// a pattern past it is refused rather than allowed to eat memory on every
/// thread.
const NFA_SIZE_LIMIT: usize = 4 << 20;

/// Positions of counted repetition one string may unroll to: bounded hex
/// jumps and regex `{n,m}` counts, summed (`[0-100]` is 100, `\w{2,40}` is
/// 40, `(ab){10}` is 20).
///
/// Linear-time matching does not make every pattern cheap. A counted
/// repetition is unrolled into automaton positions, and on crafted input —
/// long runs of the byte a jump starts with, the byte it ends with just out
/// of reach — the lazy DFA's states grow with the square of the width until
/// they overflow its cache and the engine falls back to simulating the NFA.
/// Measured on 9.5 MB of such data: `{ 41 [0-768] 42 }` 0.07 s,
/// `[0-1024]` 36 s, `[0-2048]` 58 s. A search is one call the per-file budget
/// cannot interrupt, so the width is capped, with margin, and a wider string
/// is refused. An unbounded jump `[n-]` or count `{n,}` unrolls only its
/// minimum `n`; `[-]`, `*` and `+` unroll nothing (their matches are bounded
/// in length instead, see `eval::UNBOUNDED_MATCH_LIMIT`).
pub const MAX_COUNTED_REPETITION: u64 = 512;

/// One compiled string.
#[derive(Debug)]
pub struct CompiledString {
    /// `$name` as written (`$` for an anonymous string).
    pub name: String,
    /// Matched and counted, but never shown in a finding.
    pub private: bool,
    pub fullword: bool,
    pub variants: Vec<Variant>,
    /// The longest match any variant can produce, or `None` when a variant
    /// is unbounded (`[n-]`, `*`, `+`, `{n,}`) and the YARA-style
    /// [`super::eval::UNBOUNDED_MATCH_LIMIT`] applies.
    pub max_len: Option<usize>,
}

/// One form of a string: its narrow form, or its UTF-16 (`wide`) form.
#[derive(Debug)]
pub struct Variant {
    pub re: meta::Regex,
    pub wide: bool,
}

/// Compile one string. The error is a message without the line.
pub(super) fn build(s: &StringAst) -> Result<CompiledString, String> {
    let label = if s.name.is_empty() {
        "$".to_string()
    } else {
        format!("${}", s.name)
    };
    // (pattern, wide, case-insensitive, dot matches newline)
    let mut forms: Vec<(String, bool, bool, bool)> = Vec::new();
    match &s.value {
        StringValue::Text(bytes) => {
            if s.mods.ascii || !s.mods.wide {
                forms.push((
                    text_pattern(bytes, s.mods.nocase, false),
                    false,
                    false,
                    false,
                ));
            }
            if s.mods.wide {
                forms.push((text_pattern(bytes, s.mods.nocase, true), true, false, false));
            }
        }
        StringValue::Hex(tokens) => {
            let mut p = String::new();
            hex_pattern(tokens, &mut p);
            forms.push((p, false, false, true));
        }
        StringValue::Regex {
            pattern,
            nocase,
            dotall,
        } => forms.push((pattern.clone(), false, *nocase || s.mods.nocase, *dotall)),
    }

    let mut variants = Vec::with_capacity(forms.len());
    let mut max_len = Some(0usize);
    for (pattern, wide, nocase, dotall) in forms {
        let cfg = syntax::Config::new()
            .unicode(false)
            .utf8(false)
            .case_insensitive(nocase)
            .dot_matches_new_line(dotall);
        let hir = syntax::parse_with(&pattern, &cfg)
            .map_err(|e| format!("string {label}: {}", last_line(&e.to_string())))?;
        let unrolled = counted(&hir);
        if unrolled > MAX_COUNTED_REPETITION {
            return Err(format!(
                "string {label}: its counted repetition (hex jumps and {{n,m}} counts) unrolls \
                 to {unrolled} positions; Sigil's limit is {MAX_COUNTED_REPETITION}, past which \
                 crafted input can stall the matcher — use an unbounded jump `[n-]` or `{{n,}}`, \
                 or split the string"
            ));
        }
        let props = hir.properties();
        if props.minimum_len() == Some(0) {
            return Err(format!(
                "string {label} can match zero bytes, so it would match at every offset of \
                 every file"
            ));
        }
        max_len = match (max_len, props.maximum_len()) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
        let re = meta::Regex::builder()
            .configure(
                meta::Regex::config()
                    .nfa_size_limit(Some(NFA_SIZE_LIMIT))
                    .utf8_empty(false)
                    .which_captures(WhichCaptures::Implicit),
            )
            .build_from_hir(&hir)
            .map_err(|e| format!("string {label}: {}", last_line(&e.to_string())))?;
        variants.push(Variant { re, wide });
    }
    Ok(CompiledString {
        name: label,
        private: s.mods.private,
        fullword: s.mods.fullword,
        variants,
        max_len,
    })
}

fn text_pattern(bytes: &[u8], nocase: bool, wide: bool) -> String {
    let mut p = String::with_capacity(bytes.len() * if wide { 8 } else { 4 });
    for &b in bytes {
        if nocase && b.is_ascii_alphabetic() {
            let _ = write!(
                p,
                "[\\x{:02X}\\x{:02X}]",
                b.to_ascii_uppercase(),
                b.to_ascii_lowercase()
            );
        } else {
            let _ = write!(p, "\\x{b:02X}");
        }
        if wide {
            p.push_str("\\x00");
        }
    }
    p
}

fn hex_pattern(tokens: &[HexToken], p: &mut String) {
    for t in tokens {
        match t {
            HexToken::Byte { value, mask: 0xFF } => {
                let _ = write!(p, "\\x{value:02X}");
            }
            HexToken::Byte { value, mask: 0xF0 } => {
                let lo = value & 0xF0;
                let _ = write!(p, "[\\x{lo:02X}-\\x{:02X}]", lo | 0x0F);
            }
            HexToken::Byte { value, mask: 0x0F } => {
                p.push('[');
                for hi in 0u8..16 {
                    let _ = write!(p, "\\x{:02X}", (hi << 4) | (value & 0x0F));
                }
                p.push(']');
            }
            HexToken::Byte { .. } => p.push('.'),
            HexToken::Jump { min, max } => match max {
                Some(max) if max == min => {
                    let _ = write!(p, ".{{{min}}}");
                }
                Some(max) => {
                    let _ = write!(p, ".{{{min},{max}}}?");
                }
                None => {
                    let _ = write!(p, ".{{{min},}}?");
                }
            },
            HexToken::Alt(branches) => {
                p.push_str("(?:");
                for (i, b) in branches.iter().enumerate() {
                    if i > 0 {
                        p.push('|');
                    }
                    hex_pattern(b, p);
                }
                p.push(')');
            }
        }
    }
}

/// Positions of counted repetition in `h` (see [`MAX_COUNTED_REPETITION`]).
fn counted(h: &Hir) -> u64 {
    match h.kind() {
        HirKind::Repetition(r) => {
            // `{n,m}` unrolls m copies of its body; `{n,}` unrolls n and
            // then loops; `?` (`{0,1}`) unrolls nothing worth counting.
            let copies = match r.max {
                Some(m) if m > 1 => u64::from(m),
                Some(_) => 0,
                None => u64::from(r.min),
            };
            copies
                .saturating_mul(width(&r.sub).max(1))
                .saturating_add(counted(&r.sub))
        }
        HirKind::Capture(c) => counted(&c.sub),
        HirKind::Concat(v) | HirKind::Alternation(v) => {
            v.iter().map(counted).fold(0, u64::saturating_add)
        }
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => 0,
    }
}

/// Automaton positions one copy of `h` occupies.
fn width(h: &Hir) -> u64 {
    match h.kind() {
        HirKind::Literal(l) => l.0.len() as u64,
        HirKind::Class(_) => 1,
        HirKind::Empty | HirKind::Look(_) => 0,
        HirKind::Repetition(r) => u64::from(r.max.unwrap_or(r.min))
            .max(1)
            .saturating_mul(width(&r.sub)),
        HirKind::Capture(c) => width(&c.sub),
        HirKind::Concat(v) | HirKind::Alternation(v) => {
            v.iter().map(width).fold(0, u64::saturating_add)
        }
    }
}

/// The last non-empty line: regex errors put the complaint there.
fn last_line(s: &str) -> String {
    s.lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or(s)
        .trim()
        .trim_start_matches("error: ")
        .to_string()
}
