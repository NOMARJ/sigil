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
/// they overflow its cache and the engine falls back to simulating the NFA,
/// at a cost per byte that grows with the width. Measured on 9.5 MB of
/// periodic data: `{ 41 [0-768] 42 }` 0.07 s, `[0-1024]` 36 s, `[0-2048]`
/// 58 s; on high-complexity data (no repeating period for the DFA to settle
/// into) even `[0-511]` takes 54 s. The cap does not bound the time — the
/// per-file budget does, because searches are chunked
/// (`eval::SEARCH_CHUNK`) — it bounds the cost per byte, and a wider string
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
        } => forms.push((
            yara_regex(pattern).map_err(|e| format!("string {label}: {e}"))?,
            false,
            *nocase || s.mods.nocase,
            *dotall,
        )),
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
            return Err(super::parse::outside_msg(format!(
                "string {label}: its counted repetition (hex jumps and {{n,m}} counts) unrolls \
                 to {unrolled} positions; Sigil's limit is {MAX_COUNTED_REPETITION}, past which \
                 crafted input can stall the matcher — use an unbounded jump `[n-]` or `{{n,}}`, \
                 or split the string"
            )));
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
            // The pattern parsed; what failed is the built-in engine's own
            // automaton size limit.
            .map_err(|e| {
                super::parse::outside_msg(format!("string {label}: {}", last_line(&e.to_string())))
            })?;
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

/// Largest repetition count YARA accepts (`RE_MAX_RANGE`).
const YARA_MAX_REPEAT: u32 = 32767;

/// Rewrite a YARA regular expression in the syntax `regex-syntax` parses,
/// keeping YARA's meaning.
///
/// The two dialects share most of their syntax but not all of it, and where
/// they differ, handing Rust the YARA source unchanged gives a rule that
/// loads and matches something else. YARA (checked against libyara 4.5)
/// reads an escape it has no meaning for as the character itself (`\z` is
/// `z`, `\A` is `A`, `\<` is `<`, `\v` is `v`) where Rust reads anchors and
/// word boundaries; a `{` that does not start a repetition as a literal;
/// `{,n}` as `{0,n}`; and a character class as a plain list of bytes and
/// ranges (`\w` at the end of a range is the letter `w`; no `[:alpha:]`,
/// nested classes, `&&`, `--` or `~~`, all of which are set syntax in
/// Rust). It has no `(?...)` groups and no back-references. So the source is
/// walked with YARA's grammar and every literal is emitted as `\xHH`.
fn yara_regex(src: &str) -> Result<String, String> {
    let b = src.as_bytes();
    let mut out = String::with_capacity(b.len() * 4);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                let (atom, used) = escape(b, i, false)?;
                match atom {
                    Atom::Byte(x) => push_byte(&mut out, x),
                    Atom::Set(set, _) | Atom::Assertion(set) => out.push_str(set),
                }
                i += used;
            }
            b'[' => i = class(b, i, &mut out)?,
            b'{' => match repetition(b, i)? {
                Some((min, max, used)) => {
                    let _ = match max {
                        Some(max) if max == min => write!(out, "{{{min}}}"),
                        Some(max) => write!(out, "{{{min},{max}}}"),
                        None => write!(out, "{{{min},}}"),
                    };
                    i += used;
                }
                None => {
                    push_byte(&mut out, b'{');
                    i += 1;
                }
            },
            b'(' => {
                if b.get(i + 1) == Some(&b'?') {
                    return Err("`(?` is not YARA regex syntax (YARA has no group flags, \
                                non-capturing or named groups)"
                        .into());
                }
                out.push_str("(?:");
                i += 1;
            }
            c @ (b')' | b'|' | b'*' | b'+' | b'?' | b'^' | b'$' | b'.') => {
                out.push(c as char);
                i += 1;
            }
            c => {
                push_byte(&mut out, c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// One element of a YARA regex.
enum Atom {
    Byte(u8),
    /// `\w`, `\s`, `\d` and their negations; the letter is what the escape
    /// means at either end of a class range.
    Set(&'static str, u8),
    /// `\b`, `\B` (outside a class).
    Assertion(&'static str),
}

/// The escape starting at `b[i]` (a backslash), and the bytes it spans.
fn escape(b: &[u8], i: usize, in_class: bool) -> Result<(Atom, usize), String> {
    let Some(&c) = b.get(i + 1) else {
        return Err("the expression ends with a lone `\\`".into());
    };
    Ok(match c {
        b'w' => (Atom::Set(r"\w", c), 2),
        b'W' => (Atom::Set(r"\W", c), 2),
        b's' => (Atom::Set(r"\s", c), 2),
        b'S' => (Atom::Set(r"\S", c), 2),
        b'd' => (Atom::Set(r"\d", c), 2),
        b'D' => (Atom::Set(r"\D", c), 2),
        // Inside a class YARA reads `\b` as the letter b.
        b'b' if !in_class => (Atom::Assertion(r"\b"), 2),
        b'B' if !in_class => (Atom::Assertion(r"\B"), 2),
        b'x' => {
            let hex = b
                .get(i + 2..i + 4)
                .and_then(|h| std::str::from_utf8(h).ok())
                .filter(|h| h.bytes().all(|d| d.is_ascii_hexdigit()))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or("`\\x` needs exactly two hex digits (`\\x41`)")?;
            (Atom::Byte(hex), 4)
        }
        b'n' => (Atom::Byte(b'\n'), 2),
        b't' => (Atom::Byte(b'\t'), 2),
        b'r' => (Atom::Byte(b'\r'), 2),
        b'f' => (Atom::Byte(0x0C), 2),
        b'a' => (Atom::Byte(0x07), 2),
        b'0'..=b'9' if !in_class => {
            return Err("back-references (`\\1`) are not allowed in YARA".into())
        }
        other => (Atom::Byte(other), 2),
    })
}

/// A YARA character class starting at `b[start]` (`[`), written to `out`;
/// returns the index just past its `]`.
fn class(b: &[u8], start: usize, out: &mut String) -> Result<usize, String> {
    let unterminated = || "missing terminating `]` for a character class".to_string();
    let mut i = start + 1;
    let mut s = String::from("[");
    if b.get(i) == Some(&b'^') {
        s.push('^');
        i += 1;
    }
    let mut first = true;
    loop {
        let &c = b.get(i).ok_or_else(unterminated)?;
        // A `]` first in the class is a member, not its end.
        if c == b']' && !first {
            s.push(']');
            out.push_str(&s);
            return Ok(i + 1);
        }
        first = false;
        let (lo, used) = class_atom(b, i)?;
        i += used;
        // `x-y` is a range unless the `-` is the last thing in the class.
        if b.get(i) == Some(&b'-') && b.get(i + 1).is_some_and(|n| *n != b']') {
            let (hi, used) = class_atom(b, i + 1)?;
            let (lo, hi) = (range_end(&lo), range_end(&hi));
            if lo > hi {
                return Err(format!(
                    "bad character range `\\x{lo:02X}-\\x{hi:02X}` (reversed bounds)"
                ));
            }
            push_byte(&mut s, lo);
            s.push('-');
            push_byte(&mut s, hi);
            i += 1 + used;
            continue;
        }
        match lo {
            Atom::Byte(x) => push_byte(&mut s, x),
            Atom::Set(set, _) | Atom::Assertion(set) => s.push_str(set),
        }
    }
}

fn class_atom(b: &[u8], i: usize) -> Result<(Atom, usize), String> {
    match b.get(i) {
        Some(b'\\') => escape(b, i, true),
        // YARA refuses these; bytes are written `\xHH` in a class.
        Some(&c) if !c.is_ascii() => {
            Err("a non-ASCII character in a character class (write its bytes as `\\xHH`)".into())
        }
        Some(&c) => Ok((Atom::Byte(c), 1)),
        None => Err("missing terminating `]` for a character class".into()),
    }
}

/// The byte an atom stands for at either end of a class range: YARA reads
/// `[\w-z]` as `[w-z]`.
fn range_end(a: &Atom) -> u8 {
    match a {
        Atom::Byte(x) => *x,
        Atom::Set(_, letter) => *letter,
        Atom::Assertion(_) => b'b',
    }
}

/// A repetition `{n}`, `{n,}`, `{,m}`, `{n,m}` or `{,}` at `b[i]` (digits
/// only, no spaces): `(min, max, bytes spanned)`, or `None` when the `{` is
/// a literal, as YARA reads it.
fn repetition(b: &[u8], i: usize) -> Result<Option<(u32, Option<u32>, usize)>, String> {
    let digits = |from: usize| {
        let mut j = from;
        while b.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
        }
        j
    };
    let number = |d: &[u8]| -> Result<u32, String> {
        std::str::from_utf8(d)
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|n| *n <= YARA_MAX_REPEAT)
            .ok_or_else(|| format!("repetition count is larger than YARA's {YARA_MAX_REPEAT}"))
    };
    let n_end = digits(i + 1);
    let n = &b[i + 1..n_end];
    match b.get(n_end) {
        Some(b'}') if !n.is_empty() => {
            let n = number(n)?;
            Ok(Some((n, Some(n), n_end + 1 - i)))
        }
        Some(b',') => {
            let m_end = digits(n_end + 1);
            if b.get(m_end) != Some(&b'}') {
                return Ok(None);
            }
            let min = if n.is_empty() { 0 } else { number(n)? };
            let m = &b[n_end + 1..m_end];
            let max = if m.is_empty() { None } else { Some(number(m)?) };
            if max.is_some_and(|max| max < min) {
                return Err(format!(
                    "bad repetition `{{{min},{}}}` (reversed bounds)",
                    max.unwrap_or_default()
                ));
            }
            Ok(Some((min, max, m_end + 1 - i)))
        }
        _ => Ok(None),
    }
}

fn push_byte(out: &mut String, b: u8) {
    let _ = write!(out, "\\x{b:02X}");
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
