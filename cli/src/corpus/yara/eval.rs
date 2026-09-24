//! Evaluating compiled YARA rules over a file's raw bytes.
//!
//! YARA semantics, not Sigil's line semantics: strings match anywhere in the
//! bytes, across line breaks, in binary files; `#a` counts every offset a
//! match starts at (overlapping matches included); `filesize` is the file's
//! real size. Work is lazy — a string is searched only when the condition
//! needs it — and bounded:
//!
//! - no match is longer than [`UNBOUNDED_MATCH_LIMIT`] when the string has an
//!   unbounded part, the same limit YARA applies to regular expressions, and
//!   the search walks the data in windows of that size, so a greedy `.*`
//!   cannot rescan the rest of the file once per match;
//! - `#a` stops counting at [`MAX_MATCHES_PER_STRING`], YARA's own cap;
//! - the per-file budget (`scanner::budget`) is checked between rules and
//!   inside long counts. When it runs out, evaluation stops and the caller
//!   reports the truncation.

use std::fmt::Write as _;
use std::sync::Arc;

use regex_automata::{Anchored, Input};

use super::strings::{CompiledString, Variant};
use super::{ArithOp, CmpOp, Expr, Quant, YaraFile, YaraRule};
use crate::scanner::budget::FileBudget;
use crate::scanner::{Finding, Phase};

/// Longest match of a string that has an unbounded part. YARA's own limit
/// for regular expressions (`RE_SCAN_LIMIT`) is the same 4096 bytes.
pub const UNBOUNDED_MATCH_LIMIT: usize = 4096;

/// Matches counted per string per file before `#a` stops (YARA: 1,000,000).
pub const MAX_MATCHES_PER_STRING: u64 = 1_000_000;

/// Bytes of each matched string shown in a finding.
const SNIPPET_BYTES: usize = 48;

/// Matched strings named in a finding before the rest are summarised.
const SNIPPET_STRINGS: usize = 3;

/// A contiguous run of the scanned file's bytes.
pub struct Segment<'a> {
    /// Offset of `data[0]` in the file.
    pub base: u64,
    pub data: &'a [u8],
    /// Newlines in the file before `data[0]` when the file is text; `None`
    /// for binary content, whose findings carry no line number.
    pub newlines_before: Option<usize>,
}

/// What one evaluation looks at: a whole file, or the scanned head and tail
/// of one too large to read whole.
pub struct Subject<'a> {
    pub segments: Vec<Segment<'a>>,
    pub filesize: u64,
    /// `segments` do not cover the whole file.
    pub partial: bool,
}

impl<'a> Subject<'a> {
    /// A whole file (or archive member) held in memory.
    pub fn whole(data: &'a [u8], text: bool) -> Self {
        Subject {
            segments: vec![Segment {
                base: 0,
                data,
                newlines_before: text.then_some(0),
            }],
            filesize: data.len() as u64,
            partial: false,
        }
    }
}

/// Run every rule in `files` over `subject` and return one finding per
/// matching public rule whose phase is enabled.
pub fn scan(
    files: &[Arc<YaraFile>],
    subject: &Subject<'_>,
    rel_path: &str,
    phase_enabled: &dyn Fn(Phase) -> bool,
    budget: &FileBudget,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in files {
        let mut results: Vec<bool> = Vec::with_capacity(file.rules.len());
        let mut evals: Vec<RuleEval<'_, '_>> = Vec::with_capacity(file.rules.len());
        for rule in &file.rules {
            if budget.expired() {
                return out;
            }
            let mut ev = RuleEval::new(rule, subject, budget);
            let matched = ev.boolean(&rule.condition, &results).unwrap_or(false);
            results.push(matched);
            evals.push(ev);
        }
        // A global rule that does not match switches off every rule in its
        // file, as it does in a YARA namespace.
        let globals_hold = file
            .rules
            .iter()
            .zip(&results)
            .all(|(r, m)| !r.global || *m);
        if !globals_hold {
            continue;
        }
        for ((rule, matched), mut ev) in file.rules.iter().zip(results).zip(evals) {
            if !matched || rule.private || !phase_enabled(rule.phase) {
                continue;
            }
            out.push(ev.finding(rel_path));
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct Hit {
    seg: usize,
    start: usize,
    end: usize,
    wide: bool,
}

struct RuleEval<'r, 's> {
    rule: &'r YaraRule,
    subject: &'s Subject<'s>,
    budget: &'s FileBudget,
    first: Vec<Option<Option<Hit>>>,
    count: Vec<Option<u64>>,
}

impl<'r, 's> RuleEval<'r, 's> {
    fn new(rule: &'r YaraRule, subject: &'s Subject<'s>, budget: &'s FileBudget) -> Self {
        RuleEval {
            rule,
            subject,
            budget,
            first: vec![None; rule.strings.len()],
            count: vec![None; rule.strings.len()],
        }
    }

    fn first_hit(&mut self, i: usize) -> Option<Hit> {
        if let Some(cached) = self.first[i] {
            return cached;
        }
        let rule = self.rule;
        let s = &rule.strings[i];
        let mut best: Option<Hit> = None;
        for v in &s.variants {
            for (si, seg) in self.subject.segments.iter().enumerate() {
                if let Some((start, end)) = next_in(s, v, seg.data, 0) {
                    let abs = seg.base + start as u64;
                    if best.is_none_or(|b| abs < self.subject.segments[b.seg].base + b.start as u64)
                    {
                        best = Some(Hit {
                            seg: si,
                            start,
                            end,
                            wide: v.wide,
                        });
                    }
                    break;
                }
            }
        }
        self.first[i] = Some(best);
        best
    }

    fn matched(&mut self, i: usize) -> bool {
        self.first_hit(i).is_some()
    }

    fn count(&mut self, i: usize) -> u64 {
        if let Some(n) = self.count[i] {
            return n;
        }
        let rule = self.rule;
        let s = &rule.strings[i];
        let mut n = 0u64;
        'all: for v in &s.variants {
            for seg in &self.subject.segments {
                let mut pos = 0usize;
                while let Some((start, _)) = next_in(s, v, seg.data, pos) {
                    n += 1;
                    if n >= MAX_MATCHES_PER_STRING
                        || (n.is_multiple_of(4096) && self.budget.expired())
                    {
                        break 'all;
                    }
                    pos = start + 1;
                }
            }
        }
        self.count[i] = Some(n);
        n
    }

    /// A match of string `i` starting exactly at file offset `at`.
    fn at(&self, i: usize, at: u64) -> bool {
        let s = &self.rule.strings[i];
        let limit = s.max_len.unwrap_or(UNBOUNDED_MATCH_LIMIT);
        for seg in &self.subject.segments {
            let len = seg.data.len() as u64;
            if at < seg.base || at >= seg.base + len {
                continue;
            }
            let local = (at - seg.base) as usize;
            let end = local.saturating_add(limit).min(seg.data.len());
            for v in &s.variants {
                let input = Input::new(seg.data)
                    .span(local..end)
                    .anchored(Anchored::Yes);
                if let Some(m) = v.re.search(&input) {
                    if !s.fullword || fullword_ok(seg.data, m.start(), m.end(), v.wide) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// A match of string `i` starting anywhere in `lo..=hi`.
    fn within(&self, i: usize, lo: u64, hi: u64) -> bool {
        let s = &self.rule.strings[i];
        for seg in &self.subject.segments {
            let seg_end = seg.base + seg.data.len() as u64;
            if hi < seg.base || lo >= seg_end {
                continue;
            }
            let from = (lo.max(seg.base) - seg.base) as usize;
            for v in &s.variants {
                if let Some((start, _)) = next_in(s, v, seg.data, from) {
                    if seg.base + start as u64 <= hi {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Evaluate a boolean expression. `None` is YARA's "undefined" (an
    /// arithmetic overflow, a division by zero), which a rule treats as not
    /// matching.
    fn boolean(&mut self, e: &Expr, rules: &[bool]) -> Option<bool> {
        Some(match e {
            Expr::Bool(b) => *b,
            Expr::Str(i) => self.matched(*i),
            Expr::StrAt(i, at) => {
                let at = self.integer(at, rules)?;
                at >= 0 && self.at(*i, at as u64)
            }
            Expr::StrIn(i, lo, hi) => {
                let lo = self.integer(lo, rules)?;
                let hi = self.integer(hi, rules)?;
                hi >= 0 && lo <= hi && self.within(*i, lo.max(0) as u64, hi as u64)
            }
            Expr::Of(quant, set) => self.of(quant, set, rules)?,
            Expr::RuleRef(j) => rules.get(*j).copied().unwrap_or(false),
            Expr::Not(a) => !self.boolean(a, rules)?,
            Expr::And(a, b) => {
                self.boolean(a, rules).unwrap_or(false) && self.boolean(b, rules).unwrap_or(false)
            }
            Expr::Or(a, b) => {
                self.boolean(a, rules).unwrap_or(false) || self.boolean(b, rules).unwrap_or(false)
            }
            Expr::Cmp(op, a, b) => {
                let (a, b) = (self.integer(a, rules)?, self.integer(b, rules)?);
                match op {
                    CmpOp::Eq => a == b,
                    CmpOp::Ne => a != b,
                    CmpOp::Lt => a < b,
                    CmpOp::Le => a <= b,
                    CmpOp::Gt => a > b,
                    CmpOp::Ge => a >= b,
                }
            }
            Expr::Int(_) | Expr::Filesize | Expr::Count(_) | Expr::Arith(..) | Expr::Neg(_) => {
                self.integer(e, rules)? != 0
            }
        })
    }

    fn integer(&mut self, e: &Expr, rules: &[bool]) -> Option<i64> {
        match e {
            Expr::Int(n) => Some(*n),
            Expr::Filesize => i64::try_from(self.subject.filesize).ok(),
            Expr::Count(i) => i64::try_from(self.count(*i)).ok(),
            Expr::Neg(a) => self.integer(a, rules)?.checked_neg(),
            Expr::Arith(op, a, b) => {
                let (a, b) = (self.integer(a, rules)?, self.integer(b, rules)?);
                match op {
                    ArithOp::Add => a.checked_add(b),
                    ArithOp::Sub => a.checked_sub(b),
                    ArithOp::Mul => a.checked_mul(b),
                    ArithOp::Div => a.checked_div(b),
                    ArithOp::Mod => a.checked_rem(b),
                }
            }
            _ => self.boolean(e, rules).map(i64::from),
        }
    }

    fn of(&mut self, quant: &Quant, set: &[usize], rules: &[bool]) -> Option<bool> {
        let need: u64 = match quant {
            Quant::Any => 1,
            Quant::All => set.len() as u64,
            Quant::None => return Some(!set.iter().any(|i| self.matched(*i))),
            Quant::AtLeast(n) => self.integer(n, rules)?.max(0) as u64,
            Quant::Percent(p) => {
                let p = self.integer(p, rules)?.clamp(0, 100) as u64;
                (p * set.len() as u64).div_ceil(100)
            }
        };
        let mut have = 0u64;
        for (k, i) in set.iter().enumerate() {
            if have >= need {
                break;
            }
            // Not enough strings left to reach `need`: stop searching.
            if have + ((set.len() - k) as u64) < need {
                return Some(false);
            }
            if self.matched(*i) {
                have += 1;
            }
        }
        Some(have >= need)
    }

    /// The finding for a matched rule: the earliest string match gives the
    /// line; the public strings that matched are shown, escaped and cut.
    fn finding(&mut self, rel_path: &str) -> Finding {
        let rule = self.rule;
        let mut hits: Vec<(usize, Hit)> = (0..rule.strings.len())
            .filter_map(|i| self.first_hit(i).map(|h| (i, h)))
            .collect();
        let abs = |h: &Hit| self.subject.segments[h.seg].base + h.start as u64;
        hits.sort_by_key(|(_, h)| abs(h));
        let line = hits.first().and_then(|(_, h)| {
            let seg = &self.subject.segments[h.seg];
            seg.newlines_before
                .map(|before| before + count_newlines(&seg.data[..h.start]) + 1)
        });

        let public: Vec<&(usize, Hit)> = hits
            .iter()
            .filter(|(i, _)| !rule.strings[*i].private)
            .collect();
        let mut shown: Vec<String> = public
            .iter()
            .take(SNIPPET_STRINGS)
            .map(|(i, h)| {
                let data = &self.subject.segments[h.seg].data[h.start..h.end];
                format!(
                    "{}=\"{}\"{}",
                    rule.strings[*i].name,
                    escape(data, h.wide),
                    if h.wide { " (wide)" } else { "" }
                )
            })
            .collect();
        if public.len() > SNIPPET_STRINGS {
            shown.push(format!("+{} more", public.len() - SNIPPET_STRINGS));
        }
        let what = if !shown.is_empty() {
            shown.join(", ")
        } else if !hits.is_empty() {
            "private strings only".to_string()
        } else {
            "its condition, with no string match".to_string()
        };
        let prefix = if self.subject.partial {
            "[head/tail of oversized file] "
        } else {
            ""
        };
        Finding {
            phase: rule.phase,
            rule: rule.id.clone(),
            severity: rule.severity,
            file: rel_path.to_string(),
            line,
            snippet: if rule.description == super::default_description(&rule.name) {
                format!("{prefix}YARA rule {} matched {what}", rule.name)
            } else {
                format!(
                    "{prefix}{}: YARA rule {} matched {what}",
                    rule.description, rule.name
                )
            },
            weight: rule.phase.default_weight(),
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: crate::corpus::schema::Evidence::Standalone,
        }
    }
}

/// The first match of `v` starting at or after `from` in `data` that passes
/// the `fullword` check.
fn next_in(s: &CompiledString, v: &Variant, data: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut pos = from;
    loop {
        let (start, end) = search(v, s.max_len, data, pos)?;
        if !s.fullword || fullword_ok(data, start, end, v.wide) {
            return Some((start, end));
        }
        pos = start + 1;
    }
}

/// The leftmost match starting at or after `from`.
///
/// A bounded string searches the rest of the data directly: the automaton
/// stops at most `max_len` bytes past the match start. An unbounded one is
/// searched in windows, because a greedy repetition would otherwise read to
/// the end of the data once per match: matches starting in
/// `[pos, pos + L)` are resolved within `[pos, pos + 2L)`, and a match is
/// then re-read anchored within `L` bytes of its start, so no match is
/// longer than `L` = [`UNBOUNDED_MATCH_LIMIT`]. Look-around (`\b`, `$`)
/// sees the real bytes past a window's edge, because the span is narrowed,
/// not the haystack.
fn search(v: &Variant, max_len: Option<usize>, data: &[u8], from: usize) -> Option<(usize, usize)> {
    let len = data.len();
    if from >= len {
        return None;
    }
    if max_len.is_some() {
        return v
            .re
            .search(&Input::new(data).span(from..len))
            .map(|m| (m.start(), m.end()));
    }
    if !v.re.is_match(Input::new(data).span(from..len)) {
        return None;
    }
    let l = UNBOUNDED_MATCH_LIMIT;
    let mut pos = from;
    while pos < len {
        let resolved_until = pos.saturating_add(l);
        let window_end = pos.saturating_add(2 * l).min(len);
        match v.re.search(&Input::new(data).span(pos..window_end)) {
            Some(m) if m.start() < resolved_until || window_end == len => {
                // Already within the limit: a search confined to `L` bytes
                // from this start would prefer the same match.
                if m.end() - m.start() <= l {
                    return Some((m.start(), m.end()));
                }
                let limit = m.start().saturating_add(l).min(len);
                let bounded = Input::new(data)
                    .span(m.start()..limit)
                    .anchored(Anchored::Yes);
                match v.re.search(&bounded) {
                    Some(b) => return Some((b.start(), b.end())),
                    None => pos = m.start() + 1,
                }
            }
            Some(_) => pos = resolved_until,
            None if window_end == len => return None,
            None => pos = resolved_until,
        }
    }
    None
}

/// YARA's `fullword`: the match is not preceded or followed by an ASCII
/// letter or digit (for a wide match, by one in UTF-16).
fn fullword_ok(data: &[u8], start: usize, end: usize, wide: bool) -> bool {
    let alnum = |b: u8| b.is_ascii_alphanumeric();
    if wide {
        let before = start >= 2 && data[start - 1] == 0 && alnum(data[start - 2]);
        let after = end + 1 < data.len() && alnum(data[end]) && data[end + 1] == 0;
        !before && !after
    } else {
        let before = start > 0 && alnum(data[start - 1]);
        let after = end < data.len() && alnum(data[end]);
        !before && !after
    }
}

fn count_newlines(data: &[u8]) -> usize {
    data.iter().filter(|b| **b == b'\n').count()
}

/// Matched bytes for a finding: printable ASCII as is, everything else as
/// `\xHH`, cut at [`SNIPPET_BYTES`]. A wide match is shown in its narrow
/// form (every other byte), since the interleaved NULs carry nothing.
fn escape(data: &[u8], wide: bool) -> String {
    let narrow: Vec<u8> = if wide {
        data.iter().step_by(2).copied().collect()
    } else {
        data.to_vec()
    };
    let mut out = String::new();
    for &b in narrow.iter().take(SNIPPET_BYTES) {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{b:02X}");
            }
        }
    }
    if narrow.len() > SNIPPET_BYTES {
        out.push_str("...");
    }
    out
}
