//! Evaluating compiled YARA rules over a file's raw bytes.
//!
//! YARA semantics, not Sigil's line semantics: strings match anywhere in the
//! bytes, across line breaks, in binary files; `#a` counts every offset a
//! match starts at (overlapping matches included); `filesize` is the file's
//! real size. Work is lazy — a string is searched only when the condition
//! needs it — and bounded:
//!
//! - no match is longer than [`UNBOUNDED_MATCH_LIMIT`] when the string has an
//!   unbounded part, and the search walks the data in windows of that size,
//!   so a greedy `.*` cannot rescan the rest of the file once per match;
//! - `#a` stops counting at [`MAX_MATCHES_PER_STRING`], YARA's own cap;
//! - every search runs in chunks of [`SEARCH_CHUNK`] start positions and
//!   checks the per-file budget (`scanner::budget`) between them, so the
//!   budget stops evaluation however slowly an automaton crawls over crafted
//!   bytes. A rule whose evaluation the budget cut short is not reported
//!   either way — a search cut short reads as "no match", which `not $a` or
//!   `#a < 5` would turn into a finding — and the caller reports the
//!   truncation (`PROV-BUDGET-001`).

use std::fmt::Write as _;
use std::sync::Arc;

use regex_automata::{Anchored, Input};

use super::strings::{CompiledString, Variant};
use super::{ArithOp, CmpOp, Expr, Quant, YaraFile, YaraRule};
use crate::scanner::budget::FileBudget;
use crate::scanner::{Finding, Phase};

/// Longest match of a string that has an unbounded part. Not libyara's
/// limit, in either direction (measured on libyara 4.5.4): its regular
/// expression matches stop at about 1 KB, and its unbounded hex jumps are not
/// limited at all (it chains the pieces of the string). See
/// `docs/enterprise.md` ("YARA rules", Limits).
pub const UNBOUNDED_MATCH_LIMIT: usize = 4096;

/// Matches counted per string per file before `#a` stops (YARA: 1,000,000).
pub const MAX_MATCHES_PER_STRING: u64 = 1_000_000;

/// Start positions one automaton call covers before the budget is checked
/// again. Linear-time matching is not always fast: once a wide bounded jump
/// overflows the lazy DFA's cache, the engine simulates the NFA at a few
/// microseconds per byte (measured: `{ 41 [0-511] 42 }` over 9.5 MB of
/// high-complexity data, 54 s in one call), so one call over a whole file
/// could outlast any budget.
pub const SEARCH_CHUNK: usize = 64 * 1024;

/// Real bytes kept on each side of a partial segment: two, for the UTF-16
/// `fullword` check of a `wide` string.
pub const CONTEXT_BYTES: usize = 2;

/// Bytes of each matched string shown in a finding.
const SNIPPET_BYTES: usize = 48;

/// Matched strings named in a finding before the rest are summarised.
const SNIPPET_STRINGS: usize = 3;

/// A contiguous run of the scanned file's bytes.
pub struct Segment<'a> {
    /// Offset of `data[0]` in the file.
    pub base: u64,
    /// The segment's bytes (`span`), plus up to [`CONTEXT_BYTES`] of the
    /// file's real bytes on either side when the segment is part of a larger
    /// file, so `^`, `$`, `\b` and `fullword` see what the file has there
    /// rather than an edge that is not in the file.
    pub data: &'a [u8],
    /// The part of `data` this segment evaluates: every match starts and
    /// ends inside it.
    pub span: std::ops::Range<usize>,
    /// Newlines in the file before `data[0]` when the file is text; `None`
    /// for binary content, whose findings carry no line number.
    pub newlines_before: Option<usize>,
}

impl Segment<'_> {
    /// The index in `data` of file offset `at`, when it is inside `span`.
    fn local(&self, at: u64) -> Option<usize> {
        let local = usize::try_from(at.checked_sub(self.base)?).ok()?;
        self.span.contains(&local).then_some(local)
    }
}

/// What one evaluation looks at: a whole file, or the scanned head and tail
/// of one too large to read whole.
pub struct Subject<'a> {
    pub segments: Vec<Segment<'a>>,
    /// The file's size; `None` when it is not known (an archive member cut
    /// at the member size cap), which makes `filesize` undefined.
    pub filesize: Option<u64>,
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
                span: 0..data.len(),
                newlines_before: text.then_some(0),
            }],
            filesize: Some(data.len() as u64),
            partial: false,
        }
    }

    /// The first bytes of something larger whose size is not known (an
    /// archive member cut at the member size cap): evaluated as far as they
    /// go, with `filesize` undefined and findings marked partial.
    pub fn truncated(data: &'a [u8], text: bool) -> Self {
        Subject {
            filesize: None,
            partial: true,
            ..Subject::whole(data, text)
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
    // A file an external engine evaluates (or none can) has no compiled
    // strings or condition here.
    for file in files.iter().filter(|f| f.is_builtin()) {
        let mut results: Vec<bool> = Vec::with_capacity(file.rules.len());
        let mut evals: Vec<RuleEval<'_, '_>> = Vec::with_capacity(file.rules.len());
        let mut cut_short = false;
        for rule in &file.rules {
            if budget.expired() {
                cut_short = true;
                break;
            }
            let mut ev = RuleEval::new(rule, subject, budget);
            let matched = ev.boolean(&rule.condition, &results).unwrap_or(false);
            // A search the budget cut short reads as "no match", which
            // `not $a`, `none of them` or `#a < 5` would turn into a finding.
            // A rule whose evaluation ran out of time is not reported either
            // way, nor is any rule after it; the caller reports the file as
            // not fully analysed.
            if budget.expired() {
                cut_short = true;
                break;
            }
            results.push(matched);
            evals.push(ev);
        }
        // A global rule that does not match switches off every rule in its
        // file, as it does in a YARA namespace; one the budget left
        // unevaluated leaves every rule in the file unknown.
        let globals_hold = file
            .rules
            .iter()
            .enumerate()
            .all(|(k, r)| !r.global || results.get(k).copied().unwrap_or(false));
        if globals_hold {
            for ((rule, matched), mut ev) in file.rules.iter().zip(results).zip(evals) {
                if !matched || rule.private || !phase_enabled(rule.phase) {
                    continue;
                }
                out.push(ev.finding(rel_path));
            }
        }
        if cut_short {
            return out;
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
                if let Some((start, end)) =
                    next_in(s, v, seg, seg.span.start, seg.span.end, self.budget)
                {
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
        // Every offset a match starts at, per form. The ascii and wide forms
        // of one string can both match at one offset (`"Q" wide ascii` over
        // `Q\0`), which YARA counts once, so with two forms the offsets are
        // merged rather than their counts added.
        let mut per_form: Vec<Vec<u64>> = Vec::with_capacity(s.variants.len());
        'all: for v in &s.variants {
            let mut starts = Vec::new();
            for seg in &self.subject.segments {
                let mut pos = seg.span.start;
                while let Some((start, _)) = next_in(s, v, seg, pos, seg.span.end, self.budget) {
                    starts.push(seg.base + start as u64);
                    let n = starts.len() as u64;
                    if n >= MAX_MATCHES_PER_STRING
                        || (n.is_multiple_of(4096) && self.budget.expired())
                    {
                        per_form.push(starts);
                        break 'all;
                    }
                    pos = start + 1;
                }
            }
            per_form.push(starts);
        }
        let n = match per_form.as_slice() {
            [] => 0,
            [one] => one.len() as u64,
            _ => {
                let mut all: Vec<u64> = per_form.concat();
                all.sort_unstable();
                all.dedup();
                all.len() as u64
            }
        }
        .min(MAX_MATCHES_PER_STRING);
        self.count[i] = Some(n);
        n
    }

    /// A match of string `i` starting exactly at file offset `at`.
    fn at(&self, i: usize, at: u64) -> bool {
        let s = &self.rule.strings[i];
        let limit = s.max_len.unwrap_or(UNBOUNDED_MATCH_LIMIT);
        for seg in &self.subject.segments {
            let Some(local) = seg.local(at) else {
                continue;
            };
            let end = local.saturating_add(limit).min(seg.span.end);
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

    /// A match of string `i` starting anywhere in `lo..=hi` (file offsets).
    fn within(&self, i: usize, lo: u64, hi: u64) -> bool {
        let s = &self.rule.strings[i];
        for seg in &self.subject.segments {
            let first = seg.base + seg.span.start as u64;
            let last = seg.base + seg.span.end as u64; // exclusive
            if hi < first || lo >= last {
                continue;
            }
            let from = (lo.max(first) - seg.base) as usize;
            // A start past `hi` does not count, so the search stops there.
            let until = (hi.saturating_add(1).min(last) - seg.base) as usize;
            for v in &s.variants {
                if next_in(s, v, seg, from, until, self.budget).is_some() {
                    return true;
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
            Expr::Filesize => self.subject.filesize.and_then(|f| i64::try_from(f).ok()),
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

    /// `any`/`all`/`none`/`N`/`N%` `of` a set, with YARA's reading of the
    /// edge cases (checked against libyara 4.5): `0 of` means none of them;
    /// a negative count, or a percentage of 0 or less, is met whatever
    /// matches; a percentage over 100 never is. A string listed twice in a
    /// set counts twice, as in YARA.
    fn of(&mut self, quant: &Quant, set: &[usize], rules: &[bool]) -> Option<bool> {
        let len = set.len() as u64;
        let need: u64 = match quant {
            Quant::Any => 1,
            Quant::All => len,
            Quant::None => return Some(!set.iter().any(|i| self.matched(*i))),
            Quant::AtLeast(n) => match self.integer(n, rules)? {
                0 => return Some(!set.iter().any(|i| self.matched(*i))),
                n if n < 0 => return Some(true),
                n => n as u64,
            },
            Quant::Percent(p) => match self.integer(p, rules)? {
                p if p <= 0 => return Some(true),
                // found * 100 >= p * len, as a whole number of strings.
                p => u64::try_from((p as u128 * u128::from(len)).div_ceil(100)).unwrap_or(u64::MAX),
            },
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
        let prefix = match (self.subject.partial, self.subject.filesize) {
            (false, _) => "",
            (true, Some(_)) => "[head/tail of oversized file] ",
            (true, None) => "[first part of oversized member] ",
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

/// The first match of `v` in `seg` starting in `from..until` that passes the
/// `fullword` check. Matches end within the segment's span.
fn next_in(
    s: &CompiledString,
    v: &Variant,
    seg: &Segment<'_>,
    from: usize,
    until: usize,
    budget: &FileBudget,
) -> Option<(usize, usize)> {
    let mut pos = from;
    loop {
        let (start, end) = search(v, s.max_len, seg.data, seg.span.end, pos, until, budget)?;
        if !s.fullword || fullword_ok(seg.data, start, end, v.wide) {
            return Some((start, end));
        }
        pos = start + 1;
    }
}

/// The leftmost match starting in `from..until` and ending by `end`; `None`
/// also when the budget runs out (the caller sees the expired budget).
///
/// No automaton call covers more than [`SEARCH_CHUNK`] start positions, and
/// the budget is checked before each, so a slow automaton cannot hold the
/// thread past the budget. A bounded string (longest match `m`) searches
/// each chunk plus `m` bytes: a match starting in the chunk ends within
/// that, so the leftmost one is the one a search of the whole data finds.
/// An unbounded one first asks whether anything matches within the chunk
/// plus `L` bytes (`L` = [`UNBOUNDED_MATCH_LIMIT`]; no match longer than `L`
/// counts, so a chunk that fails has none), then walks it in windows,
/// because a greedy repetition would otherwise read to the end of the data
/// once per match: matches starting in `[pos, pos + L)` are resolved within
/// `[pos, pos + 2L)`, and a match is re-read anchored within `L` bytes of
/// its start. Look-around (`\b`, `$`) sees the real bytes past a window's
/// edge, because the span is narrowed, not the haystack.
fn search(
    v: &Variant,
    max_len: Option<usize>,
    data: &[u8],
    end: usize,
    from: usize,
    until: usize,
    budget: &FileBudget,
) -> Option<(usize, usize)> {
    let until = until.min(end);
    let Some(m) = max_len else {
        return search_unbounded(v, data, end, from, until, budget);
    };
    let mut pos = from;
    while pos < until {
        if budget.expired() {
            return None;
        }
        let chunk_end = pos.saturating_add(SEARCH_CHUNK).min(until);
        let window_end = chunk_end.saturating_add(m).min(end);
        if let Some(found) = v.re.search(&Input::new(data).span(pos..window_end)) {
            // A match starting past the chunk may be cut short by the
            // window; the next chunk finds it whole.
            if found.start() < chunk_end {
                return Some((found.start(), found.end()));
            }
        }
        pos = chunk_end;
    }
    None
}

/// [`search`] for a string with an unbounded part.
fn search_unbounded(
    v: &Variant,
    data: &[u8],
    end: usize,
    from: usize,
    until: usize,
    budget: &FileBudget,
) -> Option<(usize, usize)> {
    let l = UNBOUNDED_MATCH_LIMIT;
    let mut pos = from;
    // Starts before this lie in a chunk that passed the pre-check.
    let mut checked = from;
    while pos < until {
        if budget.expired() {
            return None;
        }
        if pos >= checked {
            let chunk_end = pos.saturating_add(SEARCH_CHUNK).min(until);
            let probe_end = chunk_end.saturating_add(l).min(end);
            if !v.re.is_match(Input::new(data).span(pos..probe_end)) {
                pos = chunk_end;
                continue;
            }
            checked = chunk_end;
        }
        let resolved_until = pos.saturating_add(l);
        let window_end = pos.saturating_add(2 * l).min(end);
        match v.re.search(&Input::new(data).span(pos..window_end)) {
            Some(m) if m.start() < resolved_until || window_end == end => {
                if m.start() >= until {
                    return None;
                }
                // Already within the limit: a search confined to `L` bytes
                // from this start would prefer the same match.
                if m.end() - m.start() <= l {
                    return Some((m.start(), m.end()));
                }
                let limit = m.start().saturating_add(l).min(end);
                let bounded = Input::new(data)
                    .span(m.start()..limit)
                    .anchored(Anchored::Yes);
                match v.re.search(&bounded) {
                    Some(b) => return Some((b.start(), b.end())),
                    None => pos = m.start() + 1,
                }
            }
            Some(_) => pos = resolved_until,
            None if window_end == end => return None,
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
