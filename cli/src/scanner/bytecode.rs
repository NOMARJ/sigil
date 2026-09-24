//! Shipped Python bytecode (`ARTIFACT-001` .. `ARTIFACT-003`, `ARTIFACT-012`).
//!
//! A `.pyc` is code Python will execute that nobody can read as source. The
//! file walker deliberately skips `__pycache__/` for content scanning (it is
//! build output in a working tree), which is exactly why a skill that ships
//! bytecode is a blind spot: the reviewed `.py` looks clean while the import
//! system loads something else. The `tjade273` samples in the Datadog
//! `ai-skills` set are that attack — an *unchecked* hash-based pyc (PEP 552)
//! whose embedded source hash does not match the shipped `.py`, so Python
//! loads the bytecode without ever looking at the source.
//!
//! This module walks for bytecode on its own (so `__pycache__/` is seen),
//! reads only the 16-byte header and the string constants, and never imports
//! or executes anything.
//!
//! | Rule | Severity | Shape |
//! |---|---|---|
//! | `ARTIFACT-001` | High | Bytecode that could not be matched to its shipped source: no size field, an unchecked hash, a source too large to compare, or any divergence below (one finding per directory) |
//! | `ARTIFACT-002` | Critical, standalone | Bytecode Python runs *instead of* the shipped source: an unchecked-hash pyc whose hash does not match the `.py`, a sourceless `.pyc` at an importable location, or a pyc the import system would load as-is (unchecked hash, matching checked hash, or matching mtime+size) whose constants were compiled from other code |
//! | `ARTIFACT-003` | Critical, corroborate | Bytecode compiled from *different* source than shipped: a recorded source size that no line-ending conversion explains, a checked-hash mismatch, a `__pycache__` entry with no source, or URL constants / identifiers the source does not contain |
//! | `ARTIFACT-012` | Low | Bytecode caches that agree with their shipped source (header and constants) — what CPython writes beside a script the first time it runs; one observation per tree |
//!
//! A mismatching mtime is never evidence on its own: git checkouts and most
//! archive extractors rewrite mtimes, so it disagrees in essentially every
//! clean tree. It is used only the other way round — a timestamp pyc whose
//! mtime and size both equal the source's is one Python will load as-is. A
//! size mismatch is re-checked against CRLF↔LF conversion before it counts —
//! every one of the 39 size mismatches in `luoluoluo22-jianying-editor-skill`
//! is exactly the number of lines in the file (compiled on Windows, shipped
//! with LF).
//!
//! Headers are attacker-written, so agreement is not proof: the string
//! constants (names, literals, docstrings) of an honest pyc are made only of
//! words its source contains, and bytecode that names three or more things
//! the source never mentions was compiled from something else
//! ([`foreign_words`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{Evidence, Finding, Phase, Severity};

/// Directories the bytecode walk never enters: VCS metadata, vendored JS
/// trees and tool caches hold no Python the skill ships.
///
/// Virtual environments (`.venv/`, `venv/`) are walked on purpose: a skill
/// that ships one with a sourceless module in it, and tells the agent to run
/// `.venv/bin/python`, has hidden code where the content scan does not look.
/// What keeps a developer's own venv quiet is that the pycs pip and the
/// interpreter write agree with their sources and aggregate into one Low
/// `ARTIFACT-012` observation (before that, a non-git project with a fresh
/// `.venv` produced 105 High findings, one per cache directory, and a
/// Critical one for a regex in pip's vendored urllib3 read as a URL).
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".next",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

/// Bounds on the dedicated walk. A shipped virtual environment can hold tens
/// of thousands of files; past these the walk stops and says so.
const MAX_WALK_ENTRIES: usize = 50_000;
/// Most bytecode files whose header and constants are inspected.
const MAX_INSPECTED: usize = 2_000;
/// Largest pyc whose constants are extracted.
const MAX_PYC_BYTES: u64 = 8 * 1024 * 1024;
/// Largest source file hashed for a hash-based pyc comparison.
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
/// Cap on extracted string-constant text per pyc.
const MAX_STRINGS_BYTES: usize = 1024 * 1024;

pub const RULE_SHIPPED: &str = "ARTIFACT-001";
pub const RULE_RUNS_INSTEAD: &str = "ARTIFACT-002";
pub const RULE_DIVERGES: &str = "ARTIFACT-003";
pub const RULE_CACHE: &str = "ARTIFACT-012";

/// The parsed fixed header of a `.pyc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PycHeader {
    /// Timestamp-invalidated: Python recompiles when the source's mtime or
    /// size differ, so a stale file here is ignored at import time.
    Timestamp {
        magic: u16,
        mtime: Option<u32>,
        size: Option<u32>,
    },
    /// Hash-invalidated (PEP 552). `checked == false` means Python loads the
    /// bytecode without comparing it to the source at all.
    Hash {
        magic: u16,
        key: u64,
        checked: bool,
        hash: [u8; 8],
    },
    /// Not a CPython bytecode header.
    Invalid,
}

/// Parse the header. Magic numbers are `u16 LE` followed by `\r\n`.
pub fn parse_header(bytes: &[u8]) -> PycHeader {
    if bytes.len() < 8 || &bytes[2..4] != b"\r\n" {
        return PycHeader::Invalid;
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let u32_at = |i: usize| -> Option<u32> {
        bytes
            .get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    match magic {
        // 3.7+ (PEP 552): magic, flags, then mtime+size or an 8-byte hash.
        3392..=19_999 => {
            let Some(flags) = u32_at(4) else {
                return PycHeader::Invalid;
            };
            if flags & 1 == 0 {
                PycHeader::Timestamp {
                    magic,
                    mtime: u32_at(8),
                    size: u32_at(12),
                }
            } else {
                let Some(h) = bytes.get(8..16) else {
                    return PycHeader::Invalid;
                };
                let mut hash = [0u8; 8];
                hash.copy_from_slice(h);
                PycHeader::Hash {
                    magic,
                    key: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                    checked: flags & 2 != 0,
                    hash,
                }
            }
        }
        // 3.3 .. 3.6: magic, mtime, size.
        3230..=3391 => PycHeader::Timestamp {
            magic,
            mtime: u32_at(4),
            size: u32_at(8),
        },
        // 3.0 .. 3.2 and Python 2: magic, mtime; no size field.
        3000..=3229 | 20_000..=u16::MAX => PycHeader::Timestamp {
            magic,
            mtime: u32_at(4),
            size: None,
        },
        _ => PycHeader::Invalid,
    }
}

// ---------------------------------------------------------------------------
// SipHash — CPython's `_imp.source_hash` is SipHash keyed with (magic, 0).
// SipHash-1-3 (CPython 3.11+) is checked against CPython 3.11's
// `_imp.source_hash` in the tests below, and SipHash-2-4 (3.7 .. 3.10)
// against CPython 3.10's. Both are computed and either match counts: a chance
// collision is 2^-64.
// ---------------------------------------------------------------------------

fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-c-d with 128-bit key (`k0`, `k1`), returned little-endian as
/// CPython stores it in the pyc header.
pub fn siphash(k0: u64, k1: u64, data: &[u8], c: usize, d: usize) -> [u8; 8] {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let full = data.len() / 8 * 8;
    for chunk in data[..full].as_chunks::<8>().0 {
        let m = u64::from_le_bytes(*chunk);
        v[3] ^= m;
        for _ in 0..c {
            sip_round(&mut v);
        }
        v[0] ^= m;
    }
    let mut last = ((data.len() as u64) & 0xff) << 56;
    for (i, b) in data[full..].iter().enumerate() {
        last |= (*b as u64) << (8 * i);
    }
    v[3] ^= last;
    for _ in 0..c {
        sip_round(&mut v);
    }
    v[0] ^= last;
    v[2] ^= 0xff;
    for _ in 0..d {
        sip_round(&mut v);
    }
    (v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes()
}

/// Does `hash` match `source` under either CPython keyed-hash variant?
fn hash_matches(key: u64, hash: &[u8; 8], source: &[u8]) -> bool {
    siphash(key, 0, source, 1, 3) == *hash || siphash(key, 0, source, 2, 4) == *hash
}

/// The source as it would have been before a line-ending conversion: LF→CRLF
/// and CRLF→LF variants. A repository that normalises line endings changes
/// the bytes a pyc was compiled from without changing the code.
fn line_ending_variants(source: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let has_crlf = source.windows(2).any(|w| w == b"\r\n");
    if has_crlf {
        let mut lf = Vec::with_capacity(source.len());
        let mut i = 0;
        while i < source.len() {
            if source[i] == b'\r' && source.get(i + 1) == Some(&b'\n') {
                i += 1;
                continue;
            }
            lf.push(source[i]);
            i += 1;
        }
        out.push(lf);
    }
    if source.contains(&b'\n') {
        let mut crlf = Vec::with_capacity(source.len() + source.len() / 16);
        for (i, b) in source.iter().enumerate() {
            if *b == b'\n' && (i == 0 || source[i - 1] != b'\r') {
                crlf.push(b'\r');
            }
            crlf.push(*b);
        }
        out.push(crlf);
    }
    out
}

/// Does a recorded source size agree with the shipped source, allowing for a
/// line-ending conversion in either direction? Sizes are stored mod 2^32.
pub fn size_agrees(recorded: u32, source: &[u8]) -> bool {
    let len = source.len() as u64;
    let crlf = source.windows(2).filter(|w| *w == b"\r\n").count() as u64;
    let lf = source.iter().filter(|b| **b == b'\n').count() as u64;
    let lone_lf = lf - crlf;
    let rec = recorded as u64;
    let m = |x: u64| x & 0xffff_ffff;
    rec == m(len) || rec == m(len + lone_lf) || rec == m(len.saturating_sub(crlf))
}

// ---------------------------------------------------------------------------
// String constants
// ---------------------------------------------------------------------------

fn printable_ascii(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| (0x20..0x7f).contains(b) || matches!(b, b'\t' | b'\n' | b'\r'))
}

/// Pull the string constants out of marshalled code without a full marshal
/// parser: marshal writes every `str` as a type byte (`z`/`Z` short ASCII
/// with a one-byte length; `a`/`A`/`u`/`t` with a four-byte length),
/// optionally OR'd with the 0x80 ref flag. Anything that decodes as a
/// plausible string is kept, one per line. False positives here are random
/// byte runs that happen to decode as text, which only ever add text to scan.
pub fn string_constants(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut i = 0usize;
    while i < body.len() && total < MAX_STRINGS_BYTES {
        let t = body[i] & 0x7f;
        match t {
            b'z' | b'Z' if i + 1 < body.len() => {
                let n = body[i + 1] as usize;
                let end = i + 2 + n;
                if n >= 4 && end <= body.len() && printable_ascii(&body[i + 2..end]) {
                    let s = String::from_utf8_lossy(&body[i + 2..end]).into_owned();
                    total += s.len();
                    out.push(s);
                    i = end;
                    continue;
                }
            }
            b'a' | b'A' | b'u' | b't' if i + 5 <= body.len() => {
                let n = u32::from_le_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]])
                    as usize;
                let end = i + 5 + n;
                if (4..=MAX_STRINGS_BYTES).contains(&n) && end <= body.len() {
                    if let Ok(s) = std::str::from_utf8(&body[i + 5..end]) {
                        let printable = s
                            .chars()
                            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r'))
                            .count();
                        if !s.contains('\0') && printable * 20 >= s.chars().count() * 19 {
                            total += s.len();
                            out.push(s.to_string());
                            i = end;
                            continue;
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// The host of a URL-shaped word, if it has a real scheme (letters, then
/// letters, digits, `+ - .`) and a real host name (a dotted name or
/// `localhost`, with an optional port and userinfo). A regex such as
/// urllib3's `^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(?://...` contains `://` and
/// is not a URL: before this check, pip's own vendored `url.py` in a fresh
/// virtualenv read as bytecode "compiled from different source".
fn url_host(word: &str) -> Option<(&str, &str)> {
    let (before, rest) = word.split_once("://")?;
    let scheme = before
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
        .next()?;
    if scheme.is_empty()
        || scheme.len() > 16
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    let host = hostport.split(':').next()?;
    let hostlike = host.len() >= 4
        && (host.contains('.') || host == "localhost")
        && !host.starts_with(['.', '-'])
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if !hostlike {
        return None;
    }
    let start = before.len() - scheme.len();
    let url = word[start..].trim_end_matches(['"', '\'', ')', ']', ',', ';', '>']);
    Some((url, host))
}

/// URL-shaped constants: the ones whose absence from the source is evidence
/// that the bytecode was compiled from something else.
fn url_constants(strings: &[String]) -> Vec<(&str, &str)> {
    strings
        .iter()
        .flat_map(|s| s.split_whitespace())
        .filter_map(url_host)
        .collect()
}

/// Is this URL constant accounted for by the source text? The compiler folds
/// implicit concatenation (`"https://" "api.example.com/v1"`) into one
/// constant, so the host appearing anywhere in the source is enough; a host
/// the source never names was compiled from something else.
fn url_in_source(url: &str, host: &str, source: &str) -> bool {
    source.contains(url) || source.contains(host)
}

/// Distinct foreign words that make bytecode "compiled from something else".
///
/// Measured by compiling every one of the 799 `.py` files in the four clean
/// vendor skill catalogues with CPython 3.10, 3.11, 3.12 and 3.13 and running
/// this extraction over each result: no honest pyc had more than one foreign
/// word (`return`, the annotations key, before it was allow-listed; a folded
/// constant such as `"d0" "d1" ...`). The two `tjade273` backdoor pycs have 10
/// and 11 (`eval`, `environ`, `PWNED`, ...).
const FOREIGN_WORDS_MIN: usize = 3;
/// Most distinct words checked per pyc.
const MAX_WORDS_CHECKED: usize = 4_000;

/// Identifier-like words (4+ characters, starting with a letter or `_`) in
/// `s`, skipping compiler-made names written in angle brackets (`<module>`,
/// `func.<locals>.<listcomp>`).
fn words(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_word(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_word(b[i]) {
            i += 1;
        }
        let bracketed = start > 0 && b[start - 1] == b'<' && b.get(i) == Some(&b'>');
        let tok = s[start..i].trim_start_matches(|c: char| c.is_ascii_digit());
        if !bracketed && tok.len() >= 4 {
            out.push(tok);
        }
    }
    out
}

/// Identifier-like words in the bytecode's string constants (names, string
/// literals, docstrings) that the shipped source never mentions. An honest
/// pyc is built only out of words its source contains; bytecode compiled
/// from other code names things the reviewed file does not.
pub fn foreign_words(strings: &[String], source: &str) -> Vec<String> {
    let source_words: std::collections::HashSet<&str> = words(source).into_iter().collect();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut foreign: Vec<String> = Vec::new();
    for s in strings {
        // `co_filename`: the absolute path the file was compiled at.
        let lower = s.to_ascii_lowercase();
        if (lower.ends_with(".py") || lower.ends_with(".pyw"))
            && (s.contains('/') || s.contains('\\'))
        {
            continue;
        }
        for w in words(s) {
            if seen.len() >= MAX_WORDS_CHECKED {
                return foreign;
            }
            if !seen.insert(w) {
                continue;
            }
            // Dunders are compiler vocabulary; a word of one repeated letter
            // is a folded constant ("a" * 40); `return` is the annotations
            // key and `format` the parameter of 3.14's generated `__annotate__`.
            if (w.starts_with("__") && w.ends_with("__"))
                || w.bytes().all(|c| c == w.as_bytes()[0])
                || w == "return"
                || w == "format"
            {
                continue;
            }
            // Private names are mangled: `__attr` in class `Foo` is `_Foo__attr`.
            let demangled = match w.get(1..).and_then(|r| r.find("__")) {
                Some(p) if w.starts_with('_') && p > 0 => &w[p + 1..],
                _ => w,
            };
            if source_words.contains(w)
                || source_words.contains(demangled)
                || source.contains(demangled)
            {
                continue;
            }
            foreign.push(w.to_string());
        }
    }
    foreign
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// Whether the git index at `root` tracks any bytecode.
///
/// The bytecode walk honours `.gitignore` inside a git checkout (a developer's
/// own `__pycache__` is build output, not something they ship) — unless the
/// repository *tracks* bytecode anyway, which is the force-added-past-the-
/// ignore-file shape. Index entries end in the path followed by NUL padding,
/// so a byte search for `.pyc\0` is enough to know; no git process is run.
fn index_tracks_bytecode(root: &Path) -> bool {
    let Ok(bytes) = std::fs::read(root.join(".git").join("index")) else {
        return false;
    };
    bytes.windows(5).any(|w| w == b".pyc\0" || w == b".pyo\0")
}

fn is_bytecode_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".pyc") || lower.ends_with(".pyo")
}

/// Every bytecode file under `root`, honouring `.sigilignore` always and
/// `.gitignore` only in a git checkout whose index tracks no bytecode.
/// Returns the files and whether the walk hit its entry cap.
pub fn find_bytecode(root: &Path) -> (Vec<PathBuf>, bool) {
    if root.is_file() {
        let is_pyc = root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_bytecode_name);
        return (
            if is_pyc {
                vec![root.to_path_buf()]
            } else {
                vec![]
            },
            false,
        );
    }
    let honour_gitignore = !index_tracks_bytecode(root);
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(honour_gitignore)
        .require_git(true)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .parents(false)
        .add_custom_ignore_filename(".sigilignore");
    builder.filter_entry(|entry| {
        let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
        !is_dir || !SKIP_DIRS.contains(&entry.file_name().to_string_lossy().as_ref())
    });
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut capped = false;
    for entry in builder.build().filter_map(|e| e.ok()) {
        seen += 1;
        if seen > MAX_WALK_ENTRIES {
            capped = true;
            break;
        }
        if entry.file_type().is_some_and(|t| t.is_file())
            && is_bytecode_name(&entry.file_name().to_string_lossy())
        {
            out.push(entry.into_path());
        }
    }
    out.sort();
    (out, capped)
}

/// Where the source for a bytecode file would live, and whether the bytecode
/// sits in `__pycache__/` (only importable alongside its source) or at a
/// legacy location (importable on its own when there is no source).
fn source_for(pyc: &Path) -> (Vec<PathBuf>, bool) {
    let name = pyc
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = pyc.parent().unwrap_or(Path::new(""));
    let in_cache = parent
        .file_name()
        .is_some_and(|n| n.to_string_lossy() == "__pycache__");
    if in_cache {
        // `<module>.<tag>[.opt-N].pyc` — module names cannot contain dots.
        let stem = name.split('.').next().unwrap_or_default();
        let dir = parent.parent().unwrap_or(Path::new(""));
        (
            vec![
                dir.join(format!("{stem}.py")),
                dir.join(format!("{stem}.pyw")),
            ],
            true,
        )
    } else {
        let stem = name
            .rsplit_once('.')
            .map(|(s, _)| s.to_string())
            .unwrap_or(name.clone());
        (
            vec![
                parent.join(format!("{stem}.py")),
                parent.join(format!("{stem}.pyw")),
            ],
            false,
        )
    }
}

/// A unit of text for the content phases that is not a file on disk.
#[derive(Debug, Clone)]
pub struct VirtualFile {
    /// The path findings are reported against.
    pub rel_path: String,
    pub text: String,
    /// Composable locator (see [`Finding::locator`]).
    pub locator: String,
    /// Prefixed to every snippet so a reader knows the text was derived.
    pub label: &'static str,
    /// The unit's exact bytes, when they are a file of their own (an archive
    /// member) and differ from `text`: invalid UTF-8, or a member the content
    /// phases do not read, kept only for the byte-level YARA pass.
    pub raw: Option<Vec<u8>>,
    /// The unit is a file's own bytes (an archive member), so byte-level
    /// rules apply to it. False for derived text such as bytecode constants,
    /// whose file is evaluated on disk.
    pub is_file: bool,
    /// The member was cut at the per-member size cap: its bytes are its
    /// first part only, so byte-level rules see an unknown `filesize`.
    pub truncated: bool,
}

/// What the bytecode pass found.
#[derive(Debug, Default)]
pub struct BytecodeScan {
    pub findings: Vec<Finding>,
    /// String constants of bytecode that is not the shipped source, for the
    /// content phases to read.
    pub units: Vec<VirtualFile>,
}

pub(crate) fn finding(
    phase: Phase,
    rule: &str,
    severity: Severity,
    file: &str,
    snippet: String,
    weight: u32,
    evidence: Evidence,
) -> Finding {
    Finding {
        phase,
        rule: rule.to_string(),
        severity,
        file: file.to_string(),
        line: None,
        snippet,
        weight,
        kev: false,
        epss: 0.0,
        fingerprint: String::new(),
        locator: None,
        evidence,
    }
}

fn rel(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Inspect every shipped bytecode file under `root`.
pub fn scan(root: &Path, strip_base: &Path) -> BytecodeScan {
    let (files, capped) = find_bytecode(root);
    let mut out = BytecodeScan::default();
    if files.is_empty() {
        return out;
    }

    // Inspect first: whether a file is only an observation depends on what
    // it turns out to be.
    let mut diverging: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut consistent: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    let mut uninspected: Vec<String> = Vec::new();
    for (i, pyc) in files.iter().enumerate() {
        let r = rel(strip_base, pyc);
        if i >= MAX_INSPECTED {
            uninspected.push(r);
        } else if inspect_one(pyc, strip_base, &mut out, &mut diverging) {
            consistent.push(r);
        } else {
            unverified.push(r);
        }
    }
    // Past the cap nothing is known about a file, and a thousand directories
    // of it are one fact, not a thousand High findings.
    if let Some(first) = uninspected.first() {
        out.findings.push(finding(
            Phase::Provenance,
            RULE_SHIPPED,
            Severity::High,
            first,
            format!(
                "{} more Python bytecode file(s) past the inspection cap of {MAX_INSPECTED} \
                 were not compared with their source (first: {first})",
                uninspected.len()
            ),
            3,
            Evidence::Standalone,
        ));
    }

    // ARTIFACT-001: bytecode that could not be shown to be its shipped
    // source, one finding per directory, so a vendored tree with a thousand
    // cached modules is one observation rather than a thousand.
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in unverified {
        let dir = r
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default();
        by_dir.entry(dir).or_default().push(r);
    }
    for (dir, members) in &by_dir {
        let names: Vec<&str> = members
            .iter()
            .take(4)
            .map(|m| m.rsplit('/').next().unwrap_or(m))
            .collect();
        let more = if members.len() > names.len() {
            format!(", +{} more", members.len() - names.len())
        } else {
            String::new()
        };
        let place = if dir.is_empty() { "." } else { dir.as_str() };
        out.findings.push(finding(
            Phase::Provenance,
            RULE_SHIPPED,
            Severity::High,
            &members[0],
            format!(
                "Python bytecode shipped: {} file(s) in {place}/ ({}{more}). Bytecode runs \
                 but cannot be reviewed as source, and these could not be matched to it",
                members.len(),
                names.join(", ")
            ),
            3,
            Evidence::Standalone,
        ));
    }
    if capped {
        out.findings.push(finding(
            Phase::Provenance,
            RULE_SHIPPED,
            Severity::High,
            ".",
            format!(
                "Bytecode walk stopped after {MAX_WALK_ENTRIES} entries; further bytecode \
                 may be present and was not inspected"
            ),
            3,
            Evidence::Standalone,
        ));
    }

    // ARTIFACT-012: caches that agree with their source in every way this
    // pass can check. This is what CPython writes beside a script the first
    // time it runs, so an installed skill that has been used once has them;
    // one Low observation for the whole tree, never a verdict.
    if !consistent.is_empty() {
        let mut dirs: Vec<&str> = consistent
            .iter()
            .map(|r| r.rsplit_once('/').map(|(d, _)| d).unwrap_or("."))
            .collect();
        dirs.dedup();
        let shown: Vec<&str> = dirs.iter().take(3).copied().collect();
        let more = if dirs.len() > shown.len() {
            format!(", +{} more", dirs.len() - shown.len())
        } else {
            String::new()
        };
        out.findings.push(finding(
            Phase::Provenance,
            RULE_CACHE,
            Severity::Low,
            &consistent[0],
            format!(
                "{} Python bytecode cache file(s) that match their shipped .py (header size, \
                 hash and constants agree) in {}{more}",
                consistent.len(),
                shown.join(", ")
            ),
            1,
            Evidence::Standalone,
        ));
    }

    // ARTIFACT-003 is reported once per directory, like ARTIFACT-001: a
    // sloppy sdist with twenty stale caches is one fact about its build, and
    // must not add twenty Critical findings' worth of score.
    for members in diverging.values() {
        let (first, reason) = &members[0];
        let more = if members.len() > 1 {
            let others: Vec<&str> = members[1..]
                .iter()
                .take(4)
                .map(|(f, _)| f.rsplit('/').next().unwrap_or(f))
                .collect();
            format!(
                " (and {} more in this directory: {}{})",
                members.len() - 1,
                others.join(", "),
                if members.len() > 5 { ", ..." } else { "" }
            )
        } else {
            String::new()
        };
        out.findings.push(finding(
            Phase::Obfuscation,
            RULE_DIVERGES,
            Severity::Critical,
            first,
            format!("{reason}{more}"),
            5,
            Evidence::Corroborate,
        ));
    }
    out
}

/// Seconds-resolution mtime as CPython records it (`int(st_mtime) & 0xFFFFFFFF`).
fn mtime_u32(p: &Path) -> Option<u32> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some((secs & 0xffff_ffff) as u32)
}

/// Inspect one bytecode file, pushing any divergence finding. Returns true
/// when the file is a cache that agrees with its shipped source in every way
/// checked here (header size or hash, no foreign URL, no foreign words) — an
/// observation, not a finding.
fn inspect_one(
    pyc: &Path,
    strip_base: &Path,
    out: &mut BytecodeScan,
    diverging: &mut BTreeMap<String, Vec<(String, String)>>,
) -> bool {
    let r = rel(strip_base, pyc);
    let Ok(meta) = std::fs::metadata(pyc) else {
        return false;
    };
    if meta.len() > MAX_PYC_BYTES {
        return false;
    }
    let Ok(bytes) = std::fs::read(pyc) else {
        return false;
    };
    let header = parse_header(&bytes);
    if header == PycHeader::Invalid {
        // Not loadable by CPython; presence is already ARTIFACT-001.
        return false;
    }
    let (candidates, in_cache) = source_for(pyc);
    let source_path = candidates.iter().find(|p| p.is_file());
    let source: Option<Vec<u8>> = source_path.and_then(|p| {
        let len = std::fs::metadata(p).ok()?.len();
        if len > MAX_SOURCE_BYTES {
            return None;
        }
        std::fs::read(p).ok()
    });
    let body_start = match header {
        PycHeader::Timestamp { magic, .. } if (3392..20_000).contains(&magic) => 16,
        PycHeader::Timestamp { magic, .. } if (3230..3392).contains(&magic) => 12,
        PycHeader::Timestamp { .. } => 8,
        PycHeader::Hash { .. } => 16,
        PycHeader::Invalid => return false,
    };
    let strings = string_constants(bytes.get(body_start..).unwrap_or(&[]));

    // Whether the import system would load this file as-is in place of
    // compiling the shipped source: an unchecked-hash pyc always is; a
    // checked-hash pyc is when its hash matches; a timestamp pyc in
    // __pycache__ is when its recorded mtime and size equal the source file's
    // (which an archive that preserves mtimes makes easy to arrange).
    let mut runs_as_is = false;
    // Whether the header agrees with the shipped source.
    let mut header_agrees = false;

    // (rule, severity, evidence, reason) for the strongest divergence found.
    let mut verdict: Option<(&str, Severity, Evidence, String)> = None;
    match (&source, &header) {
        (None, _) if source_path.is_some() => {
            // Source exists but is too large to compare: say nothing more.
        }
        (None, _) if !in_cache => {
            verdict = Some((
                RULE_RUNS_INSTEAD,
                Severity::Critical,
                Evidence::Standalone,
                "sourceless bytecode at an importable location — `import` loads this file \
                 directly and there is no source to review"
                    .to_string(),
            ));
        }
        (None, _) => {
            verdict = Some((
                RULE_DIVERGES,
                Severity::Critical,
                Evidence::Corroborate,
                "bytecode in __pycache__ with no matching .py source — the code it was \
                 compiled from is not shipped"
                    .to_string(),
            ));
        }
        (
            Some(src),
            PycHeader::Hash {
                key, checked, hash, ..
            },
        ) => {
            let matches = hash_matches(*key, hash, src)
                || line_ending_variants(src)
                    .iter()
                    .any(|v| hash_matches(*key, hash, v));
            runs_as_is = in_cache && (!*checked || matches);
            // An unchecked hash is never compared with anything, so a match
            // proves only that whoever built the file knew the source.
            header_agrees = matches && *checked;
            if !matches {
                verdict = Some(if *checked {
                    (
                        RULE_DIVERGES,
                        Severity::Critical,
                        Evidence::Corroborate,
                        "checked hash-based pyc whose source hash does not match the shipped \
                         .py — compiled from different source"
                            .to_string(),
                    )
                } else {
                    (
                        RULE_RUNS_INSTEAD,
                        Severity::Critical,
                        Evidence::Standalone,
                        "UNCHECKED hash-based pyc (PEP 552) whose source hash does not match \
                         the shipped .py — Python loads this bytecode without consulting the \
                         source, so the reviewed file is not the code that runs"
                            .to_string(),
                    )
                });
            }
        }
        (
            Some(src),
            PycHeader::Timestamp {
                size: Some(sz),
                mtime,
                ..
            },
        ) => {
            if size_agrees(*sz, src) {
                header_agrees = true;
                runs_as_is = in_cache
                    && u64::from(*sz) == (src.len() as u64 & 0xffff_ffff)
                    && mtime.is_some()
                    && *mtime == source_path.and_then(|p| mtime_u32(p));
            } else {
                verdict = Some((
                    RULE_DIVERGES,
                    Severity::Critical,
                    Evidence::Corroborate,
                    format!(
                        "pyc records a {sz}-byte source but the shipped .py is {} bytes, and \
                         no line-ending conversion explains the difference — compiled from \
                         different source",
                        src.len()
                    ),
                ));
            }
        }
        _ => {}
    }

    // A header that agrees can still hide different code: URL constants or
    // identifiers the shipped source never mentions were compiled from
    // something else. When Python would load the file as-is, that is the
    // code that runs instead of the reviewed source.
    if verdict.is_none() {
        if let Some(src) = &source {
            let text = String::from_utf8_lossy(src);
            let foreign_urls: Vec<&str> = url_constants(&strings)
                .into_iter()
                .filter(|(u, host)| !url_in_source(u, host, &text))
                .map(|(u, _)| u)
                .collect();
            let reason = if let Some(first) = foreign_urls.first() {
                Some(format!(
                    "bytecode contains {} URL constant(s) absent from the shipped source \
                     (e.g. {first})",
                    foreign_urls.len()
                ))
            } else {
                let foreign = foreign_words(&strings, &text);
                (foreign.len() >= FOREIGN_WORDS_MIN).then(|| {
                    let shown: Vec<&str> = foreign.iter().take(6).map(String::as_str).collect();
                    format!(
                        "bytecode names {} identifier(s)/string(s) the shipped source never \
                         mentions ({}) — compiled from different code",
                        foreign.len(),
                        shown.join(", ")
                    )
                })
            };
            if let Some(reason) = reason {
                verdict = Some(if runs_as_is {
                    (
                        RULE_RUNS_INSTEAD,
                        Severity::Critical,
                        Evidence::Standalone,
                        format!(
                            "{reason}; Python loads this file as-is instead of compiling the \
                             shipped .py"
                        ),
                    )
                } else {
                    (
                        RULE_DIVERGES,
                        Severity::Critical,
                        Evidence::Corroborate,
                        reason,
                    )
                });
            }
        }
    }

    let Some((rule, severity, evidence, reason)) = verdict else {
        return header_agrees;
    };
    if rule == RULE_DIVERGES {
        let dir = r
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default();
        diverging.entry(dir).or_default().push((r.clone(), reason));
    } else {
        out.findings.push(finding(
            Phase::Obfuscation,
            rule,
            severity,
            &r,
            reason,
            5,
            evidence,
        ));
    }

    // The bytecode is not the reviewed source, so its constants are the only
    // readable view of what it does: hand them to the content phases.
    if !strings.is_empty() {
        out.units.push(VirtualFile {
            rel_path: r.clone(),
            text: strings.join("\n"),
            locator: format!("pyc://{r}|constants"),
            label: "bytecode constants",
            raw: None,
            is_file: false,
            truncated: false,
        });
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a timestamp pyc header for CPython 3.11 (magic 3495).
    fn ts_pyc(size: u32, body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&3495u16.to_le_bytes());
        b.extend_from_slice(b"\r\n");
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(body);
        b
    }

    /// Build a hash-based pyc header for CPython 3.11 over `source`.
    fn hash_pyc(checked: bool, source: &[u8], body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&3495u16.to_le_bytes());
        b.extend_from_slice(b"\r\n");
        let key = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
        b.extend_from_slice(&(if checked { 3u32 } else { 1u32 }).to_le_bytes());
        b.extend_from_slice(&siphash(key, 0, source, 1, 3));
        b.extend_from_slice(body);
        b
    }

    /// Marshal-style short ASCII string constant.
    fn z(s: &str) -> Vec<u8> {
        let mut v = vec![b'z' | 0x80, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn write(dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn rules(scan: &BytecodeScan) -> Vec<(String, Severity)> {
        scan.findings
            .iter()
            .map(|f| (f.rule.clone(), f.severity))
            .collect()
    }

    /// Test vectors produced by CPython 3.11's own `_imp.source_hash` with
    /// the 3.11 magic word as key (checked in scripts, not hand-computed).
    #[test]
    fn siphash13_matches_cpython_source_hash() {
        let key = u32::from_le_bytes([0xa7, 0x0d, 0x0d, 0x0a]) as u64;
        assert_eq!(hex::encode(siphash(key, 0, b"", 1, 3)), "738d9cd5d5e87f73");
        assert_eq!(hex::encode(siphash(key, 0, b"a", 1, 3)), "fa30db0730dcbf07");
    }

    #[test]
    fn header_parsing_covers_every_layout() {
        assert!(matches!(
            parse_header(&ts_pyc(10, b"")),
            PycHeader::Timestamp { size: Some(10), .. }
        ));
        assert!(matches!(
            parse_header(&hash_pyc(false, b"x", b"")),
            PycHeader::Hash { checked: false, .. }
        ));
        assert!(matches!(
            parse_header(&hash_pyc(true, b"x", b"")),
            PycHeader::Hash { checked: true, .. }
        ));
        // 3.6 layout: magic, mtime, size.
        let mut py36 = 3379u16.to_le_bytes().to_vec();
        py36.extend_from_slice(b"\r\n\0\0\0\0\x07\0\0\0");
        assert!(matches!(
            parse_header(&py36),
            PycHeader::Timestamp { size: Some(7), .. }
        ));
        assert_eq!(parse_header(b"not bytecode at all"), PycHeader::Invalid);
        assert_eq!(parse_header(b"\0"), PycHeader::Invalid);
    }

    #[test]
    fn line_ending_conversion_is_not_a_mismatch() {
        let lf = b"a = 1\nb = 2\n";
        assert!(size_agrees(lf.len() as u32, lf));
        // Compiled on Windows (CRLF), shipped with LF.
        assert!(size_agrees(lf.len() as u32 + 2, lf));
        let crlf = b"a = 1\r\nb = 2\r\n";
        assert!(size_agrees(crlf.len() as u32 - 2, crlf));
        // A real edit is still a mismatch.
        assert!(!size_agrees(lf.len() as u32 + 31, lf));
    }

    #[test]
    fn string_constants_come_out_of_marshal_data() {
        let mut body = vec![0xe3, 0, 0, 0];
        body.extend(z("https://drop.invalid/dl/1/helper.pyc"));
        body.extend([b'a' | 0x80, 6, 0, 0, 0]);
        body.extend_from_slice(b"subpro");
        body.extend(z("ab")); // too short, dropped
        let s = string_constants(&body);
        assert!(s.contains(&"https://drop.invalid/dl/1/helper.pyc".to_string()));
        assert!(s.contains(&"subpro".to_string()));
        assert!(!s.contains(&"ab".to_string()));
    }

    #[test]
    fn unchecked_hash_pyc_that_is_not_the_source_is_critical() {
        let d = tempfile::tempdir().unwrap();
        let shipped = b"def f():\n    return 1\n";
        write(d.path(), "s/utils.py", shipped);
        let other = b"def f():\n    return 2  # not the shipped code\n";
        write(
            d.path(),
            "s/__pycache__/utils.cpython-311.pyc",
            &hash_pyc(false, other, &z("not the shipped code")),
        );
        let scan = scan(d.path(), d.path());
        let r = rules(&scan);
        assert!(r.contains(&(RULE_SHIPPED.into(), Severity::High)), "{r:?}");
        let f = scan
            .findings
            .iter()
            .find(|f| f.rule == RULE_RUNS_INSTEAD)
            .expect("ARTIFACT-002");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.evidence, Evidence::Standalone);
        assert_eq!(scan.units.len(), 1, "constants handed to the phases");
    }

    #[test]
    fn bytecode_that_is_the_source_is_only_an_observation() {
        let d = tempfile::tempdir().unwrap();
        let shipped = b"def f():\n    return 1\n";
        write(d.path(), "s/utils.py", shipped);
        write(
            d.path(),
            "s/__pycache__/utils.cpython-311.pyc",
            &hash_pyc(false, shipped, &z("return value")),
        );
        write(
            d.path(),
            "s/__pycache__/utils.cpython-312.pyc",
            &ts_pyc(shipped.len() as u32 + 2, &z("return value")), // CRLF compile
        );
        let scan = scan(d.path(), d.path());
        let r = rules(&scan);
        // The unchecked pyc's hash matches, but Python never checks it, so a
        // match proves nothing about the code: still "shipped, unverified".
        // The timestamp pyc agrees (CRLF compile) and names nothing foreign:
        // an observation only.
        assert_eq!(
            r,
            vec![
                (RULE_SHIPPED.into(), Severity::High),
                (RULE_CACHE.into(), Severity::Low)
            ],
            "{r:?}"
        );
        assert!(scan.findings[0].file.ends_with("cpython-311.pyc"));
        assert!(scan.units.is_empty());
    }

    /// A timestamp pyc stamped with the source's own mtime.
    fn ts_pyc_for(source: &Path, body: &[u8]) -> Vec<u8> {
        let len = std::fs::metadata(source).unwrap().len() as u32;
        let mut b = ts_pyc(len, body);
        b[8..12].copy_from_slice(&mtime_u32(source).unwrap().to_le_bytes());
        b
    }

    #[test]
    fn siphash24_matches_cpython_310_source_hash() {
        // `_imp.source_hash` under CPython 3.10.20 (SipHash-2-4), keyed with
        // the 3.10 magic word (0x0a0d0d6f); computed by the interpreter, not
        // by hand.
        let key = u32::from_le_bytes([0x6f, 0x0d, 0x0d, 0x0a]) as u64;
        assert_eq!(hex::encode(siphash(key, 0, b"", 2, 4)), "8cc0cd2525e7fd27");
        assert_eq!(hex::encode(siphash(key, 0, b"a", 2, 4)), "3f75554bda1e742f");
        assert_eq!(
            hex::encode(siphash(key, 0, b"xxxxxxxx", 2, 4)),
            "65a65b7ede06ca93"
        );
        assert_eq!(
            hex::encode(siphash(key, 0, &[b'x'; 17], 2, 4)),
            "2a475d3083f9ddcb"
        );
        assert_eq!(
            hex::encode(siphash(key, 0, b"def f():\n    return 1\n", 2, 4)),
            "990c9db73497884c"
        );
    }

    #[test]
    fn a_skill_that_has_run_once_is_not_high() {
        // CPython writes __pycache__/x.cpython-3xx.pyc beside a script the
        // first time it runs: mtime and size of the source, constants out of
        // the source. An installed skill that was used once looks like this.
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "SKILL.md", b"# CSV\n");
        let src = b"import csv\n\ndef main(path):\n    print(len(list(csv.reader(open(path)))), 'rows')\n";
        write(d.path(), "scripts/summary.py", src);
        let body: Vec<u8> = [
            "csv", "main", "path", "print", "list", "reader", "open", "rows",
        ]
        .iter()
        .flat_map(|s| z(s))
        .collect();
        let pyc = ts_pyc_for(&d.path().join("scripts/summary.py"), &body);
        write(
            d.path(),
            "scripts/__pycache__/summary.cpython-311.pyc",
            &pyc,
        );
        let s = scan(d.path(), d.path());
        assert_eq!(rules(&s), vec![(RULE_CACHE.into(), Severity::Low)]);
        assert_eq!(s.findings[0].weight, 1);
        assert!(s.units.is_empty());
    }

    #[test]
    fn a_forged_header_does_not_hide_different_code() {
        // Unchecked-hash pyc whose header hash is computed over the SHIPPED
        // source (so it "matches") while the body is other code: Python runs
        // it without looking at the source.
        let d = tempfile::tempdir().unwrap();
        let shipped = b"def f():\n    return 1\n";
        write(d.path(), "s/utils.py", shipped);
        let mut body = z("subprocess");
        body.extend(z("check_output"));
        body.extend(z("harvest_keys"));
        write(
            d.path(),
            "s/__pycache__/utils.cpython-311.pyc",
            &hash_pyc(false, shipped, &body),
        );
        let s = scan(d.path(), d.path());
        let f = s
            .findings
            .iter()
            .find(|f| f.rule == RULE_RUNS_INSTEAD)
            .unwrap_or_else(|| panic!("ARTIFACT-002 expected: {:?}", s.findings));
        assert_eq!(f.evidence, Evidence::Standalone);
        assert!(f.snippet.contains("subprocess"), "{}", f.snippet);
        assert_eq!(s.units.len(), 1, "constants handed to the phases");

        // Same forgery on a timestamp pyc: mtime and size copied from the
        // source, so the import system loads it as-is. Standalone too.
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "s/utils.py", shipped);
        let pyc = ts_pyc_for(&d.path().join("s/utils.py"), &body);
        write(d.path(), "s/__pycache__/utils.cpython-311.pyc", &pyc);
        let s = scan(d.path(), d.path());
        assert!(
            s.findings
                .iter()
                .any(|f| f.rule == RULE_RUNS_INSTEAD && f.evidence == Evidence::Standalone),
            "{:?}",
            s.findings
        );

        // With a stale mtime Python recompiles the source instead, so the
        // divergence is evidence about the build, not code that runs.
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "s/utils.py", shipped);
        write(
            d.path(),
            "s/__pycache__/utils.cpython-311.pyc",
            &ts_pyc(shipped.len() as u32, &body),
        );
        let r = rules(&scan(d.path(), d.path()));
        assert!(
            r.contains(&(RULE_DIVERGES.into(), Severity::Critical)),
            "{r:?}"
        );
        assert!(!r.iter().any(|(id, _)| id == RULE_RUNS_INSTEAD), "{r:?}");
    }

    #[test]
    fn url_constants_are_real_urls() {
        let strings: Vec<String> = [
            // urllib3's URI regex, folded from implicit concatenation.
            "^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(?://([^\\/?#]*))?([^?#]*)",
            "see https://drop.invalid/dl/1/helper.pyc)",
            "git+ssh://git@github.com:org/repo.git",
            "http://localhost:8080/ready",
            "scheme://",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let urls = url_constants(&strings);
        assert_eq!(
            urls,
            vec![
                ("https://drop.invalid/dl/1/helper.pyc", "drop.invalid"),
                ("git+ssh://git@github.com:org/repo.git", "github.com"),
                ("http://localhost:8080/ready", "localhost"),
            ]
        );
        // Implicit concatenation splits scheme and host in the source.
        let source = "BASE = (\"https://\" \"api.example.com/v1\")\n";
        assert!(url_in_source(
            "https://api.example.com/v1",
            "api.example.com",
            source
        ));
        assert!(!url_in_source(
            "https://drop.example.net/x",
            "drop.example.net",
            source
        ));
    }

    #[test]
    fn foreign_words_ignore_what_the_compiler_adds() {
        let source =
            "class ScriptFile:\n    def __add(self):\n        return [x for x in self.items]\n";
        let strings: Vec<String> = [
            "ScriptFile",
            "_ScriptFile__add",
            "ScriptFile.__add.<locals>.<listcomp>",
            "<module>",
            "/home/builder/proj/script_file.py",
            "items",
            "return",
            "aaaaaaaa",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert!(foreign_words(&strings, source).is_empty());
        let payload: Vec<String> = ["environ", "eval", "PWNED unsafe"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            foreign_words(&payload, source),
            vec!["environ", "eval", "PWNED", "unsafe"]
        );
    }

    #[test]
    fn a_virtualenv_is_one_observation_unless_it_hides_something() {
        // pip-compiled caches in a local venv: consistent, one Low finding
        // however many directories they sit in.
        let d = tempfile::tempdir().unwrap();
        for pkg in ["pip", "pip/_internal", "setuptools", "idna"] {
            let src = format!(".venv/lib/python3.11/site-packages/{pkg}/__init__.py");
            write(d.path(), &src, b"from . import core\n");
            let pyc = ts_pyc_for(&d.path().join(&src), &z("core"));
            write(
                d.path(),
                &format!(
                    ".venv/lib/python3.11/site-packages/{pkg}/__pycache__/__init__.cpython-311.pyc"
                ),
                &pyc,
            );
        }
        let s = scan(d.path(), d.path());
        assert_eq!(rules(&s), vec![(RULE_CACHE.into(), Severity::Low)]);
        assert!(s.findings[0].snippet.starts_with("4 Python bytecode cache"));
        // A sourceless module shipped inside a venv is importable from its
        // interpreter: reported like anywhere else (SkillSpector SC8 has the
        // same case).
        write(d.path(), ".venv/lib/payload.pyc", &ts_pyc(10, b""));
        let r = rules(&scan(d.path(), d.path()));
        assert!(
            r.contains(&(RULE_RUNS_INSTEAD.into(), Severity::Critical)),
            "{r:?}"
        );
        assert!(r.contains(&(RULE_SHIPPED.into(), Severity::High)), "{r:?}");
    }

    #[test]
    fn stale_size_orphans_and_foreign_urls_diverge() {
        let d = tempfile::tempdir().unwrap();
        let shipped = b"x = 1\ny = 2\n";
        write(d.path(), "a.py", shipped);
        write(d.path(), "__pycache__/a.cpython-311.pyc", &ts_pyc(999, b""));
        write(
            d.path(),
            "__pycache__/gone.cpython-311.pyc",
            &ts_pyc(5, b""),
        );
        write(d.path(), "b.py", b"URL = 'https://example.org/api'\n");
        write(
            d.path(),
            "__pycache__/b.cpython-311.pyc",
            &ts_pyc(33, &z("https://evil.example.net/drop")),
        );
        let scan = scan(d.path(), d.path());
        let diverging: Vec<&Finding> = scan
            .findings
            .iter()
            .filter(|f| f.rule == RULE_DIVERGES)
            .collect();
        // Three diverging files in one directory: one finding naming all three.
        assert_eq!(diverging.len(), 1, "{:?}", scan.findings);
        assert!(
            diverging[0].snippet.contains("and 2 more"),
            "{}",
            diverging[0].snippet
        );
        assert!(scan
            .findings
            .iter()
            .filter(|f| f.rule == RULE_DIVERGES)
            .all(|f| f.evidence == Evidence::Corroborate));
        // One ARTIFACT-001 for the directory, not one per file.
        assert_eq!(
            scan.findings
                .iter()
                .filter(|f| f.rule == RULE_SHIPPED)
                .count(),
            1
        );
    }

    #[test]
    fn sourceless_legacy_pyc_is_importable_and_critical() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "payload.pyc", &ts_pyc(10, b""));
        let scan = scan(d.path(), d.path());
        assert!(scan
            .findings
            .iter()
            .any(|f| f.rule == RULE_RUNS_INSTEAD && f.severity == Severity::Critical));
        // A file merely named .pyc that is not bytecode is presence only.
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "notes.pyc", b"plain text");
        let r = rules(&scan_owned(d.path()));
        assert_eq!(r, vec![(RULE_SHIPPED.into(), Severity::High)]);
    }

    fn scan_owned(p: &Path) -> BytecodeScan {
        scan(p, p)
    }

    #[test]
    fn a_tree_without_bytecode_costs_nothing() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "main.py", b"print('hi')\n");
        let s = scan(d.path(), d.path());
        assert!(s.findings.is_empty() && s.units.is_empty());
    }

    #[test]
    fn gitignored_cache_is_skipped_unless_the_index_tracks_bytecode() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".git")).unwrap();
        write(d.path(), ".gitignore", b"__pycache__/\n");
        write(d.path(), "m.py", b"x = 1\n");
        write(d.path(), "__pycache__/m.cpython-311.pyc", &ts_pyc(6, b""));
        assert!(find_bytecode(d.path()).0.is_empty(), "local build output");
        // The index lists a pyc: it was force-added past the ignore file.
        write(
            d.path(),
            ".git/index",
            b"DIRC\0\0\0\x02__pycache__/m.cpython-311.pyc\0\0",
        );
        assert_eq!(find_bytecode(d.path()).0.len(), 1);
    }
}
