//! Is this file written by a person or emitted by a tool?
//!
//! Bundlers, minifiers and sourcemap writers produce text with a shape no
//! human writes: one line holding hundreds of kilobytes, or an average line
//! length in the thousands. That shape is what makes such files expensive to
//! scan, so the scanner needs to be able to name it.
//!
//! The threshold is measured, not guessed. Over the 20-package clean control
//! set (1,818 text files) the longest line of a hand-written file sits at the
//! 99th percentile at 570 bytes, and the largest non-generated outlier is a
//! 2,368-byte Markdown badge row; this crate's own Rust sources top out at 345.
//! Every file above 4 KB on a single line in those trees is machine output:
//! `axios.min.js` (63 KB line), `axios.min.js.map` (267 KB line),
//! `lodash.min.js` (4.2 KB lines). So the classifier keys on line *shape*
//! alone — no extension list, no bundler-banner regex — which is why it works
//! the same way on a minified `.py`, a `.map`, or a single-line JSON blob.
//!
//! Classification is descriptive. It reports what a file looks like; it does
//! **not** decide which rules run. A malicious payload is very often shipped
//! exactly like this — the compromised `@antv/g6-pc` carries its dropper as a
//! 499 KB single-line `index.js` — so a classifier that suppressed detection
//! on machine-generated text would switch the scanner off precisely where the
//! attacker put the code.

/// Longest line, in bytes, at or above which a file is machine-generated.
///
/// Set well clear of the measured hand-written 99th percentile (570 bytes) and
/// of the largest observed hand-written outlier (a 2,368-byte Markdown line),
/// so ordinary source, prose and configuration never trip it.
pub const MACHINE_LINE_BYTES: usize = 4096;

/// Mean line length, in bytes, at or above which a file is machine-generated
/// even without one enormous line — the shape of a bundle that has been
/// re-wrapped, or of a data file with long uniform records.
pub const MACHINE_MEAN_LINE_BYTES: usize = 1024;

/// The measured line shape of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineShape {
    pub lines: usize,
    pub longest_line: usize,
    pub bytes: usize,
}

impl LineShape {
    /// Measure `contents` in a single pass.
    pub fn measure(contents: &str) -> LineShape {
        let mut lines = 0usize;
        let mut longest = 0usize;
        for line in contents.lines() {
            lines += 1;
            if line.len() > longest {
                longest = line.len();
            }
        }
        LineShape {
            lines,
            longest_line: longest,
            bytes: contents.len(),
        }
    }

    /// Mean line length, 0 for an empty file.
    pub fn mean_line(&self) -> usize {
        self.bytes.checked_div(self.lines).unwrap_or(0)
    }

    /// Does this file look like tool output rather than something a person
    /// typed?
    pub fn is_machine_generated(&self) -> bool {
        self.longest_line >= MACHINE_LINE_BYTES || self.mean_line() >= MACHINE_MEAN_LINE_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic synthetic inputs — no randomness anywhere in this file.
    fn source_like() -> String {
        (0..400)
            .map(|i| format!("fn helper_{i}(value: usize) -> usize {{ value + {i} }}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn minified_like() -> String {
        // One 120 KB line, the shape a bundler emits.
        format!("!function(e,t){{{}}}(0,0);", "a=b+c;".repeat(20_000))
    }

    #[test]
    fn ordinary_source_is_not_machine_generated() {
        let s = source_like();
        let shape = LineShape::measure(&s);
        assert_eq!(shape.lines, 400);
        assert!(shape.longest_line < MACHINE_LINE_BYTES, "{shape:?}");
        assert!(!shape.is_machine_generated(), "{shape:?}");
    }

    #[test]
    fn a_minified_bundle_is_machine_generated() {
        let s = minified_like();
        let shape = LineShape::measure(&s);
        assert_eq!(shape.lines, 1);
        assert!(shape.is_machine_generated(), "{shape:?}");
    }

    /// A re-wrapped bundle has no single enormous line but a huge mean.
    #[test]
    fn a_rewrapped_bundle_is_machine_generated_by_mean_length() {
        let line = "a=b+c;".repeat(300); // 1800 bytes, under the single-line cap
        let s = (0..50).map(|_| line.clone()).collect::<Vec<_>>().join("\n");
        let shape = LineShape::measure(&s);
        assert!(shape.longest_line < MACHINE_LINE_BYTES, "{shape:?}");
        assert!(shape.mean_line() >= MACHINE_MEAN_LINE_BYTES, "{shape:?}");
        assert!(shape.is_machine_generated(), "{shape:?}");
    }

    /// The empty file must not divide by zero or be called machine output.
    #[test]
    fn empty_and_tiny_files_are_not_machine_generated() {
        for s in ["", "\n", "print('hi')\n"] {
            assert!(
                !LineShape::measure(s).is_machine_generated(),
                "classified {s:?} as machine output"
            );
        }
        assert_eq!(LineShape::measure("").mean_line(), 0);
    }

    /// A long prose line — the largest hand-written shape seen in the control
    /// set was a 2,368-byte Markdown row — must stay on the human side.
    #[test]
    fn a_long_markdown_line_is_not_machine_generated() {
        let badge = format!(
            "# Title\n\n{}\n\nmore prose\n",
            "[![b](https://img.example/x.svg)](https://example.com/y) ".repeat(40)
        );
        let shape = LineShape::measure(&badge);
        assert!(shape.longest_line > 2000, "{shape:?}");
        assert!(!shape.is_machine_generated(), "{shape:?}");
    }

    /// The threshold has to sit above what people write and below what tools
    /// emit; if these ever cross, the classifier is meaningless.
    ///
    /// 2,368 bytes is the longest hand-written line measured across the
    /// 20-package clean control set (a Markdown badge row in
    /// `charset-normalizer`'s README).
    const LONGEST_HAND_WRITTEN_LINE_MEASURED: usize = 2368;

    #[test]
    fn thresholds_are_ordered() {
        const _: () = assert!(MACHINE_MEAN_LINE_BYTES < MACHINE_LINE_BYTES);
        const _: () = assert!(MACHINE_LINE_BYTES > LONGEST_HAND_WRITTEN_LINE_MEASURED);
    }
}
