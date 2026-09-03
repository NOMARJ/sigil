//! Opt-in scan profiling: `SIGIL_TIMING=1`.
//!
//! A scan that takes 46 s on one package and 0.2 s on the next is not a
//! mystery worth guessing at. This module attributes the wall clock to the
//! stages of the per-file pipeline (read, normalise, decode worklist, each
//! regex phase, correlation) and records the slowest files with the shape
//! data — size, line count, longest line — that explains why they were slow.
//!
//! It is off unless `SIGIL_TIMING` is set to something other than `0`, and
//! when off the only cost is one already-resolved `OnceLock` read plus a
//! branch per measured region. Nothing is printed on stdout, ever: the report
//! goes to stderr so `--format json` stays machine-readable.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// A measured stage of the scan.
///
/// Ordered as the pipeline runs, which is also the order the report prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Walk,
    Provenance,
    Read,
    Invisible,
    Normalize,
    Markers,
    Derive,
    PhaseInstallHooks,
    PhaseCodePatterns,
    PhaseNetworkExfil,
    PhaseCredentials,
    PhaseObfuscation,
    PhasePromptInjection,
    PhaseSkillSecurity,
    PhaseInferenceSecurity,
    CloudSignatures,
    OversizedTail,
    Suppress,
    Correlate,
    KnownGood,
    Manifests,
}

impl Stage {
    /// Every stage, in pipeline order.
    pub const ALL: [Stage; 21] = [
        Stage::Walk,
        Stage::Provenance,
        Stage::Read,
        Stage::Invisible,
        Stage::Normalize,
        Stage::Markers,
        Stage::Derive,
        Stage::PhaseInstallHooks,
        Stage::PhaseCodePatterns,
        Stage::PhaseNetworkExfil,
        Stage::PhaseCredentials,
        Stage::PhaseObfuscation,
        Stage::PhasePromptInjection,
        Stage::PhaseSkillSecurity,
        Stage::PhaseInferenceSecurity,
        Stage::CloudSignatures,
        Stage::OversizedTail,
        Stage::Suppress,
        Stage::Correlate,
        Stage::KnownGood,
        Stage::Manifests,
    ];

    fn index(self) -> usize {
        Stage::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    fn label(self) -> &'static str {
        match self {
            Stage::Walk => "walk",
            Stage::Provenance => "provenance",
            Stage::Read => "read",
            Stage::Invisible => "invisible-unicode",
            Stage::Normalize => "normalize",
            Stage::Markers => "markers",
            Stage::Derive => "derive (decode worklist)",
            Stage::PhaseInstallHooks => "phase install_hooks",
            Stage::PhaseCodePatterns => "phase code_patterns",
            Stage::PhaseNetworkExfil => "phase network_exfil",
            Stage::PhaseCredentials => "phase credentials",
            Stage::PhaseObfuscation => "phase obfuscation",
            Stage::PhasePromptInjection => "phase prompt_injection",
            Stage::PhaseSkillSecurity => "phase skill_security",
            Stage::PhaseInferenceSecurity => "phase inference_security",
            Stage::CloudSignatures => "cloud signatures",
            Stage::OversizedTail => "oversized tail",
            Stage::Suppress => "suppress",
            Stage::Correlate => "correlate",
            Stage::KnownGood => "known-good",
            Stage::Manifests => "manifests",
        }
    }
}

/// What one file cost, and the shape facts that explain it.
#[derive(Debug, Clone)]
pub struct FileRecord {
    pub path: String,
    pub nanos: u64,
    pub bytes: usize,
    pub lines: usize,
    pub longest_line: usize,
    pub derived_units: usize,
    /// Whether the minified/bundled classifier claimed this file.
    pub bundled: bool,
    /// Whether the per-file budget ran out before the worklist drained.
    pub budget_exhausted: bool,
}

/// Accumulated timings for one scan.
pub struct Timing {
    stages: Vec<AtomicU64>,
    files: Mutex<Vec<FileRecord>>,
}

impl Timing {
    fn new() -> Self {
        Timing {
            stages: Stage::ALL.iter().map(|_| AtomicU64::new(0)).collect(),
            files: Mutex::new(Vec::new()),
        }
    }

    fn add(&self, stage: Stage, d: Duration) {
        self.stages[stage.index()].fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    }

    fn record_file(&self, rec: FileRecord) {
        if let Ok(mut files) = self.files.lock() {
            files.push(rec);
        }
    }
}

static TIMING: OnceLock<Option<Timing>> = OnceLock::new();

/// The active profiler, or `None` when `SIGIL_TIMING` is unset or `0`.
pub fn timing() -> Option<&'static Timing> {
    TIMING
        .get_or_init(|| match std::env::var("SIGIL_TIMING") {
            Ok(v) if v != "0" && !v.is_empty() => Some(Timing::new()),
            _ => None,
        })
        .as_ref()
}

/// Is profiling on? Callers use this to skip gathering shape data that is
/// only needed for the report.
pub fn enabled() -> bool {
    timing().is_some()
}

/// Time `f` against `stage`. When profiling is off this is `f()` plus a
/// branch — no clock is read.
pub fn measure<T>(stage: Stage, f: impl FnOnce() -> T) -> T {
    match timing() {
        Some(t) => {
            let start = Instant::now();
            let out = f();
            t.add(stage, start.elapsed());
            out
        }
        None => f(),
    }
}

/// Add an already-measured duration to a stage.
pub fn add(stage: Stage, d: Duration) {
    if let Some(t) = timing() {
        t.add(stage, d);
    }
}

/// Record one file's cost and shape. No-op when profiling is off.
pub fn record_file(rec: FileRecord) {
    if let Some(t) = timing() {
        t.record_file(rec);
    }
}

fn human(nanos: u64) -> String {
    let secs = nanos as f64 / 1e9;
    if secs >= 1.0 {
        format!("{secs:>8.3}s")
    } else {
        format!("{:>8.1}ms", nanos as f64 / 1e6)
    }
}

fn human_bytes(b: usize) -> String {
    if b >= 1 << 20 {
        format!("{:.1}MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1 << 10 {
        format!("{:.0}KB", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

/// Print the profile to stderr. Called once at the end of a scan; a no-op
/// when profiling is off.
pub fn report(files_scanned: usize, wall: Duration, slowest: usize) {
    let Some(t) = timing() else { return };

    eprintln!(
        "[sigil timing] {files_scanned} files, {:.3}s wall (stage totals below are summed across scan threads, so they exceed wall time)",
        wall.as_secs_f64()
    );
    let mut rows: Vec<(Stage, u64)> = Stage::ALL
        .iter()
        .map(|s| (*s, t.stages[s.index()].load(Ordering::Relaxed)))
        .filter(|(_, n)| *n > 0)
        .collect();
    rows.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let total: u64 = rows.iter().map(|(_, n)| *n).sum();
    for (stage, nanos) in &rows {
        let pct = if total > 0 {
            100.0 * *nanos as f64 / total as f64
        } else {
            0.0
        };
        eprintln!(
            "[sigil timing]   {:<26} {} {:>5.1}%",
            stage.label(),
            human(*nanos),
            pct
        );
    }

    let Ok(mut files) = t.files.lock() else {
        return;
    };
    files.sort_by_key(|f| std::cmp::Reverse(f.nanos));
    let shown = files.len().min(slowest);
    if shown > 0 {
        eprintln!("[sigil timing] slowest {shown} files:");
        for f in files.iter().take(shown) {
            eprintln!(
                "[sigil timing]   {} {:>8} {:>7} lines longest-line {:>9} derived {:>3}{}{}  {}",
                human(f.nanos),
                human_bytes(f.bytes),
                f.lines,
                f.longest_line,
                f.derived_units,
                if f.bundled { " bundled" } else { "" },
                if f.budget_exhausted { " BUDGET" } else { "" },
                f.path
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stage table must be total: `index()` is a position lookup, so a
    /// variant missing from `ALL` would silently share slot 0 with `Walk`.
    #[test]
    fn every_stage_has_a_distinct_slot() {
        let mut seen: Vec<usize> = Stage::ALL.iter().map(|s| s.index()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), Stage::ALL.len(), "duplicate or missing slot");
        assert_eq!(seen.first(), Some(&0));
        assert_eq!(seen.last(), Some(&(Stage::ALL.len() - 1)));
    }

    #[test]
    fn labels_are_unique() {
        let mut labels: Vec<&str> = Stage::ALL.iter().map(|s| s.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(before, labels.len(), "two stages share a label");
    }

    /// `measure` must return the closure's value whether or not profiling is
    /// on — the tests run without `SIGIL_TIMING`, so this covers the off path.
    #[test]
    fn measure_is_transparent() {
        assert_eq!(measure(Stage::Read, || 7), 7);
        record_file(FileRecord {
            path: "a.js".into(),
            nanos: 1,
            bytes: 2,
            lines: 1,
            longest_line: 2,
            derived_units: 0,
            bundled: false,
            budget_exhausted: false,
        });
    }
}
