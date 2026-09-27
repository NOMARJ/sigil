//! Per-file wall-clock budget.
//!
//! Analysis of one file is not bounded by the file's size. The decode worklist
//! (`scanner::derive`) turns encoded content into more content to scan, and a
//! single machine-generated line can be megabytes long, so one pathological
//! file can hold a whole scan hostage. A scanner that hangs on one input is a
//! denial of service against the person running it, and — worse — a scan that
//! is quietly abandoned looks exactly like a scan that found nothing.
//!
//! So the budget does two things, and the second matters more than the first:
//!
//! 1. it stops the pipeline for that file once the clock runs out, keeping
//!    every finding made before that point; and
//! 2. it makes the truncation **visible**, as a Low Provenance finding
//!    ([`BUDGET_RULE_ID`]) naming the file, so a reviewer can see that the
//!    file was not fully analysed rather than inferring a clean result.
//!
//! The default is [`DEFAULT_FILE_BUDGET_SECS`]; `SIGIL_FILE_BUDGET_SECS`
//! overrides it, and `0` turns the budget off entirely for a deliberately
//! exhaustive run.

use std::time::{Duration, Instant};

/// Wall-clock seconds one file may spend in the content pipeline before the
/// remaining work is dropped.
///
/// Chosen against measurement, not taste. The slowest single file in the
/// 268-package evaluation subset is `@antv/gi-assets-scene`'s 5.3 MB
/// `dist/index.min.js` at 2.33 s; nothing else comes close. 30 s leaves an
/// order of magnitude of headroom over that, which is the point: this is a
/// safety valve against a worklist that will not terminate, not a throttle on
/// ordinary scanning. A tighter bound was tried first and rejected — at 2 s it
/// truncated that real package and cost it a High finding, which is precisely
/// the kind of silent detection loss a budget must not introduce.
pub const DEFAULT_FILE_BUDGET_SECS: f64 = 30.0;

/// Environment variable that overrides [`DEFAULT_FILE_BUDGET_SECS`]. `0`
/// disables the budget.
pub const BUDGET_ENV: &str = "SIGIL_FILE_BUDGET_SECS";

/// Rule id for the finding that records a truncated file.
pub const BUDGET_RULE_ID: &str = "PROV-BUDGET-001";

/// Read the configured per-file budget.
///
/// An unparseable or negative value falls back to the default rather than
/// silently disabling the budget: a typo in an environment variable must not
/// quietly remove a bound.
pub fn configured_budget() -> Option<Duration> {
    let secs = match std::env::var(BUDGET_ENV) {
        Ok(v) => v.trim().parse::<f64>().ok().filter(|s| *s >= 0.0),
        Err(_) => None,
    }
    .unwrap_or(DEFAULT_FILE_BUDGET_SECS);
    if secs <= 0.0 {
        None
    } else {
        Some(Duration::from_secs_f64(secs))
    }
}

/// A deadline for the analysis of one file.
#[derive(Debug, Clone, Copy)]
pub struct FileBudget {
    deadline: Option<Instant>,
}

impl FileBudget {
    /// Start a budget running now. `None` means no bound.
    pub fn start(limit: Option<Duration>) -> Self {
        FileBudget {
            deadline: limit.map(|d| Instant::now() + d),
        }
    }

    /// A budget that never expires — used by callers that scan a single small
    /// string, and by the tests.
    pub fn unbounded() -> Self {
        FileBudget { deadline: None }
    }

    /// A budget that is already spent, for testing the truncation path.
    #[cfg(test)]
    pub fn spent() -> Self {
        FileBudget {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
        }
    }

    /// Has the clock run out?
    pub fn expired(&self) -> bool {
        match self.deadline {
            Some(d) => Instant::now() >= d,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbounded_never_expires() {
        assert!(!FileBudget::unbounded().expired());
    }

    #[test]
    fn a_spent_budget_reports_expired() {
        assert!(FileBudget::spent().expired());
    }

    #[test]
    fn a_fresh_budget_has_time_left() {
        let b = FileBudget::start(Some(Duration::from_secs(30)));
        assert!(!b.expired());
    }

    #[test]
    fn a_zero_budget_is_immediately_expired() {
        let b = FileBudget::start(Some(Duration::from_nanos(0)));
        assert!(b.expired());
    }
}
