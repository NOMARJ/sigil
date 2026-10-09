//! PEP 440 versions and version specifiers, as far as `sigil pip` needs
//! them: to pick, from the versions an index lists, the release that
//! `pip install <spec>` would pick. The rules are those of `packaging`
//! (which pip vendors): its version grammar, ordering, specifier operators
//! and the way a specifier set lets pre-releases in.

use std::cmp::Ordering;
use std::sync::OnceLock;

use regex::Regex;

/// `packaging.version.VERSION_PATTERN`, anchored, case-insensitive.
const VERSION_PATTERN: &str = r"(?ix)^\s*
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?P<pre>
            [-_\.]?
            (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [-_\.]?
                (?P<post_l>post|rev|r)
                [-_\.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?P<dev>
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
    \s*$";

fn version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(VERSION_PATTERN).expect("valid version pattern"))
}

/// A pre-release kind, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Pre {
    A,
    B,
    Rc,
}

/// One segment of a local version label: numbers sort above letters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Local {
    Str(String),
    Num(u64),
}

/// A sort key part that may be below or above every value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Bound<T> {
    Below,
    Is(T),
    Above,
}

/// A parsed PEP 440 version.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(Pre, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<Local>>,
}

fn num(s: Option<regex::Match<'_>>) -> Option<u64> {
    match s {
        Some(m) => m.as_str().parse().ok(),
        None => Some(0),
    }
}

impl Version {
    /// Parse a version as `packaging.version.Version` does; `None` when it
    /// is not one (or a number does not fit in 64 bits).
    pub fn parse(s: &str) -> Option<Version> {
        let c = version_re().captures(s)?;
        let epoch = match c.name("epoch") {
            Some(m) => m.as_str().parse().ok()?,
            None => 0,
        };
        let release = c
            .name("release")?
            .as_str()
            .split('.')
            .map(|p| p.parse().ok())
            .collect::<Option<Vec<u64>>>()?;
        let pre = match c.name("pre_l") {
            Some(l) => {
                let kind = match l.as_str().to_ascii_lowercase().as_str() {
                    "a" | "alpha" => Pre::A,
                    "b" | "beta" => Pre::B,
                    _ => Pre::Rc,
                };
                Some((kind, num(c.name("pre_n"))?))
            }
            None => None,
        };
        let post = if let Some(n) = c.name("post_n1") {
            Some(n.as_str().parse().ok()?)
        } else if c.name("post_l").is_some() {
            Some(num(c.name("post_n2"))?)
        } else {
            None
        };
        let dev = match c.name("dev_l") {
            Some(_) => Some(num(c.name("dev_n"))?),
            None => None,
        };
        let local = c.name("local").map(|m| {
            m.as_str()
                .split(['-', '_', '.'])
                .map(|seg| match seg.parse::<u64>() {
                    Ok(n) if seg.bytes().all(|b| b.is_ascii_digit()) => Local::Num(n),
                    _ => Local::Str(seg.to_ascii_lowercase()),
                })
                .collect()
        });
        Some(Version {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// A pre-release or a development release.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    fn is_postrelease(&self) -> bool {
        self.post.is_some()
    }

    /// The version without its local label.
    fn public(&self) -> Version {
        Version {
            local: None,
            ..self.clone()
        }
    }

    /// Epoch and release only.
    fn base(&self) -> Version {
        Version {
            epoch: self.epoch,
            release: self.release.clone(),
            pre: None,
            post: None,
            dev: None,
            local: None,
        }
    }

    /// `packaging`'s `_cmpkey`.
    #[allow(clippy::type_complexity)]
    fn key(
        &self,
    ) -> (
        u64,
        &[u64],
        Bound<(Pre, u64)>,
        Bound<u64>,
        Bound<u64>,
        Bound<&[Local]>,
    ) {
        let mut n = self.release.len();
        while n > 0 && self.release[n - 1] == 0 {
            n -= 1;
        }
        let pre = match (self.pre, self.post, self.dev) {
            (None, None, Some(_)) => Bound::Below,
            (None, _, _) => Bound::Above,
            (Some(p), _, _) => Bound::Is(p),
        };
        let post = self.post.map_or(Bound::Below, Bound::Is);
        let dev = self.dev.map_or(Bound::Above, Bound::Is);
        let local = self.local.as_deref().map_or(Bound::Below, Bound::Is);
        (self.epoch, &self.release[..n], pre, post, dev, local)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// One version specifier (`>=2.0`, `==1.4.*`, `~=1.2`, ...).
#[derive(Debug, Clone)]
pub struct Specifier {
    op: String,
    version: String,
}

impl Specifier {
    /// A specifier from its operator and version text; `None` when the
    /// version does not parse for that operator.
    pub fn new(op: &str, version: &str) -> Option<Specifier> {
        let version = version.trim();
        match op {
            "===" => {}
            "==" | "!=" => {
                let v = version.strip_suffix(".*").unwrap_or(version);
                let parsed = Version::parse(v)?;
                // A prefix match is on a release (`==1.4.*`), with no
                // pre/post/dev part and no local label.
                if v.len() != version.len()
                    && (parsed.pre.is_some()
                        || parsed.post.is_some()
                        || parsed.dev.is_some()
                        || parsed.local.is_some())
                {
                    return None;
                }
            }
            "~=" => {
                let parsed = Version::parse(version)?;
                if parsed.release.len() < 2 || parsed.local.is_some() {
                    return None;
                }
            }
            "<=" | ">=" | "<" | ">" => {
                Version::parse(version)?;
            }
            _ => return None,
        }
        Some(Specifier {
            op: op.to_string(),
            version: version.to_string(),
        })
    }

    /// Pins one version: `==` without a wildcard, or `===`.
    pub fn pins(&self) -> bool {
        self.op == "===" || (self.op == "==" && !self.version.ends_with(".*"))
    }

    /// `Specifier.prereleases`: an inclusive operator naming a pre-release
    /// lets pre-releases in.
    fn allows_prereleases(&self) -> bool {
        matches!(self.op.as_str(), "==" | ">=" | "<=" | "~=" | "===")
            && Version::parse(self.version.strip_suffix(".*").unwrap_or(&self.version))
                .is_some_and(|v| v.is_prerelease())
    }

    fn spec_version(&self) -> Version {
        Version::parse(self.version.strip_suffix(".*").unwrap_or(&self.version))
            .expect("checked in Specifier::new")
    }

    /// `Specifier.contains(v, prereleases)`. `raw` is the text `v` was
    /// parsed from (`===` compares text).
    fn contains(&self, v: &Version, raw: &str, prereleases: bool) -> bool {
        if v.is_prerelease() && !prereleases {
            return false;
        }
        match self.op.as_str() {
            "===" => raw.trim().eq_ignore_ascii_case(&self.version),
            "==" => self.equal(v),
            "!=" => !self.equal(v),
            "<=" => v.public() <= self.spec_version(),
            ">=" => v.public() >= self.spec_version(),
            "<" => {
                let s = self.spec_version();
                if *v >= s {
                    return false;
                }
                // `<3.1` does not match 3.1.dev0 unless it names a
                // pre-release itself.
                !(!s.is_prerelease() && v.is_prerelease() && v.base() == s.base())
            }
            ">" => {
                let s = self.spec_version();
                if *v <= s {
                    return false;
                }
                // `>3.1` matches neither 3.1.post1 (unless it names a
                // post-release) nor a local version of 3.1.
                if !s.is_postrelease() && v.is_postrelease() && v.base() == s.base() {
                    return false;
                }
                !(v.local.is_some() && v.base() == s.base())
            }
            "~=" => {
                let s = self.spec_version();
                if v.public() < s {
                    return false;
                }
                let prefix = &s.release[..s.release.len() - 1];
                v.epoch == s.epoch && padded_starts_with(&v.release, prefix)
            }
            _ => false,
        }
    }

    fn equal(&self, v: &Version) -> bool {
        if let Some(prefix) = self.version.strip_suffix(".*") {
            let s = Version::parse(prefix).expect("checked in Specifier::new");
            return v.epoch == s.epoch && padded_starts_with(&v.release, &s.release);
        }
        let s = self.spec_version();
        if s.local.is_none() {
            v.public() == s
        } else {
            *v == s
        }
    }
}

/// `release`, padded with zeros to the length of `prefix`, starts with it.
fn padded_starts_with(release: &[u64], prefix: &[u64]) -> bool {
    prefix
        .iter()
        .enumerate()
        .all(|(i, p)| release.get(i).copied().unwrap_or(0) == *p)
}

/// The version `pip install` picks among `available` for a requirement with
/// these specifiers: the highest that matches, with pre-releases in only
/// when `allow_prereleases` (pip's `--pre`), when a specifier names one, or,
/// with no specifier at all, when there is nothing else. Versions that do
/// not parse are skipped, as pip skips them.
pub fn best_match<'a>(
    available: &'a [String],
    specifiers: &[Specifier],
    allow_prereleases: bool,
) -> Option<&'a str> {
    let parsed: Vec<(Version, &str)> = available
        .iter()
        .filter_map(|s| Version::parse(s).map(|v| (v, s.as_str())))
        .collect();
    let candidates: Vec<&(Version, &str)> = if specifiers.is_empty() {
        let finals: Vec<_> = parsed
            .iter()
            .filter(|(v, _)| allow_prereleases || !v.is_prerelease())
            .collect();
        if finals.is_empty() {
            parsed.iter().collect()
        } else {
            finals
        }
    } else {
        let pre = allow_prereleases || specifiers.iter().any(Specifier::allows_prereleases);
        parsed
            .iter()
            .filter(|(v, raw)| specifiers.iter().all(|s| s.contains(v, raw, pre)))
            .collect()
    };
    candidates
        .into_iter()
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, raw)| *raw)
}

#[cfg(test)]
#[path = "pep440_tests.rs"]
mod tests;
