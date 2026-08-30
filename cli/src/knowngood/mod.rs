//! Known-good corpus: recognise published code instead of re-judging it.
//!
//! See `docs/adr/ADR-0011-known-good-corpus.md`.
//!
//! Sigil judges every file solely by whether its text matches a malicious
//! pattern, with no notion of code it already knows to be fine. That produces
//! two problems this module addresses.
//!
//! First, the false-positive rate is structural: clean packages are mostly
//! *well-known* code — bundled runtimes, vendored libraries, minified
//! dependencies — and re-litigating all of it every scan is where the measured
//! 70% clean-set FP rate comes from. Recognising a file as published-unmodified
//! removes that noise at the root rather than describing it with ever more
//! suppression predicates.
//!
//! Second, and more importantly, a copy of a popular library with three lines
//! changed is the `event-stream` / `ua-parser-js` shape, and Sigil cannot
//! currently see it at any severity. The trust ledger (ADR-0006) detects drift
//! from what *this user* approved; nothing detects "this claims to be lodash
//! 4.17.21 and is not".
//!
//! Ghidra splits the equivalent problem in two: Function ID stores exact
//! hashes of known library functions, and BSim handles the fuzzy "modified
//! copy" case with normalised feature vectors. The tiers answer different
//! questions and need different indexes. Tier 1 (exact) is implemented here;
//! tier 2 (fuzzy) is specified in the ADR and the on-disk format reserves a
//! field for it.
//!
//! **The corpus can explain code, never excuse it.** A file that is simply
//! unknown is scanned and reported normally — absence must not fail open into
//! false confidence. And because an index that can suppress findings is a
//! trust input, it is signature-verified on the same policy as signature packs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One published file, as released.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownFile {
    /// Path within the package, e.g. `package/dist/index.js`.
    pub path: String,
    /// SHA-256 of the file as published (tier 1, exact).
    pub sha256: String,
    /// Normalised hash for tier 2 (fuzzy). Reserved; see ADR-0011.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized: Option<String>,
}

/// One published release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownRelease {
    /// `npm`, `pypi`, …
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub files: Vec<KnownFile>,
}

impl KnownRelease {
    pub fn coordinate(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

/// An installed known-good index file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownGoodIndex {
    #[serde(default = "default_format")]
    pub format: String,
    pub releases: Vec<KnownRelease>,
}

fn default_format() -> String {
    "sigil-known-good/v1".to_string()
}

/// What a lookup found for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// Byte-identical to this file in this published release.
    Exact { coordinate: String, path: String },
    /// Nothing known about this content.
    Unknown,
}

/// The loaded index, keyed for lookup.
#[derive(Debug, Default)]
pub struct KnownGood {
    /// sha256 -> (coordinate, path within the release)
    by_hash: HashMap<String, (String, String)>,
    /// coordinate -> every file in that release, for drift detection
    by_release: HashMap<String, Vec<KnownFile>>,
    releases: usize,
    files: usize,
}

impl KnownGood {
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn release_count(&self) -> usize {
        self.releases
    }

    pub fn file_count(&self) -> usize {
        self.files
    }

    pub fn from_indexes(indexes: Vec<KnownGoodIndex>) -> Self {
        let mut kg = KnownGood::default();
        for index in indexes {
            for release in index.releases {
                let coord = release.coordinate();
                for file in &release.files {
                    kg.by_hash
                        .entry(file.sha256.clone())
                        .or_insert_with(|| (coord.clone(), file.path.clone()));
                    kg.files += 1;
                }
                kg.by_release.insert(coord, release.files);
                kg.releases += 1;
            }
        }
        kg
    }

    /// Look up file content.
    pub fn lookup(&self, contents: &[u8]) -> Match {
        match self.by_hash.get(&hash_bytes(contents)) {
            Some((coordinate, path)) => Match::Exact {
                coordinate: coordinate.clone(),
                path: path.clone(),
            },
            None => Match::Unknown,
        }
    }

    /// Does this release exist in the index at all?
    ///
    /// Part of the index query surface, exercised by the tests; drift
    /// detection reaches for `release_paths` instead.
    #[allow(dead_code)]
    pub fn knows_release(&self, coordinate: &str) -> bool {
        self.by_release.contains_key(coordinate)
    }

    /// How many files the index holds for a release.
    #[allow(dead_code)]
    pub fn release_file_count(&self, coordinate: &str) -> usize {
        self.by_release
            .get(coordinate)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// The paths a release is published with.
    ///
    /// Drift detection needs these: a file is evidence of tampering when the
    /// release *is supposed to contain* that path and the bytes on disk are
    /// not the published bytes. Checking against the release's own manifest
    /// avoids flagging unrelated files that merely sit nearby.
    pub fn release_paths(&self, coordinate: &str) -> Vec<&str> {
        self.by_release
            .get(coordinate)
            .map(|files| files.iter().map(|f| f.path.as_str()).collect())
            .unwrap_or_default()
    }
}

/// Hex SHA-256 of some bytes.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Returns `~/.sigil/known-good/`.
pub fn known_good_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sigil").join("known-good"))
}

/// Load every installed index.
///
/// Indexes are signature-verified on the same policy as signature packs
/// (`SIGIL_PACK_PUBLIC_KEY`): an index that can suppress findings is a trust
/// input, and a tampered one is a way to hide real findings. Verification
/// failure is fatal for the same reason it is fatal for packs.
pub fn load_installed() -> Result<KnownGood, String> {
    let Some(dir) = known_good_dir() else {
        return Ok(KnownGood::default());
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(KnownGood::default()), // absent is normal
    };

    let mut indexes = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[known-good] skipping {}: {e}", path.display());
                continue;
            }
        };
        if let Err(e) = crate::corpus::loader::verify_pack_if_keyed(&raw) {
            eprintln!("[known-good] {}: {e}", path.display());
            return Err(e);
        }
        match serde_json::from_str::<KnownGoodIndex>(&raw) {
            Ok(index) => indexes.push(index),
            Err(e) => eprintln!("[known-good] skipping {}: parse error: {e}", path.display()),
        }
    }

    Ok(KnownGood::from_indexes(indexes))
}

/// Build an index by hashing a directory tree.
///
/// This is how an index is produced today. Populating a corpus across all of
/// npm and PyPI is separate infrastructure (ADR-0011) and deliberately out of
/// scope here; the mechanism is complete and usable without it.
pub fn build_index(
    root: &Path,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<KnownGoodIndex, String> {
    let mut files = Vec::new();
    let walker = walkdir::WalkDir::new(root).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        files.push(KnownFile {
            path: rel,
            sha256: hash_bytes(&bytes),
            normalized: None,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(KnownGoodIndex {
        format: default_format(),
        releases: vec![KnownRelease {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            files,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> KnownGoodIndex {
        KnownGoodIndex {
            format: default_format(),
            releases: vec![KnownRelease {
                ecosystem: "npm".to_string(),
                name: "leftpad".to_string(),
                version: "1.3.0".to_string(),
                files: vec![
                    KnownFile {
                        path: "package/index.js".to_string(),
                        sha256: hash_bytes(b"module.exports = leftpad;\n"),
                        normalized: None,
                    },
                    KnownFile {
                        path: "package/README.md".to_string(),
                        sha256: hash_bytes(b"# leftpad\n"),
                        normalized: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn recognises_published_content() {
        let kg = KnownGood::from_indexes(vec![index()]);
        assert_eq!(
            kg.lookup(b"module.exports = leftpad;\n"),
            Match::Exact {
                coordinate: "npm:leftpad@1.3.0".to_string(),
                path: "package/index.js".to_string(),
            }
        );
    }

    /// One changed byte must not match. This is the property the whole
    /// trojanised-dependency detection rests on.
    #[test]
    fn a_single_changed_byte_is_not_a_match() {
        let kg = KnownGood::from_indexes(vec![index()]);
        assert_eq!(kg.lookup(b"module.exports = leftpad;;\n"), Match::Unknown);
        assert_eq!(kg.lookup(b"module.exports = evil;\n"), Match::Unknown);
    }

    #[test]
    fn unknown_content_is_unknown_not_an_error() {
        let kg = KnownGood::from_indexes(vec![index()]);
        assert_eq!(kg.lookup(b"something entirely new"), Match::Unknown);
    }

    /// Absence must not fail open: an empty corpus recognises nothing, so
    /// everything is scanned and reported normally.
    #[test]
    fn empty_corpus_recognises_nothing() {
        let kg = KnownGood::default();
        assert!(kg.is_empty());
        assert_eq!(kg.lookup(b"module.exports = leftpad;\n"), Match::Unknown);
    }

    #[test]
    fn counts_releases_and_files() {
        let kg = KnownGood::from_indexes(vec![index()]);
        assert_eq!(kg.release_count(), 1);
        assert_eq!(kg.file_count(), 2);
        assert!(kg.knows_release("npm:leftpad@1.3.0"));
        assert_eq!(kg.release_file_count("npm:leftpad@1.3.0"), 2);
        assert!(!kg.knows_release("npm:leftpad@9.9.9"));
    }

    #[test]
    fn builds_an_index_from_a_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("package")).unwrap();
        std::fs::write(
            dir.path().join("package/index.js"),
            b"module.exports = 1;\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("package/util.js"), b"module.exports = 2;\n").unwrap();

        let idx = build_index(dir.path(), "npm", "demo", "1.0.0").expect("build");
        assert_eq!(idx.releases.len(), 1);
        assert_eq!(idx.releases[0].files.len(), 2);
        // Paths are relative, forward-slashed and sorted for a stable index.
        assert_eq!(idx.releases[0].files[0].path, "package/index.js");
        assert_eq!(idx.releases[0].files[1].path, "package/util.js");

        // The built index recognises exactly the content it was built from.
        let kg = KnownGood::from_indexes(vec![idx]);
        assert!(matches!(
            kg.lookup(b"module.exports = 1;\n"),
            Match::Exact { .. }
        ));
        assert_eq!(kg.lookup(b"module.exports = 3;\n"), Match::Unknown);
    }

    #[test]
    fn index_round_trips_through_json() {
        let idx = index();
        let json = serde_json::to_string(&idx).expect("serialize");
        let back: KnownGoodIndex = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.releases.len(), 1);
        assert_eq!(back.releases[0].files.len(), 2);
        assert_eq!(back.format, "sigil-known-good/v1");
    }
}
