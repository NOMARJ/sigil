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
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One published file, as released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
///
/// `source_url` and `archive_sha256` are optional and additive: an index
/// written before they existed still parses. They exist so the provenance of
/// every hash in the index is auditable — an index is a *trust* input, and
/// "trust these 75,905 hashes" is only reviewable if each release says which
/// archive it was hashed from and what that archive's digest was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownRelease {
    /// `npm`, `pypi`, …
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Registry URL of the archive these hashes were taken from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// SHA-256 of that archive, as the registry published it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_sha256: Option<String>,
    pub files: Vec<KnownFile>,
}

impl KnownRelease {
    pub fn coordinate(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

/// The only on-disk format this build reads or writes.
pub const INDEX_FORMAT: &str = "sigil-known-good/v1";

/// An installed known-good index file.
///
/// One file holds any number of releases, so a corpus of hundreds of packages
/// is one index rather than hundreds of files. `name` and `generated` are
/// additive metadata describing the index as a whole: which corpus this is and
/// when it was built, so an operator looking at `~/.sigil/known-good/` can tell
/// what they installed without reading 11 MB of hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownGoodIndex {
    #[serde(default = "default_format")]
    pub format: String,
    /// Corpus name, e.g. `top-packages-2026-09`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When the index was built, as a date or RFC 3339 timestamp. Supplied by
    /// the builder rather than read from the clock, so rebuilding the same
    /// inputs produces the same bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<String>,
    pub releases: Vec<KnownRelease>,
}

fn default_format() -> String {
    INDEX_FORMAT.to_string()
}

/// What an index holds, for the operator-facing commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexStats {
    pub releases: usize,
    pub files: usize,
    /// Sorted, deduplicated ecosystems present in the index.
    pub ecosystems: Vec<String>,
}

/// Where a release's bytes came from.
#[derive(Debug, Clone, Default)]
pub struct ReleaseSource {
    pub url: Option<String>,
    pub archive_sha256: Option<String>,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl KnownGoodIndex {
    /// Reject anything that is not a well-formed index.
    ///
    /// This runs before an index is installed, because installing is the point
    /// at which a file gains the power to suppress findings. Everything checked
    /// here is a property that, if violated, would make the index silently
    /// useless or ambiguous rather than loudly broken: a lookup table keyed on
    /// lowercase hex can never match an uppercase digest, and two entries for
    /// the same coordinate leave "what does this release contain" undefined.
    pub fn validate(&self) -> Result<IndexStats, String> {
        if self.format != INDEX_FORMAT {
            return Err(format!(
                "unsupported format {:?} (expected {INDEX_FORMAT})",
                self.format
            ));
        }
        if self.releases.is_empty() {
            return Err("index contains no releases".to_string());
        }

        let mut files = 0usize;
        let mut ecosystems: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for release in &self.releases {
            if release.ecosystem.trim().is_empty()
                || release.name.trim().is_empty()
                || release.version.trim().is_empty()
            {
                return Err(format!(
                    "release {:?} is missing ecosystem, name or version",
                    release.coordinate()
                ));
            }
            let coord = release.coordinate();
            if !seen.insert(coord.clone()) {
                return Err(format!("duplicate release {coord}"));
            }
            if release.files.is_empty() {
                return Err(format!("release {coord} indexes no files"));
            }
            if let Some(sha) = &release.archive_sha256 {
                if !is_sha256_hex(sha) {
                    return Err(format!("release {coord}: archive_sha256 is not a SHA-256"));
                }
            }
            for file in &release.files {
                if file.path.is_empty() {
                    return Err(format!("release {coord}: empty file path"));
                }
                let p = Path::new(&file.path);
                if p.is_absolute()
                    || p.components()
                        .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
                {
                    return Err(format!(
                        "release {coord}: file path {:?} escapes the release root",
                        file.path
                    ));
                }
                if !is_sha256_hex(&file.sha256) {
                    return Err(format!(
                        "release {coord}: {:?} has a malformed sha256",
                        file.path
                    ));
                }
                files += 1;
            }
            if !ecosystems.contains(&release.ecosystem) {
                ecosystems.push(release.ecosystem.clone());
            }
        }
        ecosystems.sort();

        Ok(IndexStats {
            releases: self.releases.len(),
            files,
            ecosystems,
        })
    }
}

/// Combine per-release indexes into one.
///
/// The schema already holds any number of releases in a single file, so a
/// merge is a concatenation with two rules that keep the result unambiguous:
/// a coordinate that appears twice with identical contents collapses to one
/// entry, and a coordinate that appears twice with *different* contents is an
/// error rather than a silent last-writer-wins. Releases are sorted so that
/// merging the same inputs always produces the same bytes.
pub fn merge_indexes(
    indexes: Vec<KnownGoodIndex>,
    name: Option<String>,
    generated: Option<String>,
) -> Result<KnownGoodIndex, String> {
    let mut releases: Vec<KnownRelease> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();

    for index in indexes {
        if index.format != INDEX_FORMAT {
            return Err(format!(
                "unsupported format {:?} (expected {INDEX_FORMAT})",
                index.format
            ));
        }
        for release in index.releases {
            let coord = release.coordinate();
            match seen.get(&coord) {
                Some(&i) => {
                    if releases[i] != release {
                        return Err(format!(
                            "conflicting definitions of {coord}: the same release cannot be \
                             indexed twice with different contents"
                        ));
                    }
                }
                None => {
                    seen.insert(coord, releases.len());
                    releases.push(release);
                }
            }
        }
    }

    releases.sort_by(|a, b| {
        (&a.ecosystem, &a.name, &a.version).cmp(&(&b.ecosystem, &b.name, &b.version))
    });

    Ok(KnownGoodIndex {
        format: INDEX_FORMAT.to_string(),
        name,
        generated,
        releases,
    })
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

/// Install an index into `~/.sigil/known-good/`.
///
/// Validation happens *here*, at the moment a file gains the power to suppress
/// findings, rather than at load time where a malformed index would only be
/// skipped with a warning on every subsequent scan.
///
/// The file is copied byte-for-byte rather than re-serialised, so a
/// `meta.signature` survives installation: re-encoding would change the signed
/// bytes and turn a correctly signed index into a verification failure.
/// Signature policy is unchanged from load time — the same
/// `SIGIL_PACK_PUBLIC_KEY` check runs here, so an index that would be rejected
/// at scan time is refused now instead of breaking every later scan.
pub fn install_index(src: &Path) -> Result<(PathBuf, IndexStats), String> {
    let raw = std::fs::read_to_string(src).map_err(|e| format!("{}: {e}", src.display()))?;

    crate::corpus::loader::verify_pack_if_keyed(&raw)?;

    let index: KnownGoodIndex = serde_json::from_str(&raw)
        .map_err(|e| format!("{}: not a known-good index: {e}", src.display()))?;
    let stats = index
        .validate()
        .map_err(|e| format!("{}: {e}", src.display()))?;

    // `load_installed` only reads `*.json`; installing anything else would
    // succeed and then be silently ignored.
    let file_name = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{}: cannot determine a file name", src.display()))?;
    if !file_name.ends_with(".json") {
        return Err(format!(
            "{file_name}: index file name must end in .json (installed indexes are loaded by extension)"
        ));
    }

    let dir = known_good_dir().ok_or_else(|| "cannot determine home directory".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let dest = dir.join(file_name);
    std::fs::write(&dest, raw.as_bytes()).map_err(|e| format!("{}: {e}", dest.display()))?;

    Ok((dest, stats))
}

/// Remove an installed index by file name.
///
/// Deleting the file by hand is equally supported — the directory is plain
/// JSON on disk with no side state. This exists so that removal is scoped: it
/// only ever touches `~/.sigil/known-good/`, and a name with a path separator
/// or a `..` is refused rather than resolved.
pub fn remove_index(file_name: &str) -> Result<PathBuf, String> {
    let mut components = Path::new(file_name).components();
    let single_segment =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !single_segment {
        return Err(format!(
            "{file_name:?} is not a plain file name in the known-good directory"
        ));
    }

    let dir = known_good_dir().ok_or_else(|| "cannot determine home directory".to_string())?;
    let target = dir.join(file_name);
    if !target.is_file() {
        return Err(format!("{} is not installed", target.display()));
    }
    std::fs::remove_file(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    Ok(target)
}

/// One index file on disk, as `status` reports it.
#[derive(Debug, Clone)]
pub struct InstalledIndex {
    pub path: PathBuf,
    pub bytes: u64,
    pub name: Option<String>,
    pub generated: Option<String>,
    /// `Err` for a file that is present but unusable, so `status` can say so
    /// rather than quietly under-reporting the corpus.
    pub stats: Result<IndexStats, String>,
}

/// List the index files in `~/.sigil/known-good/`.
pub fn list_installed() -> Vec<InstalledIndex> {
    let Some(dir) = known_good_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<InstalledIndex> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .map(|path| {
            let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let parsed = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|raw| {
                    serde_json::from_str::<KnownGoodIndex>(&raw).map_err(|e| e.to_string())
                });
            match parsed {
                Ok(index) => InstalledIndex {
                    bytes,
                    name: index.name.clone(),
                    generated: index.generated.clone(),
                    stats: index.validate(),
                    path,
                },
                Err(e) => InstalledIndex {
                    path,
                    bytes,
                    name: None,
                    generated: None,
                    stats: Err(e),
                },
            }
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Build an index by hashing a directory tree.
///
/// `root` is the archive root, so recorded paths are the paths *inside the
/// published archive* (`package/index.js` for an npm tarball,
/// `requests-2.34.2/requests/api.py` for a PyPI sdist). Drift detection anchors
/// a release by stripping its indexed path from the scanned path, so recording
/// archive-internal paths is what lets a vendored copy be located anywhere in a
/// tree and still be recognised.
pub fn build_index(
    root: &Path,
    ecosystem: &str,
    name: &str,
    version: &str,
    source: &ReleaseSource,
) -> Result<KnownGoodIndex, String> {
    let mut files = Vec::new();
    let walker = walkdir::WalkDir::new(root).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(path);

        // Skip what lives *inside* a `.git` directory — a local repository is
        // not published content. A regular file *named* `.git` is a submodule
        // gitlink and is published, so it must be indexed: the scanner reads
        // it and reports on it, and anything the scanner sees but the index
        // does not is noise the corpus cannot explain. Only the path relative
        // to the release root matters; where the build tree happens to sit is
        // not part of the release.
        if rel
            .parent()
            .is_some_and(|p| p.components().any(|c| c.as_os_str() == ".git"))
        {
            continue;
        }

        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        files.push(KnownFile {
            path: rel.to_string_lossy().replace('\\', "/"),
            sha256: hash_bytes(&bytes),
            normalized: None,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(KnownGoodIndex {
        format: default_format(),
        name: None,
        generated: None,
        releases: vec![KnownRelease {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source_url: source.url.clone(),
            archive_sha256: source.archive_sha256.clone(),
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
            name: None,
            generated: None,
            releases: vec![KnownRelease {
                ecosystem: "npm".to_string(),
                name: "leftpad".to_string(),
                version: "1.3.0".to_string(),
                source_url: Some("https://registry.npmjs.org/leftpad/-/leftpad-1.3.0.tgz".into()),
                archive_sha256: Some(hash_bytes(b"tarball")),
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

    fn other_index() -> KnownGoodIndex {
        KnownGoodIndex {
            format: default_format(),
            name: None,
            generated: None,
            releases: vec![KnownRelease {
                ecosystem: "pypi".to_string(),
                name: "six".to_string(),
                version: "1.17.0".to_string(),
                source_url: None,
                archive_sha256: None,
                files: vec![KnownFile {
                    path: "six-1.17.0/six.py".to_string(),
                    sha256: hash_bytes(b"__version__ = '1.17.0'\n"),
                    normalized: None,
                }],
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

        let idx = build_index(
            dir.path(),
            "npm",
            "demo",
            "1.0.0",
            &ReleaseSource::default(),
        )
        .expect("build");
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

    // ---- merge -------------------------------------------------------

    /// The schema holds any number of releases in one file, so merging is a
    /// concatenation. What has to be true afterwards is that every release
    /// survives and the result still validates.
    #[test]
    fn merge_combines_releases_and_round_trips() {
        let merged = merge_indexes(
            vec![index(), other_index()],
            Some("top-packages-test".to_string()),
            Some("2026-09-03".to_string()),
        )
        .expect("merge");

        let stats = merged.validate().expect("merged index must validate");
        assert_eq!(stats.releases, 2);
        assert_eq!(stats.files, 3);
        assert_eq!(
            stats.ecosystems,
            vec!["npm".to_string(), "pypi".to_string()]
        );

        let json = serde_json::to_string(&merged).expect("serialize");
        let back: KnownGoodIndex = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name.as_deref(), Some("top-packages-test"));
        assert_eq!(back.generated.as_deref(), Some("2026-09-03"));
        assert_eq!(back.validate().expect("round-tripped index"), stats);

        // Provenance survives the round trip: without it the hashes are
        // unauditable.
        let npm = back
            .releases
            .iter()
            .find(|r| r.ecosystem == "npm")
            .expect("npm release");
        assert_eq!(
            npm.source_url.as_deref(),
            Some("https://registry.npmjs.org/leftpad/-/leftpad-1.3.0.tgz")
        );
        assert!(npm.archive_sha256.is_some());

        // And a merged index recognises content from either input.
        let kg = KnownGood::from_indexes(vec![back]);
        assert!(matches!(
            kg.lookup(b"module.exports = leftpad;\n"),
            Match::Exact { .. }
        ));
        assert!(matches!(
            kg.lookup(b"__version__ = '1.17.0'\n"),
            Match::Exact { .. }
        ));
    }

    /// Merging is order-independent and idempotent, so rebuilding an index
    /// from the same inputs produces the same bytes.
    #[test]
    fn merge_is_deterministic_and_idempotent() {
        let a = merge_indexes(vec![index(), other_index()], None, None).expect("merge");
        let b = merge_indexes(vec![other_index(), index()], None, None).expect("merge");
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );

        // The same release twice collapses rather than duplicating.
        let c = merge_indexes(vec![index(), index()], None, None).expect("merge");
        assert_eq!(c.releases.len(), 1);
    }

    /// Two different definitions of the same coordinate leave "what does this
    /// release contain" undefined, which is exactly the ambiguity drift
    /// detection cannot tolerate. It is an error, not last-writer-wins.
    #[test]
    fn merge_rejects_conflicting_definitions_of_one_release() {
        let mut tampered = index();
        tampered.releases[0].files[0].sha256 = hash_bytes(b"evil");
        let err = merge_indexes(vec![index(), tampered], None, None).expect_err("must reject");
        assert!(err.contains("conflicting"), "{err}");
    }

    #[test]
    fn merge_rejects_a_foreign_format() {
        let mut foreign = index();
        foreign.format = "sigil-pack/v1".to_string();
        assert!(merge_indexes(vec![foreign], None, None).is_err());
    }

    // ---- validation --------------------------------------------------

    #[test]
    fn validate_accepts_a_well_formed_index() {
        let stats = index().validate().expect("valid");
        assert_eq!(stats.releases, 1);
        assert_eq!(stats.files, 2);
    }

    #[test]
    fn validate_rejects_an_empty_index() {
        let empty = KnownGoodIndex {
            format: default_format(),
            name: None,
            generated: None,
            releases: Vec::new(),
        };
        assert!(empty.validate().is_err());
    }

    /// The lookup table is keyed on lowercase hex, so a digest in any other
    /// shape can never match. Rejecting it at install time is the difference
    /// between a loud error and an index that silently recognises nothing.
    #[test]
    fn validate_rejects_malformed_hashes() {
        for bad in ["", "abc", &"A".repeat(64), &"z".repeat(64)] {
            let mut idx = index();
            idx.releases[0].files[0].sha256 = bad.to_string();
            assert!(idx.validate().is_err(), "must reject sha256 {bad:?}");
        }
    }

    #[test]
    fn validate_rejects_paths_that_escape_the_release_root() {
        // sigil:ignore-next-line SKILL-013 -- the traversal strings are the input this test rejects
        for bad in ["../../etc/passwd", "/etc/passwd", ""] {
            let mut idx = index();
            idx.releases[0].files[0].path = bad.to_string();
            assert!(idx.validate().is_err(), "must reject path {bad:?}");
        }
    }

    #[test]
    fn validate_rejects_duplicate_and_incomplete_releases() {
        let mut dup = index();
        let clone = dup.releases[0].clone();
        dup.releases.push(clone);
        assert!(
            dup.validate().is_err(),
            "duplicate coordinate must be rejected"
        );

        let mut blank = index();
        blank.releases[0].version = "  ".to_string();
        assert!(blank.validate().is_err(), "blank version must be rejected");

        let mut fileless = index();
        fileless.releases[0].files.clear();
        assert!(
            fileless.validate().is_err(),
            "empty release must be rejected"
        );
    }

    /// A local `.git` directory is not published content, but a regular file
    /// named `.git` is a submodule gitlink that ships inside the archive.
    /// Anything the scanner reads and the index does not hold is noise the
    /// corpus cannot explain, so the gitlink has to be indexed.
    #[test]
    fn indexes_a_gitlink_file_but_not_a_git_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = dir.path().join("package");
        std::fs::create_dir_all(pkg.join(".git/objects")).unwrap();
        std::fs::create_dir_all(pkg.join("vendor/libuv")).unwrap();
        std::fs::write(pkg.join(".git/objects/blob"), b"internal\n").unwrap();
        std::fs::write(pkg.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        std::fs::write(
            pkg.join("vendor/libuv/.git"),
            b"gitdir: ../../.git/modules/libuv\n",
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), b"module.exports = 1;\n").unwrap();

        let idx = build_index(
            dir.path(),
            "pypi",
            "demo",
            "1.0.0",
            &ReleaseSource::default(),
        )
        .expect("build");
        let paths: Vec<&str> = idx.releases[0]
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(paths, vec!["package/index.js", "package/vendor/libuv/.git"]);
    }

    /// Arbitrary JSON is not an index. Serde's defaults fill in `format`, so
    /// the guard that actually stops `{"releases": []}` is validation, not
    /// deserialisation — this pins that.
    #[test]
    fn arbitrary_json_is_not_an_index() {
        assert!(serde_json::from_str::<KnownGoodIndex>("{}").is_err());
        assert!(serde_json::from_str::<KnownGoodIndex>("[]").is_err());
        assert!(serde_json::from_str::<KnownGoodIndex>("not json").is_err());

        let shell: KnownGoodIndex =
            serde_json::from_str(r#"{"releases":[]}"#).expect("parses with defaults");
        assert_eq!(shell.format, INDEX_FORMAT);
        assert!(shell.validate().is_err(), "an empty shell must not install");
    }

    /// A signature pack is a different document that happens to be JSON;
    /// installing one would install an index that recognises nothing.
    #[test]
    fn a_signature_pack_is_not_an_index() {
        let pack = r#"{"format":"sigil-pack/v1","releases":[]}"#;
        let parsed: KnownGoodIndex = serde_json::from_str(pack).expect("parses");
        let err = parsed.validate().expect_err("must reject");
        assert!(err.contains("unsupported format"), "{err}");
    }
}
