//! Scan-target ingestion: archives, download URLs and GitHub tree links.
//!
//! `sigil scan` takes a directory, a single file or a git URL. People get
//! agent skills in other shapes too: a `.skill` or `.zip` handed over in a
//! chat, a release tarball, a link to a raw `SKILL.md`, or a GitHub
//! `/tree/<ref>/<dir>` link to one skill inside a large repository. Each of
//! those is materialised here into a fresh quarantine directory, and the
//! normal scan then runs on that directory.
//!
//! Every path in this module fails closed. An archive that is unsafe to
//! unpack is not partly unpacked and scanned — a scan of the half that
//! extracted would report a verdict about something the user never
//! received. The refusal is an error (exit 2) naming the entry and the rule
//! it broke:
//!
//! - entry names that are absolute, carry a drive letter, climb out with
//!   `..`, contain NUL, or nest deeper than [`Limits::max_depth`];
//! - symlinks, hard links, device nodes and FIFOs (a symlink is how an
//!   archive writes outside its directory on a *second* extraction, and
//!   none of them is content a scanner can judge);
//! - duplicate entries (two members with one name: which one an installer
//!   keeps is up to the installer, so the scan cannot know what it saw);
//! - encrypted members, and archive formats this build cannot read;
//! - more than [`Limits::max_entries`] members, or more than
//!   [`Limits::max_bytes`] written, counted on the bytes actually
//!   decompressed rather than on the sizes the headers declare.
//!
//! Downloads are https or http only, bounded by [`MAX_DOWNLOAD_BYTES`],
//! follow at most [`MAX_REDIRECTS`] redirects, refuse an https-to-http
//! downgrade, and refuse loopback, link-local (cloud metadata), private and
//! other non-public addresses unless `SIGIL_ALLOW_PRIVATE_URLS=1`. The
//! address check runs on every hop against the resolved addresses, and the
//! connection is pinned to the address that was checked, so a DNS answer
//! that changes between the check and the connect cannot redirect it.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use colored::Colorize;

/// Largest body a download may have.
pub const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// Redirect hops followed before giving up.
pub const MAX_REDIRECTS: usize = 5;

/// Extraction caps for one archive.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Members (files and directories) an archive may hold.
    pub max_entries: usize,
    /// Bytes that may be written while unpacking.
    pub max_bytes: u64,
    /// Path components a member name may have.
    pub max_depth: usize,
}

impl Default for Limits {
    /// Sized for agent skills and small packages: a skill is a few files; the
    /// largest vendor skill in the 455-skill clean corpus is a few MiB. These
    /// sit two orders of magnitude above that and far below a bomb.
    fn default() -> Self {
        Limits {
            max_entries: 20_000,
            max_bytes: 1024 * 1024 * 1024,
            max_depth: 48,
        }
    }
}

/// What unpacking produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub files: usize,
    pub bytes: u64,
    pub format: &'static str,
}

/// Container format, judged from the file's leading bytes rather than its
/// name: a `.skill` is a zip, a `.crate` is a gzipped tar, and a renamed
/// archive must not slip past as an opaque "file".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Gzip,
    Tar,
    /// A recognised archive this build cannot unpack.
    Unsupported(&'static str),
    NotArchive,
}

pub fn sniff(path: &Path) -> io::Result<Format> {
    let mut f = File::open(path)?;
    let mut head = [0u8; 512];
    let mut n = 0;
    while n < head.len() {
        let got = f.read(&mut head[n..])?;
        if got == 0 {
            break;
        }
        n += got;
    }
    Ok(sniff_bytes(&head[..n]))
}

fn sniff_bytes(h: &[u8]) -> Format {
    if h.starts_with(b"PK\x03\x04") || h.starts_with(b"PK\x05\x06") || h.starts_with(b"PK\x07\x08")
    {
        return Format::Zip;
    }
    if h.starts_with(&[0x1f, 0x8b]) {
        return Format::Gzip;
    }
    if h.len() >= 262 && &h[257..262] == b"ustar" {
        return Format::Tar;
    }
    if h.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Format::Unsupported("xz");
    }
    if h.len() >= 10 && h.starts_with(b"BZh") && &h[4..10] == b"\x31\x41\x59\x26\x53\x59" {
        return Format::Unsupported("bzip2");
    }
    if h.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Format::Unsupported("zstd");
    }
    if h.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Format::Unsupported("7z");
    }
    if h.starts_with(b"Rar!\x1a\x07") {
        return Format::Unsupported("rar");
    }
    Format::NotArchive
}

// ---------------------------------------------------------------------------
// Safe extraction
// ---------------------------------------------------------------------------

/// Validate one member name and turn it into a path relative to the
/// extraction root. `Ok(None)` is the archive's own root (`./`).
///
/// Backslashes are treated as separators: the zip spec says `/`, but Windows
/// tools write `\`, and a name like `..\..\x` must be judged by what a
/// Windows extractor would do with it, not by what Linux happens to do.
fn safe_relative(name: &str, max_depth: usize) -> Result<Option<PathBuf>, String> {
    if name.contains('\0') {
        return Err(format!("entry name contains NUL: {name:?}"));
    }
    let unified = name.replace('\\', "/");
    if unified.starts_with('/') {
        return Err(format!("absolute path entry: {name:?}"));
    }
    let b = unified.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return Err(format!("drive-letter path entry: {name:?}"));
    }
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for comp in unified.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return Err(format!("path traversal entry (zip-slip): {name:?}")),
            c => {
                out.push(c);
                depth += 1;
            }
        }
    }
    if depth == 0 {
        return Ok(None);
    }
    if depth > max_depth {
        return Err(format!(
            "entry nests deeper than {max_depth} directories: {name:?}"
        ));
    }
    Ok(Some(out))
}

/// Book-keeping shared by the zip and tar paths.
struct Sink<'a> {
    dest: &'a Path,
    limits: Limits,
    stats: Stats,
    seen: HashSet<PathBuf>,
}

impl<'a> Sink<'a> {
    fn new(dest: &'a Path, limits: Limits, format: &'static str) -> Self {
        Sink {
            dest,
            limits,
            stats: Stats {
                format,
                ..Stats::default()
            },
            seen: HashSet::new(),
        }
    }

    fn count(&mut self, name: &str) -> Result<(), String> {
        self.stats.files += 1;
        if self.stats.files > self.limits.max_entries {
            return Err(format!(
                "archive has more than {} entries (stopped at {name:?})",
                self.limits.max_entries
            ));
        }
        Ok(())
    }

    fn dir(&mut self, rel: &Path, name: &str) -> Result<(), String> {
        self.count(name)?;
        fs::create_dir_all(self.dest.join(rel))
            .map_err(|e| format!("cannot create directory for {name:?}: {e}"))
    }

    fn file(&mut self, rel: PathBuf, name: &str, body: &mut dyn Read) -> Result<(), String> {
        self.count(name)?;
        if !self.seen.insert(rel.clone()) {
            return Err(format!("duplicate entry: {name:?}"));
        }
        let out = self.dest.join(&rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create directory for {name:?}: {e}"))?;
        }
        let budget = self.limits.max_bytes.saturating_sub(self.stats.bytes);
        let written = write_bounded(body, &out, budget).map_err(|e| match e {
            BoundedError::Cap => format!(
                "archive expands past {} MiB (stopped at {name:?})",
                self.limits.max_bytes / (1024 * 1024)
            ),
            BoundedError::Io(e) => format!("cannot write {name:?}: {e}"),
        })?;
        self.stats.bytes += written;
        Ok(())
    }
}

enum BoundedError {
    Cap,
    Io(io::Error),
}

/// Copy `body` into a new file, refusing to write more than `budget` bytes.
/// The count is taken on the decompressed stream, so a header that lies
/// about the size cannot buy extra room. `create_new` means nothing already
/// on disk is ever overwritten.
fn write_bounded(body: &mut dyn Read, out: &Path, budget: u64) -> Result<u64, BoundedError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(BoundedError::Io)?;
    let mut limited = body.take(budget.saturating_add(1));
    let n = io::copy(&mut limited, &mut f).map_err(BoundedError::Io)?;
    if n > budget {
        drop(f);
        let _ = fs::remove_file(out);
        return Err(BoundedError::Cap);
    }
    Ok(n)
}

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

fn extract_zip(src: &Path, sink: &mut Sink) -> Result<(), String> {
    let file = File::open(src).map_err(|e| format!("cannot open archive: {e}"))?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| format!("not a readable zip archive: {e}"))?;
    if zip.len() > sink.limits.max_entries {
        return Err(format!(
            "archive declares {} entries (cap {})",
            zip.len(),
            sink.limits.max_entries
        ));
    }
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| match e {
            zip::result::ZipError::UnsupportedArchive(msg) => {
                format!("entry #{i} cannot be read ({msg}): encrypted or unsupported members are refused")
            }
            other => format!("entry #{i} is corrupt: {other}"),
        })?;
        let name = entry.name().to_string();
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & S_IFMT;
            if kind == S_IFLNK {
                return Err(format!("symlink entry refused: {name:?}"));
            }
            if kind != 0 && kind != S_IFREG && kind != S_IFDIR {
                return Err(format!("special-file entry refused: {name:?}"));
            }
        }
        let Some(rel) = safe_relative(&name, sink.limits.max_depth)? else {
            continue;
        };
        if entry.is_dir() {
            sink.dir(&rel, &name)?;
        } else {
            sink.file(rel, &name, &mut entry)?;
        }
    }
    Ok(())
}

fn extract_tar<R: Read>(reader: R, sink: &mut Sink) -> Result<(), String> {
    use tar::EntryType;
    let mut ar = tar::Archive::new(reader);
    let entries = ar
        .entries()
        .map_err(|e| format!("not a readable tar archive: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("corrupt tar entry: {e}"))?;
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let kind = entry.header().entry_type();
        match kind {
            EntryType::Regular | EntryType::Continuous => {
                let Some(rel) = safe_relative(&name, sink.limits.max_depth)? else {
                    continue;
                };
                sink.file(rel, &name, &mut entry)?;
            }
            EntryType::Directory => {
                if let Some(rel) = safe_relative(&name, sink.limits.max_depth)? {
                    sink.dir(&rel, &name)?;
                }
            }
            // Metadata records the tar crate normally folds into the next
            // member; nothing to write.
            EntryType::XGlobalHeader
            | EntryType::XHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink => continue,
            EntryType::Symlink => return Err(format!("symlink entry refused: {name:?}")),
            EntryType::Link => return Err(format!("hard-link entry refused: {name:?}")),
            other => return Err(format!("special-file entry refused ({other:?}): {name:?}")),
        }
    }
    Ok(())
}

/// Unpack `src` into `dest` (which must exist and should be empty) under
/// `limits`. On error, whatever was written stays in `dest`; the caller
/// discards it — see [`prepare`].
pub fn extract(src: &Path, dest: &Path, limits: Limits) -> Result<Stats, String> {
    match sniff(src).map_err(|e| format!("cannot read {}: {e}", src.display()))? {
        Format::Zip => {
            let mut sink = Sink::new(dest, limits, "zip");
            extract_zip(src, &mut sink)?;
            Ok(sink.stats)
        }
        Format::Tar => {
            let mut sink = Sink::new(dest, limits, "tar");
            let f = File::open(src).map_err(|e| format!("cannot open archive: {e}"))?;
            extract_tar(io::BufReader::new(f), &mut sink)?;
            Ok(sink.stats)
        }
        Format::Gzip => extract_gzip(src, dest, limits),
        Format::Unsupported(kind) => Err(format!(
            "{kind} archives are not supported by this build; unpack it yourself and run `sigil scan <dir>`"
        )),
        Format::NotArchive => Err("not an archive".to_string()),
    }
}

/// A gzip stream is either a tarball or one compressed file. Decompress it
/// once (bounded), then look at what came out.
fn extract_gzip(src: &Path, dest: &Path, limits: Limits) -> Result<Stats, String> {
    let tmp = sibling_tmp(dest, "gunzip");
    {
        let f = File::open(src).map_err(|e| format!("cannot open archive: {e}"))?;
        let mut gz = flate2::read::MultiGzDecoder::new(io::BufReader::new(f));
        write_bounded(&mut gz, &tmp, limits.max_bytes).map_err(|e| match e {
            BoundedError::Cap => format!(
                "gzip stream expands past {} MiB",
                limits.max_bytes / (1024 * 1024)
            ),
            BoundedError::Io(e) => format!("corrupt gzip stream: {e}"),
        })?;
    }
    let inner = sniff(&tmp).map_err(|e| format!("cannot read decompressed stream: {e}"));
    let result = match inner {
        Ok(Format::Tar) => {
            let mut sink = Sink::new(dest, limits, "tar.gz");
            let f = File::open(&tmp).map_err(|e| format!("cannot reopen stream: {e}"))?;
            extract_tar(io::BufReader::new(f), &mut sink).map(|_| sink.stats)
        }
        Ok(Format::NotArchive) => {
            let name = src
                .file_name()
                .map(|n| n.to_string_lossy().trim_end_matches(".gz").to_string())
                .map(|n| sanitize_file_name(&n, "file"))
                .unwrap_or_else(|| "file".to_string());
            let bytes = fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
            fs::rename(&tmp, dest.join(&name))
                .map(|_| Stats {
                    files: 1,
                    bytes,
                    format: "gzip",
                })
                .map_err(|e| format!("cannot place decompressed file: {e}"))
        }
        Ok(other) => Err(format!(
            "gzip wraps a nested {other:?} container; unpack it yourself and run `sigil scan <dir>`"
        )),
        Err(e) => Err(e),
    };
    let _ = fs::remove_file(&tmp);
    result
}

/// Keep a file or directory name to a conservative character set so a
/// hostile URL or archive name cannot shape the quarantine layout.
fn sanitize_file_name(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    let trimmed = cleaned.trim_start_matches('.');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// A scratch path next to `dir`, never inside it: an archive member with
/// the same name as a scratch file must not be able to collide with it.
fn sibling_tmp(dir: &Path, what: &str) -> PathBuf {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "sigil".to_string());
    dir.parent()
        .unwrap_or(dir)
        .join(format!(".{name}.{what}.tmp"))
}

// ---------------------------------------------------------------------------
// Target classification
// ---------------------------------------------------------------------------

/// What `sigil scan <target>` has to do before it can scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// A directory, a plain file, or a git URL: the existing paths handle it.
    Passthrough,
    /// A local archive to unpack into quarantine.
    LocalArchive(PathBuf),
    /// A URL to one file or one archive.
    Download(String),
    /// `https://github.com/<o>/<r>/tree/<ref>/<dir>`: clone, scan `<dir>`.
    GitHubTree { repo: String, segments: Vec<String> },
}

/// URL path suffixes that name a single file or an archive rather than a
/// repository. Anything else over http(s) keeps its existing meaning: a git
/// remote.
const DOWNLOAD_SUFFIXES: &[&str] = &[
    // archives
    ".zip",
    ".skill",
    ".tar.gz",
    ".tgz",
    ".tar",
    ".whl",
    ".vsix",
    ".crate",
    ".gz",
    // single files an agent consumes or runs
    ".md",
    ".markdown",
    ".mdc",
    ".txt",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".sh",
    ".bash",
    ".ps1",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".rb",
    ".pl",
];

/// Hosts that only ever serve file bodies.
const RAW_HOSTS: &[&str] = &[
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
];

pub fn plan(target: &str) -> Result<Plan, String> {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        let url = reqwest::Url::parse(t).map_err(|e| format!("invalid URL {t:?}: {e}"))?;
        return Ok(plan_url(&url));
    }
    let p = Path::new(t);
    // Only a regular file can be an archive; a directory or a missing path
    // keeps its existing handling (and its existing error message).
    if p.is_file() {
        return match sniff(p) {
            Ok(Format::NotArchive) => Ok(Plan::Passthrough),
            Ok(_) => Ok(Plan::LocalArchive(p.to_path_buf())),
            Err(e) => Err(format!("cannot read {}: {e}", p.display())),
        };
    }
    Ok(Plan::Passthrough)
}

fn plan_url(url: &reqwest::Url) -> Plan {
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    let segs: Vec<String> = url
        .path_segments()
        .map(|s| s.filter(|x| !x.is_empty()).map(percent_decode).collect())
        .unwrap_or_default();
    if host == "github.com" || host == "www.github.com" {
        if segs.len() >= 4 && segs[2] == "tree" {
            return Plan::GitHubTree {
                repo: format!(
                    "https://github.com/{}/{}.git",
                    segs[0],
                    segs[1].trim_end_matches(".git")
                ),
                segments: segs[3..].to_vec(),
            };
        }
        // A /blob/ page is an HTML viewer; fetching it would scan the
        // forge's markup instead of the file.
        if segs.len() >= 5 && (segs[2] == "blob" || segs[2] == "raw") {
            let rest: Vec<&str> = url
                .path_segments()
                .map(|s| s.filter(|x| !x.is_empty()).skip(3).collect())
                .unwrap_or_default();
            return Plan::Download(format!(
                "https://raw.githubusercontent.com/{}/{}/{}",
                segs[0],
                segs[1],
                rest.join("/")
            ));
        }
    }
    if host == "gitlab.com" {
        let mut raw: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
        if let Some(i) = raw.iter().position(|s| *s == "-") {
            if raw.get(i + 1) == Some(&"blob") {
                raw[i + 1] = "raw";
                let mut u = url.clone();
                u.set_path(&raw.join("/"));
                return Plan::Download(u.to_string());
            }
        }
    }
    if RAW_HOSTS.contains(&host.as_str()) {
        return Plan::Download(url.to_string());
    }
    let path = url.path().to_ascii_lowercase();
    if DOWNLOAD_SUFFIXES.iter().any(|s| path.ends_with(s)) {
        return Plan::Download(url.to_string());
    }
    Plan::Passthrough
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct DownloadPolicy {
    /// Permit loopback, link-local and private addresses.
    pub allow_private: bool,
    pub max_bytes: u64,
}

impl DownloadPolicy {
    pub fn from_env() -> Self {
        DownloadPolicy {
            allow_private: std::env::var("SIGIL_ALLOW_PRIVATE_URLS").as_deref() == Ok("1"),
            max_bytes: MAX_DOWNLOAD_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Downloaded {
    pub final_url: reqwest::Url,
    pub content_type: Option<String>,
    pub bytes: u64,
}

/// Is this address somewhere a scan target should never come from by
/// default? Loopback and link-local cover local services and cloud metadata
// sigil:ignore-next-line NET-013 -- names the metadata address this check refuses
/// endpoints (169.254.169.254); private, shared and unique-local cover the
/// internal network.
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 shared
                || o[0] == 0
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
        }
    }
}

/// An outbound proxy is configured. The proxy, not this process, then
/// resolves and connects to the target, so a local DNS failure is not an
/// error and there is no address to pin.
fn proxy_configured() -> bool {
    [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()))
}

/// Check one hop: scheme, host, and every address the host resolves to.
/// Returns the address to pin the connection to.
async fn vet_hop(
    url: &reqwest::Url,
    policy: &DownloadPolicy,
) -> Result<Option<SocketAddr>, String> {
    match url.scheme() {
        "https" | "http" => {}
        other => return Err(format!("refusing {other}:// URL (only https and http)")),
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("URL has no host: {url}"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(a) => a.collect(),
            // Behind a proxy, only the proxy may be able to resolve names.
            Err(_) if proxy_configured() && !host.eq_ignore_ascii_case("localhost") => {
                return Ok(None)
            }
            Err(e) => return Err(format!("cannot resolve {host}: {e}")),
        }
    };
    if addrs.is_empty() {
        return Err(format!("{host} resolved to no addresses"));
    }
    if !policy.allow_private {
        if let Some(bad) = addrs.iter().find(|a| is_non_public(a.ip())) {
            return Err(format!(
                "refusing to fetch from {host} ({}): a non-public address. \
                 Set SIGIL_ALLOW_PRIVATE_URLS=1 to allow internal mirrors",
                bad.ip()
            ));
        }
    }
    Ok(if host.parse::<IpAddr>().is_ok() {
        None
    } else {
        addrs.first().copied()
    })
}

/// Download `url` into `out` (which must not exist) under `policy`.
pub async fn download(
    url: &str,
    out: &Path,
    policy: &DownloadPolicy,
) -> Result<Downloaded, String> {
    let mut current = reqwest::Url::parse(url).map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    for _hop in 0..=MAX_REDIRECTS {
        let pin = vet_hop(&current, policy).await?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(300))
            .user_agent(concat!("sigil/", env!("CARGO_PKG_VERSION")));
        if let (Some(addr), Some(host)) = (pin, current.host_str()) {
            builder = builder.resolve(host, addr);
        }
        let client = builder
            .build()
            .map_err(|e| format!("cannot build HTTP client: {e}"))?;
        let mut resp = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| format!("download failed: {e}"))?;
        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("redirect without a Location header from {current}"))?;
            let next = current
                .join(loc)
                .map_err(|e| format!("bad redirect target {loc:?}: {e}"))?;
            if current.scheme() == "https" && next.scheme() != "https" {
                return Err(format!("refusing redirect that downgrades https to {next}"));
            }
            current = next;
            continue;
        }
        if !status.is_success() {
            return Err(format!("download failed: HTTP {status} from {current}"));
        }
        if let Some(len) = resp.content_length() {
            if len > policy.max_bytes {
                return Err(format!(
                    "download is {len} bytes, over the {} MiB cap",
                    policy.max_bytes / (1024 * 1024)
                ));
            }
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out)
            .map_err(|e| format!("cannot create {}: {e}", out.display()))?;
        let mut total = 0u64;
        loop {
            let chunk = match resp.chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    drop(f);
                    let _ = fs::remove_file(out);
                    return Err(format!("download interrupted: {e}"));
                }
            };
            total += chunk.len() as u64;
            if total > policy.max_bytes {
                drop(f);
                let _ = fs::remove_file(out);
                return Err(format!(
                    "download exceeded the {} MiB cap",
                    policy.max_bytes / (1024 * 1024)
                ));
            }
            f.write_all(&chunk)
                .map_err(|e| format!("cannot write download: {e}"))?;
        }
        return Ok(Downloaded {
            final_url: current,
            content_type,
            bytes: total,
        });
    }
    Err(format!(
        "more than {MAX_REDIRECTS} redirects fetching {url}"
    ))
}

/// Name for a downloaded single file. The scanner keys some rules on the file
/// name, so a skill fetched from an extension-less URL is named `SKILL.md`
/// when its body is front-matter markdown.
fn downloaded_file_name(
    url: &reqwest::Url,
    content_type: Option<&str>,
    body_head: &[u8],
) -> String {
    let last = url
        .path_segments()
        .and_then(|mut s| s.next_back().map(percent_decode))
        .unwrap_or_default();
    let name = sanitize_file_name(&last, "");
    let has_ext = name.contains('.');
    let looks_md =
        body_head.starts_with(b"---") || content_type.is_some_and(|c| c.contains("markdown"));
    if name.is_empty() || (!has_ext && looks_md) {
        return "SKILL.md".to_string();
    }
    name
}

// ---------------------------------------------------------------------------
// GitHub tree URLs
// ---------------------------------------------------------------------------

/// Split `/tree/` segments into `(ref, subdirectory)` using the refs the
/// remote advertises. A branch may contain `/` (`feature/x`), so the longest
/// advertised ref that prefixes the segments wins.
fn split_tree_ref(refs: &[String], segments: &[String]) -> Option<(String, Vec<String>)> {
    let mut best: Option<(usize, &String)> = None;
    for r in refs {
        let parts: Vec<&str> = r.split('/').collect();
        if parts.len() <= segments.len()
            && parts.iter().zip(segments).all(|(a, b)| *a == b.as_str())
            && best.is_none_or(|(n, _)| parts.len() > n)
        {
            best = Some((parts.len(), r));
        }
    }
    best.map(|(n, r)| (r.clone(), segments[n..].to_vec()))
}

fn parse_ls_remote(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split('\t').nth(1))
        .filter(|r| !r.ends_with("^{}"))
        .filter_map(|r| {
            r.strip_prefix("refs/heads/")
                .or_else(|| r.strip_prefix("refs/tags/"))
        })
        .map(str::to_string)
        .collect()
}

fn git(args: &[&str]) -> Result<std::process::Output, String> {
    std::process::Command::new("git")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("cannot run git: {e}"))
}

fn materialise_tree(repo: &str, segments: &[String], dest: &Path) -> Result<PathBuf, String> {
    let ls = git(&["ls-remote", "--heads", "--tags", repo])?;
    if !ls.status.success() {
        return Err(format!(
            "git ls-remote {repo} failed: {}",
            String::from_utf8_lossy(&ls.stderr).trim()
        ));
    }
    let refs = parse_ls_remote(&String::from_utf8_lossy(&ls.stdout));
    let (git_ref, sub) = split_tree_ref(&refs, segments).ok_or_else(|| {
        format!(
            "no branch or tag of {repo} matches {:?} (commit-SHA tree links are not supported; use a branch or tag)",
            segments.join("/")
        )
    })?;
    for s in &sub {
        if s == ".." || s == "." || s.contains('\\') || s.contains('\0') {
            return Err(format!(
                "tree path escapes the repository: {}",
                sub.join("/")
            ));
        }
    }
    let clone_dir = dest.join("repo");
    let clone_str = clone_dir.to_string_lossy().to_string();
    // core.symlinks=false: a symlink in the repository is checked out as a
    // plain file holding its target, so nothing in the clone points outside
    // it and the scanner sees the link text.
    let st = git(&[
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.ext.allow=never",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--branch",
        &git_ref,
        repo,
        &clone_str,
    ])?;
    if !st.status.success() {
        return Err(format!(
            "git clone {repo} ({git_ref}) failed: {}",
            String::from_utf8_lossy(&st.stderr).trim()
        ));
    }
    let target = sub.iter().fold(clone_dir.clone(), |p, s| p.join(s));
    let root = fs::canonicalize(&clone_dir).map_err(|e| format!("clone vanished: {e}"))?;
    let resolved = fs::canonicalize(&target)
        .map_err(|_| format!("{} does not exist in {repo}@{git_ref}", sub.join("/")))?;
    if !resolved.starts_with(&root) || !resolved.is_dir() {
        return Err(format!(
            "{} is not a directory inside {repo}@{git_ref}",
            sub.join("/")
        ));
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// A target materialised into quarantine, ready for the normal scan.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The quarantine directory holding the unpacked target.
    pub root: PathBuf,
}

fn progress(format: &str, msg: String) {
    if format == "text" {
        println!("{msg}");
    } else {
        eprintln!("{msg}");
    }
}

/// Resolve a `sigil scan` target. `Ok(None)` means "not ours": the caller
/// keeps its existing handling (directory, plain file, git URL).
pub async fn prepare(
    target: &str,
    format: &str,
    verbose: bool,
) -> Result<Option<Prepared>, String> {
    let plan = plan(target)?;
    let (source, source_type) = match &plan {
        Plan::Passthrough => return Ok(None),
        Plan::LocalArchive(p) => (
            fs::canonicalize(p)
                .unwrap_or_else(|_| p.clone())
                .display()
                .to_string(),
            "archive",
        ),
        Plan::Download(u) => (u.clone(), "url"),
        Plan::GitHubTree { .. } => (target.trim().to_string(), "git"),
    };
    let entry = crate::quarantine::add(&source, source_type)
        .map_err(|e| format!("failed to create quarantine entry: {e}"))?;
    let result = materialise(&plan, &entry.path, format, verbose).await;
    match result {
        Ok(root) => {
            progress(
                format,
                format!(
                    "{} quarantined as {} (sigil approve {} / sigil reject {})",
                    "sigil:".bold().cyan(),
                    entry.id,
                    entry.id,
                    entry.id
                ),
            );
            Ok(Some(Prepared { root }))
        }
        Err(e) => {
            // Fail closed: nothing half-unpacked stays on disk, and the
            // quarantine record says why.
            let _ = crate::quarantine::reject(&entry.id, Some(&format!("ingest refused: {e}")));
            Err(format!("refusing to scan {}: {e}", target.trim()))
        }
    }
}

async fn materialise(
    plan: &Plan,
    qdir: &Path,
    format: &str,
    verbose: bool,
) -> Result<PathBuf, String> {
    match plan {
        Plan::Passthrough => unreachable!("handled by prepare"),
        Plan::LocalArchive(p) => {
            progress(
                format,
                format!(
                    "{} unpacking {} into quarantine...",
                    "sigil:".bold().cyan(),
                    p.display().to_string().bold()
                ),
            );
            let stats = extract(p, qdir, Limits::default())?;
            report_stats(format, &stats);
            Ok(qdir.to_path_buf())
        }
        Plan::Download(url) => {
            progress(
                format,
                format!(
                    "{} downloading {} into quarantine...",
                    "sigil:".bold().cyan(),
                    url.bold()
                ),
            );
            let partial = sibling_tmp(qdir, "download");
            let got = download(url, &partial, &DownloadPolicy::from_env()).await?;
            if verbose {
                eprintln!(
                    "downloaded {} bytes from {} ({})",
                    got.bytes,
                    got.final_url,
                    got.content_type.as_deref().unwrap_or("no content-type")
                );
            }
            let fmt = sniff(&partial).map_err(|e| format!("cannot read download: {e}"))?;
            match fmt {
                Format::NotArchive => {
                    let mut head = [0u8; 16];
                    let n = File::open(&partial)
                        .and_then(|mut f| f.read(&mut head))
                        .unwrap_or(0);
                    let name = downloaded_file_name(
                        &got.final_url,
                        got.content_type.as_deref(),
                        &head[..n],
                    );
                    if got
                        .content_type
                        .as_deref()
                        .is_some_and(|c| c.starts_with("text/html"))
                        && !name.ends_with(".html")
                    {
                        eprintln!(
                            "{} the server returned an HTML page, not the file itself; \
                             if this is a repository viewer, pass the raw-file URL",
                            "warning:".bold().yellow()
                        );
                    }
                    fs::rename(&partial, qdir.join(&name))
                        .map_err(|e| format!("cannot place download: {e}"))?;
                    Ok(qdir.to_path_buf())
                }
                _ => {
                    let stats = extract(&partial, qdir, Limits::default());
                    let _ = fs::remove_file(&partial);
                    report_stats(format, &stats?);
                    Ok(qdir.to_path_buf())
                }
            }
        }
        Plan::GitHubTree { repo, segments } => {
            progress(
                format,
                format!(
                    "{} cloning {} into quarantine to scan {}...",
                    "sigil:".bold().cyan(),
                    repo.bold(),
                    segments.join("/")
                ),
            );
            materialise_tree(repo, segments, qdir)
        }
    }
}

fn report_stats(format: &str, stats: &Stats) {
    progress(
        format,
        format!(
            "{} unpacked {} entr{} ({} KiB, {})",
            "sigil:".bold().cyan(),
            stats.files,
            if stats.files == 1 { "y" } else { "ies" },
            stats.bytes.div_ceil(1024),
            stats.format
        ),
    );
}

#[cfg(test)]
#[path = "ingest_tests.rs"]
mod tests;
