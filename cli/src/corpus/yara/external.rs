//! External YARA engines: YARA-X (`yr`) and classic YARA (`yara`).
//!
//! The built-in engine evaluates the string-matching core of YARA. Rules
//! that need more — modules (`pe`, `elf`, `math`, `hash`, `dotnet`, ...),
//! loops, offset reads, `xor`/`base64` strings — are handed to an engine the
//! machine already has, selected with `--yara-engine` (or the policy key
//! `yara_engine`):
//!
//! - `auto` (default): the built-in engine for every file it can evaluate
//!   whole; the others go to `yr`, else `yara`. With neither installed they
//!   load unevaluated, and every scan says so as incomplete coverage
//!   (`PROV-INCOMPLETE-001`), which `--fail-on-incomplete` fails on.
//! - `builtin`: the built-in engine only; a file it cannot evaluate is
//!   refused, as before this module existed.
//! - `yara-x`, `yara`: every YARA file goes to that engine, which must be
//!   installed, or the load fails.
//!
//! **How an engine is run.** No shell is involved: the engine is started
//! with an argument vector, from its absolute path. It is found on `PATH`,
//! skipping relative entries (`.` would run a binary from the current
//! directory, which may be the tree being scanned), and a binary inside the
//! scanned tree is never run. Each run gets a private temporary directory
//! (mode 0700 on Unix) holding:
//!
//! - `r/<n>.yar`: the rule files, as the exact bytes Sigil read, verified
//!   and validated at load — never the files on disk again;
//! - `r/sigil.yar`: one rule of Sigil's own, `sigil_evaluated`, true for
//!   every file, in its own namespace (so no user rule, global or not, can
//!   affect it). The engine reports it for every file it finished, which is
//!   how Sigil knows what was evaluated: a file without it was not, and is
//!   reported as incomplete coverage rather than passed as clean;
//! - `t/<n>`: each file to scan, as a symbolic link to it (a copy where
//!   links are not available) or, for an archive member, its bytes. The
//!   engine only ever sees these names, so a path with spaces, line breaks
//!   or bytes that are not UTF-8 cannot confuse its output;
//! - `list`: the `t/<n>` names, one per line (`--scan-list`).
//!
//! Each rule file is its own namespace (`f<n>`), as it is its own Sigil
//! pack. Output is read line by line as it streams (`ns:rule t/<n>`, then
//! `0x<offset>:<length>:<string>: <data>` per match, which both engines
//! print), keeping a few matches per rule, so a rule that matches a million
//! times cannot exhaust memory. An evaluation is bounded by
//! [`TIMEOUT_ENV`] (default [`DEFAULT_TIMEOUT_SECS`]); classic YARA also
//! gets the per-file budget as its per-file timeout. A run that crashes or
//! exits with an error is followed by runs over halves of the files it did
//! not finish, so the one file an engine cannot get through is reported and
//! the others are still evaluated.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::{FileEngine, YaraFile, YaraRule};
use crate::corpus::custom::CustomPack;
use crate::scanner::{Finding, Phase};

/// Environment variable bounding an external engine's work for one scan
/// (every run of it), in seconds (`0`: none).
pub const TIMEOUT_ENV: &str = "SIGIL_YARA_TIMEOUT_SECS";

/// Default bound on that work.
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Bound on `--version` and `--help` probes.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Namespace and name of the rule that marks each file an engine finished.
const SENTINEL_NAMESPACE: &str = "sigil";
const SENTINEL_RULE: &str = "sigil_evaluated";

/// Longest output line kept; longer ones (an enormous match) are skipped.
const MAX_LINE: usize = 64 * 1024;

/// Standard error kept per run.
const MAX_STDERR: usize = 1024 * 1024;

/// Matched strings named in a finding (as for the built-in engine).
const SNIPPET_STRINGS: usize = 3;

/// Characters of each matched string shown in a finding.
const SNIPPET_CHARS: usize = 48;

// ---------------------------------------------------------------------------
// Engines
// ---------------------------------------------------------------------------

/// `--yara-engine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineMode {
    Auto,
    Builtin,
    YaraX,
    Yara,
}

impl EngineMode {
    /// The values `--yara-engine` and `yara_engine` accept.
    pub const NAMES: &'static [&'static str] = &["auto", "builtin", "yara-x", "yara"];

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "auto" => EngineMode::Auto,
            "builtin" | "built-in" => EngineMode::Builtin,
            "yara-x" | "yarax" | "yr" => EngineMode::YaraX,
            "yara" | "libyara" => EngineMode::Yara,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            EngineMode::Auto => "auto",
            EngineMode::Builtin => "builtin",
            EngineMode::YaraX => "yara-x",
            EngineMode::Yara => "yara",
        }
    }
}

/// An external engine's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineKind {
    /// YARA-X's command-line tool, `yr`.
    YaraX,
    /// Classic YARA (libyara) command-line tool, `yara`.
    Yara,
}

impl EngineKind {
    /// The executable's name.
    pub fn program(self) -> &'static str {
        match self {
            EngineKind::YaraX => "yr",
            EngineKind::Yara => "yara",
        }
    }

    pub fn product(self) -> &'static str {
        match self {
            EngineKind::YaraX => "YARA-X",
            EngineKind::Yara => "YARA",
        }
    }

    /// Flags a run needs; an engine without them is refused.
    fn required_flags(self) -> &'static [&'static str] {
        match self {
            EngineKind::YaraX => &[
                "--scan-list",
                "--print-namespace",
                "--print-strings",
                "--timeout",
            ],
            EngineKind::Yara => &[
                "--scan-list",
                "--print-namespace",
                "--print-strings",
                "--print-string-length",
                "--timeout",
            ],
        }
    }

    /// Flags used when the engine has them.
    fn optional_flags(self) -> &'static [&'static str] {
        match self {
            EngineKind::YaraX => &[
                "--disable-console-logs",
                "--disable-warnings",
                "--relaxed-re-syntax",
            ],
            EngineKind::Yara => &["--disable-console-logs", "--no-warnings"],
        }
    }
}

/// An installed engine, found and probed.
#[derive(Debug)]
pub struct Engine {
    pub kind: EngineKind,
    /// Absolute path of the executable.
    pub path: PathBuf,
    pub version: String,
    /// Which of [`EngineKind::optional_flags`] this build has.
    flags: Vec<&'static str>,
}

impl Engine {
    /// `YARA-X 1.20.0`.
    pub fn label(&self) -> String {
        format!("{} {}", self.kind.product(), self.version)
    }

    fn has(&self, flag: &str) -> bool {
        self.flags.contains(&flag)
    }
}

/// The executable name on this platform.
fn exe_name(program: &str) -> String {
    if cfg!(windows) {
        format!("{program}.exe")
    } else {
        program.to_string()
    }
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Find `kind`'s executable on `path_var` (a `PATH` value) and probe it.
///
/// Relative entries are skipped: `.` or an empty entry would run a binary
/// from the current directory, which may be the tree under scan. The first
/// match is the one used, as a shell would; if it is not the engine it
/// claims to be, that is an error, not a reason to look further.
#[cfg(test)]
pub fn find(kind: EngineKind, path_var: Option<OsString>) -> Result<Engine, String> {
    find_excluding(kind, path_var, None)
}

/// [`find`], never considering a directory inside `excluded` (the tree
/// about to be scanned): a program shipped in the code under judgement is
/// not run, not even to ask its version.
pub fn find_excluding(
    kind: EngineKind,
    path_var: Option<OsString>,
    excluded: Option<&Path>,
) -> Result<Engine, String> {
    let program = exe_name(kind.program());
    let paths = path_var.unwrap_or_default();
    let mut passed_over = false;
    for dir in std::env::split_paths(&paths) {
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(&program);
        if !is_executable(&candidate) {
            continue;
        }
        if let Some(ex) = excluded {
            let real = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
            let real_dir = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
            if real.starts_with(ex) || real_dir.starts_with(ex) {
                passed_over = true;
                continue;
            }
        }
        return probe(kind, &candidate);
    }
    Err(format!(
        "{} (`{}`) is not installed: no `{}` in an absolute PATH directory{}",
        kind.product(),
        kind.program(),
        program,
        if passed_over {
            " outside the scanned tree (one inside it was not considered)"
        } else {
            ""
        }
    ))
}

/// Ask an executable for its version and flags, and accept it as `kind`
/// only when it has every flag a run needs.
pub fn probe(kind: EngineKind, path: &Path) -> Result<Engine, String> {
    let version_out = run_capture(path, &["--version"], PROBE_TIMEOUT).map_err(|e| {
        format!(
            "{} did not answer `--version` ({e}); it does not look like {}",
            path.display(),
            kind.product()
        )
    })?;
    // `yara` prints `4.5.0`; `yr` prints `yara-x-cli 1.20.0`.
    let version = version_out
        .split_whitespace()
        .rev()
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "{}: `--version` printed no version number; it does not look like {}",
                path.display(),
                kind.product()
            )
        })?;
    let help_args: &[&str] = match kind {
        EngineKind::YaraX => &["scan", "--help"],
        EngineKind::Yara => &["--help"],
    };
    let help = run_capture(path, help_args, PROBE_TIMEOUT)
        .map_err(|e| format!("{}: `{}` failed ({e})", path.display(), help_args.join(" ")))?;
    let has = |flag: &str| {
        help.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .any(|w| w == flag)
    };
    let missing: Vec<&str> = kind
        .required_flags()
        .iter()
        .copied()
        .filter(|f| !has(f))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{} is {} {version}, which lacks {}; Sigil needs {}",
            path.display(),
            kind.product(),
            missing.join(", "),
            match kind {
                EngineKind::YaraX => "YARA-X 1.0 or later",
                EngineKind::Yara => "YARA 4.x with --scan-list",
            }
        ));
    }
    Ok(Engine {
        kind,
        path: path.to_path_buf(),
        version,
        flags: kind
            .optional_flags()
            .iter()
            .copied()
            .filter(|f| has(f))
            .collect(),
    })
}

/// A working directory for a probe that no untrusted party can write to.
fn neutral_dir() -> PathBuf {
    if cfg!(unix) {
        PathBuf::from("/")
    } else {
        std::env::temp_dir()
    }
}

/// Run a short command and return its standard output and error, or why it
/// failed.
fn run_capture(path: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut cmd = Command::new(path);
    cmd.args(args);
    let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let collect = Arc::clone(&out);
    // Never from Sigil's own working directory, which is often the tree
    // about to be scanned: a program resolves some things against its
    // working directory (a dynamic loader given an empty or `.` entry in
    // LD_LIBRARY_PATH loads libraries from it). Scan runs use their private
    // directory; a probe uses one no one else can write to.
    let ran = run(
        cmd,
        Some(&neutral_dir()),
        Some(timeout),
        Arc::new(Mutex::new(move |line: &[u8]| {
            if let Ok(mut o) = collect.lock() {
                if o.len() < MAX_LINE * 4 {
                    o.extend_from_slice(line);
                    o.push(b'\n');
                }
            }
        })),
    );
    let out = out.lock().map(|o| o.clone()).unwrap_or_default();
    if let Some(e) = ran.spawn_error {
        return Err(e);
    }
    if ran.timed_out {
        return Err(format!("no answer within {} s", timeout.as_secs()));
    }
    if !ran.status.is_some_and(|s| s.success()) {
        return Err(format!(
            "exit status {}",
            ran.status
                .and_then(|s| s.code())
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    let mut text = String::from_utf8_lossy(&out).into_owned();
    text.push_str(&ran.stderr);
    Ok(strip_ansi(&text))
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

struct Configured {
    mode: EngineMode,
    source: String,
}

static CONFIGURED: Mutex<Option<Configured>> = Mutex::new(None);
static FOUND_YARA_X: OnceLock<Result<Arc<Engine>, String>> = OnceLock::new();
static FOUND_YARA: OnceLock<Result<Arc<Engine>, String>> = OnceLock::new();

/// Set the engine mode for YARA files loaded from now on in this process.
/// `source` names where it came from (`--yara-engine`, a policy file).
pub fn configure(mode: EngineMode, source: impl Into<String>) {
    if let Ok(mut c) = CONFIGURED.lock() {
        *c = Some(Configured {
            mode,
            source: source.into(),
        });
    }
}

static EXCLUDED: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Never look for an engine inside `root`, the tree about to be scanned.
/// Called before any YARA file loads; the scan checks again before it runs
/// an engine.
pub fn exclude_from_search(root: &Path) {
    if let Ok(mut e) = EXCLUDED.lock() {
        *e = std::fs::canonicalize(root).ok();
    }
}

/// The engine installed on this machine for `kind`, found once per process.
fn system_engine(kind: EngineKind) -> Result<Arc<Engine>, String> {
    let cell = match kind {
        EngineKind::YaraX => &FOUND_YARA_X,
        EngineKind::Yara => &FOUND_YARA,
    };
    cell.get_or_init(|| {
        let excluded = EXCLUDED.lock().ok().and_then(|e| e.clone());
        find_excluding(kind, std::env::var_os("PATH"), excluded.as_deref()).map(Arc::new)
    })
    .clone()
}

/// Which engine a load uses.
pub struct Selection {
    pub mode: EngineMode,
    /// Where the mode came from, for messages.
    pub source: String,
    engines: Engines,
}

/// Where a [`Selection`] finds its engines.
enum Engines {
    /// This machine's `PATH`, searched once per process.
    System,
    /// Exactly these.
    #[cfg(test)]
    Fixed(Vec<Arc<Engine>>),
    /// This `PATH` value, searched on each call.
    #[cfg(test)]
    Path(OsString),
}

impl Selection {
    /// The configured mode (default `auto`) with this machine's engines.
    pub fn current() -> Selection {
        let (mode, source) = CONFIGURED
            .lock()
            .ok()
            .and_then(|c| c.as_ref().map(|c| (c.mode, c.source.clone())))
            .unwrap_or((EngineMode::Auto, "default".to_string()));
        Selection {
            mode,
            source,
            engines: Engines::System,
        }
    }

    /// A mode with exactly these engines available.
    #[cfg(test)]
    pub fn with_engines(mode: EngineMode, engines: Vec<Engine>) -> Selection {
        Selection {
            mode,
            source: "test".to_string(),
            engines: Engines::Fixed(engines.into_iter().map(Arc::new).collect()),
        }
    }

    /// A mode with the engines found on this `PATH` value.
    #[cfg(test)]
    pub fn with_path(mode: EngineMode, path: OsString) -> Selection {
        Selection {
            mode,
            source: "test".to_string(),
            engines: Engines::Path(path),
        }
    }

    /// The engine of `kind`, or why there is none.
    pub fn engine(&self, kind: EngineKind) -> Result<Arc<Engine>, String> {
        match &self.engines {
            Engines::System => system_engine(kind),
            #[cfg(test)]
            Engines::Fixed(engines) => {
                engines
                    .iter()
                    .find(|e| e.kind == kind)
                    .cloned()
                    .ok_or_else(|| {
                        format!("{} (`{}`) is not installed", kind.product(), kind.program())
                    })
            }
            #[cfg(test)]
            Engines::Path(path) => find(kind, Some(path.clone())).map(Arc::new),
        }
    }

    /// Why neither engine can be used, one clause per engine: not
    /// installed, found only inside the scanned tree, or found but not
    /// usable (it did not answer as the engine does, or lacks a flag).
    pub fn unavailable(&self) -> String {
        [EngineKind::YaraX, EngineKind::Yara]
            .into_iter()
            .filter_map(|k| self.engine(k).err())
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// What `auto` hands a file the built-in engine cannot evaluate to:
    /// YARA-X, else classic YARA.
    pub fn auto_engine(&self) -> Option<Arc<Engine>> {
        self.engine(EngineKind::YaraX)
            .ok()
            .or_else(|| self.engine(EngineKind::Yara).ok())
    }
}

/// The whole-run bound from [`TIMEOUT_ENV`]; `None` when set to 0.
pub fn run_timeout() -> Option<Duration> {
    match std::env::var(TIMEOUT_ENV) {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
        },
        _ => Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
    }
}

// ---------------------------------------------------------------------------
// Running a process
// ---------------------------------------------------------------------------

/// How a process ended.
struct Ran {
    status: Option<ExitStatus>,
    timed_out: bool,
    spawn_error: Option<String>,
    stderr: String,
}

/// Receives each line of a process's standard output.
type Sink = Arc<Mutex<dyn FnMut(&[u8]) + Send>>;

/// How long the output readers get, once the process has ended, to drain
/// its pipes. Only a program that leaves a child holding them open (a
/// wrapper script killed at the time limit) makes this wait matter.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Run `cmd` with no standard input, passing each line of its standard
/// output to `sink` as it arrives (lines over [`MAX_LINE`] are dropped),
/// and keeping the first [`MAX_STDERR`] bytes of its standard error. Past
/// `timeout` the process is killed. Both pipes are drained on their own
/// threads, so a chatty engine never blocks on a full pipe, and a reader
/// still blocked [`DRAIN_GRACE`] after the process ended is left behind
/// rather than allowed to hold the scan.
fn run(mut cmd: Command, cwd: Option<&Path>, timeout: Option<Duration>, sink: Sink) -> Ran {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Ran {
                status: None,
                timed_out: false,
                spawn_error: Some(e.to_string()),
                stderr: String::new(),
            }
        }
    };
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let mut readers = 0;
    if let Some(out) = child.stdout.take() {
        let tx = done_tx.clone();
        std::thread::spawn(move || {
            stream_lines(out, &sink);
            let _ = tx.send(());
        });
        readers += 1;
    }
    let errbuf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    if let Some(err) = child.stderr.take() {
        let tx = done_tx.clone();
        let buf = Arc::clone(&errbuf);
        std::thread::spawn(move || {
            read_capped(err, &buf);
            let _ = tx.send(());
        });
        readers += 1;
    }
    drop(done_tx);
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(st)) => break (Some(st), false),
            Ok(None) if timeout.is_some_and(|t| started.elapsed() >= t) => {
                let _ = child.kill();
                break (child.wait().ok(), true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(15)),
            Err(_) => {
                let _ = child.kill();
                break (child.wait().ok(), false);
            }
        }
    };
    let drain_until = Instant::now() + DRAIN_GRACE;
    for _ in 0..readers {
        let left = drain_until.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    let stderr = errbuf
        .lock()
        .map(|b| strip_ansi(&String::from_utf8_lossy(&b)))
        .unwrap_or_default();
    Ran {
        status,
        timed_out,
        spawn_error: None,
        stderr,
    }
}

/// Feed each line of `r` to `sink`, dropping lines longer than
/// [`MAX_LINE`] without holding them.
fn stream_lines(r: impl Read, sink: &Sink) {
    let mut reader = BufReader::with_capacity(64 * 1024, r);
    let mut line: Vec<u8> = Vec::new();
    let mut overflow = false;
    let emit = |line: &[u8]| {
        if let Ok(mut f) = sink.lock() {
            f(line);
        }
    };
    loop {
        let (consumed, done) = match reader.fill_buf() {
            Ok([]) => break,
            Ok(buf) => match buf.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    if !overflow && line.len() + i <= MAX_LINE {
                        line.extend_from_slice(&buf[..i]);
                    } else {
                        overflow = true;
                    }
                    (i + 1, true)
                }
                None => {
                    if !overflow && line.len() + buf.len() <= MAX_LINE {
                        line.extend_from_slice(buf);
                    } else {
                        overflow = true;
                    }
                    (buf.len(), false)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        reader.consume(consumed);
        if done {
            if !overflow {
                emit(&line);
            }
            line.clear();
            overflow = false;
        }
    }
    if !overflow && !line.is_empty() {
        emit(&line);
    }
}

/// Read `r` to its end into `into`, keeping the first [`MAX_STDERR`] bytes.
fn read_capped(r: impl Read, into: &Mutex<Vec<u8>>) {
    let mut reader = BufReader::new(r);
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(mut kept) = into.lock() {
                    let room = MAX_STDERR.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Remove terminal escape sequences and other control characters (except
/// newline and tab) from engine output before Sigil shows or parses it.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // Parameters and intermediates, then one final byte.
                for f in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&f) {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// The working directory of a run
// ---------------------------------------------------------------------------

/// A private temporary directory, removed (with everything in it, links
/// themselves and never what they point to) when dropped.
struct Workdir {
    path: PathBuf,
}

impl Workdir {
    fn create() -> std::io::Result<Workdir> {
        let base = std::env::temp_dir();
        let mut last = None;
        for _ in 0..8 {
            let path = base.join(format!("sigil-yara-{}", uuid::Uuid::new_v4().simple()));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => {
                    for sub in ["r", "t"] {
                        std::fs::create_dir(path.join(sub))?;
                    }
                    return Ok(Workdir { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no temporary directory")))
    }

    /// Write the rule files (`r/<n>.yar`) and the sentinel rule. Returns the
    /// rule arguments, `f<n>:r/<n>.yar` then `sigil:r/sigil.yar`.
    fn write_rules(&self, sources: &[&[u8]]) -> std::io::Result<Vec<String>> {
        let mut args = Vec::with_capacity(sources.len() + 1);
        for (n, src) in sources.iter().enumerate() {
            std::fs::write(self.path.join(format!("r/{n}.yar")), src)?;
            args.push(format!("f{n}:r/{n}.yar"));
        }
        std::fs::write(
            self.path.join("r/sigil.yar"),
            format!("rule {SENTINEL_RULE} {{ condition: true }}\n"),
        )?;
        args.push(format!("{SENTINEL_NAMESPACE}:r/sigil.yar"));
        Ok(args)
    }

    /// Stage one target as `t/<n>`.
    fn stage(&self, n: usize, source: &Source<'_>) -> Result<(), String> {
        let dest = self.path.join(format!("t/{n}"));
        match source {
            Source::Bytes(b) => std::fs::write(&dest, b).map_err(|e| e.to_string()),
            Source::Disk(p) => {
                let abs = std::fs::canonicalize(p).map_err(|e| e.to_string())?;
                link(&abs, &dest).map_err(|e| e.to_string())
            }
            Source::NotEvaluated(_) | Source::Excluded => Ok(()),
        }
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn link(target: &Path, dest: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, dest)
}

#[cfg(not(unix))]
fn link(target: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::hard_link(target, dest).or_else(|_| std::fs::copy(target, dest).map(|_| ()))
}

// ---------------------------------------------------------------------------
// Reading an engine's output
// ---------------------------------------------------------------------------

/// One matched string, as the engine printed it.
#[derive(Debug, Clone)]
struct StringHit {
    id: String,
    data: String,
}

/// One rule that matched one target.
#[derive(Debug, Clone)]
struct Hit {
    /// Index of the rule file (`f<n>`).
    file: usize,
    rule: String,
    /// The first match of each of the first strings, in output order.
    shown: Vec<StringHit>,
    /// Distinct strings matched beyond `shown`.
    more: Vec<String>,
    /// The earliest match offset.
    first_offset: Option<u64>,
}

/// What a run's standard output said, target by target.
#[derive(Debug, Default)]
struct Output {
    evaluated: Vec<bool>,
    hits: Vec<Vec<Hit>>,
    /// The rule the next `0x...` lines belong to.
    current: Option<(usize, usize)>,
}

impl Output {
    fn new(targets: usize) -> Output {
        Output {
            evaluated: vec![false; targets],
            hits: vec![Vec::new(); targets],
            current: None,
        }
    }

    fn line(&mut self, raw: &[u8]) {
        let text = strip_ansi(&String::from_utf8_lossy(raw));
        let line = text.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return;
        }
        if let Some(rest) = line.strip_prefix("0x") {
            self.string_line(rest);
            return;
        }
        self.current = None;
        // `<namespace>:<rule> <target>`; the target is `t/<n>`, so the last
        // word, whatever an engine prints between them.
        let mut words = line.split_whitespace();
        let (Some(first), Some(last)) = (words.next(), line.split_whitespace().next_back()) else {
            return;
        };
        let (Some((ns, rule)), Some(target)) = (first.split_once(':'), target_index(last)) else {
            return;
        };
        if target >= self.evaluated.len() {
            return;
        }
        if ns == SENTINEL_NAMESPACE && rule == SENTINEL_RULE {
            self.evaluated[target] = true;
            return;
        }
        let Some(file) = ns.strip_prefix('f').and_then(|n| n.parse::<usize>().ok()) else {
            return;
        };
        self.hits[target].push(Hit {
            file,
            rule: rule.to_string(),
            shown: Vec::new(),
            more: Vec::new(),
            first_offset: None,
        });
        self.current = Some((target, self.hits[target].len() - 1));
    }

    /// `<hex offset>:<length>:<string id>: <data>`; YARA-X may insert
    /// ` xor(<key>,<plaintext>)` after the id.
    fn string_line(&mut self, rest: &str) {
        let Some((target, h)) = self.current else {
            return;
        };
        let mut parts = rest.splitn(3, ':');
        let (Some(off), Some(_len), Some(tail)) = (parts.next(), parts.next(), parts.next()) else {
            return;
        };
        let Ok(offset) = u64::from_str_radix(off, 16) else {
            return;
        };
        let (id_part, data) = tail.split_once(": ").unwrap_or((tail, ""));
        let id = id_part
            .split_whitespace()
            .next()
            .unwrap_or(id_part)
            .to_string();
        let hit = &mut self.hits[target][h];
        hit.first_offset = Some(hit.first_offset.map_or(offset, |o| o.min(offset)));
        if hit.shown.iter().any(|s| s.id == id) || hit.more.contains(&id) {
            return;
        }
        if hit.shown.len() < SNIPPET_STRINGS {
            hit.shown.push(StringHit {
                id,
                data: shorten(data),
            });
        } else {
            hit.more.push(id);
        }
    }
}

/// `t/<n>` (as printed; `./t/<n>` or `t\<n>` too) to `n`.
fn target_index(word: &str) -> Option<usize> {
    let w = word.trim_start_matches("./").trim_start_matches(".\\");
    w.strip_prefix("t/")
        .or_else(|| w.strip_prefix("t\\"))
        .and_then(|n| n.parse().ok())
}

/// A matched string's text for a snippet: printable characters only (the
/// engines already escape the rest), cut at [`SNIPPET_CHARS`].
fn shorten(data: &str) -> String {
    let clean: String = data.chars().filter(|c| !c.is_control()).collect();
    let mut out: String = clean.chars().take(SNIPPET_CHARS).collect();
    if clean.chars().count() > SNIPPET_CHARS {
        out.push_str("...");
    }
    out
}

/// The lines of an engine's standard error that mention target `t/<n>`.
fn errors_by_target(stderr: &str) -> HashMap<usize, String> {
    let mut out: HashMap<usize, String> = HashMap::new();
    for line in stderr.lines() {
        let Some(at) = line.find("t/") else {
            continue;
        };
        let digits: String = line[at + 2..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        // Not `t/12` inside a longer word (such as `list/12`).
        let bounded = at == 0
            || !line[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '/');
        if let (true, Ok(n)) = (bounded, digits.parse::<usize>()) {
            out.entry(n).or_insert_with(|| line.trim().to_string());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Validation at load
// ---------------------------------------------------------------------------

/// Check every YARA file of a load that an external engine evaluates with
/// that engine, all in one run per engine. A file the engine refuses makes
/// its pack an error naming the file and the engine's own message; a pack
/// is never kept with rules the engine would not run.
pub fn validate_packs(packs: &[CustomPack]) -> Result<(), Vec<String>> {
    let files: Vec<&YaraFile> = packs
        .iter()
        .filter_map(|p| p.pack.yara.as_deref())
        .collect();
    validate_files(&files)
}

/// The rule files one engine checks, with the exact bytes it is given.
type CheckGroup<'a> = (Arc<Engine>, Vec<(&'a YaraFile, &'a [u8])>);

/// [`validate_packs`] for files.
pub fn validate_files(files: &[&YaraFile]) -> Result<(), Vec<String>> {
    let mut groups: Vec<CheckGroup<'_>> = Vec::new();
    for f in files {
        if let FileEngine::External { engine, source } = &f.engine {
            match groups.iter_mut().find(|(e, _)| Arc::ptr_eq(e, engine)) {
                Some((_, g)) => g.push((f, source)),
                None => groups.push((Arc::clone(engine), vec![(f, source)])),
            }
        }
    }
    let mut errors = Vec::new();
    for (engine, group) in &groups {
        errors.extend(validate_group(engine, group));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Compile `group` with `engine` over an empty file. When the batch fails,
/// the files the errors name are refused and the rest are tried again
/// (classic YARA stops at the first failing file), so every problem is
/// found and no file is accepted untried. If the engine names no file, the
/// files are checked one by one.
fn validate_group(engine: &Engine, group: &[(&YaraFile, &[u8])]) -> Vec<String> {
    let mut errors = Vec::new();
    let unchecked = |i: usize, e: &str| {
        format!(
            "{}: could not be checked with {} ({}): {e}",
            group[i].0.path.display(),
            engine.label(),
            engine.path.display()
        )
    };
    let mut remaining: Vec<usize> = (0..group.len()).collect();
    while !remaining.is_empty() {
        let sources: Vec<&[u8]> = remaining.iter().map(|i| group[*i].1).collect();
        match compile_check(engine, &sources) {
            Err(e) => {
                errors.extend(remaining.iter().map(|i| unchecked(*i, &e)));
                break;
            }
            Ok(Checked::Compiled) => break,
            Ok(Checked::Failed { by_file, .. }) if !by_file.is_empty() => {
                for (pos, msgs) in &by_file {
                    errors.push(refusal(engine, group[remaining[*pos]].0, msgs, *pos));
                }
                remaining = remaining
                    .iter()
                    .enumerate()
                    .filter(|(pos, _)| !by_file.contains_key(pos))
                    .map(|(_, i)| *i)
                    .collect();
            }
            Ok(Checked::Failed { stderr, .. }) => {
                if let [only] = remaining[..] {
                    errors.push(refusal(engine, group[only].0, &stderr, 0));
                    break;
                }
                for i in &remaining {
                    match compile_check(engine, &[group[*i].1]) {
                        Ok(Checked::Compiled) => {}
                        Ok(Checked::Failed { stderr, .. }) => {
                            errors.push(refusal(engine, group[*i].0, &stderr, 0))
                        }
                        Err(e) => errors.push(unchecked(*i, &e)),
                    }
                }
                break;
            }
        }
    }
    errors
}

/// The refusal of one file, with the engine's messages naming the file by
/// its real path rather than its temporary name (`r/<pos>.yar`).
fn refusal(engine: &Engine, file: &YaraFile, msgs: &str, pos: usize) -> String {
    let real = file.path.display().to_string();
    let text = msgs.replace(&format!("r/{pos}.yar"), &real);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut shown = lines
        .iter()
        .take(40)
        .copied()
        .collect::<Vec<_>>()
        .join("\n    ");
    if shown.is_empty() {
        shown = "(the engine printed no message)".to_string();
    }
    format!(
        "{real}: refused by {} ({}):\n    {shown}",
        engine.label(),
        engine.path.display()
    )
}

/// What an engine made of a set of rule files.
enum Checked {
    Compiled,
    Failed {
        /// Position in the set -> the engine's errors naming that file.
        by_file: HashMap<usize, String>,
        /// Everything it printed on standard error.
        stderr: String,
    },
}

/// Compile `sources` (as `f<n>`) with `engine`, scanning an empty file.
fn compile_check(engine: &Engine, sources: &[&[u8]]) -> Result<Checked, String> {
    let dir = Workdir::create().map_err(|e| format!("temporary directory: {e}"))?;
    let mut rules = dir.write_rules(sources).map_err(|e| e.to_string())?;
    // The sentinel is not needed to check rules.
    rules.pop();
    std::fs::write(dir.path.join("empty"), b"").map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&engine.path);
    if engine.kind == EngineKind::YaraX {
        cmd.arg("scan");
        if engine.has("--relaxed-re-syntax") {
            cmd.arg("--relaxed-re-syntax");
        }
    }
    if engine.has("--disable-console-logs") {
        cmd.arg("--disable-console-logs");
    }
    cmd.args(&rules).arg("empty");
    let limit = run_timeout();
    let ran = run(
        cmd,
        Some(&dir.path),
        limit,
        Arc::new(Mutex::new(|_: &[u8]| {})),
    );
    if let Some(e) = ran.spawn_error {
        return Err(e);
    }
    if ran.timed_out {
        return Err(format!(
            "no answer within {} s ({TIMEOUT_ENV})",
            limit.map(|d| d.as_secs()).unwrap_or(0)
        ));
    }
    if ran.status.is_some_and(|s| s.success()) {
        return Ok(Checked::Compiled);
    }
    Ok(Checked::Failed {
        by_file: errors_by_rule_file(&ran.stderr, sources.len()),
        stderr: ran.stderr,
    })
}

/// Group an engine's compile errors by the rule file (`r/<n>.yar`) they
/// name. YARA prints `error: rule "x" in r/3.yar(7): ...` or
/// `r/3.yar(7): error: ...`; YARA-X prints an `error[...]` line, then
/// `--> r/3.yar:7:5` and the source excerpt. Warnings are left out.
fn errors_by_rule_file(stderr: &str, files: usize) -> HashMap<usize, String> {
    let mut blocks: Vec<String> = Vec::new();
    let mut in_error = false;
    for line in stderr.lines() {
        let t = line.trim_start();
        let starts_block = t.starts_with("error") || t.starts_with("warning");
        let yara_style = t.starts_with("r/") && t.contains("): error");
        if starts_block || yara_style {
            in_error = (t.starts_with("error") || yara_style)
                && !(t.starts_with("error:") && t.ends_with("error(s) found"));
            if in_error {
                blocks.push(line.to_string());
            }
        } else if in_error {
            if let Some(b) = blocks.last_mut() {
                b.push('\n');
                b.push_str(line);
            }
        }
    }
    let mut out: HashMap<usize, String> = HashMap::new();
    for b in blocks {
        for n in rule_files_named(&b) {
            if n < files {
                let e = out.entry(n).or_default();
                if !e.is_empty() {
                    e.push('\n');
                }
                e.push_str(&b);
            }
        }
    }
    out
}

/// Every `r/<n>.yar` named in `text`.
fn rule_files_named(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("r/") {
        let tail = &rest[at + 2..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() && tail[digits.len()..].starts_with(".yar") {
            if let Ok(n) = digits.parse::<usize>() {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        rest = tail;
    }
    out
}

// ---------------------------------------------------------------------------
// Evaluation during a scan
// ---------------------------------------------------------------------------

/// Where a unit's bytes are, for an external engine.
pub enum Source<'a> {
    /// A file on disk, which the engine reads itself.
    Disk(&'a Path),
    /// Bytes held in memory (an archive member).
    Bytes(&'a [u8]),
    /// Not given to the engine, for this reason; reported as incomplete
    /// coverage.
    NotEvaluated(String),
    /// Not given to the engine and not reported (reported elsewhere, or not
    /// a file of its own).
    Excluded,
}

/// One unit of a scan: what findings are reported against, and its bytes.
pub struct Unit<'a> {
    pub rel_path: String,
    pub source: Source<'a>,
}

/// What the external engines found: findings per unit (in the order given)
/// and findings about the scan as a whole.
#[derive(Default)]
pub struct Evaluation {
    pub per_unit: Vec<Vec<Finding>>,
    pub global: Vec<Finding>,
}

/// The coverage finding for rules that were not evaluated at all:
/// `Not fully inspected: ...` on the scan as a whole.
fn not_evaluated_globally(what: String) -> Finding {
    crate::scanner::coverage::partial_finding("", what)
}

/// The findings for YARA files loaded unevaluated (no external engine): one
/// per file whose rules could have reported in an enabled phase.
pub fn unevaluated_findings(
    files: &[Arc<YaraFile>],
    phase_enabled: &dyn Fn(Phase) -> bool,
) -> Vec<Finding> {
    files
        .iter()
        .filter_map(|f| match &f.engine {
            FileEngine::Unevaluated {
                reasons,
                unavailable,
            } => Some((f, reasons, unavailable)),
            _ => None,
        })
        .filter(|(f, _, _)| f.public_rules().any(|r| phase_enabled(r.phase)))
        .map(|(f, reasons, unavailable)| {
            let first = reasons.first().map(String::as_str).unwrap_or("");
            let more = match reasons.len() {
                0 | 1 => String::new(),
                n => format!(" (+{} more)", n - 1),
            };
            not_evaluated_globally(format!(
                "YARA rules in {} ({} rule{}) were not evaluated: they need an external YARA \
                 engine and none can be used here ({unavailable}) — {first}{more}. Install \
                 YARA-X or YARA, or pass --yara-engine builtin to refuse the file instead",
                f.path.display(),
                f.public_rules().count(),
                if f.public_rules().count() == 1 {
                    ""
                } else {
                    "s"
                },
            ))
        })
        .collect()
}

/// Time limits of one evaluation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The whole evaluation, every run included ([`TIMEOUT_ENV`]); YARA-X is
    /// given what is left of it as its own `--timeout`, which bounds a whole
    /// run.
    pub total: Option<Duration>,
    /// Each file, for classic YARA, whose `--timeout` is per file: the
    /// per-file budget (`SIGIL_FILE_BUDGET_SECS`).
    pub per_file: Option<Duration>,
    /// How long past `total` the process may run before it is killed, so
    /// an engine's own time-limit message comes first.
    pub grace: Duration,
}

impl Limits {
    /// The limits the environment sets.
    pub fn from_env() -> Limits {
        Limits {
            total: run_timeout(),
            per_file: crate::scanner::budget::configured_budget(),
            grace: Duration::from_secs(10),
        }
    }
}

/// Evaluate the externally evaluated YARA `files` over `units`, one engine
/// run per engine (more only after a run that fails part-way; see
/// [`run_group`]). `scan_root` is the scan target, a directory or a single
/// file: an engine inside it, or that is it, is never run.
pub fn evaluate(
    files: &[Arc<YaraFile>],
    units: &[Unit<'_>],
    phase_enabled: &dyn Fn(Phase) -> bool,
    scan_root: Option<&Path>,
) -> Evaluation {
    evaluate_with(files, units, phase_enabled, scan_root, Limits::from_env())
}

/// [`evaluate`] with explicit limits.
pub fn evaluate_with(
    files: &[Arc<YaraFile>],
    units: &[Unit<'_>],
    phase_enabled: &dyn Fn(Phase) -> bool,
    scan_root: Option<&Path>,
    limits: Limits,
) -> Evaluation {
    let mut ev = Evaluation {
        per_unit: (0..units.len()).map(|_| Vec::new()).collect(),
        global: Vec::new(),
    };
    let mut groups: Vec<(Arc<Engine>, Vec<&YaraFile>)> = Vec::new();
    for f in files {
        let FileEngine::External { engine, .. } = &f.engine else {
            continue;
        };
        // A file none of whose rules can report in an enabled phase is not
        // worth a run.
        if !f.public_rules().any(|r| phase_enabled(r.phase)) {
            continue;
        }
        match groups.iter_mut().find(|(e, _)| Arc::ptr_eq(e, engine)) {
            Some((_, g)) => g.push(f),
            None => groups.push((Arc::clone(engine), vec![f])),
        }
    }
    if groups.is_empty() {
        return ev;
    }
    for (i, u) in units.iter().enumerate() {
        if let Source::NotEvaluated(why) = &u.source {
            ev.per_unit[i].push(crate::scanner::coverage::partial_finding(
                &u.rel_path,
                format!("not evaluated by the external YARA rules: {why}"),
            ));
        }
    }
    for (engine, group) in &groups {
        let ctx = RunContext {
            units,
            phase_enabled,
            scan_root,
            limits,
        };
        run_group(engine, group, &ctx, &mut ev);
    }
    ev
}

/// What every engine run of one evaluation shares.
struct RunContext<'a, 'u> {
    units: &'a [Unit<'u>],
    phase_enabled: &'a dyn Fn(Phase) -> bool,
    scan_root: Option<&'a Path>,
    limits: Limits,
}

/// A short summary of what a group of rule files is, for messages.
fn describe_group(group: &[&YaraFile]) -> String {
    let rules: usize = group.iter().map(|f| f.public_rules().count()).sum();
    let names: Vec<String> = group
        .iter()
        .take(3)
        .map(|f| {
            f.path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        })
        .collect();
    format!(
        "{} rule{} in {}{}",
        rules,
        if rules == 1 { "" } else { "s" },
        names.join(", "),
        if group.len() > 3 {
            format!(" and {} more file(s)", group.len() - 3)
        } else {
            String::new()
        }
    )
}

fn run_group(engine: &Engine, group: &[&YaraFile], ctx: &RunContext<'_, '_>, ev: &mut Evaluation) {
    let units = ctx.units;
    let what = describe_group(group);
    // An engine that ships inside the tree being judged is never run.
    if let Some(root) = ctx.scan_root.and_then(|r| std::fs::canonicalize(r).ok()) {
        let exe = std::fs::canonicalize(&engine.path).unwrap_or_else(|_| engine.path.clone());
        if exe.starts_with(&root) {
            ev.global.push(not_evaluated_globally(format!(
                "YARA rules ({what}) were not evaluated: the engine {} is inside the scanned \
                 tree, and Sigil never runs a program from the code it is judging",
                engine.path.display()
            )));
            return;
        }
    }
    let dir = match Workdir::create() {
        Ok(d) => d,
        Err(e) => {
            ev.global.push(not_evaluated_globally(format!(
                "YARA rules ({what}) were not evaluated: no temporary directory for {} ({e})",
                engine.label()
            )));
            return;
        }
    };
    let sources: Vec<&[u8]> = group
        .iter()
        .map(|f| match &f.engine {
            FileEngine::External { source, .. } => &source[..],
            _ => &[][..],
        })
        .collect();
    let rule_args = match dir.write_rules(&sources) {
        Ok(a) => a,
        Err(e) => {
            ev.global.push(not_evaluated_globally(format!(
                "YARA rules ({what}) were not evaluated: could not write them for {} ({e})",
                engine.label()
            )));
            return;
        }
    };

    // Stage the targets: target n is unit `staged[n]`.
    let mut staged: Vec<usize> = Vec::new();
    for (i, u) in units.iter().enumerate() {
        if !matches!(u.source, Source::Disk(_) | Source::Bytes(_)) {
            continue;
        }
        let n = staged.len();
        match dir.stage(n, &u.source) {
            Ok(()) => staged.push(i),
            Err(e) => ev.per_unit[i].push(crate::scanner::coverage::partial_finding(
                &u.rel_path,
                format!("not evaluated by the external YARA rules: could not be staged ({e})"),
            )),
        }
    }
    if staged.is_empty() {
        return;
    }

    // The first run covers every target. A run that ends early without
    // being out of time (the engine crashed, or exited with an error) is
    // followed by runs over the targets it did not finish, split in halves,
    // so that one file an engine cannot get through costs the other files
    // nothing: a half that completes is evaluated, a half that fails is
    // split again, and a single file that fails is the one reported. (What
    // an engine printed before it failed is not enough to find that file:
    // classic YARA buffers its output, so the results of files it finished
    // last are lost with it.)
    let started = Instant::now();
    let mut done = Output::new(staged.len());
    let mut errors: HashMap<usize, String> = HashMap::new();
    let mut failed_on: HashMap<usize, String> = HashMap::new();
    let mut abandoned: Vec<usize> = Vec::new();
    let mut given_up: Option<String> = None;
    let mut last_failure: Option<String> = None;
    let mut runs = 0usize;
    let mut queue: std::collections::VecDeque<Vec<usize>> =
        std::collections::VecDeque::from([(0..staged.len()).collect::<Vec<usize>>()]);
    while let Some(batch) = queue.pop_front() {
        if given_up.is_some() {
            abandoned.extend(batch);
            continue;
        }
        if runs >= MAX_RUNS {
            given_up = Some(format!(
                "{} (gave up after {MAX_RUNS} runs)",
                last_failure.clone().unwrap_or_default()
            ));
            abandoned.extend(batch);
            continue;
        }
        let left = ctx
            .limits
            .total
            .map(|t| t.saturating_sub(started.elapsed()));
        if left.is_some_and(|l| l.is_zero()) {
            given_up = Some(time_limit_reached(ctx.limits.total));
            abandoned.extend(batch);
            continue;
        }
        runs += 1;
        let mut pass = run_once(engine, &dir, &rule_args, &batch, staged.len(), left, ctx);
        for &n in &batch {
            if pass.output.evaluated[n] {
                done.evaluated[n] = true;
                done.hits[n] = std::mem::take(&mut pass.output.hits[n]);
            } else if let Some(m) = pass.errors.remove(&n) {
                errors.entry(n).or_insert(m);
            }
        }
        let unfinished = |errors: &HashMap<usize, String>| -> Vec<usize> {
            batch
                .iter()
                .copied()
                .filter(|n| !done.evaluated[*n] && !errors.contains_key(n))
                .collect()
        };
        match pass.failure {
            None => {}
            Some(RunFailure::Final(why)) => {
                // Out of time (or not started): what the batch left, errors
                // included, is said once for the scan.
                given_up = Some(why);
                abandoned.extend(batch.iter().copied().filter(|n| !done.evaluated[*n]));
            }
            Some(RunFailure::Retry(why)) => {
                let left = unfinished(&errors);
                match left.len() {
                    0 => {}
                    1 => {
                        failed_on.insert(left[0], why);
                    }
                    k => {
                        let (a, b) = left.split_at(k / 2);
                        queue.push_back(a.to_vec());
                        queue.push_back(b.to_vec());
                        last_failure = Some(why);
                    }
                }
            }
        }
    }

    if let Some(why) = &given_up {
        if !abandoned.is_empty() {
            ev.global.push(not_evaluated_globally(format!(
                "YARA rules ({what}) were not evaluated on {} of {} file(s): {} ({}) {why}",
                abandoned.len(),
                staged.len(),
                engine.label(),
                engine.path.display()
            )));
        }
    }
    let abandoned: std::collections::HashSet<usize> = abandoned.into_iter().collect();

    let per_file_timeout = ctx
        .limits
        .per_file
        .filter(|_| engine.kind == EngineKind::Yara);
    let rules: Vec<HashMap<&str, &YaraRule>> = group
        .iter()
        .map(|f| f.rules.iter().map(|r| (r.name.as_str(), r)).collect())
        .collect();
    for (n, unit_idx) in staged.iter().enumerate() {
        let unit = &units[*unit_idx];
        if !done.evaluated[n] {
            // A file the engine did not finish: its matches, if any, are
            // not reported either way (a cut-short evaluation can make
            // `not $a` true), and the file is reported as not fully
            // inspected. Files left when the engine was given up on are
            // said once, above.
            if abandoned.contains(&n) {
                continue;
            }
            let finding = if let Some(why) = failed_on.get(&n) {
                crate::scanner::coverage::partial_finding(
                    &unit.rel_path,
                    format!(
                        "not evaluated by the external YARA rules: {} ({}) {why} on this file, \
                         run on its own",
                        engine.label(),
                        engine.path.display()
                    ),
                )
            } else {
                let why = errors
                    .get(&n)
                    .map(|m| m.replace(&format!("t/{n}"), &unit.rel_path));
                match &why {
                    Some(m) if m.to_ascii_lowercase().contains("timed out") => {
                        crate::scanner::budget_finding(&unit.rel_path, per_file_timeout)
                    }
                    _ => crate::scanner::coverage::partial_finding(
                        &unit.rel_path,
                        format!(
                            "not evaluated by the external YARA rules ({}): {}",
                            engine.label(),
                            why.unwrap_or_else(|| "the engine returned no result for it".into())
                        ),
                    ),
                }
            };
            ev.per_unit[*unit_idx].push(finding);
            continue;
        }
        // The unit's bytes are read once for all its matches' lines.
        let offsets: Vec<u64> = done.hits[n].iter().filter_map(|h| h.first_offset).collect();
        let lines: HashMap<u64, usize> = if offsets.is_empty() {
            HashMap::new()
        } else {
            lines_at(&unit.source, &offsets)
        };
        for hit in &done.hits[n] {
            let Some(file_rules) = rules.get(hit.file) else {
                continue;
            };
            // A match of a rule the outline did not list (it should list
            // every rule) is still reported, at the default severity and
            // phase, rather than dropped.
            let unlisted;
            let rule = match file_rules.get(hit.rule.as_str()) {
                Some(r) => *r,
                None => {
                    unlisted = unlisted_rule(&hit.rule);
                    &unlisted
                }
            };
            if rule.private || !(ctx.phase_enabled)(rule.phase) {
                continue;
            }
            let line = hit.first_offset.and_then(|o| lines.get(&o).copied());
            ev.per_unit[*unit_idx].push(finding(engine, rule, hit, &unit.rel_path, line));
        }
    }
}

/// Most engine runs one evaluation makes: the first over every file, then,
/// after a run that fails part-way, runs over halves of what it left (see
/// [`run_group`]). Bounded because each run compiles the rules again.
const MAX_RUNS: usize = 16;

/// Why one run did not complete.
enum RunFailure {
    /// It could not be started, or ran out of time: nothing more is tried.
    Final(String),
    /// It crashed or exited with an error: what it left is tried again.
    Retry(String),
}

/// What one run over a batch of targets produced.
struct Pass {
    output: Output,
    /// Per-target errors from its standard error, for targets of the batch.
    errors: HashMap<usize, String>,
    failure: Option<RunFailure>,
}

/// The message for a run stopped by [`TIMEOUT_ENV`].
fn time_limit_reached(total: Option<Duration>) -> String {
    format!(
        "stopped at its time limit of {} s ({TIMEOUT_ENV}; 0 for none)",
        total.map(|t| t.as_secs()).unwrap_or(0)
    )
}

/// Run `engine` once over the targets `batch` (`t/<n>`), with `left` of the
/// evaluation's time.
fn run_once(
    engine: &Engine,
    dir: &Workdir,
    rule_args: &[String],
    batch: &[usize],
    targets: usize,
    left: Option<Duration>,
    ctx: &RunContext<'_, '_>,
) -> Pass {
    let failed = |why: RunFailure| Pass {
        output: Output::new(targets),
        errors: HashMap::new(),
        failure: Some(why),
    };
    let list: String = batch.iter().map(|n| format!("t/{n}\n")).collect();
    if let Err(e) = std::fs::write(dir.path.join("list"), &list) {
        return failed(RunFailure::Final(format!(
            "could not be given its scan list ({e})"
        )));
    }
    let mut cmd = Command::new(&engine.path);
    match engine.kind {
        EngineKind::YaraX => {
            cmd.args([
                "scan",
                "--print-namespace",
                "--print-strings=48",
                "--scan-list",
            ]);
            for f in [
                "--disable-console-logs",
                "--disable-warnings",
                "--relaxed-re-syntax",
            ] {
                if engine.has(f) {
                    cmd.arg(f);
                }
            }
            // YARA-X's timeout bounds the whole run: what is left of the
            // evaluation's, in whole seconds rounded up (the watchdog below
            // still stops it at the bound plus the grace).
            if let Some(t) = left {
                cmd.arg(format!(
                    "--timeout={}",
                    t.as_secs_f64().ceil().max(1.0) as u64
                ));
            }
        }
        EngineKind::Yara => {
            cmd.args([
                "--print-namespace",
                "--print-strings",
                "--print-string-length",
                "--scan-list",
            ]);
            for f in ["--disable-console-logs", "--no-warnings"] {
                if engine.has(f) {
                    cmd.arg(f);
                }
            }
            // Classic YARA's timeout is per file: the per-file budget.
            if let Some(b) = ctx.limits.per_file {
                cmd.arg(format!(
                    "--timeout={}",
                    b.as_secs_f64().ceil().max(1.0) as u64
                ));
            }
        }
    }
    cmd.args(rule_args).arg("list");
    let output = Arc::new(Mutex::new(Output::new(targets)));
    let sink = Arc::clone(&output);
    // A little past the engine's own bound, so its own message comes first.
    let watchdog = left.map(|t| t + ctx.limits.grace);
    let ran = run(
        cmd,
        Some(&dir.path),
        watchdog,
        Arc::new(Mutex::new(move |line: &[u8]| {
            if let Ok(mut o) = sink.lock() {
                o.line(line);
            }
        })),
    );
    // What the engine said so far (all of it, unless a reader was left
    // behind on a pipe some child of the engine still holds).
    let mut output = match output.lock() {
        Ok(mut o) => std::mem::take(&mut *o),
        Err(_) => Output::new(targets),
    };
    // Only this batch's targets count (an engine prints nothing else).
    let mut in_batch = vec![false; targets];
    for &n in batch {
        in_batch[n] = true;
    }
    for (n, wanted) in in_batch.iter().enumerate() {
        if !wanted {
            output.evaluated[n] = false;
            output.hits[n].clear();
        }
    }
    let errors: HashMap<usize, String> = errors_by_target(&ran.stderr)
        .into_iter()
        .filter(|(n, _)| in_batch.get(*n).copied().unwrap_or(false))
        .collect();
    let first_error = ran
        .stderr
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("error"))
        .map(str::to_string);
    let yara_x_timed_out = engine.kind == EngineKind::YaraX
        && errors
            .values()
            .any(|m| m.to_ascii_lowercase().contains("timeout"));
    let failure = if let Some(e) = &ran.spawn_error {
        Some(RunFailure::Final(format!("could not be started ({e})")))
    } else if ran.timed_out || yara_x_timed_out {
        Some(RunFailure::Final(time_limit_reached(ctx.limits.total)))
    } else if !ran.status.is_some_and(|s| s.success()) {
        Some(RunFailure::Retry(format!(
            "failed (exit status {}){}",
            ran.status
                .and_then(|s| s.code())
                .map(|c| c.to_string())
                .unwrap_or_else(|| "none: killed by a signal".into()),
            first_error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        )))
    } else {
        None
    };
    Pass {
        output,
        errors,
        failure,
    }
}

/// A rule an engine reported that Sigil's outline of its file did not list.
fn unlisted_rule(name: &str) -> YaraRule {
    YaraRule {
        name: name.to_string(),
        id: super::sigil_id(name).unwrap_or_else(|| "YARA-UNNAMED".to_string()),
        line: 0,
        private: false,
        global: false,
        tags: Vec::new(),
        description: super::default_description(name),
        author: None,
        references: Vec::new(),
        severity: super::DEFAULT_SEVERITY,
        phase: super::DEFAULT_PHASE,
        remediation: None,
        strings: Vec::new(),
        condition: super::Expr::Bool(false),
        source: String::new(),
    }
}

/// The finding for one rule that matched one unit.
fn finding(
    engine: &Engine,
    rule: &YaraRule,
    hit: &Hit,
    rel_path: &str,
    line: Option<usize>,
) -> Finding {
    let mut shown: Vec<String> = hit
        .shown
        .iter()
        .map(|s| format!("{}: {}", s.id, s.data))
        .collect();
    if !hit.more.is_empty() {
        shown.push(format!("+{} more", hit.more.len()));
    }
    let what = if shown.is_empty() {
        "its condition, with no string match".to_string()
    } else {
        shown.join(", ")
    };
    let head = if rule.description == super::default_description(&rule.name) {
        String::new()
    } else {
        format!("{}: ", rule.description)
    };
    Finding {
        phase: rule.phase,
        rule: rule.id.clone(),
        severity: rule.severity,
        file: rel_path.to_string(),
        line,
        snippet: format!(
            "{head}YARA rule {} matched {what} (evaluated by {})",
            rule.name,
            engine.label()
        ),
        weight: rule.phase.default_weight(),
        kev: false,
        epss: 0.0,
        fingerprint: String::new(),
        locator: None,
        evidence: crate::corpus::schema::Evidence::Standalone,
    }
}

/// Counts newlines through a unit's bytes, fed in order, and records the
/// line each wanted offset falls on.
struct LineCounter {
    /// Wanted offsets, ascending, without repeats.
    wanted: Vec<u64>,
    next: usize,
    pos: u64,
    newlines: usize,
    found: HashMap<u64, usize>,
}

impl LineCounter {
    fn new(offsets: &[u64]) -> LineCounter {
        let mut wanted = offsets.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        LineCounter {
            found: HashMap::with_capacity(wanted.len()),
            wanted,
            next: 0,
            pos: 0,
            newlines: 0,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        let count = |b: &[u8]| b.iter().filter(|c| **c == b'\n').count();
        let mut start = 0usize;
        while let Some(&want) = self.wanted.get(self.next) {
            let Ok(upto) = usize::try_from(want - self.pos) else {
                break;
            };
            if upto > chunk.len() {
                break;
            }
            self.newlines += count(&chunk[start..upto]);
            start = upto;
            self.found.insert(want, self.newlines + 1);
            self.next += 1;
        }
        self.newlines += count(&chunk[start..]);
        self.pos += chunk.len() as u64;
    }

    /// The lines found; an offset past the end (an engine should report
    /// none) is on the last line.
    fn finish(mut self) -> HashMap<u64, usize> {
        for want in &self.wanted[self.next..] {
            self.found.insert(*want, self.newlines + 1);
        }
        self.found
    }
}

/// The line of each byte offset in a unit, as the built-in engine reports
/// it, reading the unit once. Empty for binary content (a file that is not
/// decodable text; for one over the content-scan size, a NUL in its first
/// 2 MB, as for its head and tail; for an archive member, any NUL byte).
fn lines_at(source: &Source<'_>, offsets: &[u64]) -> HashMap<u64, usize> {
    use std::io::{Seek, SeekFrom};
    let mut lines = LineCounter::new(offsets);
    match source {
        Source::Bytes(b) => {
            if b.contains(&0) {
                return HashMap::new();
            }
            lines.feed(b);
        }
        Source::Disk(p) => {
            let Ok(meta) = std::fs::metadata(p) else {
                return HashMap::new();
            };
            if meta.len() <= crate::scanner::MAX_CONTENT_SCAN_BYTES {
                let Ok(bytes) = std::fs::read(p) else {
                    return HashMap::new();
                };
                if crate::scanner::textdecode::decode(&bytes).is_none() {
                    return HashMap::new();
                }
                lines.feed(&bytes);
                return lines.finish();
            }
            let Ok(mut file) = std::fs::File::open(p) else {
                return HashMap::new();
            };
            let mut head = Vec::new();
            if (&mut file).take(2_000_000).read_to_end(&mut head).is_err()
                || head.contains(&0)
                || file.seek(SeekFrom::Start(0)).is_err()
            {
                return HashMap::new();
            }
            let last = offsets.iter().copied().max().unwrap_or(0);
            let mut before = file.take(last);
            let mut buf = vec![0u8; 1 << 20];
            while let Ok(n) = before.read(&mut buf) {
                if n == 0 {
                    break;
                }
                lines.feed(&buf[..n]);
            }
        }
        Source::NotEvaluated(_) | Source::Excluded => return HashMap::new(),
    }
    lines.finish()
}

#[cfg(test)]
mod tests;
