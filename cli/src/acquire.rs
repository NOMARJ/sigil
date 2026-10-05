//! What `sigil pip` and `sigil npm` hand to pip and npm.
//!
//! Both commands exist to look at a package *before* any of its code runs.
//! pip and npm will run package code while merely fetching it in several
//! cases, so by default Sigil only asks them for things that need no build:
//!
//! - pip: `pip download` of a source distribution prepares its metadata by
//!   running the package's own setup code (setup.py or its build backend).
//!   Sigil passes `--only-binary=:all:` so pip fetches prebuilt wheels only.
//!   That option does not cover a requirement that names a local path, a URL
//!   or a VCS checkout (pip 24.0 builds those regardless), so such specs are
//!   refused before pip runs, as is a name that pip would read as an archive
//!   file in the working directory (`foo.tar.gz`).
//! - npm: `npm pack` runs a local directory's prepack/prepare/postpack
//!   scripts, and for a git spec it clones, installs and prepares the
//!   checkout. Sigil passes `--ignore-scripts`, but npm 10.9.7 (pacote
//!   19.0.2) still runs a directory's or git checkout's `prepare` script with
//!   that flag set, so anything that is not a registry package by name is
//!   refused before npm runs.
//!
//! By default pip runs in the (empty) quarantine directory, so nothing in
//! the caller's directory can be read as a local archive; npm always runs
//! there, where it writes the tarball.
//!
//! `--allow-build-scripts` lifts the refusal and drops the two options, for
//! code the user already trusts, and runs pip from the caller's directory
//! (as 1.3.7 did) so a relative path means what the user typed; the command
//! then prints a warning that the package's own code may run on this machine
//! before the scan.
//!
//! Every spec is passed after `--`, and one starting with `-` is refused
//! outright, so a spec can never be read as an option.

use std::ffi::OsString;
use std::path::Path;

/// The opt-in flag, as the user types it.
pub const ALLOW_BUILD_SCRIPTS: &str = "--allow-build-scripts";

/// pip's archive suffixes (`pip._internal.utils.filetypes`): a requirement
/// ending in one is read as a file path, built if it is a source archive.
const PIP_ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip",
    ".whl",
    ".tar.bz2",
    ".tbz",
    ".tar.gz",
    ".tgz",
    ".tar",
    ".tar.xz",
    ".txz",
    ".tlz",
    ".tar.lz",
    ".tar.lzma",
];

/// npm-package-arg's `isFileType`: a name or range ending in one is a
/// tarball path.
const NPM_TARBALL_SUFFIXES: &[&str] = &[".tgz", ".tar.gz", ".tar"];

/// Which package manager a spec is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Pip,
    Npm,
}

impl Manager {
    fn command(self) -> &'static str {
        match self {
            Manager::Pip => "pip",
            Manager::Npm => "npm",
        }
    }
}

/// Why a spec was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// Never handed to pip or npm, with or without `--allow-build-scripts`
    /// (empty, starts with `-`, contains a control character).
    Unusable(String),
    /// Something other than a registry package by name: pip or npm would
    /// build it or run its scripts. Accepted with `--allow-build-scripts`.
    NotRegistry(String),
    /// Not a well-formed registry spec. Passed through unchecked with
    /// `--allow-build-scripts` (pip or npm then reports it).
    Malformed(String),
}

/// The spec `sigil pip <package> [-V <version>]` downloads.
pub fn pip_spec(package: &str, version: Option<&str>) -> String {
    match version {
        Some(v) => format!("{package}=={v}"),
        None => package.to_string(),
    }
}

/// The spec `sigil npm <package> [-V <version>]` packs.
pub fn npm_spec(package: &str, version: Option<&str>) -> String {
    match version {
        Some(v) => format!("{package}@{v}"),
        None => package.to_string(),
    }
}

/// Check a spec before anything is created or run. With
/// `allow_build_scripts`, only [`SpecError::Unusable`] is returned.
pub fn check_spec(
    manager: Manager,
    spec: &str,
    allow_build_scripts: bool,
) -> Result<(), SpecError> {
    if spec.trim().is_empty() {
        return Err(SpecError::Unusable("the package spec is empty".into()));
    }
    if spec.trim_start().starts_with('-') {
        return Err(SpecError::Unusable(
            "a package spec cannot start with '-' (it would be read as an option)".into(),
        ));
    }
    if spec.chars().any(char::is_control) {
        return Err(SpecError::Unusable(
            "the package spec contains a control character".into(),
        ));
    }
    if allow_build_scripts {
        return Ok(());
    }
    match manager {
        Manager::Pip => check_pip(spec),
        Manager::Npm => check_npm(spec),
    }
}

/// `pip download` arguments (after the `pip` command word). By default it
/// is run with the quarantine directory as the working directory too, so
/// nothing in the caller's directory can be picked up as a local archive.
pub fn pip_download_args(dest: &Path, spec: &str, allow_build_scripts: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["download".into(), "--no-deps".into()];
    if !allow_build_scripts {
        args.push("--only-binary=:all:".into());
    }
    args.push("--dest".into());
    args.push(dest.as_os_str().to_owned());
    args.push("--".into());
    args.push(spec.into());
    args
}

/// `npm pack` arguments (after the `npm` command word). Run in the
/// quarantine directory, where the tarball is written.
pub fn npm_pack_args(spec: &str, allow_build_scripts: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["pack".into()];
    if !allow_build_scripts {
        args.push("--ignore-scripts".into());
    }
    args.push("--".into());
    args.push(spec.into());
    args
}

/// The refusal printed (after `error: `) when [`check_spec`] fails.
pub fn refusal(manager: Manager, spec: &str, err: &SpecError) -> String {
    let cmd = manager.command();
    let example = match manager {
        Manager::Pip => "`sigil pip requests` or `sigil pip requests==2.32.3`",
        Manager::Npm => "`sigil npm left-pad` or `sigil npm left-pad@1.3.0`",
    };
    match err {
        SpecError::Unusable(why) => format!("sigil {cmd} will not download `{spec}`: {why}."),
        SpecError::NotRegistry(why) => {
            let runs = match manager {
                Manager::Pip => {
                    "By default only index packages named directly are fetched: pip builds a \
                     local path, URL or VCS checkout by running the package's own setup code \
                     (setup.py or its build backend), even with --only-binary=:all:, on this \
                     machine, before Sigil can scan it"
                }
                Manager::Npm => {
                    "By default only registry packages named directly are fetched: npm runs a \
                     local directory's or git checkout's prepare script while packing it, even \
                     with --ignore-scripts, on this machine, before Sigil can scan it"
                }
            };
            format!(
                "sigil {cmd} will not download `{spec}`: {why}.\n  {runs}.\n  \
                 Name a registry package instead, e.g. {example}.\n  \
                 To accept that risk for code you already trust, re-run with {ALLOW_BUILD_SCRIPTS}."
            )
        }
        SpecError::Malformed(why) => {
            let expected = match manager {
                Manager::Pip => {
                    "a package name with optional [extras] and version specifiers, e.g. \
                     requests, requests[socks], requests==2.32.3 or \"requests>=2,<3\""
                }
                Manager::Npm => {
                    "a package name (scoped allowed) with an optional @version, @tag or @range, \
                     e.g. left-pad, @types/node, left-pad@1.3.0, left-pad@latest or \"left-pad@^1.3\""
                }
            };
            format!("sigil {cmd} will not download `{spec}`: {why}.\n  Expected {expected}.")
        }
    }
}

/// The warning printed (after `warning: `) when `--allow-build-scripts` is
/// given.
pub fn opt_in_warning(manager: Manager, spec: &str) -> String {
    let what = match manager {
        Manager::Pip => format!(
            "pip may build `{spec}` from source (a source distribution, local path, URL or VCS \
             checkout), which runs the package's own setup code (setup.py or its build backend)"
        ),
        Manager::Npm => format!(
            "npm may run `{spec}`'s lifecycle scripts while packing it (a directory's prepare, \
             prepack and postpack; for a git spec it also installs the checkout's dependencies, \
             which runs install scripts, and its prepare script)"
        ),
    };
    format!(
        "{ALLOW_BUILD_SCRIPTS}: {what} on this machine, with your privileges, BEFORE Sigil scans \
         anything. Quarantine does not contain that code. Only use this for code you already trust."
    )
}

/// Printed after a failed default `pip download`: the commonest cause is a
/// package (or version) published only as a source distribution.
pub fn pip_wheel_only_hint(spec: &str) -> String {
    format!(
        "Sigil asks pip for prebuilt wheels only (--only-binary=:all:), so nothing in the package \
         runs before the scan. If `{spec}` (or that version of it) is published only as a source \
         distribution, there is no wheel to fetch, and building one would run its setup code on \
         this machine. To accept that for code you already trust, re-run with {ALLOW_BUILD_SCRIPTS}."
    )
}

// ---------------------------------------------------------------------------
// pip: a PEP 508 requirement without a URL or environment marker
// ---------------------------------------------------------------------------

fn ends_with_any(s: &str, suffixes: &[&str]) -> bool {
    let lower = s.to_ascii_lowercase();
    suffixes.iter().any(|x| lower.ends_with(x))
}

/// A URL scheme at the start (`https:`, `git+ssh:`, `file:`, `c:` too).
fn has_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for c in chars {
        match c {
            ':' => return true,
            c if c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-') => {}
            _ => return false,
        }
    }
    false
}

/// A PEP 508 name: ASCII letters and digits, with `.`, `_` and `-` inside.
fn is_pep508_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn check_pip(spec: &str) -> Result<(), SpecError> {
    let lower = spec.to_ascii_lowercase();
    for vcs in ["git+", "hg+", "svn+", "bzr+"] {
        if lower.starts_with(vcs) {
            return Err(SpecError::NotRegistry("it is a VCS reference".into()));
        }
    }
    if spec.contains("://") || has_scheme(spec) {
        return Err(SpecError::NotRegistry("it is a URL".into()));
    }
    if spec.contains('@') {
        return Err(SpecError::NotRegistry(
            "it is a direct reference (`name @ url`)".into(),
        ));
    }
    if spec.contains('/') || spec.contains('\\') || spec.starts_with('.') || spec.starts_with('~') {
        return Err(SpecError::NotRegistry("it is a local path".into()));
    }
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(spec.len());
    // pip reads `foo.tar.gz`, `foo.whl[x]` and `foo==1.zip` as files.
    if ends_with_any(spec, PIP_ARCHIVE_SUFFIXES)
        || ends_with_any(&spec[..name_end], PIP_ARCHIVE_SUFFIXES)
    {
        return Err(SpecError::NotRegistry(
            "pip reads it as an archive file path".into(),
        ));
    }
    parse_pip_requirement(spec).map_err(SpecError::Malformed)
}

/// `name [extras] [specifier ("," specifier)*]`, whitespace allowed between
/// tokens. Versions take PEP 440's characters (`*` for `==1.*`, `!` for an
/// epoch, `+` for a local label).
fn parse_pip_requirement(spec: &str) -> Result<(), String> {
    let b = spec.as_bytes();
    let mut i = 0;
    let name = take_name(spec, &mut i);
    if !is_pep508_name(name) {
        return Err("it does not start with a valid package name".into());
    }
    skip_ws(b, &mut i);
    if b.get(i) == Some(&b'[') {
        i += 1;
        skip_ws(b, &mut i);
        if b.get(i) == Some(&b']') {
            i += 1;
        } else {
            loop {
                skip_ws(b, &mut i);
                if !is_pep508_name(take_name(spec, &mut i)) {
                    return Err("an extra is not a valid name".into());
                }
                skip_ws(b, &mut i);
                match b.get(i) {
                    Some(b',') => i += 1,
                    Some(b']') => {
                        i += 1;
                        break;
                    }
                    _ => return Err("the [extras] list is not closed".into()),
                }
            }
        }
        skip_ws(b, &mut i);
    }
    if i == b.len() {
        return Ok(());
    }
    loop {
        skip_ws(b, &mut i);
        let rest = &spec[i..];
        let op = ["===", "~=", "==", "!=", "<=", ">=", "<", ">"]
            .into_iter()
            .find(|op| rest.starts_with(op))
            .ok_or("expected a version specifier (==, >=, <=, !=, ~=, <, >, ===)")?;
        i += op.len();
        skip_ws(b, &mut i);
        let start = i;
        while i < b.len()
            && (b[i].is_ascii_alphanumeric()
                || matches!(b[i], b'.' | b'_' | b'-' | b'+' | b'!' | b'*'))
        {
            i += 1;
        }
        if i == start {
            return Err(format!("`{op}` is not followed by a version"));
        }
        skip_ws(b, &mut i);
        match b.get(i) {
            None => return Ok(()),
            Some(b',') => i += 1,
            Some(_) => {
                return Err("it has text after the version specifiers \
                            (environment markers are not accepted)"
                    .into())
            }
        }
    }
}

/// The run of name characters at `*i`, advancing past it.
fn take_name<'a>(s: &'a str, i: &mut usize) -> &'a str {
    let b = s.as_bytes();
    let start = *i;
    while *i < b.len() && (b[*i].is_ascii_alphanumeric() || matches!(b[*i], b'.' | b'_' | b'-')) {
        *i += 1;
    }
    &s[start..*i]
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t') {
        *i += 1;
    }
}

// ---------------------------------------------------------------------------
// npm: a registry package name with an optional version, tag or range
// ---------------------------------------------------------------------------

/// A name or scope segment: letters, digits, `.`, `_`, `~`, `-`, starting
/// with a letter or digit (npm refuses a leading `.` or `_`). Uppercase is
/// allowed: older registry packages use it.
fn is_npm_segment(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'~' | b'-'))
}

fn check_npm(spec: &str) -> Result<(), SpecError> {
    let lower = spec.to_ascii_lowercase();
    if ["github:", "gitlab:", "bitbucket:", "gist:", "git:", "git+"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return Err(SpecError::NotRegistry("it is a git spec".into()));
    }
    if lower.starts_with("file:") {
        return Err(SpecError::NotRegistry("it is a local file: spec".into()));
    }
    if spec.contains("://") || has_scheme(spec) {
        return Err(SpecError::NotRegistry(
            "it is a URL (a tarball or a git repository)".into(),
        ));
    }
    if spec.starts_with('.')
        || spec.starts_with('/')
        || spec.starts_with('~')
        || spec.contains('\\')
    {
        return Err(SpecError::NotRegistry("it is a local path".into()));
    }

    // `name` / `@scope/name`, then an optional `@<version|tag|range>`.
    let (scope, rest) = match spec.strip_prefix('@') {
        Some(r) => match r.split_once('/') {
            Some((scope, rest)) => (Some(scope), rest),
            None => {
                return Err(SpecError::Malformed(
                    "a scoped name needs `@scope/name`".into(),
                ))
            }
        },
        None => (None, spec),
    };
    let (name, range) = match rest.split_once('@') {
        Some((n, r)) => (n, Some(r)),
        None => (rest, None),
    };
    let lower_range = range.map(str::to_ascii_lowercase);
    if lower_range
        .as_deref()
        .is_some_and(|r| r.starts_with("npm:"))
    {
        return Err(SpecError::NotRegistry(
            "it is an npm: alias (name the package directly)".into(),
        ));
    }
    if spec.contains(':') {
        return Err(SpecError::NotRegistry(
            "it is a git spec or URL (it contains ':')".into(),
        ));
    }
    if spec.contains('#') {
        return Err(SpecError::NotRegistry(
            "it is a git spec (`#` names a commit or branch)".into(),
        ));
    }
    if name.contains('/') || range.is_some_and(|r| r.contains('/')) {
        let why = if scope.is_none() && range.is_none() && name.split('/').count() == 2 {
            "it is a GitHub owner/repo shorthand, which npm fetches with git"
        } else {
            "it is a path or git spec, not a registry name"
        };
        return Err(SpecError::NotRegistry(why.into()));
    }
    if ends_with_any(name, NPM_TARBALL_SUFFIXES)
        || range.is_some_and(|r| ends_with_any(r, NPM_TARBALL_SUFFIXES))
    {
        return Err(SpecError::NotRegistry(
            "npm reads it as a tarball file path".into(),
        ));
    }

    if let Some(scope) = scope {
        if !is_npm_segment(scope) {
            return Err(SpecError::Malformed("the scope is not a valid name".into()));
        }
    }
    if !is_npm_segment(name) {
        return Err(SpecError::Malformed("the package name is not valid".into()));
    }
    // npm-package-arg reads a range starting with `.` as a file path.
    if range.is_some_and(|r| r.starts_with('.')) {
        return Err(SpecError::NotRegistry(
            "npm reads the part after `@` as a file path".into(),
        ));
    }
    if let Some(r) = range {
        // Words of a range start with a version, an operator or `x`/`*`;
        // the one word that starts with `-` is the hyphen-range operator
        // (`1.2.3 - 2.0.0`).
        let valid = !r.trim().is_empty()
            && !r.starts_with(' ')
            && r.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '.' | '_' | '-' | '+' | '^' | '~' | '<' | '>' | '=' | '*' | '|' | ' '
                    )
            })
            && r.split(' ').all(|w| w == "-" || !w.starts_with('-'));
        if !valid {
            return Err(SpecError::Malformed(
                "the part after `@` is not a version, tag or range".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "acquire_tests.rs"]
mod tests;
