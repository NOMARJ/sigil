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
//!   file in the working directory (`foo.tar.gz`). pip can also be handed
//!   such requirements by its environment (`PIP_REQUIREMENT`,
//!   `PIP_CONSTRAINT`, `PIP_EDITABLE`), which Sigil removes from pip's
//!   environment, or by a config file, which Sigil reads with `pip config
//!   list` and refuses.
//!
//!   A wheel-only download of an unpinned or ranged spec would quietly fall
//!   back to an older release when the newest one has no wheel, so Sigil
//!   first asks the index which versions exist (`pip index versions`, which
//!   builds nothing), picks the one `pip install <spec>` would pick, and
//!   downloads exactly that one; when it has no wheel the command fails.
//! - npm: `npm pack` runs a local directory's prepack/prepare/postpack
//!   scripts, and for a git spec it clones, installs and prepares the
//!   checkout. Sigil passes `--ignore-scripts`, but npm 10.9.7 (pacote
//!   19.0.2) still runs a directory's or git checkout's `prepare` script with
//!   that flag set, so anything that is not a registry package by name is
//!   refused before npm runs. A registry's metadata can itself point a
//!   version's tarball at a git repository, so Sigil resolves the spec with
//!   `npm view` first, checks the tarball URL is a plain http(s) download,
//!   and packs that URL.
//!
//! By default pip and npm run in the (empty) quarantine directory, so nothing
//! in the caller's directory can be read as a local archive.
//!
//! `--allow-build-scripts` lifts the refusals and drops the two options, for
//! code the user already trusts, and runs pip and npm from the caller's
//! directory (as 1.3.7 did for pip) so a relative path means what the user
//! typed; the command then prints a warning that the package's own code may
//! run on this machine before the scan.
//!
//! Every spec is passed after `--`, and one starting with `-` is refused
//! outright, so a spec can never be read as an option.

use std::cmp::Ordering;
use std::ffi::OsString;
use std::path::Path;

use crate::pep440::{self, Specifier};

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

/// pip options that add requirements of their own to every `pip download`.
/// A requirement, constraint or editable entry can name a local path, URL or
/// VCS checkout, which pip builds even with `--only-binary=:all:`.
const PIP_ADDED_REQUIREMENTS: &[&str] = &["requirement", "constraint", "editable"];

/// hosted-git-info's hosts (npm 10.9.7): npm reads an http(s) URL on one of
/// them (with or without `www.`) as a git repository, not a tarball.
const NPM_GIT_HOSTS: &[&str] = &[
    "github.com",
    "gist.github.com",
    "gitlab.com",
    "bitbucket.org",
    "git.sr.ht",
];

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
    /// An `npm:` alias: it stands for another registry package, named
    /// here. Accepted with `--allow-build-scripts`.
    Alias(String),
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
        Manager::Pip => check_pip(spec).map(|_| ()),
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

/// `pip index versions` arguments: every version the index has of `name`
/// that pip could install here (wheels for this platform or a source
/// distribution), pre-releases included, yanked ones not. Builds nothing.
pub fn pip_index_args(name: &str) -> Vec<OsString> {
    ["index", "versions", "--pre", "--", name]
        .into_iter()
        .map(OsString::from)
        .collect()
}

/// `npm view` arguments: what the registry says `spec` resolves to. Runs
/// nothing from the package.
pub fn npm_view_args(spec: &str) -> Vec<OsString> {
    [
        "view",
        "--json",
        "--",
        spec,
        "name",
        "version",
        "dist.tarball",
        "deprecated",
        "dist-tags.latest",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

/// `npm pack` arguments (after the `npm` command word). By default `target`
/// is a resolved tarball URL and npm runs in the quarantine directory, where
/// it writes the tarball. With the opt-in, npm runs in the caller's
/// directory, so `pack_destination` names the quarantine directory.
pub fn npm_pack_args(
    target: &str,
    allow_build_scripts: bool,
    pack_destination: Option<&Path>,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["pack".into()];
    if !allow_build_scripts {
        args.push("--ignore-scripts".into());
    }
    if let Some(dest) = pack_destination {
        args.push("--pack-destination".into());
        args.push(dest.as_os_str().to_owned());
    }
    args.push("--".into());
    args.push(target.into());
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
            let path_hint = if manager == Manager::Npm && is_relative_npm_path(spec) {
                " (a relative path is read from your current directory)"
            } else {
                ""
            };
            format!(
                "sigil {cmd} will not download `{spec}`: {why}.\n  {runs}.\n  \
                 Name a registry package instead, e.g. {example}.\n  \
                 To accept that risk for code you already trust, re-run with \
                 {ALLOW_BUILD_SCRIPTS}{path_hint}."
            )
        }
        SpecError::Alias(target) => format!(
            "sigil {cmd} will not download `{spec}`: it is an npm: alias for `{target}`.\n  \
             Sigil scans the package it names, so name it directly: `sigil npm {target}`."
        ),
        SpecError::Malformed(why) => {
            let expected = match manager {
                Manager::Pip => {
                    "a package name with optional [extras] and version specifiers, e.g. \
                     requests, requests[socks], requests==2.32.3, \"requests>=2,<3\" or \
                     \"requests (>=2)\""
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

/// A spec npm would read as a path relative to its working directory.
fn is_relative_npm_path(spec: &str) -> bool {
    let s = spec.strip_prefix("file:").unwrap_or(spec);
    s.starts_with("./")
        || s.starts_with("../")
        || s == "."
        || s == ".."
        || (!s.starts_with('/') && !s.contains(':') && ends_with_any(s, NPM_TARBALL_SUFFIXES))
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

/// pip's stderr says it found nothing it was allowed to download (a
/// wheel-only download of a release with no wheel for this platform says
/// this, and so does a name or version the index does not have).
pub fn pip_found_no_distribution(stderr: &str) -> bool {
    stderr.contains("No matching distribution found")
        || stderr.contains("Could not find a version that satisfies")
}

/// Printed after a failed default `pip download` when pip found nothing to
/// download. `resolved`: the release Sigil picked for an unpinned or ranged
/// spec (it is on the index, so the missing piece is a wheel).
pub fn pip_wheel_only_hint(spec: &str, resolved: Option<&str>) -> String {
    let what = match resolved {
        Some(pinned) => format!(
            "`{pinned}` is the release `pip install {spec}` would install here, and pip found no \
             prebuilt wheel of it for this platform: it is probably published only as a source \
             distribution. Sigil does not scan an older release in its place, because that is \
             not what the install would get. Pin a version that has a wheel (and install that \
             same version), or"
        ),
        None => format!(
            "If `{spec}` exists on the index, pip found no prebuilt wheel of it for this \
             platform: it is probably published only as a source distribution. Pin a version \
             that has a wheel, or"
        ),
    };
    format!(
        "Sigil asks pip for prebuilt wheels only (--only-binary=:all:), because building a \
         source distribution runs the package's own setup code on this machine before the scan. \
         {what} for code you already trust, re-run with {ALLOW_BUILD_SCRIPTS}."
    )
}

// ---------------------------------------------------------------------------
// pip: what its environment and config add to every download
// ---------------------------------------------------------------------------

/// pip's name for a setting from the environment or a config file: lower
/// case, `_` as `-`, a leading `--` dropped (`Configuration._normalized_keys`).
fn pip_setting_name(raw: &str) -> String {
    let name = raw.to_ascii_lowercase().replace('_', "-");
    name.strip_prefix("--").map(str::to_string).unwrap_or(name)
}

/// The `PIP_*` variables that make pip add requirements, constraints or
/// editables to a download (pip reads any variable starting with `PIP_`,
/// whatever the case of the rest). Removed from pip's environment by default.
pub fn pip_env_to_remove<I>(vars: I) -> Vec<OsString>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .filter_map(|(k, _)| {
            let name = k.to_str()?.strip_prefix("PIP_")?;
            PIP_ADDED_REQUIREMENTS
                .contains(&pip_setting_name(name).as_str())
                .then_some(k)
        })
        .collect()
}

/// One `section.key='value'` line of `pip config list`.
fn pip_config_entries(list: &str) -> impl Iterator<Item = (&str, String, &str)> {
    list.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        let (section, name) = match key.strip_prefix(":env:.") {
            Some(name) => (":env:", name),
            None => key.split_once('.')?,
        };
        Some((section, pip_setting_name(name.trim()), value.trim()))
    })
}

/// The settings in `pip config list` output that add requirements,
/// constraints or editables to a `pip download` (pip reads the `global` and
/// `download` sections for it, and the environment).
pub fn pip_config_added_requirements(list: &str) -> Vec<String> {
    pip_config_entries(list)
        .filter(|(section, name, _)| {
            matches!(*section, "global" | "download" | ":env:")
                && PIP_ADDED_REQUIREMENTS.contains(&name.as_str())
        })
        .map(|(section, name, _)| format!("{section}.{name}"))
        .collect()
}

/// pip's config lets `pip install` pick pre-releases (`pre` set true in
/// the `global` or `install` section, or `PIP_PRE`).
pub fn pip_config_allows_prereleases(list: &str) -> bool {
    pip_config_entries(list).any(|(section, name, value)| {
        matches!(section, "global" | "install" | ":env:")
            && name == "pre"
            && matches!(
                value
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_ascii_lowercase()
                    .as_str(),
                "y" | "yes" | "t" | "true" | "on" | "1"
            )
    })
}

/// The refusal printed when pip's config adds requirements to downloads.
pub fn pip_config_refusal(keys: &[String]) -> String {
    format!(
        "sigil pip will not run pip with this configuration: {} adds requirements to every \
         `pip download`. A requirement, constraint or editable entry can name a local path, URL \
         or VCS checkout, which pip builds by running its code, even with --only-binary=:all:, \
         on this machine, before Sigil can scan anything.\n  Remove the setting for this \
         command (for example `PIP_CONFIG_FILE=/dev/null sigil pip …`, which skips every pip \
         config file, index settings included), or, for code you already trust, re-run with \
         {ALLOW_BUILD_SCRIPTS}.",
        keys.join(", ")
    )
}

/// The versions `pip index versions` listed (its `Available versions:`
/// line).
pub fn parse_pip_index_versions(stdout: &str) -> Option<Vec<String>> {
    let list = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Available versions:"))?;
    let versions: Vec<String> = list
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    (!versions.is_empty()).then_some(versions)
}

// ---------------------------------------------------------------------------
// pip: a PEP 508 requirement without a URL or environment marker
// ---------------------------------------------------------------------------

/// A registry requirement: a name, optional extras, version specifiers.
#[derive(Debug, Clone)]
pub struct PipRequirement {
    pub name: String,
    pub specifiers: Vec<Specifier>,
}

impl PipRequirement {
    /// Pins one version (`==1.0`, `===1.0`): there is nothing to resolve.
    pub fn is_pinned(&self) -> bool {
        self.specifiers.iter().any(Specifier::pins)
    }

    /// Of the versions an index lists, the one `pip install` would pick.
    pub fn best_match<'a>(
        &self,
        available: &'a [String],
        allow_prereleases: bool,
    ) -> Option<&'a str> {
        pep440::best_match(available, &self.specifiers, allow_prereleases)
    }
}

/// Parse a spec that [`check_spec`] accepted for pip.
pub fn pip_requirement(spec: &str) -> Result<PipRequirement, SpecError> {
    check_pip(spec)
}

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

fn check_pip(spec: &str) -> Result<PipRequirement, SpecError> {
    // pip strips the requirement before it reads it.
    let trimmed = spec.trim();
    let lower = trimmed.to_ascii_lowercase();
    for vcs in ["git+", "hg+", "svn+", "bzr+"] {
        if lower.starts_with(vcs) {
            return Err(SpecError::NotRegistry("it is a VCS reference".into()));
        }
    }
    if trimmed.contains("://") || has_scheme(trimmed) {
        return Err(SpecError::NotRegistry("it is a URL".into()));
    }
    if trimmed.contains('@') {
        return Err(SpecError::NotRegistry(
            "it is a direct reference (`name @ url`)".into(),
        ));
    }
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.starts_with('.')
        || trimmed.starts_with('~')
    {
        return Err(SpecError::NotRegistry("it is a local path".into()));
    }
    let name_end = trimmed
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(trimmed.len());
    // pip reads `foo.tar.gz`, `foo.whl[x]` and `foo==1.zip` as files.
    if ends_with_any(trimmed, PIP_ARCHIVE_SUFFIXES)
        || ends_with_any(&trimmed[..name_end], PIP_ARCHIVE_SUFFIXES)
    {
        return Err(SpecError::NotRegistry(
            "pip reads it as an archive file path".into(),
        ));
    }
    parse_pip_requirement(spec).map_err(SpecError::Malformed)
}

/// `name [extras] [specifier ("," specifier)*]`, or the specifiers in
/// parentheses (`name (>=2)`), whitespace allowed between tokens. A version
/// starts with a letter or digit and takes PEP 440's characters (`*` for
/// `==1.*`, `!` for an epoch, `+` for a local label).
fn parse_pip_requirement(spec: &str) -> Result<PipRequirement, String> {
    let b = spec.as_bytes();
    let mut i = 0;
    let name = take_name(spec, &mut i);
    if !is_pep508_name(name) {
        return Err("it does not start with a valid package name".into());
    }
    let mut req = PipRequirement {
        name: name.to_string(),
        specifiers: Vec::new(),
    };
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
        return Ok(req);
    }
    let parenthesised = b[i] == b'(';
    if parenthesised {
        i += 1;
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
        if !b.get(i).is_some_and(u8::is_ascii_alphanumeric) {
            return Err(format!(
                "`{op}` is not followed by a version (a version starts with a letter or digit)"
            ));
        }
        while i < b.len()
            && (b[i].is_ascii_alphanumeric()
                || matches!(b[i], b'.' | b'_' | b'-' | b'+' | b'!' | b'*'))
        {
            i += 1;
        }
        let version = &spec[start..i];
        let specifier = Specifier::new(op, version)
            .ok_or_else(|| format!("`{op}{version}` is not a valid version specifier"))?;
        req.specifiers.push(specifier);
        skip_ws(b, &mut i);
        match b.get(i) {
            None if !parenthesised => return Ok(req),
            Some(b')') if parenthesised => {
                i += 1;
                skip_ws(b, &mut i);
                return if i == b.len() {
                    Ok(req)
                } else {
                    Err("it has text after the version specifiers \
                         (environment markers are not accepted)"
                        .into())
                };
            }
            Some(b',') => i += 1,
            None => return Err("the `(` before the version specifiers is not closed".into()),
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
    if let Some(target) = range.and_then(|r| {
        r.get(..4)
            .filter(|p| p.eq_ignore_ascii_case("npm:"))
            .map(|_| &r[4..])
    }) {
        return Err(SpecError::Alias(target.to_string()));
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
        let why = match name.split_once('/') {
            Some((owner, repo))
                if scope.is_none()
                    && range.is_none()
                    && !owner.is_empty()
                    && !repo.is_empty()
                    && !repo.contains('/') =>
            {
                "it is a GitHub owner/repo shorthand, which npm fetches with git"
            }
            Some((_, "")) if scope.is_none() && range.is_none() => {
                "it is a local path (a directory)"
            }
            _ => "it is a path or git spec, not a registry name",
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

// ---------------------------------------------------------------------------
// npm: what the registry resolves a spec to
// ---------------------------------------------------------------------------

/// One version `npm view` listed for a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmRelease {
    pub name: String,
    pub version: String,
    pub tarball: String,
    pub deprecated: bool,
    pub latest: Option<String>,
}

impl NpmRelease {
    /// `name@version`, as npm writes it.
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// Parse `npm view --json <spec> name version dist.tarball deprecated
/// dist-tags.latest`: one object for a version or tag, an array of them for
/// a range that several versions match.
pub fn parse_npm_view(stdout: &str) -> Result<Vec<NpmRelease>, String> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("npm view printed something other than JSON ({e})"))?;
    let items = match v {
        serde_json::Value::Array(a) => a,
        o @ serde_json::Value::Object(_) => vec![o],
        _ => return Err("npm view printed no package data".into()),
    };
    let field = |o: &serde_json::Value, k: &str| -> Option<String> {
        o.get(k).and_then(|x| x.as_str()).map(str::to_string)
    };
    let mut out = Vec::new();
    for o in &items {
        if o.get("error").is_some() {
            return Err("npm view reported an error".into());
        }
        let (Some(name), Some(version), Some(tarball)) = (
            field(o, "name"),
            field(o, "version"),
            field(o, "dist.tarball"),
        ) else {
            return Err(
                "npm view did not give a name, version and tarball URL for every version".into(),
            );
        };
        out.push(NpmRelease {
            name,
            version,
            tarball,
            // npm-pick-manifest tests `!mani.deprecated`: an empty string
            // is not a deprecation.
            deprecated: match o.get("deprecated") {
                None | Some(serde_json::Value::Null) => false,
                Some(serde_json::Value::String(s)) => !s.is_empty(),
                Some(serde_json::Value::Bool(b)) => *b,
                Some(_) => true,
            },
            latest: field(o, "dist-tags.latest"),
        });
    }
    if out.is_empty() {
        return Err("npm view listed no version".into());
    }
    Ok(out)
}

/// The release `npm pack` would pick among those `npm view` listed: the
/// only one for a version or tag; for a range, the `latest` tag when it
/// matches and is not deprecated, else the highest non-deprecated version,
/// else the highest (npm-pick-manifest; it also weighs `engines`, which
/// this does not).
pub fn pick_npm_release(releases: &[NpmRelease]) -> Option<&NpmRelease> {
    if let [only] = releases {
        return Some(only);
    }
    if let Some(latest) = releases
        .iter()
        .find(|r| !r.deprecated && r.latest.as_deref() == Some(r.version.as_str()))
    {
        return Some(latest);
    }
    releases.iter().max_by(|a, b| {
        (!a.deprecated)
            .cmp(&!b.deprecated)
            .then_with(|| semver_cmp(&a.version, &b.version))
    })
}

/// Check the tarball URL a registry gave for a release: it must be a plain
/// http(s) download that npm fetches as a tarball. `file:` and git URLs, and
/// http(s) URLs on hosts npm reads as git repositories, make npm clone or
/// pack a directory and run its prepare script.
pub fn check_npm_tarball_url(url: &str) -> Result<(), String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| format!("`{url}` is not a URL npm downloads"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "the registry gives `{url}` as the tarball, which npm would not fetch as a plain \
             download (it is not an http(s) URL)"
        ));
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if NPM_GIT_HOSTS.contains(&host) {
        return Err(format!(
            "the registry gives `{url}` as the tarball, and npm reads a URL on {host} as a git \
             repository, which it clones and prepares"
        ));
    }
    Ok(())
}

/// The refusal printed when the registry's tarball URL is not a plain
/// download.
pub fn npm_tarball_refusal(release: &str, why: &str) -> String {
    format!(
        "sigil npm will not download `{release}`: {why}.\n  Packing it would run its prepare \
         script on this machine before Sigil can scan it. Check which registry npm uses here \
         (`npm config get registry`); for code you already trust, re-run with \
         {ALLOW_BUILD_SCRIPTS}."
    )
}

/// SemVer 2.0 precedence (what node-semver's compare uses): major, minor,
/// patch, then a release above its pre-releases, pre-release identifiers
/// numeric below alphanumeric. Build metadata is ignored. A version that
/// does not parse sorts below every one that does.
pub fn semver_cmp(a: &str, b: &str) -> Ordering {
    fn parse(v: &str) -> Option<([u64; 3], Vec<&str>)> {
        let v = v.trim().trim_start_matches(['v', '=']);
        let v = v.split('+').next()?;
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, p.split('.').collect()),
            None => (v, Vec::new()),
        };
        let mut nums = core.split('.').map(|n| n.parse::<u64>().ok());
        let parsed = [nums.next()??, nums.next()??, nums.next()??];
        nums.next().is_none().then_some((parsed, pre))
    }
    fn ident(a: &str, b: &str) -> Ordering {
        match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => a.cmp(b),
        }
    }
    match (parse(a), parse(b)) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some((x, xp)), Some((y, yp))) => {
            x.cmp(&y)
                .then_with(|| match (xp.is_empty(), yp.is_empty()) {
                    (true, true) => Ordering::Equal,
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    (false, false) => xp
                        .iter()
                        .zip(&yp)
                        .map(|(p, q)| ident(p, q))
                        .find(|o| *o != Ordering::Equal)
                        .unwrap_or_else(|| xp.len().cmp(&yp.len())),
                })
        }
    }
}

#[cfg(test)]
#[path = "acquire_tests.rs"]
mod tests;
