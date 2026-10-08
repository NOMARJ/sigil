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
//!   pip runs in the caller's directory, so a relative `PIP_FIND_LINKS` or
//!   config path means what it does for `pip install`: with archive-like
//!   names refused, a registry spec cannot be read as a file there.
//! - npm: `npm pack` runs a local directory's prepack/prepare/postpack
//!   scripts, and for a git spec it clones, installs and prepares the
//!   checkout. Sigil passes `--ignore-scripts`, but npm 10.9.7 (pacote
//!   19.0.2) still runs a directory's or git checkout's `prepare` script with
//!   that flag set, so anything that is not a registry package by name is
//!   refused before npm runs. A registry's metadata can itself point a
//!   version's tarball at a git repository, and `npm pack <name>@<version>`
//!   fetches the registry's metadata again (with a different `Accept`
//!   header than `npm view`, so a registry can answer the two requests
//!   differently), so by default Sigil does not run `npm pack` at all. It
//!   resolves the spec with `npm view` (the one metadata request), checks the
//!   name, the version and the tarball URL it gives (a plain http(s) download
//!   from the registry's own host, as npm-package-arg and hosted-git-info
//!   classify it), downloads exactly that URL itself (no credentials, a size
//!   cap, no redirect off http(s)), and checks the bytes against the
//!   registry's `dist.integrity`, as `npm install` would, before anything
//!   reads them. Nothing in that path can run package code, and nothing
//!   fetches a second description of the release. Handing the URL to `npm
//!   pack` is no way round it: npm 10.9.7 names the file it writes after the
//!   `package.json` inside a bare tarball, which its author controls (a
//!   version of `1.0.0/../../x` puts the file outside quarantine), and npm 12
//!   refuses a URL spec without `--allow-remote=all`.
//!
//! `--allow-build-scripts` lifts the refusals and drops the two options, for
//! code the user already trusts, and runs npm from the caller's directory
//! so a relative path means what the user typed; the command then prints a
//! warning that the package's own code may run on this machine before the
//! scan. It needs a person's confirmation first (a prompt at a terminal, or
//! `SIGIL_ALLOW_BUILD_SCRIPTS=1` for a script or CI job that has decided to
//! trust the code), so a shell with no terminal, such as an AI agent's, does
//! not pass it by writing the flag. A file or directory the user already has is better scanned where
//! it is (`sigil scan <path>`), which runs nothing from it: the refusal for
//! a local path says so.
//!
//! Every spec is passed after `--`, and one starting with `-` is refused
//! outright, so a spec can never be read as an option.

use std::cmp::Ordering;
use std::ffi::OsString;
use std::path::Path;

use crate::pep440::{self, Specifier};

/// The opt-in flag, as the user types it.
pub const ALLOW_BUILD_SCRIPTS: &str = "--allow-build-scripts";

/// The environment variable that confirms [`ALLOW_BUILD_SCRIPTS`] where
/// there is no terminal to ask on (a script or CI job that has decided to
/// trust the code). The Claude Code hook and the MCP `check_command` tool
/// ask about a command that sets it.
pub const ALLOW_BUILD_SCRIPTS_ENV: &str = "SIGIL_ALLOW_BUILD_SCRIPTS";

/// Whether the value of [`ALLOW_BUILD_SCRIPTS_ENV`] confirms the opt-in:
/// exactly `1`.
pub fn opt_in_env_confirms(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| v == "1")
}

/// Whether a line typed at the confirmation prompt says yes: the word
/// `yes`, in any case, and nothing else.
pub fn answer_confirms(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("yes")
}

/// The prompt shown (after the warning) at a terminal.
pub fn opt_in_prompt(manager: Manager, spec: &str) -> String {
    format!(
        "Run {}'s own code for `{spec}` on this machine before it is scanned? Type yes to \
         continue:",
        manager.command()
    )
}

/// The refusal printed (after `error: `) when [`ALLOW_BUILD_SCRIPTS`] is
/// given and nothing confirms it: no terminal to ask on, and
/// [`ALLOW_BUILD_SCRIPTS_ENV`] is not `1`.
pub fn opt_in_unconfirmed(manager: Manager, spec: &str) -> String {
    let cmd = manager.command();
    format!(
        "{ALLOW_BUILD_SCRIPTS} runs {cmd}'s build or lifecycle code for `{spec}` on this machine \
         before Sigil scans it, so it needs a person to confirm, and there is no terminal to ask \
         on (stdin or stderr is not one). Run it at a terminal and answer the prompt. A script or \
         CI job that has decided to trust this code can set {ALLOW_BUILD_SCRIPTS_ENV}=1 for the \
         command. Nothing was downloaded or run."
    )
}

/// `s` as one shell word: unchanged when it holds only characters a shell
/// leaves alone, else quoted: a Windows drive path (`C:\my dir`, whose
/// backslashes are no escape there) in double quotes, anything else in
/// single quotes.
pub fn shell_quote(s: &str) -> String {
    let plain = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '~' | '-'
            )
    };
    if !s.is_empty() && s.chars().all(plain) {
        return s.to_string();
    }
    if is_drive_path(s) {
        return if s.chars().all(|c| plain(c) || c == '\\') {
            s.to_string()
        } else {
            format!("\"{}\"", s.replace('"', ""))
        };
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

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

/// pip options that add requirements of their own to every `pip download`.
/// A requirement, constraint or editable entry can name a local path, URL or
/// VCS checkout, which pip builds even with `--only-binary=:all:`.
const PIP_ADDED_REQUIREMENTS: &[&str] = &["requirement", "constraint", "editable"];

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
    /// A file or directory on this machine (`path`: what pip or npm would
    /// read). `sigil scan <path>` scans it where it is, running nothing.
    /// Accepted with `--allow-build-scripts`.
    LocalPath { why: String, path: String },
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

/// `-V <version>` on a package that already names a version or range
/// (`wheelok>=1 -V 1.0` would be `wheelok>=1==1.0`, `left-pad@1 -V 1.0.0`
/// `left-pad@1@1.0.0`): which of the two to use is the user's call, so it is
/// refused with that said, ahead of any other check of the combined spec.
pub fn version_flag_conflict(
    manager: Manager,
    package: &str,
    version: Option<&str>,
) -> Option<String> {
    let version = version?;
    let package = package.trim();
    let named = match manager {
        Manager::Pip => pip_requirement(package)
            .ok()
            .filter(|r| !r.specifiers.is_empty())
            .map(|_| ()),
        // A scope's `@` starts the name; a second `@` starts a version.
        Manager::Npm => package.chars().skip(1).any(|c| c == '@').then_some(()),
    };
    named?;
    let cmd = manager.command();
    Some(format!(
        "sigil {cmd} was given a version twice: `{package}` already names one, and -V/--version \
         `{version}` names another. Give the version in the spec (`{package}`) or with \
         -V/--version, not both."
    ))
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

/// `pip download` arguments (after the `pip` command word). pip runs in the
/// caller's directory, as `pip install` would: [`check_spec`] has refused
/// anything pip could read as a file there, and `dest` is where it saves.
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
        "dist.integrity",
        "dist.shasum",
        "deprecated",
        "dist-tags.latest",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

/// `npm config get <key>` arguments: one setting, as npm resolves it from
/// its command line, environment and `.npmrc` files.
pub fn npm_config_get_args(key: &str) -> Vec<OsString> {
    ["config", "get", key].into_iter().map(OsString::from).collect()
}

/// `npm pack` arguments (after the `npm` command word) for the opt-in
/// (`--allow-build-scripts`) only: `spec` as typed, packed into
/// `pack_destination` (npm runs in the caller's directory, so a relative path
/// means what the user typed). By default Sigil never runs `npm pack`: it
/// downloads the tarball `npm view` named itself (see the module docs).
pub fn npm_pack_args(spec: &str, pack_destination: &Path) -> Vec<OsString> {
    vec![
        "pack".into(),
        "--pack-destination".into(),
        pack_destination.as_os_str().to_owned(),
        "--".into(),
        spec.into(),
    ]
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
                 To accept that risk for code you already trust, re-run with \
                 {ALLOW_BUILD_SCRIPTS} (Sigil then asks you to confirm)."
            )
        }
        SpecError::LocalPath { why, path } => {
            let from = match manager {
                Manager::Pip => "the package index",
                Manager::Npm => "the registry",
            };
            format!(
                "sigil {cmd} will not download `{spec}`: {why}.\n  sigil {cmd} fetches packages \
                 from {from} by name, e.g. {example}. To check a file or directory you already \
                 have, scan it where it is: `sigil scan {}` reads it (archives included) and \
                 runs nothing from it.",
                shell_quote(path)
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
         {what} for code you already trust, re-run with {ALLOW_BUILD_SCRIPTS} (Sigil then asks \
         you to confirm).\n  To read the \
         source distribution without building it, scan its file from the index: \
         `sigil scan <URL of the .tar.gz>` (the link is on the project's PyPI download page); \
         that reads the archive and runs nothing from it."
    )
}

/// What to tell the user (after pip's own messages) when `pip index versions`
/// failed, or listed no release, for `name`. `stderr` is pip's.
pub fn pip_index_failure_hint(stderr: &str, name: &str) -> String {
    if stderr.contains("unknown command \"index\"") {
        format!(
            "Sigil asks the index which release `pip install {name}` would install, then \
             downloads only that release's wheel. `pip index` exists from pip 21.2 on and this \
             pip does not have it: upgrade pip, or pin a version: `sigil pip {name}==<version>`."
        )
    } else if pip_found_no_distribution(stderr) {
        format!(
            "The index has no release of `{name}` that pip can install here. Check the \
             spelling of the name (pinning a version will not help a package that is not \
             there)."
        )
    } else {
        format!(
            "Sigil asks the index which release `pip install {name}` would install, then \
             downloads only that release's wheel, and pip listed no release of `{name}`. If it \
             exists, pin a version: `sigil pip {name}==<version>`."
        )
    }
}

/// `spec` without its extras (`requests[socks]==2.32.3` is recorded as
/// `requests==2.32.3`): the name of the release that was scanned. `pip
/// download --no-deps` fetches the same file either way.
pub fn pip_release_name(spec: &str) -> String {
    let spec = spec.trim();
    let Some(open) = spec.find('[') else {
        return spec.to_string();
    };
    let Some(close) = spec[open..].find(']') else {
        return spec.to_string();
    };
    format!("{}{}", spec[..open].trim_end(), &spec[open + close + 1..])
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
         command: `PIP_CONFIG_FILE=/dev/null sigil pip …` skips every pip config file, index \
         settings included, so give the index in the environment too if you need one \
         (`PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=<url> sigil pip …`). Or, for code you \
         already trust, re-run with {ALLOW_BUILD_SCRIPTS} (Sigil then asks you to confirm).",
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

/// A Windows drive path (`C:\x`, `c:/x`): a letter, a colon, a separator. It
/// reads as a URL scheme to [`has_scheme`], but it is a local path, and is
/// reported (and pointed at `sigil scan`) as one.
fn is_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')
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
    if is_drive_path(trimmed) {
        return Err(SpecError::LocalPath {
            why: "it is a local path (a Windows drive path)".into(),
            path: trimmed.to_string(),
        });
    }
    // `name @ https://…` is a direct reference; the `@` of a URL's userinfo
    // (`https://user@host/…`) comes after the scheme.
    let direct_reference = match (trimmed.find('@'), trimmed.find("://")) {
        (Some(at), Some(url)) => at < url,
        (Some(_), None) => true,
        _ => false,
    };
    if direct_reference {
        return Err(SpecError::NotRegistry(
            "it is a direct reference (`name @ url`)".into(),
        ));
    }
    if trimmed.contains("://") || has_scheme(trimmed) {
        return Err(SpecError::NotRegistry("it is a URL".into()));
    }
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.starts_with('.')
        || trimmed.starts_with('~')
    {
        return Err(SpecError::LocalPath {
            why: "it is a local path".into(),
            path: trimmed.to_string(),
        });
    }
    let name_end = trimmed
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(trimmed.len());
    // pip reads `foo.tar.gz`, `foo.whl[x]` and `foo==1.zip` as files.
    let archive = if ends_with_any(trimmed, PIP_ARCHIVE_SUFFIXES) {
        Some(trimmed)
    } else if ends_with_any(&trimmed[..name_end], PIP_ARCHIVE_SUFFIXES) {
        Some(&trimmed[..name_end])
    } else {
        None
    };
    if let Some(path) = archive {
        return Err(SpecError::LocalPath {
            why: "pip reads it as an archive file path".into(),
            path: path.to_string(),
        });
    }
    // Trimmed, as pip reads it: ` six==1.17.0` is a spec pip accepts.
    parse_pip_requirement(trimmed).map_err(SpecError::Malformed)
}

const MARKER_REFUSAL: &str = "it has an environment marker (`; …`), which Sigil does not \
                              evaluate (environment markers are not accepted): name the package \
                              and its version specifiers only";

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
        if rest.starts_with(';') {
            return Err(MARKER_REFUSAL.into());
        }
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
                } else if b[i] == b';' {
                    Err(MARKER_REFUSAL.into())
                } else {
                    Err("it has text after the version specifiers \
                         (environment markers are not accepted)"
                        .into())
                };
            }
            Some(b',') => i += 1,
            None => return Err("the `(` before the version specifiers is not closed".into()),
            Some(b';') => return Err(MARKER_REFUSAL.into()),
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

/// npm-package-arg 12.0.2's `isFileType`, `/[.](?:tgz|tar.gz|tar)$/i`: a
/// name or range it matches is read as a tarball path. The `.` inside
/// `tar.gz` is a regex wildcard (any character but a line end), so
/// `foo.tar-gz` and `foo.tarxgz` are tarball paths to npm too.
fn npa_is_file_type(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.ends_with(".tgz") || lower.ends_with(".tar") {
        return true;
    }
    let Some(rest) = lower.strip_suffix("gz") else {
        return false;
    };
    let mut chars = rest.chars();
    chars
        .next_back()
        .is_some_and(|c| !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
        && chars.as_str().ends_with(".tar")
}

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
    // `npm:left-pad@1.3.0` on its own: the alias target with no alias name.
    if lower.starts_with("npm:") {
        return Err(SpecError::Alias(spec[4..].to_string()));
    }
    if ["github:", "gitlab:", "bitbucket:", "gist:", "git:", "git+"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return Err(SpecError::NotRegistry("it is a git spec".into()));
    }
    if lower.starts_with("file:") {
        let path = &spec[5..];
        let path = match path.strip_prefix("//") {
            Some(p) if p.starts_with('/') => p,
            _ => path,
        };
        return Err(SpecError::LocalPath {
            why: "it is a local file: spec".into(),
            path: path.to_string(),
        });
    }
    if is_drive_path(spec) {
        return Err(SpecError::LocalPath {
            why: "it is a local path (a Windows drive path)".into(),
            path: spec.to_string(),
        });
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
        return Err(SpecError::LocalPath {
            why: "it is a local path".into(),
            path: spec.to_string(),
        });
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
                return Err(SpecError::LocalPath {
                    why: "it is a local path (a directory)".into(),
                    path: spec.to_string(),
                });
            }
            _ => "it is a path or git spec, not a registry name",
        };
        return Err(SpecError::NotRegistry(why.into()));
    }
    // An unscoped name (the whole spec is then the path) or any range that
    // npm-package-arg reads as a tarball file; `@scope/x.tgz` is a registry
    // name to it.
    let tarball = if scope.is_none() && npa_is_file_type(name) {
        Some(spec)
    } else {
        range.filter(|r| npa_is_file_type(r))
    };
    if let Some(path) = tarball {
        return Err(SpecError::LocalPath {
            why: "npm reads it as a tarball file path".into(),
            path: path.to_string(),
        });
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
    if let Some(r) = range.filter(|r| r.starts_with('.')) {
        return Err(SpecError::LocalPath {
            why: "npm reads the part after `@` as a file path".into(),
            path: r.to_string(),
        });
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
    /// `dist.integrity`: Subresource Integrity hashes of the tarball.
    pub integrity: Option<String>,
    /// `dist.shasum`: the tarball's sha1, hex (older registries give only
    /// this).
    pub shasum: Option<String>,
    pub deprecated: bool,
    pub latest: Option<String>,
}

impl NpmRelease {
    /// `name@version`, as npm writes it.
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// Whether `name` is a package name safe to print and to make part of a file
/// name: `name` or `@scope/name`, each part of letters, digits and
/// `. _ ~ ! ' ( ) * -` (npm's legacy name rule: what `encodeURIComponent`
/// leaves alone), neither part `.` or `..`, at most 214 characters.
fn npm_name_is_safe(name: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p != "."
            && p != ".."
            && p.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '.' | '_' | '~' | '!' | '\'' | '(' | ')' | '*' | '-')
            })
    };
    name.len() <= 214
        && match name.strip_prefix('@') {
            Some(scoped) => scoped
                .split_once('/')
                .is_some_and(|(scope, rest)| part(scope) && part(rest)),
            None => part(name),
        }
}

/// Whether `version` is made only of what a semver version holds (letters,
/// digits, `.`, `+`, `-`): it can be made part of a file name.
fn npm_version_is_safe(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 256
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
}

/// When a bare name (or `name@*`) resolves, npm skips a `latest` tag that is
/// deprecated (npm-pick-manifest) in favour of the highest version that is
/// not, but `npm view <name>` shows only the tag. For such a spec, the
/// package name to ask about in the range form (see
/// [`npm_all_versions_spec`]).
pub fn npm_name_for_default_pick(spec: &str) -> Option<String> {
    let name = spec.strip_suffix("@*").unwrap_or(spec);
    // A bare name has no `@` after its first character (a scope's `@`).
    (!name.is_empty() && !name.chars().skip(1).any(|c| c == '@')).then(|| name.to_string())
}

/// The spec that makes `npm view` list every release of `name` (a range
/// lists them; a bare name or `*` lists only the `latest` tag).
pub fn npm_all_versions_spec(name: &str) -> String {
    format!("{name}@>=0")
}

/// Parse `npm view --json <spec> name version dist.tarball dist.integrity
/// dist.shasum deprecated dist-tags.latest`: one object for a version or
/// tag, an array of them for a range that several versions match.
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
        // The name and version are printed, recorded in the quarantine index
        // and made into the file name `npm pack` writes
        // (`<name>-<version>.tgz`): a registry that gives one a path
        // separator or a control character could put the file elsewhere or
        // write to the terminal.
        if !npm_name_is_safe(&name) {
            return Err(format!(
                "the registry gives `{}` as a package name, which is not a valid npm package name",
                name.escape_debug()
            ));
        }
        if !npm_version_is_safe(&version) {
            return Err(format!(
                "the registry gives `{}` as the version of `{name}`, which is not a valid version",
                version.escape_debug()
            ));
        }
        out.push(NpmRelease {
            name,
            version,
            tarball,
            integrity: field(o, "dist.integrity"),
            shasum: field(o, "dist.shasum"),
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

/// `url` as it may be shown: the user name and password of an `scheme://user:pw@host`
/// authority, which a registry's metadata could put there, replaced by
/// `***`, and control characters escaped.
pub fn redact_url(url: &str) -> String {
    let shown = match url.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            match rest[..end].rfind('@') {
                Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
                None => url.to_string(),
            }
        }
        None => url.to_string(),
    };
    shown.escape_debug().to_string()
}

/// Check the tarball URL a registry gave for a release: it must be a plain
/// http(s) download that npm fetches as a tarball. `file:` and git URLs, and
/// http(s) URLs that npm reads as a git repository, make npm clone or pack
/// a directory and run its prepare script.
///
/// The caller hands npm this same string, so what is checked here is what
/// npm reads. That needs more than a parse: [`reqwest::Url::parse`] drops
/// leading spaces and control characters and any tab or line break, but
/// npm-package-arg takes a string as a URL only when it starts with
/// `[a-z]+:`, and reads anything else (` https://x/../../dir`, `ht<TAB>tps://…`)
/// as a local path, a directory it would prepare. So the string must begin
/// with `http://` or `https://` at its first byte and hold no whitespace or
/// control character.
pub fn check_npm_tarball_url(url: &str) -> Result<(), String> {
    // Escaped, so a control character in a registry's string cannot reach
    // the terminal through the message, and without any credentials in it.
    let shown = redact_url(url);
    let parsed =
        reqwest::Url::parse(url).map_err(|_| format!("`{shown}` is not a URL npm downloads"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "the registry gives `{shown}` as the tarball, which npm would not fetch as a plain \
             download (it is not an http(s) URL)"
        ));
    }
    let starts = |prefix: &str| {
        url.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    if !(starts("http://") || starts("https://"))
        || url
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(format!(
            "the registry gives `{shown}` as the tarball, which is not written as a plain \
             `http://` or `https://` URL (with no space or control character in it), so npm \
             could read it as a local path, which it packs and prepares"
        ));
    }
    if let Some(host) = npm_git_repo_host(&parsed) {
        return Err(format!(
            "the registry gives `{shown}` as the tarball, and npm reads that URL as a git \
             repository on {host} (not a tarball download), which it clones and prepares"
        ));
    }
    Ok(())
}

/// The git host, when npm reads an http(s) URL as a git repository there
/// rather than as a tarball to download. npm-package-arg asks
/// hosted-git-info (8.1.0 in npm 10.9.7), which knows five hosts (`www.`
/// stripped) and reads a URL on one as a repository only when the host's
/// `extract` finds a user and project in its path. Ported from there, except
/// that every host is checked for `http:` as for `https:` (hosted-git-info
/// takes plain `http:` only for GitHub) and a malformed `%` escape, which
/// hosted-git-info gives up on, still counts: both refuse more, never less.
fn npm_git_repo_host(url: &reqwest::Url) -> Option<&'static str> {
    let host = url.host_str()?.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let path = url.path();
    // `pathname.split('/', n)`: piece `i`, or "" past the end.
    let piece = |i: usize| path.split('/').nth(i).unwrap_or("");
    // A project name: not empty once a `.git` suffix is dropped.
    let project = |i: usize| {
        let name = piece(i);
        !name.strip_suffix(".git").unwrap_or(name).is_empty()
    };
    let (name, repo) = match host {
        "github.com" => {
            // `/user/project[.git]`, or `/user/project/tree/<ref>`.
            let kind = piece(3);
            (
                "github.com",
                (kind.is_empty() || kind == "tree") && !piece(1).is_empty() && project(2),
            )
        }
        "bitbucket.org" => (
            "bitbucket.org",
            piece(3) != "get" && !piece(1).is_empty() && project(2),
        ),
        "gitlab.com" => {
            // Any depth of groups; `/-/` (package registry, releases, raw
            // files) and `/archive.tar.gz` are downloads.
            let p = path.strip_prefix('/').unwrap_or(path);
            let git = !p.contains("/-/")
                && !p.contains("/archive.tar.gz")
                && p.rsplit_once('/').is_some_and(|(user, project)| {
                    !user.is_empty() && !project.strip_suffix(".git").unwrap_or(project).is_empty()
                });
            ("gitlab.com", git)
        }
        "gist.github.com" => (
            "gist.github.com",
            piece(3) != "raw" && !(piece(1).is_empty() && piece(2).is_empty()),
        ),
        "git.sr.ht" => (
            "git.sr.ht",
            piece(3) != "archive" && !piece(1).is_empty() && project(2),
        ),
        _ => return None,
    };
    repo.then_some(name)
}

/// What a registry says its tarball hashes to: `dist.integrity` (Subresource
/// Integrity: as ssri checks it, the strongest algorithm listed must match
/// one of its hashes), else `dist.shasum` (sha1, hex). `npm install <name>`
/// checks the download this way; Sigil checks the tarball it downloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmDigest {
    /// `sha512`, `sha384`, `sha256`, `sha1` (an SRI hash), or `sha1-hex`.
    algorithm: &'static str,
    /// The hashes of that algorithm that would be accepted (base64, or hex).
    wanted: Vec<String>,
    /// How the message names it.
    what: String,
}

impl NpmDigest {
    /// The digest to check against, or why there is none Sigil can check.
    pub fn new(integrity: Option<&str>, shasum: Option<&str>) -> Result<NpmDigest, String> {
        match integrity.map(str::trim).filter(|s| !s.is_empty()) {
            Some(sri) => {
                // `algorithm-base64digest[?options]`, whitespace separated.
                let hashes: Vec<(&str, &str)> = sri
                    .split_whitespace()
                    .filter_map(|h| {
                        let (algorithm, rest) = h.split_once('-')?;
                        Some((algorithm, rest.split('?').next().unwrap_or(rest)))
                    })
                    .collect();
                let Some(algorithm) = ["sha512", "sha384", "sha256", "sha1"]
                    .into_iter()
                    .find(|a| hashes.iter().any(|(x, _)| x == a))
                else {
                    return Err(format!(
                        "the registry's integrity for it (`{}`) has no sha512, sha384, sha256 \
                         or sha1 hash to check",
                        sri.escape_debug()
                    ));
                };
                Ok(NpmDigest {
                    algorithm,
                    wanted: hashes
                        .iter()
                        .filter(|(a, _)| *a == algorithm)
                        .map(|(_, d)| (*d).to_string())
                        .collect(),
                    what: format!("integrity the registry gives (`{}`)", sri.escape_debug()),
                })
            }
            None => match shasum.map(str::trim).filter(|s| !s.is_empty()) {
                Some(hex) => Ok(NpmDigest {
                    algorithm: "sha1-hex",
                    wanted: vec![hex.to_string()],
                    what: format!("shasum the registry gives ({})", hex.escape_debug()),
                }),
                None => Err("the registry gives no integrity or shasum for it, so what would \
                             be scanned cannot be tied to what `npm install` accepts"
                    .into()),
            },
        }
    }

    /// Whether `data` hashes to this digest.
    pub fn verify(&self, mut data: impl std::io::Read) -> Result<(), String> {
        use base64::Engine as _;
        fn hash<D: sha2::Digest + std::io::Write>(
            r: &mut dyn std::io::Read,
        ) -> std::io::Result<Vec<u8>> {
            let mut h = D::new();
            std::io::copy(r, &mut h)?;
            Ok(h.finalize().to_vec())
        }
        let digest = match self.algorithm {
            "sha512" => hash::<sha2::Sha512>(&mut data),
            "sha384" => hash::<sha2::Sha384>(&mut data),
            "sha256" => hash::<sha2::Sha256>(&mut data),
            _ => hash::<sha1::Sha1>(&mut data),
        }
        .map_err(|e| format!("could not read the tarball Sigil downloaded: {e}"))?;
        let (got, matches) = if self.algorithm == "sha1-hex" {
            let got = hex::encode(&digest);
            let ok = self.wanted.iter().any(|w| w.eq_ignore_ascii_case(&got));
            (format!("sha1 {got}"), ok)
        } else {
            let got = base64::engine::general_purpose::STANDARD.encode(&digest);
            let ok = self.wanted.iter().any(|w| *w == got);
            (format!("{}-{got}", self.algorithm), ok)
        };
        if matches {
            Ok(())
        } else {
            Err(format!(
                "the tarball Sigil downloaded hashes to {got}, which is not the {}",
                self.what
            ))
        }
    }
}

/// The message printed (after `error: `) when what `npm view` gave for `spec`
/// cannot be used: not JSON, no tarball, or a name or version that is not
/// valid (`why` says which). docs/troubleshooting.md quotes it.
pub fn npm_view_unreadable(spec: &str, why: &str) -> String {
    format!("could not read what npm resolves `{spec}` to: {why}")
}

/// The refusal printed when the downloaded tarball does not match the
/// registry's integrity.
pub fn npm_integrity_refusal(release: &str, why: &str) -> String {
    format!(
        "sigil npm will not scan `{release}`: {why}.\n  Sigil scans a tarball only when it \
         matches the digest the registry lists, as `npm install` requires (it refuses a mismatch \
         with EINTEGRITY); a scan of any other bytes says nothing about what would be installed. \
         Try again later or check which registry npm uses here (`npm config get registry`)."
    )
}

/// The refusal printed when the registry's tarball URL is not a plain
/// download.
pub fn npm_tarball_refusal(release: &str, why: &str) -> String {
    format!(
        "sigil npm will not download `{release}`: {why}.\n  Handing it to npm would clone or pack \
         it and run its prepare script on this machine before Sigil can scan it. Check which \
         registry npm uses here (`npm config get registry`); for code you already trust, re-run \
         with {ALLOW_BUILD_SCRIPTS} (Sigil then asks you to confirm)."
    )
}

/// The refusal printed when the tarball is not on the registry's own host, or
/// the URL carries credentials: Sigil downloads it itself, without any.
pub fn npm_host_refusal(release: &str, why: &str) -> String {
    format!(
        "sigil npm will not download `{release}`: {why}.\n  Sigil downloads the tarball itself, \
         without credentials and only from the host of the registry npm resolved the package \
         from. Check which registry npm uses here (`npm config get registry`; \
         `npm config get replace-registry-host` decides whether npm fetches tarballs that name \
         registry.npmjs.org from your registry instead); for code you already trust, re-run with \
         {ALLOW_BUILD_SCRIPTS} (Sigil then asks you to confirm)."
    )
}

/// The message printed (after `error: `) when the download itself failed.
pub fn npm_download_failure(release: &str, why: &str) -> String {
    let credentials = if why.contains("HTTP 401") || why.contains("HTTP 403") {
        "\n  The registry wants credentials for this tarball. Sigil downloads it without any, so \
         that no token of npm's is sent anywhere but by npm itself. To check a package from a \
         registry that needs a token, fetch the tarball yourself (`npm pack <name>@<version>` in \
         an empty directory) and scan the file: `sigil scan <file>.tgz` runs nothing from it."
    } else {
        ""
    };
    format!(
        "sigil npm could not download the tarball of `{release}`: {why}.{credentials}\n  Sigil \
         downloads it itself, so its proxy settings are the environment's (HTTPS_PROXY, \
         HTTP_PROXY, NO_PROXY), not npm's `proxy` setting."
    )
}

/// The file Sigil writes a downloaded tarball to: `<name>-<version>.tgz`
/// with the leading `@` dropped and `/` made `-`, as `npm pack` names it,
/// from a name and version [`parse_npm_view`] has checked. Any character a
/// file name should not hold becomes `_`, and a leading `.` too, so the
/// scanner never meets a hidden directory.
pub fn npm_tarball_file_name(name: &str, version: &str) -> String {
    let base = name.strip_prefix('@').unwrap_or(name).replace('/', "-");
    let mut file: String = format!("{base}-{version}.tgz")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if file.starts_with('.') {
        file.replace_range(..1, "_");
    }
    file
}

/// The host and explicit port of a URL (none for its scheme's default
/// port), for comparing hosts whatever the scheme.
fn host_and_port(url: &reqwest::Url) -> Option<(String, Option<u16>)> {
    Some((
        url.host_str()?.trim_end_matches('.').to_ascii_lowercase(),
        url.port(),
    ))
}

/// Check that a tarball URL a registry gave is on the host of the registry
/// npm resolved the package from (`registry`: what `npm config get registry`,
/// or `@scope:registry`, prints) and carries no credentials, and give that
/// host and port. Sigil downloads the tarball itself and sends nothing but a
/// GET, so a registry's metadata cannot make it fetch from another host
/// (npm 12 applies the same rule to its own downloads). A scheme difference
/// is not checked: the bytes are checked against the integrity the metadata
/// gives, over whatever transport.
pub fn check_npm_tarball_host(tarball: &str, registry: &str) -> Result<(String, u16), String> {
    let shown = redact_url(tarball);
    let url = reqwest::Url::parse(tarball)
        .map_err(|_| format!("`{shown}` is not a URL npm downloads"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "the registry gives `{shown}` as the tarball, a URL with a user name or password in \
             it"
        ));
    }
    let registry_url = reqwest::Url::parse(registry.trim()).map_err(|_| {
        format!(
            "npm's registry setting (`{}`) is not a URL, so the tarball's host cannot be checked \
             against it",
            registry.trim().escape_debug()
        )
    })?;
    let (Some(want), Some(got)) = (host_and_port(&registry_url), host_and_port(&url)) else {
        return Err(format!("`{shown}` has no host to download from"));
    };
    if want != got {
        let show = |(host, port): &(String, Option<u16>)| match port {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        return Err(format!(
            "the registry gives `{shown}` as the tarball, on {}, which is not the host of the \
             registry npm resolved the package from ({})",
            show(&got).escape_debug(),
            show(&want).escape_debug()
        ));
    }
    Ok((got.0, url.port_or_known_default().unwrap_or(443)))
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
