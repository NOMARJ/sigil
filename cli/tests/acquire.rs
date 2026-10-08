//! `sigil pip` / `sigil npm` never let pip or npm run package code by
//! default: end-to-end tests of what the real binary hands to pip and npm.
//!
//! Most tests put test-double `pip` and `npm` executables first on PATH. They
//! only record their argv, working directory and environment, print canned
//! output for the lookups Sigil makes first (`pip config list`, `pip index
//! versions`, `npm view`) and exit; nothing touches a network. The
//! `real_pip_*` tests use the real pip, offline, against local fixtures
//! whose only side effect, should pip run their code, is an empty marker
//! file; they are skipped when pip is not installed. Every run gets its own
//! HOME, so the quarantine is temporary.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Records how it was run (per subcommand), prints canned output for the
/// lookups, and exits with `$SIGIL_TEST_FAKE_EXIT` (default 0) for a
/// download or pack, after printing `$SIGIL_TEST_FAKE_STDERR` to stderr. On
/// success a download saves a placeholder file into `--dest` (unless
/// `$SIGIL_TEST_PIP_SAVES` is 0) and a pack copies `$SIGIL_TEST_PACK_FILE`,
/// when set, to `--pack-destination` or its working directory, as the real
/// tools would.
const FAKE_TOOL: &str = r#"#!/bin/sh
tool=$(basename "$0")
sub=$1
for a in "$@"; do printf '%s\n' "$a"; done > "$SIGIL_TEST_LOG_DIR/$tool-$sub.argv"
pwd -P > "$SIGIL_TEST_LOG_DIR/$tool-$sub.cwd"
env > "$SIGIL_TEST_LOG_DIR/$tool-$sub.env"
case "$tool $sub" in
  "pip config") printf '%s' "${SIGIL_TEST_PIP_CONFIG:-}"; exit 0 ;;
  "pip index") printf '%s\n' "${SIGIL_TEST_PIP_INDEX:-}"; exit 0 ;;
  "npm view") printf '%s\n' "${SIGIL_TEST_NPM_VIEW:-}"; exit 0 ;;
esac
if [ -n "${SIGIL_TEST_FAKE_STDERR:-}" ]; then printf '%s\n' "$SIGIL_TEST_FAKE_STDERR" >&2; fi
status=${SIGIL_TEST_FAKE_EXIT:-0}
if [ "$status" = 0 ]; then
  dest=.; prev=
  for a in "$@"; do
    case "$prev" in --dest|--pack-destination) dest=$a ;; esac
    prev=$a
  done
  case "$tool $sub" in
    "pip download")
      if [ "${SIGIL_TEST_PIP_SAVES:-1}" = 1 ]; then printf 'placeholder\n' > "$dest/downloaded.txt"; fi ;;
    "npm pack")
      if [ -n "${SIGIL_TEST_PACK_FILE:-}" ]; then cp "$SIGIL_TEST_PACK_FILE" "$dest/"; fi ;;
  esac
fi
exit "$status"
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    logs: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let bin = root.join("bin");
    let logs = root.join("logs");
    for d in [&home, &bin, &logs] {
        std::fs::create_dir_all(d).unwrap();
    }
    for tool in ["pip", "npm"] {
        let p = bin.join(tool);
        std::fs::write(&p, FAKE_TOOL).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    Fixture {
        _dir: dir,
        root,
        home,
        bin,
        logs,
    }
}

/// Run sigil with the test doubles first on PATH.
fn sigil(fx: &Fixture, args: &[&str], env: &[(&str, &str)]) -> Output {
    let path = format!(
        "{}:{}",
        fx.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    run_sigil(fx, args, &path, env)
}

fn run_sigil(fx: &Fixture, args: &[&str], path: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigil"));
    cmd.args(args)
        .current_dir(&fx.root)
        .env("HOME", &fx.home)
        .env("PATH", path)
        .env("NO_COLOR", "1")
        .env("SIGIL_TEST_LOG_DIR", &fx.logs)
        .env_remove("SIGIL_QUARANTINE_DIR")
        .env_remove("SIGIL_POLICY_FILE")
        .env_remove("SIGIL_PACK_PUBLIC_KEY")
        .env_remove("SIGIL_NO_PROJECT_CONFIG");
    // The caller's own pip settings must not leak into the tests.
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("PIP_") {
            cmd.env_remove(k);
        }
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run sigil")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

/// The argv and working directory a test double recorded for one
/// subcommand (`pip-download`, `pip-index`, `npm-view`, ...), if it ran.
fn recorded(fx: &Fixture, call: &str) -> Option<(Vec<String>, PathBuf)> {
    let argv = std::fs::read_to_string(fx.logs.join(format!("{call}.argv"))).ok()?;
    let cwd = std::fs::read_to_string(fx.logs.join(format!("{call}.cwd"))).ok()?;
    Some((
        argv.lines().map(str::to_string).collect(),
        PathBuf::from(cwd.trim_end()),
    ))
}

/// The environment variable names a test double saw for one subcommand.
fn recorded_env(fx: &Fixture, call: &str) -> Vec<String> {
    std::fs::read_to_string(fx.logs.join(format!("{call}.env")))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
        .collect()
}

/// Nothing of this tool ran.
fn ran_nothing(fx: &Fixture, tool: &str) -> bool {
    std::fs::read_dir(&fx.logs)
        .unwrap()
        .filter_map(Result::ok)
        .all(|e| {
            !e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{tool}-"))
        })
}

fn quarantine_root(fx: &Fixture) -> PathBuf {
    fx.home.join(".sigil").join("quarantine")
}

/// Quarantine item directories created so far.
fn quarantine_items(fx: &Fixture) -> Vec<PathBuf> {
    match std::fs::read_dir(quarantine_root(fx)) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The one quarantine directory this run created.
fn only_item(fx: &Fixture) -> PathBuf {
    let items = quarantine_items(fx);
    assert_eq!(items.len(), 1, "expected one quarantine entry: {items:?}");
    items[0].canonicalize().unwrap()
}

/// A real npm tarball (`package/package.json`, `package/index.js`) at
/// `<root>/packed/<name>-<version>.tgz`, and its integrity as a registry
/// gives it (`sha512-<base64>`).
fn npm_tarball(fx: &Fixture, name: &str, version: &str) -> (PathBuf, String) {
    use base64::Engine as _;
    use sha2::Digest as _;
    let dir = fx.root.join("packed");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}-{version}.tgz"));
    let f = std::fs::File::create(&path).unwrap();
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for (file, body) in [
        (
            "package/package.json",
            format!("{{\"name\":\"{name}\",\"version\":\"{version}\"}}\n"),
        ),
        ("package/index.js", "module.exports = 1;\n".to_string()),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, file, body.as_bytes()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    let digest = sha2::Sha512::digest(std::fs::read(&path).unwrap());
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    );
    (path, integrity)
}

/// `npm view --json` output for one release.
fn npm_view(name: &str, version: &str, tarball: &str, integrity: &str) -> String {
    serde_json::json!({
        "name": name,
        "version": version,
        "dist.tarball": tarball,
        "dist.integrity": integrity,
        "dist-tags.latest": version,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// pip
// ---------------------------------------------------------------------------

#[test]
fn pip_downloads_wheels_only_into_the_quarantine_directory() {
    let fx = fixture();
    let out = sigil(&fx, &["pip", "requests", "-V", "2.32.3"], &[]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let q = only_item(&fx);
    let (argv, cwd) = recorded(&fx, "pip-download").expect("pip ran");
    assert_eq!(
        argv,
        [
            "download",
            "--no-deps",
            "--only-binary=:all:",
            "--dest",
            &q.to_string_lossy(),
            "--",
            "requests==2.32.3",
        ]
    );
    // From the caller's directory, as `pip install` runs, so relative pip
    // settings mean the same (the spec check refuses anything pip could
    // read as a file there).
    assert_eq!(cwd, fx.root, "pip runs in the caller's directory");
    // A pinned spec needs no lookup; pip's config is read first.
    assert!(recorded(&fx, "pip-index").is_none());
    let (config, _) = recorded(&fx, "pip-config").expect("pip config list ran");
    assert_eq!(config, ["config", "list"]);
    assert!(!stderr(&out).contains("--allow-build-scripts"));
}

#[test]
fn pip_resolves_an_unpinned_spec_to_the_release_pip_install_picks() {
    let index = "markerpkg (2.0)\nAvailable versions: 2.0, 1.0, 3.0b1";
    for (spec, pinned) in [
        ("markerpkg", "markerpkg==2.0"),
        ("markerpkg[extra]", "markerpkg==2.0"),
        ("markerpkg<2", "markerpkg==1.0"),
        ("markerpkg (>=1, <2)", "markerpkg==1.0"),
        ("markerpkg>=3.0b1", "markerpkg==3.0b1"),
    ] {
        let fx = fixture();
        let out = sigil(&fx, &["pip", spec], &[("SIGIL_TEST_PIP_INDEX", index)]);
        assert_eq!(code(&out), 0, "{spec}: {}", stderr(&out));
        let q = only_item(&fx);
        let (argv, cwd) = recorded(&fx, "pip-index").expect("pip index ran");
        assert_eq!(argv, ["index", "versions", "--pre", "--", "markerpkg"]);
        assert_eq!(cwd, fx.root);
        assert!(q.join("downloaded.txt").exists());
        let (argv, _) = recorded(&fx, "pip-download").expect("pip download ran");
        assert_eq!(argv.last().map(String::as_str), Some(pinned), "{spec}");
        assert!(argv.iter().any(|a| a == "--only-binary=:all:"));
        assert!(
            stdout(&out).contains("resolves to"),
            "{spec}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn pip_resolution_failures_download_nothing() {
    for (spec, index, says) in [
        (
            "markerpkg>5",
            "markerpkg (2.0)\nAvailable versions: 2.0, 1.0",
            "no release of `markerpkg`",
        ),
        ("markerpkg", "", "pin a version"),
    ] {
        let fx = fixture();
        let out = sigil(&fx, &["pip", spec], &[("SIGIL_TEST_PIP_INDEX", index)]);
        assert_eq!(code(&out), 2, "{spec}: {}", stderr(&out));
        assert!(stderr(&out).contains(says), "{spec}: {}", stderr(&out));
        assert!(recorded(&fx, "pip-download").is_none(), "{spec} downloaded");
        assert!(
            quarantine_items(&fx).is_empty(),
            "{spec} left a quarantine entry"
        );
    }
}

#[test]
fn an_index_version_that_reads_as_a_file_is_refused() {
    // A PEP 440 local label can end like an archive; pip would read
    // `markerpkg==2.0+x.zip` as a file in the caller's directory.
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "markerpkg"],
        &[(
            "SIGIL_TEST_PIP_INDEX",
            "markerpkg (2.0+x.zip)\nAvailable versions: 2.0+x.zip, 1.0",
        )],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("will not download `markerpkg==2.0+x.zip`"),
        "{}",
        stderr(&out)
    );
    assert!(recorded(&fx, "pip-download").is_none());
    assert!(quarantine_items(&fx).is_empty());
}

#[test]
fn a_release_without_a_wheel_fails_instead_of_an_older_one_being_scanned() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "sdist-only-pkg"],
        &[
            (
                "SIGIL_TEST_PIP_INDEX",
                "sdist-only-pkg (2.0)\nAvailable versions: 2.0, 1.0",
            ),
            ("SIGIL_TEST_FAKE_EXIT", "1"),
            (
                "SIGIL_TEST_FAKE_STDERR",
                "ERROR: No matching distribution found for sdist-only-pkg==2.0",
            ),
        ],
    );
    assert_eq!(code(&out), 2);
    let err = stderr(&out);
    assert!(err.contains("pip download failed"), "{err}");
    assert!(
        err.contains("`sdist-only-pkg==2.0` is the release"),
        "{err}"
    );
    assert!(err.contains("--only-binary=:all:"), "{err}");
    assert!(err.contains("--allow-build-scripts"), "{err}");
    let (argv, _) = recorded(&fx, "pip-download").unwrap();
    assert_eq!(argv.last().map(String::as_str), Some("sdist-only-pkg==2.0"));
    // The failed download leaves no empty PENDING entry to approve.
    assert!(quarantine_items(&fx).is_empty());
    let list = sigil(&fx, &["list"], &[]);
    assert!(
        !stdout(&list).contains("sdist-only-pkg"),
        "{}",
        stdout(&list)
    );
}

#[test]
fn the_wheel_hint_follows_only_a_missing_distribution() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "requests==2.32.3"],
        &[
            ("SIGIL_TEST_FAKE_EXIT", "1"),
            (
                "SIGIL_TEST_FAKE_STDERR",
                "ERROR: Could not install packages due to an OSError: no space left",
            ),
        ],
    );
    assert_eq!(code(&out), 2);
    let err = stderr(&out);
    assert!(err.contains("pip download failed"), "{err}");
    assert!(!err.contains("--only-binary"), "{err}");

    let out = sigil(
        &fx,
        &["pip", "docopt==0.6.2"],
        &[
            ("SIGIL_TEST_FAKE_EXIT", "1"),
            (
                "SIGIL_TEST_FAKE_STDERR",
                "ERROR: No matching distribution found for docopt==0.6.2",
            ),
        ],
    );
    let err = stderr(&out);
    assert!(err.contains("If `docopt==0.6.2` exists"), "{err}");
}

#[test]
fn pip_env_requirement_settings_are_left_out_of_pips_environment() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "requests==2.32.3"],
        &[
            ("PIP_CONSTRAINT", "/x/constraints.txt"),
            ("PIP_Requirement", "/x/requirements.txt"),
            ("PIP_EDITABLE", "/x/project"),
            ("PIP_INDEX_URL", "https://example.invalid/simple"),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    for call in ["pip-config", "pip-download"] {
        let env = recorded_env(&fx, call);
        for k in ["PIP_CONSTRAINT", "PIP_Requirement", "PIP_EDITABLE"] {
            assert!(!env.iter().any(|e| e == k), "{call} saw {k}");
        }
        assert!(env.iter().any(|e| e == "PIP_INDEX_URL"), "{call}: {env:?}");
    }
    let err = stderr(&out);
    assert!(err.contains("PIP_CONSTRAINT is left out"), "{err}");
}

#[test]
fn pip_config_requirement_settings_are_refused() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "requests"],
        &[(
            "SIGIL_TEST_PIP_CONFIG",
            "global.index-url='https://example.invalid/simple'\ndownload.requirement='/x/r.txt'\n",
        )],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("download.requirement"), "{err}");
    assert!(recorded(&fx, "pip-download").is_none());
    assert!(recorded(&fx, "pip-index").is_none());
    assert!(quarantine_items(&fx).is_empty());
    // An install-only setting is not what `pip download` reads.
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "requests==2.32.3"],
        &[("SIGIL_TEST_PIP_CONFIG", "install.constraint='/x/c.txt'\n")],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
}

#[test]
fn a_relative_quarantine_dir_is_used_as_one_absolute_path() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "requests==2.32.3"],
        &[("SIGIL_QUARANTINE_DIR", "relq")],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let (argv, _) = recorded(&fx, "pip-download").unwrap();
    let dest = PathBuf::from(&argv[4]);
    assert!(dest.is_absolute(), "{argv:?}");
    assert_eq!(dest.parent(), Some(fx.root.join("relq").as_path()));
    assert!(dest.join("downloaded.txt").exists());
}

#[test]
fn pip_opt_in_drops_only_binary_and_warns() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "--allow-build-scripts", "./local-project"],
        &[("PIP_CONSTRAINT", "/x/constraints.txt")],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let q = only_item(&fx);
    let (argv, cwd) = recorded(&fx, "pip-download").expect("pip ran");
    // As in 1.3.7: from the caller's directory, so `./local-project` is the
    // one the user meant, with the caller's pip settings.
    assert_eq!(cwd, fx.root, "opted-in pip runs in the caller's directory");
    assert_eq!(
        argv,
        [
            "download",
            "--no-deps",
            "--dest",
            &q.to_string_lossy(),
            "--",
            "./local-project",
        ]
    );
    assert!(recorded_env(&fx, "pip-download")
        .iter()
        .any(|k| k == "PIP_CONSTRAINT"));
    assert!(recorded(&fx, "pip-config").is_none());
    assert!(recorded(&fx, "pip-index").is_none());
    let err = stderr(&out);
    assert!(err.contains("warning:"), "{err}");
    assert!(err.contains("BEFORE Sigil scans"), "{err}");
}

#[test]
fn a_download_that_saves_nothing_is_an_error_not_a_clean_scan() {
    // pip does not copy a local directory into --dest: with the opt-in its
    // build code runs and quarantine stays empty. That is never LOW RISK
    // and never auto-approved.
    let fx = fixture();
    let out = sigil(
        &fx,
        &[
            "pip",
            "./local-project",
            "--allow-build-scripts",
            "--auto-approve",
        ],
        &[("SIGIL_TEST_PIP_SAVES", "0")],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("saved nothing into quarantine"), "{err}");
    assert!(err.contains("sigil scan <path>"), "{err}");
    assert!(!stdout(&out).contains("LOW RISK"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("auto-approved"), "{}", stdout(&out));
    assert!(quarantine_items(&fx).is_empty());
    let list = sigil(&fx, &["list"], &[]);
    assert!(
        !stdout(&list).contains("local-project"),
        "{}",
        stdout(&list)
    );

    // The same for npm, by default: a pack that wrote no tarball.
    let fx = fixture();
    let (_, integrity) = npm_tarball(&fx, "left-pad", "1.3.0");
    let view = npm_view(
        "left-pad",
        "1.3.0",
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        &integrity,
    );
    let out = sigil(&fx, &["npm", "left-pad"], &[("SIGIL_TEST_NPM_VIEW", &view)]);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("saved nothing into quarantine"),
        "{}",
        stderr(&out)
    );
    assert!(quarantine_items(&fx).is_empty());
}

#[test]
fn pip_refusals_run_nothing_and_quarantine_nothing() {
    let fx = fixture();
    for args in [
        vec!["pip", "./local-project"],
        vec!["pip", "/abs/project"],
        vec!["pip", "https://example.invalid/pkg-1.0.tar.gz"],
        vec!["pip", "git+https://example.invalid/owner/repo"],
        vec!["pip", "pkg @ https://example.invalid/pkg-1.0.tar.gz"],
        vec!["pip", "markerpkg.tgz"],
        vec!["pip", "x==1.zip "],
        vec!["pip", "requests>=2", "-V", "2.32.3"],
        vec![
            "pip",
            "requests",
            "-V",
            "2 @ https://example.invalid/x.tar.gz",
        ],
        vec!["pip", "x", "--version=--allow-build-scripts"],
        // Only reachable after `--`: clap reads a bare `-r` as an option.
        vec!["pip", "--", "-r"],
        vec!["pip", "--allow-build-scripts", "--", "--index-url=x"],
    ] {
        let out = sigil(&fx, &args, &[]);
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("will not download"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert!(ran_nothing(&fx, "pip"), "{args:?} ran pip");
        assert!(
            quarantine_items(&fx).is_empty(),
            "{args:?} created a quarantine entry"
        );
    }
    // A local path is pointed at `sigil scan`, which runs nothing from it;
    // a URL or VCS reference at the opt-in.
    let out = sigil(&fx, &["pip", "./local-project"], &[]);
    let err = stderr(&out);
    assert!(err.contains("`sigil scan ./local-project`"), "{err}");
    assert!(!err.contains("--allow-build-scripts"), "{err}");
    let out = sigil(&fx, &["pip", "git+https://example.invalid/o/r"], &[]);
    assert!(
        stderr(&out).contains("--allow-build-scripts"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

const TYPES_NODE_TARBALL: &str = "https://registry.npmjs.org/@types/node/-/node-20.1.0.tgz";

#[test]
fn npm_packs_the_resolved_registry_tarball_with_scripts_off() {
    let fx = fixture();
    let (packed, integrity) = npm_tarball(&fx, "types-node", "20.1.0");
    let view = npm_view("@types/node", "20.1.0", TYPES_NODE_TARBALL, &integrity);
    let packed = packed.to_string_lossy().into_owned();
    let out = sigil(
        &fx,
        &["--format", "json", "npm", "@types/node", "-V", "20.1.0"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            ("SIGIL_TEST_PACK_FILE", &packed),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let q = only_item(&fx);
    let (argv, cwd) = recorded(&fx, "npm-view").expect("npm view ran");
    assert_eq!(
        argv,
        [
            "view",
            "--json",
            "--",
            "@types/node@20.1.0",
            "name",
            "version",
            "dist.tarball",
            "dist.integrity",
            "dist.shasum",
            "deprecated",
            "dist-tags.latest",
        ]
    );
    assert_eq!(cwd, q, "npm view runs where npm pack does");
    let (argv, cwd) = recorded(&fx, "npm-pack").expect("npm pack ran");
    assert_eq!(argv, ["pack", "--ignore-scripts", "--", TYPES_NODE_TARBALL]);
    assert_eq!(cwd, q, "npm must run in the quarantine directory");
    // The tarball was unpacked and scanned, and the JSON report names the
    // release that was scanned.
    assert!(q.join("types-node-20.1.0").join("package").is_dir());
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("JSON report");
    assert_eq!(report["package"], "@types/node@20.1.0");
    assert!(report["summary"]["files_scanned"].as_u64().unwrap_or(0) >= 2);
}

#[test]
fn npm_says_which_release_a_range_resolves_to() {
    let fx = fixture();
    let (packed, integrity) = npm_tarball(&fx, "left-pad", "1.3.0");
    let view = serde_json::json!([
        {"name":"left-pad","version":"1.2.0","dist.tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz","dist.integrity":"sha512-AAAA","dist-tags.latest":"1.3.0"},
        {"name":"left-pad","version":"1.3.0","dist.tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","dist.integrity":integrity,"dist-tags.latest":"1.3.0"}
    ])
    .to_string();
    let packed = packed.to_string_lossy().into_owned();
    let out = sigil(
        &fx,
        &["npm", "left-pad@^1.2"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            ("SIGIL_TEST_PACK_FILE", &packed),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("resolves to left-pad@1.3.0"),
        "{}",
        stdout(&out)
    );
    let (argv, _) = recorded(&fx, "npm-pack").unwrap();
    assert_eq!(
        argv.last().map(String::as_str),
        Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
    );
}

/// A tarball that does not hash to the registry's integrity is what
/// `npm install` rejects (EINTEGRITY): it is never scanned or passed.
#[test]
fn npm_refuses_a_tarball_that_does_not_match_the_registry_integrity() {
    let fx = fixture();
    let (packed, integrity) = npm_tarball(&fx, "plainpkg", "1.0.0");
    let (_, other) = npm_tarball(&fx, "plainpkg-other", "1.0.0");
    assert_ne!(integrity, other);
    let packed = packed.to_string_lossy().into_owned();
    let tarball = "https://registry.npmjs.org/plainpkg/-/plainpkg-1.0.0.tgz";
    let no_hash = serde_json::json!({
        "name": "plainpkg", "version": "1.0.0", "dist.tarball": tarball,
    })
    .to_string();
    let bad_shasum = serde_json::json!({
        "name": "plainpkg", "version": "1.0.0", "dist.tarball": tarball,
        "dist.shasum": "0000000000000000000000000000000000000000",
    })
    .to_string();
    for (view, says) in [
        (
            npm_view("plainpkg", "1.0.0", tarball, &other),
            "not the integrity",
        ),
        (no_hash, "no integrity or shasum"),
        (bad_shasum, "not the shasum"),
    ] {
        let fx = fixture();
        let out = sigil(
            &fx,
            &["npm", "plainpkg", "--auto-approve"],
            &[
                ("SIGIL_TEST_NPM_VIEW", &view),
                ("SIGIL_TEST_PACK_FILE", &packed),
            ],
        );
        assert_eq!(code(&out), 2, "{view}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("will not scan `plainpkg@1.0.0`"), "{err}");
        assert!(err.contains(says), "{err}");
        assert!(err.contains("EINTEGRITY"), "{err}");
        assert!(!stdout(&out).contains("LOW RISK"), "{}", stdout(&out));
        assert!(quarantine_items(&fx).is_empty(), "{view}");
    }
    // The matching integrity passes.
    let view = npm_view("plainpkg", "1.0.0", tarball, &integrity);
    let out = sigil(
        &fx,
        &["npm", "plainpkg"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            ("SIGIL_TEST_PACK_FILE", &packed),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
}

#[test]
fn npm_refuses_a_registry_tarball_that_is_not_a_plain_download() {
    for tarball in [
        "git+file:///tmp/repo",
        "git+https://github.com/owner/repo.git",
        "https://github.com/owner/repo.tgz",
        "file:/tmp/dir",
    ] {
        let fx = fixture();
        let view = format!(
            r#"{{"name":"markreg","version":"1.0.0","dist.tarball":"{tarball}","dist-tags.latest":"1.0.0"}}"#
        );
        let out = sigil(&fx, &["npm", "markreg"], &[("SIGIL_TEST_NPM_VIEW", &view)]);
        assert_eq!(code(&out), 2, "{tarball}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("will not download `markreg@1.0.0`"), "{err}");
        assert!(recorded(&fx, "npm-pack").is_none(), "{tarball} was packed");
        assert!(quarantine_items(&fx).is_empty(), "{tarball}");
    }
}

#[test]
fn npm_packs_a_package_registry_url_on_a_git_host() {
    // GitLab's npm package registry serves tarballs from gitlab.com; npm
    // downloads such a URL as a tarball (hosted-git-info reads a `/-/` path
    // as no repository), so it is packed like any registry tarball.
    let fx = fixture();
    let tarball =
        "https://gitlab.com/api/v4/projects/123/packages/npm/@acme/pkg/-/@acme/pkg-1.0.0.tgz";
    let (packed, integrity) = npm_tarball(&fx, "acme-pkg", "1.0.0");
    let view = npm_view("@acme/pkg", "1.0.0", tarball, &integrity);
    let packed = packed.to_string_lossy().into_owned();
    let out = sigil(
        &fx,
        &["npm", "@acme/pkg"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            ("SIGIL_TEST_PACK_FILE", &packed),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let (argv, _) = recorded(&fx, "npm-pack").expect("npm pack ran");
    assert_eq!(argv.last().map(String::as_str), Some(tarball));
}

#[test]
fn npm_view_failures_pack_nothing() {
    for view in ["", "not json", r#"{"error":{"code":"E404"}}"#] {
        let fx = fixture();
        let out = sigil(&fx, &["npm", "left-pad"], &[("SIGIL_TEST_NPM_VIEW", view)]);
        assert_eq!(code(&out), 2, "{view}: {}", stderr(&out));
        assert!(recorded(&fx, "npm-pack").is_none(), "{view}");
        assert!(quarantine_items(&fx).is_empty(), "{view}");
    }
}

#[test]
fn npm_opt_in_runs_from_the_callers_directory_and_packs_into_quarantine() {
    for spec in ["github:owner/repo", "./local-dir", "file:../pkg", "pkg.tgz"] {
        let fx = fixture();
        let (packed, _) = npm_tarball(&fx, "pkg", "1.0.0");
        let packed = packed.to_string_lossy().into_owned();
        let out = sigil(
            &fx,
            &["npm", spec, "--allow-build-scripts"],
            &[("SIGIL_TEST_PACK_FILE", &packed)],
        );
        assert_eq!(code(&out), 0, "{spec}: {}", stderr(&out));
        let q = only_item(&fx);
        let (argv, cwd) = recorded(&fx, "npm-pack").expect("npm ran");
        assert_eq!(
            argv,
            [
                "pack",
                "--pack-destination",
                &q.to_string_lossy(),
                "--",
                spec
            ]
        );
        assert_eq!(cwd, fx.root, "a relative spec means what the user typed");
        assert!(recorded(&fx, "npm-view").is_none());
        let err = stderr(&out);
        assert!(err.contains("warning:"), "{err}");
        assert!(err.contains("lifecycle scripts"), "{err}");
    }
}

#[test]
fn npm_refusals_run_nothing_and_quarantine_nothing() {
    let fx = fixture();
    for (spec, scan) in [
        ("./local-dir", Some("./local-dir")),
        ("../local-dir", Some("../local-dir")),
        ("/abs/dir", Some("/abs/dir")),
        ("owner/repo", None),
        ("npmdir/", Some("npmdir/")),
        ("github:owner/repo", None),
        ("git+https://example.invalid/owner/repo.git", None),
        ("git+file:///tmp/repo", None),
        ("git@example.invalid:owner/repo.git", None),
        ("https://example.invalid/pkg-1.0.0.tgz", None),
        ("file:../pkg", Some("../pkg")),
        ("pkg.tgz", Some("pkg.tgz")),
        ("foo.tar-gz", Some("foo.tar-gz")),
        ("foo@1.tarxgz", Some("1.tarxgz")),
        ("foo@owner/repo", None),
        ("foo#main", None),
        ("@scope/name/sub", None),
    ] {
        let out = sigil(&fx, &["npm", spec], &[]);
        assert_eq!(code(&out), 2, "{spec}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("will not download"), "{spec}: {err}");
        match scan {
            // A file or directory: scan it where it is.
            Some(path) => {
                assert!(
                    err.contains(&format!("`sigil scan {path}`")),
                    "{spec}: {err}"
                );
                assert!(!err.contains("--allow-build-scripts"), "{spec}: {err}");
            }
            None => assert!(err.contains("--allow-build-scripts"), "{spec}: {err}"),
        }
        assert!(ran_nothing(&fx, "npm"), "{spec} ran npm");
        assert!(
            quarantine_items(&fx).is_empty(),
            "{spec} created a quarantine entry"
        );
    }
    let out = sigil(&fx, &["npm", "foo@npm:bar"], &[]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("`sigil npm bar`"), "{}", stderr(&out));
    let out = sigil(&fx, &["npm", "--", "-g"], &[]);
    assert_eq!(code(&out), 2);
    assert!(ran_nothing(&fx, "npm"));
}

// ---------------------------------------------------------------------------
// The MCP server's scan_package tool takes the same path
// ---------------------------------------------------------------------------

/// One `tools/call scan_package` through `sigil mcp`, with the test doubles
/// first on PATH: the tool's result object.
fn mcp_scan_package(
    fx: &Fixture,
    arguments: serde_json::Value,
    env: &[(&str, &str)],
) -> serde_json::Value {
    use std::io::Write;
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "scan_package", "arguments": arguments },
    });
    let path = format!(
        "{}:{}",
        fx.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .arg("mcp")
        .current_dir(&fx.root)
        .env("HOME", &fx.home)
        .env("PATH", path)
        .env("NO_COLOR", "1")
        .env("SIGIL_TEST_LOG_DIR", &fx.logs)
        .env_remove("SIGIL_QUARANTINE_DIR")
        .env_remove("SIGIL_POLICY_FILE")
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run sigil mcp");
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{request}").unwrap();
    }
    let out = child.wait_with_output().expect("sigil mcp output");
    let line = String::from_utf8_lossy(&out.stdout).to_string();
    let response: serde_json::Value = serde_json::from_str(line.trim()).expect("one JSON response");
    response["result"].clone()
}

#[test]
fn mcp_scan_package_gets_the_same_defaults() {
    // Refused before npm or pip runs, and the reason reaches the client.
    let fx = fixture();
    for (ecosystem, name) in [
        ("npm", "github:owner/repo"),
        ("npm", "owner/repo"),
        ("npm", "./local-dir"),
        ("pypi", "./local-project"),
        ("pypi", "git+https://example.invalid/owner/repo"),
    ] {
        let result = mcp_scan_package(
            &fx,
            serde_json::json!({ "ecosystem": ecosystem, "name": name }),
            &[],
        );
        assert_eq!(result["isError"], true, "{ecosystem} {name}: {result}");
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("will not download"),
            "{ecosystem} {name}: {text}"
        );
        assert!(ran_nothing(&fx, "npm"), "{name} ran npm");
        assert!(ran_nothing(&fx, "pip"), "{name} ran pip");
    }
    // A registry package goes through the wheel-only download.
    let result = mcp_scan_package(
        &fx,
        serde_json::json!({ "ecosystem": "pypi", "name": "requests", "version": "2.32.3" }),
        &[],
    );
    assert_eq!(result["isError"], false, "{result}");
    let (argv, _) = recorded(&fx, "pip-download").expect("pip ran");
    assert!(argv.iter().any(|a| a == "--only-binary=:all:"), "{argv:?}");
    assert_eq!(argv.last().map(String::as_str), Some("requests==2.32.3"));
    assert_eq!(result["structuredContent"]["package"], "requests==2.32.3");
}

#[test]
fn mcp_scan_package_names_the_release_it_scanned() {
    // An unpinned or ranged request: the result says which release was
    // scanned, the version to install.
    let fx = fixture();
    let result = mcp_scan_package(
        &fx,
        serde_json::json!({ "ecosystem": "pypi", "name": "markerpkg" }),
        &[(
            "SIGIL_TEST_PIP_INDEX",
            "markerpkg (2.0)\nAvailable versions: 2.0, 1.0",
        )],
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["structuredContent"]["package"], "markerpkg==2.0");

    let (packed, integrity) = npm_tarball(&fx, "left-pad", "1.3.0");
    let view = npm_view(
        "left-pad",
        "1.3.0",
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        &integrity,
    );
    let packed = packed.to_string_lossy().into_owned();
    let result = mcp_scan_package(
        &fx,
        serde_json::json!({ "ecosystem": "npm", "name": "left-pad", "version": "^1" }),
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            ("SIGIL_TEST_PACK_FILE", &packed),
        ],
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["structuredContent"]["target"], "npm:left-pad");
    assert_eq!(result["structuredContent"]["package"], "left-pad@1.3.0");
}

// ---------------------------------------------------------------------------
// The real pip, offline, against local fixtures
// ---------------------------------------------------------------------------

/// The files of a project whose in-tree build backend creates `marker` when
/// pip imports it, i.e. when pip prepares its metadata. `requires = []` and
/// `backend-path` mean pip needs no network to get that far.
fn marker_project(version: &str, marker: &Path) -> [(&'static str, String); 3] {
    let backend = format!(
        "# Test fixture: its only side effect is an empty marker file.\n\
         open({marker:?}, \"w\").close()\n\
         \n\
         def get_requires_for_build_wheel(config_settings=None):\n    return []\n\
         \n\
         def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):\n\
         \x20   import os\n\
         \x20   d = os.path.join(metadata_directory, \"markerpkg-{version}.dist-info\")\n\
         \x20   os.makedirs(d, exist_ok=True)\n\
         \x20   with open(os.path.join(d, \"METADATA\"), \"w\") as f:\n\
         \x20       f.write(\"Metadata-Version: 2.1\\nName: markerpkg\\nVersion: {version}\\n\")\n\
         \x20   return \"markerpkg-{version}.dist-info\"\n\
         \n\
         def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n\
         \x20   raise RuntimeError(\"fixture builds no wheels\")\n",
        marker = marker.to_string_lossy()
    );
    [
        (
            "pyproject.toml",
            "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n"
                .to_string(),
        ),
        ("backend.py", backend),
        (
            "PKG-INFO",
            format!("Metadata-Version: 2.1\nName: markerpkg\nVersion: {version}\n"),
        ),
    ]
}

/// `markerpkg-<version>.tar.gz` in `links`: a source distribution of
/// [`marker_project`].
fn write_marker_sdist(links: &Path, version: &str, marker: &Path) {
    let f = std::fs::File::create(links.join(format!("markerpkg-{version}.tar.gz"))).unwrap();
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for (name, body) in marker_project(version, marker) {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(
            &mut h,
            format!("markerpkg-{version}/{name}"),
            body.as_bytes(),
        )
        .unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
}

/// `markerpkg-<version>-py3-none-any.whl` in `links`: a plain module,
/// nothing in it runs when it is downloaded.
fn write_plain_wheel(links: &Path, version: &str) {
    use std::io::Write;
    let f =
        std::fs::File::create(links.join(format!("markerpkg-{version}-py3-none-any.whl"))).unwrap();
    let mut z = zip::ZipWriter::new(f);
    let opts = zip::write::FileOptions::default();
    let info = format!("markerpkg-{version}.dist-info");
    for (name, body) in [
        (
            "markerpkg/__init__.py".to_string(),
            "VALUE = 1\n".to_string(),
        ),
        (
            format!("{info}/METADATA"),
            format!("Metadata-Version: 2.1\nName: markerpkg\nVersion: {version}\n"),
        ),
        (
            format!("{info}/WHEEL"),
            "Wheel-Version: 1.0\nGenerator: sigil-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .to_string(),
        ),
        (format!("{info}/RECORD"), String::new()),
    ] {
        z.start_file(name, opts).unwrap();
        z.write_all(body.as_bytes()).unwrap();
    }
    z.finish().unwrap();
}

fn real_pip_available() -> bool {
    let available = Command::new("pip")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("skipped: pip is not installed");
    }
    available
}

/// pip offline against `links`, with no config file.
fn offline(links: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("PIP_CONFIG_FILE", "/dev/null".into()),
        ("PIP_NO_INDEX", "1".into()),
        ("PIP_FIND_LINKS", links.to_string_lossy().into_owned()),
        ("PIP_DISABLE_PIP_VERSION_CHECK", "1".into()),
        ("PIP_NO_CACHE_DIR", "1".into()),
    ]
}

fn with<'a>(
    base: &'a [(&'static str, String)],
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    base.iter()
        .map(|(k, v)| (*k, v.as_str()))
        .chain(extra.iter().copied())
        .collect()
}

#[test]
fn real_pip_never_builds_a_local_sdist_by_default() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    let marker = fx.root.join("marker-backend-ran");
    write_marker_sdist(&links, "1.0", &marker);
    let path = std::env::var("PATH").unwrap_or_default();
    let env = offline(&links);

    // The index (here: the local find-links directory) has only an sdist.
    let out = run_sigil(&fx, &["pip", "markerpkg"], &path, &with(&env, &[]));
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(!marker.exists(), "the sdist's build backend ran by default");
    assert!(
        stderr(&out).contains("--allow-build-scripts"),
        "{}",
        stderr(&out)
    );

    // The same sdist as a local path is refused before pip runs.
    let sdist = links.join("markerpkg-1.0.tar.gz");
    let out = run_sigil(
        &fx,
        &["pip", &sdist.to_string_lossy()],
        &path,
        &with(&env, &[]),
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(!marker.exists(), "a local sdist path was built");

    // The fixture is live: with the opt-in, pip does run its backend.
    let out = run_sigil(
        &fx,
        &["pip", "markerpkg", "--allow-build-scripts"],
        &path,
        &with(&env, &[]),
    );
    assert!(
        marker.exists(),
        "with --allow-build-scripts pip should have prepared the sdist; stderr: {}",
        stderr(&out)
    );
}

/// The newest release has only an sdist and an older one has a wheel: a
/// wheel-only download of `markerpkg` would quietly fetch 1.0 while `pip
/// install markerpkg` builds and installs 2.0. Sigil resolves 2.0 and
/// fails instead; a range that excludes 2.0 gets the 1.0 wheel.
#[test]
fn real_pip_does_not_scan_an_older_wheel_in_place_of_the_newest_release() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    let marker = fx.root.join("marker-sdist2-ran");
    write_plain_wheel(&links, "1.0");
    write_marker_sdist(&links, "2.0", &marker);
    let path = std::env::var("PATH").unwrap_or_default();
    let env = offline(&links);

    let out = run_sigil(&fx, &["pip", "markerpkg"], &path, &with(&env, &[]));
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("markerpkg==2.0"), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("`markerpkg==2.0` is the release"),
        "{}",
        stderr(&out)
    );
    assert!(!marker.exists(), "the 2.0 sdist's backend ran");

    let out = run_sigil(&fx, &["pip", "markerpkg<2"], &path, &with(&env, &[]));
    assert!(matches!(code(&out), 0 | 1), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("markerpkg==1.0"), "{}", stdout(&out));
    let wheel_dirs: Vec<PathBuf> = quarantine_items(&fx)
        .into_iter()
        .filter(|q| {
            q.join("markerpkg-1.0-py3-none-any.whl").exists()
                || q.join("markerpkg-1.0-py3-none-any")
                    .join("markerpkg")
                    .is_dir()
        })
        .collect();
    assert_eq!(wheel_dirs.len(), 1, "the 1.0 wheel was downloaded once");
    assert!(!marker.exists());
}

/// A constraint from the environment that names a local project, and a
/// requirement in a pip config file: pip builds both, whatever the spec.
#[test]
fn real_pip_ignores_env_constraints_and_refuses_config_requirements() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    write_plain_wheel(&links, "1.0");
    let marker = fx.root.join("marker-project-ran");
    let project = fx.root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    for (name, body) in marker_project("1.0", &marker) {
        std::fs::write(project.join(name), body).unwrap();
    }
    let constraints = fx.root.join("constraints.txt");
    std::fs::write(
        &constraints,
        format!("markerpkg @ file://{}\n", project.display()),
    )
    .unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    let env = offline(&links);
    let constraints_s = constraints.to_string_lossy().to_string();

    let out = run_sigil(
        &fx,
        &["pip", "markerpkg==1.0"],
        &path,
        &with(&env, &[("PIP_CONSTRAINT", &constraints_s)]),
    );
    assert!(matches!(code(&out), 0 | 1), "stderr: {}", stderr(&out));
    assert!(
        !marker.exists(),
        "pip built the project PIP_CONSTRAINT names"
    );
    assert!(
        stderr(&out).contains("PIP_CONSTRAINT is left out"),
        "{}",
        stderr(&out)
    );

    let requirements = fx.root.join("requirements.txt");
    std::fs::write(&requirements, format!("{}\n", project.display())).unwrap();
    let conf = fx.root.join("pip.conf");
    std::fs::write(
        &conf,
        format!("[download]\nrequirement = {}\n", requirements.display()),
    )
    .unwrap();
    let conf_s = conf.to_string_lossy().to_string();
    let env: Vec<(&str, &str)> = with(&env, &[])
        .into_iter()
        .filter(|(k, _)| *k != "PIP_CONFIG_FILE")
        .chain([("PIP_CONFIG_FILE", conf_s.as_str())])
        .collect();
    let items_before = quarantine_items(&fx).len();
    let out = run_sigil(&fx, &["pip", "markerpkg==1.0"], &path, &env);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("download.requirement"),
        "{}",
        stderr(&out)
    );
    assert!(!marker.exists(), "pip built the project pip.conf names");
    assert_eq!(quarantine_items(&fx).len(), items_before);

    // The fixture is live: with the opt-in, pip reads the constraint and
    // builds the project.
    let out = run_sigil(
        &fx,
        &["pip", "markerpkg==1.0", "--allow-build-scripts"],
        &path,
        &with(&offline(&links), &[("PIP_CONSTRAINT", &constraints_s)]),
    );
    assert!(
        marker.exists(),
        "with --allow-build-scripts pip should have built the constrained project; stderr: {}",
        stderr(&out)
    );
}

/// pip runs in the caller's directory, as `pip install` does, so a relative
/// find-links setting means the same to both (it did in 1.3.7).
#[test]
fn real_pip_reads_relative_settings_from_the_callers_directory() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("wheels");
    std::fs::create_dir_all(&links).unwrap();
    write_plain_wheel(&links, "1.0");
    let path = std::env::var("PATH").unwrap_or_default();
    let base = offline(&links);
    let env: Vec<(&str, &str)> = with(&base, &[])
        .into_iter()
        .filter(|(k, _)| *k != "PIP_FIND_LINKS")
        .chain([("PIP_FIND_LINKS", "./wheels")])
        .collect();
    for spec in ["markerpkg==1.0", "markerpkg"] {
        let before = quarantine_items(&fx).len();
        let out = run_sigil(&fx, &["pip", spec], &path, &env);
        assert!(matches!(code(&out), 0 | 1), "{spec}: {}", stderr(&out));
        let items = quarantine_items(&fx);
        assert_eq!(items.len(), before + 1, "{spec}");
        assert!(
            items.iter().any(|q| q
                .join("markerpkg-1.0-py3-none-any")
                .join("markerpkg")
                .is_dir()),
            "{spec}: the wheel from ./wheels was downloaded and unpacked"
        );
    }
}

/// With the opt-in, pip runs a local project's build backend but does not
/// copy a directory into `--dest`: nothing was downloaded, which is an
/// error, never a clean scan, and never auto-approved.
#[test]
fn real_pip_opt_in_local_directory_is_not_a_clean_scan() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    let marker = fx.root.join("marker-local-project-ran");
    let project = fx.root.join("pyproj");
    std::fs::create_dir_all(&project).unwrap();
    for (name, body) in marker_project("1.0", &marker) {
        std::fs::write(project.join(name), body).unwrap();
    }
    let path = std::env::var("PATH").unwrap_or_default();
    let env = offline(&links);

    // By default: refused, pointed at `sigil scan`, nothing ran.
    let out = run_sigil(&fx, &["pip", "./pyproj"], &path, &with(&env, &[]));
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("`sigil scan ./pyproj`"),
        "{}",
        stderr(&out)
    );
    assert!(!marker.exists());

    let out = run_sigil(
        &fx,
        &["pip", "./pyproj", "--allow-build-scripts", "--auto-approve"],
        &path,
        &with(&env, &[]),
    );
    assert!(
        marker.exists(),
        "the fixture is live: pip prepared the project; stderr: {}",
        stderr(&out)
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("saved nothing into quarantine"),
        "{}",
        stderr(&out)
    );
    assert!(!stdout(&out).contains("LOW RISK"), "{}", stdout(&out));
    assert!(quarantine_items(&fx).is_empty());
}
