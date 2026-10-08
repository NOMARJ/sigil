//! `sigil pip` / `sigil npm` never let pip or npm run package code by
//! default: end-to-end tests of what the real binary hands to pip and npm.
//!
//! Most tests put test-double `pip` and `npm` executables first on PATH. They
//! only record their argv, working directory and environment, print canned
//! output for the lookups Sigil makes first (`pip config list`, `pip index
//! versions`, `npm view`, `npm config get registry`) and exit; the only
//! network is a registry on 127.0.0.1 that serves the tarball `sigil npm`
//! downloads itself. The
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
/// tools would, after printing `$SIGIL_TEST_FAKE_STDOUT` to stdout (pip's
/// progress, npm pack's file name) and `$SIGIL_TEST_FAKE_STDERR` to stderr.
/// With `$SIGIL_TEST_FAKE_SLEEP` set, a download or pack writes
/// its pid to `<tool>-<sub>.pid` and sleeps that many seconds instead (a
/// slow transfer a test can interrupt). `$SIGIL_TEST_PIP_INDEX_FAIL` makes
/// `pip index` print that to stderr and fail (pip older than 21.2 prints
/// `unknown command "index"`); `$SIGIL_TEST_NPM_VIEW_ALL` is what an `npm
/// view` of a `<name>@>=0` range prints (every release), `$SIGIL_TEST_NPM_VIEW`
/// what any other view prints; `npm config get registry` prints
/// `$SIGIL_TEST_NPM_REGISTRY` (npm's default registry when unset) and `npm
/// config get @scope:registry` `$SIGIL_TEST_NPM_SCOPED_REGISTRY` (`undefined`
/// when unset), as npm does.
const FAKE_TOOL: &str = r#"#!/bin/sh
tool=$(basename "$0")
sub=$1
for a in "$@"; do printf '%s\n' "$a"; done > "$SIGIL_TEST_LOG_DIR/$tool-$sub.argv"
pwd -P > "$SIGIL_TEST_LOG_DIR/$tool-$sub.cwd"
env > "$SIGIL_TEST_LOG_DIR/$tool-$sub.env"
case "$tool $sub" in
  "pip config") printf '%s' "${SIGIL_TEST_PIP_CONFIG:-}"; exit 0 ;;
  "pip index")
    if [ -n "${SIGIL_TEST_PIP_INDEX_FAIL:-}" ]; then printf '%s\n' "$SIGIL_TEST_PIP_INDEX_FAIL" >&2; exit 1; fi
    printf '%s\n' "${SIGIL_TEST_PIP_INDEX:-}"; exit 0 ;;
  "npm view")
    for a in "$@"; do
      case $a in *'@>=0') if [ -n "${SIGIL_TEST_NPM_VIEW_ALL:-}" ]; then printf '%s\n' "$SIGIL_TEST_NPM_VIEW_ALL"; exit 0; fi ;; esac
    done
    printf '%s\n' "${SIGIL_TEST_NPM_VIEW:-}"; exit 0 ;;
  "npm config")
    case $3 in
      @*:registry) printf '%s\n' "${SIGIL_TEST_NPM_SCOPED_REGISTRY:-undefined}"; exit 0 ;;
      registry) printf '%s\n' "${SIGIL_TEST_NPM_REGISTRY:-https://registry.npmjs.org/}"; exit 0 ;;
    esac
    exit 1 ;;
esac
if [ -n "${SIGIL_TEST_FAKE_SLEEP:-}" ]; then
  echo $$ > "$SIGIL_TEST_LOG_DIR/$tool-$sub.pid"
  exec sleep "$SIGIL_TEST_FAKE_SLEEP"
fi
if [ -n "${SIGIL_TEST_FAKE_STDERR:-}" ]; then printf '%s\n' "$SIGIL_TEST_FAKE_STDERR" >&2; fi
if [ -n "${SIGIL_TEST_FAKE_STDOUT:-}" ]; then printf '%s\n' "$SIGIL_TEST_FAKE_STDOUT"; fi
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
    sigil_command(fx, args, path, env)
        .output()
        .expect("run sigil")
}

fn sigil_command(fx: &Fixture, args: &[&str], path: &str, env: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigil"));
    cmd.args(args)
        .current_dir(&fx.root)
        .env("HOME", &fx.home)
        .env("PATH", path)
        .env("NO_COLOR", "1")
        .env("SIGIL_TEST_LOG_DIR", &fx.logs)
        .env_remove("SIGIL_ALLOW_BUILD_SCRIPTS")
        .env_remove("SIGIL_QUARANTINE_DIR")
        .env_remove("SIGIL_POLICY_FILE")
        .env_remove("SIGIL_PACK_PUBLIC_KEY")
        .env_remove("SIGIL_NO_PROJECT_CONFIG")
        .env_remove("SIGIL_ALLOW_PRIVATE_URLS");
    // The registry the tests download from is on 127.0.0.1: no proxy of the
    // caller's stands between.
    for k in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(k);
    }
    // The caller's own pip settings must not leak into the tests.
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("PIP_") {
            cmd.env_remove(k);
        }
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd
}

/// What confirms `--allow-build-scripts` where there is no terminal, as a
/// script or CI job sets it.
const OPT_IN: (&str, &str) = ("SIGIL_ALLOW_BUILD_SCRIPTS", "1");

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

/// A registry on 127.0.0.1 serving the tarball of one release, which `sigil
/// npm` downloads itself: the tarball's URL, its integrity, and the registry
/// URL the fake `npm` reports as npm's registry (the tarball must be on its
/// host).
struct Served {
    registry: String,
    tarball: String,
    integrity: String,
}

impl Served {
    /// The environment that makes the fake `npm` report this registry.
    fn env(&self) -> (&'static str, &str) {
        ("SIGIL_TEST_NPM_REGISTRY", &self.registry)
    }
}

/// Serve a real tarball of `name`@`version` (a file-name-safe name: the
/// tarball is `<name>-<version>.tgz`) on a loopback registry.
fn serve_tarball(fx: &Fixture, name: &str, version: &str) -> Served {
    let (path, integrity) = npm_tarball(fx, name, version);
    let file = path.file_name().unwrap().to_string_lossy().into_owned();
    let bytes = std::fs::read(&path).unwrap();
    let base = serve_registry(|_| (Vec::new(), vec![(file.clone(), bytes)]));
    Served {
        tarball: format!("{base}/files/{file}"),
        registry: format!("{base}/"),
        integrity,
    }
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
        // Pinned by string equality: `==2.0` also matches `2.0+local1`.
        assert_eq!(
            argv.last().map(String::as_str),
            Some(pinned.replacen("==", "===", 1).as_str()),
            "{spec}"
        );
        assert!(argv.iter().any(|a| a == "--only-binary=:all:"));
        assert!(
            stdout(&out).contains("resolves to"),
            "{spec}: {}",
            stdout(&out)
        );
        // `sigil list` names the release that was downloaded, not the spec
        // that was typed.
        let list = sigil(&fx, &["list"], &[]);
        assert!(
            stdout(&list).contains(&format!("{pinned} (pip)")),
            "{spec}: {}",
            stdout(&list)
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
        // Nothing is said about downloading when nothing is.
        assert!(!stdout(&out).contains("downloading"), "{}", stdout(&out));
    }
}

/// `-V` on a spec that already names a version is said plainly (it used to
/// read as a marker or a malformed range), and nothing runs.
#[test]
fn a_version_flag_on_a_spec_that_names_a_version_is_refused_plainly() {
    let fx = fixture();
    for (args, spec) in [
        (vec!["pip", "wheelok>=1", "-V", "1.0"], "wheelok>=1"),
        (
            vec!["pip", "wheelok==1.0", "--version", "2.0"],
            "wheelok==1.0",
        ),
        (vec!["pip", "wheelok[x]<2", "-V", "1.0"], "wheelok[x]<2"),
        (vec!["npm", "plainpkg@1", "-V", "1.0.0"], "plainpkg@1"),
        (
            vec!["npm", "@types/node@20", "-V", "20.1.0"],
            "@types/node@20",
        ),
    ] {
        let out = sigil(&fx, &args, &[OPT_IN]);
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("was given a version twice"), "{err}");
        assert!(
            err.contains(&format!("`{spec}` already names one")),
            "{err}"
        );
        assert!(!err.contains("environment marker"), "{err}");
    }
    assert!(ran_nothing(&fx, "pip") && ran_nothing(&fx, "npm"));
    assert!(quarantine_items(&fx).is_empty());
    // A name with extras or a scope is not a version.
    let out = sigil(&fx, &["pip", "requests[socks]", "-V", "2.32.3"], &[]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

/// With no pip or npm on PATH, the message says so (the system's own
/// `No such file or directory (os error 2)` does not say which file).
#[test]
fn a_missing_pip_or_npm_is_named() {
    let fx = fixture();
    let empty = fx.root.join("empty-bin");
    std::fs::create_dir_all(&empty).unwrap();
    let path = empty.to_string_lossy().into_owned();
    for (args, tool) in [
        (vec!["pip", "requests==2.32.3"], "pip"),
        (vec!["pip", "requests"], "pip"),
        (vec!["npm", "left-pad"], "npm"),
    ] {
        let out = run_sigil(&fx, &args, &path, &[]);
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!("is {tool} installed and on PATH?")),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    assert!(quarantine_items(&fx).is_empty());
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
    assert_eq!(
        argv.last().map(String::as_str),
        Some("sdist-only-pkg===2.0")
    );
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
        &[OPT_IN, ("PIP_CONSTRAINT", "/x/constraints.txt")],
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
        &[OPT_IN, ("SIGIL_TEST_PIP_SAVES", "0")],
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

    // The same for npm with the opt-in: a pack that wrote no tarball. (By
    // default Sigil writes the tarball itself and fails if it cannot.)
    let fx = fixture();
    let out = sigil(
        &fx,
        &[
            "npm",
            "./local-dir",
            "--allow-build-scripts",
            "--auto-approve",
        ],
        &[OPT_IN],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("saved nothing into quarantine"),
        "{}",
        stderr(&out)
    );
    assert!(!stdout(&out).contains("auto-approved"), "{}", stdout(&out));
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
        vec!["pip", "C:\\x\\y"],
        vec!["pip", "six; python_version<'3'"],
        vec!["pip", "x==1.zip "],
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
    // A Windows drive path is a path, not a URL.
    let out = sigil(&fx, &["pip", "C:\\x\\y"], &[]);
    let err = stderr(&out);
    assert!(err.contains("`sigil scan C:\\x\\y`"), "{err}");
    assert!(!err.contains("it is a URL"), "{err}");
    // An environment marker is named as one.
    let out = sigil(&fx, &["pip", "six; python_version<'3'"], &[]);
    let err = stderr(&out);
    assert!(err.contains("environment marker"), "{err}");
    assert!(!err.contains("expected a version specifier"), "{err}");
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

#[test]
fn npm_downloads_the_resolved_registry_tarball_and_never_runs_npm_pack() {
    let fx = fixture();
    let served = serve_tarball(&fx, "types-node", "20.1.0");
    let view = npm_view("@types/node", "20.1.0", &served.tarball, &served.integrity);
    let out = sigil(
        &fx,
        &["--format", "json", "npm", "@types/node", "-V", "20.1.0"],
        &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
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
    assert_eq!(cwd, q, "npm view runs in the (empty) quarantine directory");
    // No `npm pack`: it would fetch the release's metadata a second time (and
    // could be told a different tarball). The tarball Sigil checked is the
    // one it downloaded, and the registry setting was read from npm.
    assert!(recorded(&fx, "npm-pack").is_none(), "npm pack ran");
    let (argv, _) = recorded(&fx, "npm-config").expect("npm config ran");
    assert_eq!(argv, ["config", "get", "registry"]);
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
    let served = serve_tarball(&fx, "left-pad", "1.3.0");
    let view = serde_json::json!([
        {"name":"left-pad","version":"1.2.0","dist.tarball":format!("{}/files/left-pad-1.2.0.tgz", served.registry.trim_end_matches('/')),"dist.integrity":"sha512-AAAA","dist-tags.latest":"1.3.0"},
        {"name":"left-pad","version":"1.3.0","dist.tarball":served.tarball,"dist.integrity":served.integrity,"dist-tags.latest":"1.3.0"}
    ])
    .to_string();
    let out = sigil(
        &fx,
        &["npm", "left-pad@^1.2"],
        &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("resolves to left-pad@1.3.0"),
        "{}",
        stdout(&out)
    );
    assert!(only_item(&fx).join("left-pad-1.3.0").is_dir());
    // The quarantine entry is named for the release, not the range typed.
    let list = sigil(&fx, &["list"], &[]);
    assert!(
        stdout(&list).contains("left-pad@1.3.0 (npm)"),
        "{}",
        stdout(&list)
    );
    assert!(!stdout(&list).contains("^1.2"), "{}", stdout(&list));
}

/// A tarball that does not hash to the registry's integrity is what
/// `npm install` rejects (EINTEGRITY): it is never scanned or passed.
#[test]
fn npm_refuses_a_tarball_that_does_not_match_the_registry_integrity() {
    let fx = fixture();
    let served = serve_tarball(&fx, "plainpkg", "1.0.0");
    let (_, other) = npm_tarball(&fx, "plainpkg-other", "1.0.0");
    assert_ne!(served.integrity, other);
    let no_hash = serde_json::json!({
        "name": "plainpkg", "version": "1.0.0", "dist.tarball": served.tarball,
    })
    .to_string();
    let bad_shasum = serde_json::json!({
        "name": "plainpkg", "version": "1.0.0", "dist.tarball": served.tarball,
        "dist.shasum": "0000000000000000000000000000000000000000",
    })
    .to_string();
    for (view, says) in [
        (
            npm_view("plainpkg", "1.0.0", &served.tarball, &other),
            "not the integrity",
        ),
        (no_hash, "no integrity or shasum"),
        (bad_shasum, "not the shasum"),
    ] {
        let fx = fixture();
        let out = sigil(
            &fx,
            &["npm", "plainpkg", "--auto-approve"],
            &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
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
    let view = npm_view("plainpkg", "1.0.0", &served.tarball, &served.integrity);
    let out = sigil(
        &fx,
        &["npm", "plainpkg"],
        &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
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
        assert!(!stdout(&out).contains("downloading"), "{}", stdout(&out));
        assert!(recorded(&fx, "npm-pack").is_none(), "{tarball} was packed");
        assert!(quarantine_items(&fx).is_empty(), "{tarball}");
    }
}

/// A registry (a private or mirrored one) whose description of a release
/// names another package than the one asked for: the scan would be of a
/// package the user did not name, and the release Sigil prints is the one the
/// docs tell them to install.
#[test]
fn npm_refuses_a_release_that_carries_another_package_name() {
    let fx = fixture();
    let served = serve_tarball(&fx, "othername", "1.0.0");
    let view = npm_view("othername", "1.0.0", &served.tarball, &served.integrity);
    let out = sigil(
        &fx,
        &["npm", "nameswap", "--auto-approve"],
        &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("you asked for `nameswap`"), "{err}");
    assert!(
        err.contains("says the package is named `othername`"),
        "{err}"
    );
    assert!(!stdout(&out).contains("resolves to"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("downloading"), "{}", stdout(&out));
    assert!(quarantine_items(&fx).is_empty());
    // A range or tag names the same package; a scoped one too; case does not
    // matter (the registry normalises it).
    for (spec, name) in [
        ("othername@^1", "othername"),
        ("OtherName", "othername"),
        ("othername@latest", "othername"),
    ] {
        let fx = fixture();
        let served = serve_tarball(&fx, name, "1.0.0");
        let view = npm_view(name, "1.0.0", &served.tarball, &served.integrity);
        let out = sigil(
            &fx,
            &["npm", spec],
            &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
        );
        assert_eq!(code(&out), 0, "{spec}: {}", stderr(&out));
    }
    // A scope is part of the name.
    let fx = fixture();
    let served = serve_tarball(&fx, "pkg", "1.0.0");
    let view = npm_view("@other/pkg", "1.0.0", &served.tarball, &served.integrity);
    let out = sigil(
        &fx,
        &["npm", "@acme/pkg"],
        &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("is named `@other/pkg`"),
        "{}",
        stderr(&out)
    );
}

/// Sigil downloads the tarball itself, from the registry's own host and
/// without credentials: a registry whose metadata names another host, or a
/// URL with a token in it, is refused before anything is fetched.
#[test]
fn npm_refuses_a_tarball_off_the_registry_host_or_with_credentials() {
    let fx = fixture();
    let served = serve_tarball(&fx, "plainpkg", "1.0.0");
    let on_registry = served.tarball.clone();
    let with_user = on_registry.replacen("http://", "http://token:pw@", 1);
    for (tarball, says) in [
        (
            "http://evil.example/plainpkg-1.0.0.tgz".to_string(),
            "not the host",
        ),
        // npm's own registry in the metadata of another registry.
        (
            "https://registry.npmjs.org/plainpkg/-/plainpkg-1.0.0.tgz".to_string(),
            "not the host",
        ),
        (with_user, "user name or password"),
    ] {
        let fx = fixture();
        let view = npm_view("plainpkg", "1.0.0", &tarball, &served.integrity);
        let out = sigil(
            &fx,
            &["npm", "plainpkg"],
            &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
        );
        assert_eq!(code(&out), 2, "{tarball}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("will not download `plainpkg@1.0.0`"), "{err}");
        assert!(err.contains(says), "{tarball}: {err}");
        assert!(!err.contains("token:pw"), "credentials were printed: {err}");
        assert!(recorded(&fx, "npm-pack").is_none(), "{tarball} was packed");
        assert!(quarantine_items(&fx).is_empty(), "{tarball}");
    }
    // A scoped package is checked against its scope's registry.
    let fx = fixture();
    let view = npm_view("@acme/pkg", "1.0.0", &served.tarball, &served.integrity);
    let out = sigil(
        &fx,
        &["npm", "@acme/pkg"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            ("SIGIL_TEST_NPM_REGISTRY", &served.registry),
            (
                "SIGIL_TEST_NPM_SCOPED_REGISTRY",
                "https://npm.acme.example/",
            ),
        ],
    );
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("not the host"), "{}", stderr(&out));
    let (argv, _) = recorded(&fx, "npm-config").expect("npm config ran");
    assert_eq!(
        argv,
        ["config", "get", "@acme:registry"],
        "the scope's registry is asked first"
    );
}

/// A registry that wants a token for tarballs is not sent one: the 401 is
/// explained.
#[test]
fn npm_explains_a_tarball_that_needs_credentials() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let fx = fixture();
    let (_, integrity) = npm_tarball(&fx, "secretpkg", "1.0.0");
    let view = npm_view(
        "secretpkg",
        "1.0.0",
        &format!("http://127.0.0.1:{port}/secretpkg-1.0.0.tgz"),
        &integrity,
    );
    let out = sigil(
        &fx,
        &["npm", "secretpkg"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            (
                "SIGIL_TEST_NPM_REGISTRY",
                &format!("http://127.0.0.1:{port}/"),
            ),
        ],
    );
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("could not download the tarball of `secretpkg@1.0.0`"),
        "{err}"
    );
    assert!(err.contains("HTTP 401"), "{err}");
    assert!(err.contains("wants credentials"), "{err}");
    assert!(quarantine_items(&fx).is_empty());
}

#[test]
fn npm_refuses_a_tarball_string_that_npm_would_read_as_a_path() {
    // The registry's string reaches `npm pack` as it is, and npm reads a
    // string that does not start with `http:` or `https:` as a path (a
    // directory, whose prepare script it runs), however a URL parser would
    // tidy it. None of these may start `npm pack`.
    for tarball in [
        " https://x/../../tmp/dir",
        "\u{1}https://x/../../tmp/dir",
        "ht\ttps://x/../../tmp/dir",
        "ht\ntps://x/../../tmp/dir",
        "\thttps://x/a.tgz",
        "https://x/a.tgz\n",
    ] {
        let fx = fixture();
        let view = npm_view("pathpkg", "1.0.0", tarball, "");
        let out = sigil(&fx, &["npm", "pathpkg"], &[("SIGIL_TEST_NPM_VIEW", &view)]);
        assert_eq!(code(&out), 2, "{tarball:?}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("will not download `pathpkg@1.0.0`"), "{err}");
        assert!(err.contains("local path"), "{err}");
        assert!(
            !err.contains(|c: char| c.is_control() && c != '\n'),
            "a control character reached the terminal: {err:?}"
        );
        assert!(
            recorded(&fx, "npm-pack").is_none(),
            "{tarball:?} was packed"
        );
        assert!(quarantine_items(&fx).is_empty(), "{tarball:?}");
    }
}

#[test]
fn parallel_runs_that_fail_leave_a_whole_index_and_no_pending_entry() {
    // Every run adds its quarantine entry and, its download failing,
    // discards it again: two index writes per run, from eight processes
    // sharing one quarantine. Without a lock on the index, runs fail with
    // "failed to parse quarantine index" or leave entries behind.
    let fx = fixture();
    // Nothing listens on port 1: the download is refused at once.
    let tarball = "http://127.0.0.1:1/pkg-1.0.0.tgz";
    let outputs: Vec<(String, i32, String)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|n| {
                let fx = &fx;
                scope.spawn(move || {
                    let mut seen = Vec::new();
                    for round in 0..3 {
                        let name = format!("par{n}x{round}");
                        let view = npm_view(&name, "1.0.0", tarball, "sha512-AAAA");
                        let out = sigil(
                            fx,
                            &["npm", &name],
                            &[
                                ("SIGIL_TEST_NPM_VIEW", &view),
                                ("SIGIL_TEST_NPM_REGISTRY", "http://127.0.0.1:1/"),
                            ],
                        );
                        seen.push((name, code(&out), stderr(&out)));
                    }
                    seen
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("worker"))
            .collect()
    });
    assert_eq!(outputs.len(), 24);
    for (name, status, err) in &outputs {
        assert_eq!(*status, 2, "{name}: {err}");
        assert!(
            err.contains("could not download the tarball"),
            "{name}: {err}"
        );
        assert!(!err.contains("quarantine index"), "{name}: {err}");
        assert!(!err.contains("quarantine entry"), "{name}: {err}");
    }
    assert!(
        quarantine_items(&fx).is_empty(),
        "{:?}",
        quarantine_items(&fx)
    );
    let list = sigil(&fx, &["list"], &[]);
    assert_eq!(code(&list), 0, "{}", stderr(&list));
    assert!(!stdout(&list).contains("PENDING"), "{}", stdout(&list));
}

/// Wait (up to `secs`) for `path` to exist.
fn wait_for_file(path: &Path, secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    path.exists()
}

/// A registry on 127.0.0.1 that answers a tarball request with a head
/// promising a body and then sends none, for as long as the test process
/// lives (a slow transfer a test can interrupt). `seen` is created when a
/// request has arrived.
fn serve_stalled(seen: PathBuf) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\npartial",
                );
                let _ = s.flush();
                let _ = std::fs::write(&seen, "requested");
                std::thread::sleep(std::time::Duration::from_secs(60));
            });
        }
    });
    base
}

#[test]
fn an_interrupted_download_leaves_no_pending_entry() {
    // Ctrl-C (SIGINT) or a `timeout` (SIGTERM) during a slow transfer ends
    // the process at once unless it is caught: no drop runs, and the empty
    // PENDING entry stays for `sigil list` and `sigil approve`.
    for (tool, signal, want) in [
        ("npm", "INT", 130),
        ("npm", "TERM", 143),
        ("pip", "TERM", 143),
    ] {
        let fx = fixture();
        let requested = fx.root.join("requested");
        let base = serve_stalled(requested.clone());
        let view = npm_view(
            "slowpkg",
            "1.0.0",
            &format!("{base}/slowpkg-1.0.0.tgz"),
            "sha512-AAAA",
        );
        let path = format!(
            "{}:{}",
            fx.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let args: &[&str] = if tool == "npm" {
            &["npm", "slowpkg"]
        } else {
            &["pip", "slowpkg==1.0"]
        };
        let registry = format!("{base}/");
        let mut child = sigil_command(
            &fx,
            args,
            &path,
            &[
                ("SIGIL_TEST_NPM_VIEW", &view),
                ("SIGIL_TEST_NPM_REGISTRY", &registry),
                ("SIGIL_TEST_FAKE_SLEEP", "30"),
            ],
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run sigil");
        // npm: sigil downloads the tarball itself (the registry above stalls
        // it); pip: the test double sleeps.
        let transfer_pid = fx.logs.join("pip-download.pid");
        let started = if tool == "npm" {
            requested.clone()
        } else {
            transfer_pid.clone()
        };
        assert!(
            wait_for_file(&started, 20),
            "{tool}: the transfer never started"
        );
        assert_eq!(
            quarantine_items(&fx).len(),
            1,
            "{tool}: an entry exists mid-download"
        );

        let sent = Command::new("kill")
            .args(["-s", signal, &child.id().to_string()])
            .status()
            .expect("kill");
        assert!(sent.success());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("{tool} {signal}: sigil did not exit after the signal");
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        };
        // The transfer's own process (it inherited sigil's stderr) is not
        // the test's to leave running; stderr only ends once it is gone.
        if tool == "pip" {
            if let Ok(pid) = std::fs::read_to_string(&transfer_pid) {
                let _ = Command::new("kill").arg(pid.trim()).status();
            }
        }
        let mut err = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            use std::io::Read;
            let _ = pipe.read_to_string(&mut err);
        }
        assert_eq!(status.code(), Some(want), "{tool} {signal}: {err}");
        assert!(
            err.contains("removed the unscanned quarantine entry"),
            "{tool} {signal}: {err}"
        );
        assert!(quarantine_items(&fx).is_empty(), "{tool} {signal}");
        let list = sigil(&fx, &["list"], &[]);
        assert!(
            !stdout(&list).contains("PENDING"),
            "{tool} {signal}: {}",
            stdout(&list)
        );
    }
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
            &[OPT_IN, ("SIGIL_TEST_PACK_FILE", &packed)],
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
        ("C:\\x", Some("C:\\x")),
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
        .env_remove("SIGIL_ALLOW_BUILD_SCRIPTS")
        .env_remove("SIGIL_QUARANTINE_DIR")
        .env_remove("SIGIL_POLICY_FILE")
        .env_remove("SIGIL_ALLOW_PRIVATE_URLS")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
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
fn mcp_scan_package_explains_a_missing_wheel_in_full() {
    // pip's own progress and ERROR lines come first; the advice (pin a
    // version that has a wheel) comes last and must reach the agent.
    let fx = fixture();
    let noise = "Looking in indexes: https://pypi.example/simple\n".repeat(30);
    let result = mcp_scan_package(
        &fx,
        serde_json::json!({ "ecosystem": "pypi", "name": "idx-pkg" }),
        &[
            (
                "SIGIL_TEST_PIP_INDEX",
                "idx-pkg (2.0)\nAvailable versions: 2.0, 1.0",
            ),
            ("SIGIL_TEST_FAKE_EXIT", "1"),
            (
                "SIGIL_TEST_FAKE_STDERR",
                &format!("{noise}ERROR: No matching distribution found for idx-pkg==2.0"),
            ),
        ],
    );
    assert_eq!(result["isError"], true, "{result}");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(text.contains("`idx-pkg==2.0` is the release"), "{text}");
    assert!(text.contains("Pin a version that has a wheel"), "{text}");
    assert!(text.contains("--allow-build-scripts"), "{text}");
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

    let served = serve_tarball(&fx, "left-pad", "1.3.0");
    let view = npm_view("left-pad", "1.3.0", &served.tarball, &served.integrity);
    let result = mcp_scan_package(
        &fx,
        serde_json::json!({ "ecosystem": "npm", "name": "left-pad", "version": "^1" }),
        &[("SIGIL_TEST_NPM_VIEW", &view), served.env()],
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
        &with(&env, &[OPT_IN]),
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

/// An index that lists `2.0` and `2.0+local1`: the release Sigil resolved to
/// (`2.0`) is the file it downloads, not the local variant that `==2.0` also
/// matches and pip would take as the highest.
#[test]
fn real_pip_downloads_the_resolved_release_not_its_local_variant() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    write_plain_wheel(&links, "2.0");
    write_plain_wheel(&links, "2.0+local1");
    let path = std::env::var("PATH").unwrap_or_default();
    let env = offline(&links);

    let out = run_sigil(&fx, &["pip", "markerpkg>2.0a1"], &path, &with(&env, &[]));
    assert!(matches!(code(&out), 0 | 1), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("resolves to markerpkg==2.0"),
        "{}",
        stdout(&out)
    );
    let q = only_item(&fx);
    assert!(
        q.join("markerpkg-2.0-py3-none-any")
            .join("markerpkg")
            .is_dir(),
        "the 2.0 wheel was downloaded: {:?}",
        std::fs::read_dir(&q)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );
    assert!(
        !q.join("markerpkg-2.0+local1-py3-none-any").exists(),
        "the local variant was downloaded"
    );
    // The entry names the release that was downloaded.
    let list = sigil(&fx, &["list"], &[]);
    assert!(
        stdout(&list).contains("markerpkg==2.0 (pip)"),
        "{}",
        stdout(&list)
    );
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
        &with(
            &offline(&links),
            &[OPT_IN, ("PIP_CONSTRAINT", &constraints_s)],
        ),
    );
    assert!(
        marker.exists(),
        "with --allow-build-scripts pip should have built the constrained project; stderr: {}",
        stderr(&out)
    );
}

/// A `global-option` or `build-option` setting makes pip (before 24.2) drop
/// `--only-binary=:all:` and build a source distribution: its build backend
/// ran, with the setting in the environment or in a config file. Neither
/// reaches pip now.
#[test]
fn real_pip_is_not_told_to_build_by_a_build_option_setting() {
    if !real_pip_available() {
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    let marker = fx.root.join("marker-backend-ran");
    write_marker_sdist(&links, "2.0", &marker);
    let path = std::env::var("PATH").unwrap_or_default();
    let env = offline(&links);

    // Control: no setting, only an sdist on the index: nothing is built.
    for spec in ["markerpkg==2.0", "markerpkg"] {
        let out = run_sigil(&fx, &["pip", spec], &path, &with(&env, &[]));
        assert_eq!(code(&out), 2, "{spec}: {}", stderr(&out));
        assert!(!marker.exists(), "{spec}: the sdist's backend ran");
    }

    // The settings in the environment are left out of pip's environment.
    for var in [
        "PIP_GLOBAL_OPTION",
        "PIP_BUILD_OPTION",
        "PIP_INSTALL_OPTION",
    ] {
        for spec in ["markerpkg==2.0", "markerpkg"] {
            let out = run_sigil(&fx, &["pip", spec], &path, &with(&env, &[(var, "--quiet")]));
            assert_eq!(code(&out), 2, "{var} {spec}: {}", stderr(&out));
            assert!(
                stderr(&out).contains(&format!("{var} is left out")),
                "{var}: {}",
                stderr(&out)
            );
            assert!(!marker.exists(), "{var} {spec}: the sdist's backend ran");
        }
    }

    // In a config file, they are refused, and nothing is created.
    for key in ["global-option", "build-option"] {
        let conf = fx.root.join(format!("pip-{key}.conf"));
        std::fs::write(&conf, format!("[global]\n{key} = --quiet\n")).unwrap();
        let conf_s = conf.to_string_lossy().to_string();
        let env: Vec<(&str, &str)> = with(&env, &[])
            .into_iter()
            .filter(|(k, _)| *k != "PIP_CONFIG_FILE")
            .chain([("PIP_CONFIG_FILE", conf_s.as_str())])
            .collect();
        let before = quarantine_items(&fx).len();
        for spec in ["markerpkg==2.0", "markerpkg"] {
            let out = run_sigil(&fx, &["pip", spec], &path, &env);
            assert_eq!(code(&out), 2, "{key} {spec}: {}", stderr(&out));
            assert!(
                stderr(&out).contains(&format!("global.{key}")),
                "{key}: {}",
                stderr(&out)
            );
            assert!(!marker.exists(), "{key} {spec}: the sdist's backend ran");
        }
        assert_eq!(quarantine_items(&fx).len(), before);
    }

    // The fixture is live: with the opt-in and the setting, pip does build.
    let out = run_sigil(
        &fx,
        &["pip", "markerpkg==2.0", "--allow-build-scripts"],
        &path,
        &with(&env, &[OPT_IN, ("PIP_GLOBAL_OPTION", "--quiet")]),
    );
    assert!(
        marker.exists(),
        "with --allow-build-scripts pip should have built the sdist; stderr: {}",
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
        &with(&env, &[OPT_IN]),
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

// ---------------------------------------------------------------------------
// --allow-build-scripts needs a person, or the variable a script sets
// ---------------------------------------------------------------------------

/// A flag in a command line is not a person's decision (an agent's shell or
/// a pipeline writes flags too): with no terminal and no
/// `SIGIL_ALLOW_BUILD_SCRIPTS=1`, the opt-in is refused before anything is
/// downloaded or run, whatever the spec.
#[test]
fn the_opt_in_is_refused_without_a_terminal_or_the_variable() {
    for args in [
        vec!["pip", "./local-project", "--allow-build-scripts"],
        vec!["pip", "requests", "--allow-build-scripts"],
        vec!["npm", "./local-dir", "--allow-build-scripts"],
        vec!["npm", "github:owner/repo", "--allow-build-scripts"],
        vec!["npm", "left-pad", "--allow-build-scripts"],
    ] {
        // Not set, or set to anything but `1`.
        for value in [None, Some(""), Some("0"), Some("true"), Some("yes")] {
            let fx = fixture();
            let env: Vec<(&str, &str)> = value
                .map(|v| vec![("SIGIL_ALLOW_BUILD_SCRIPTS", v)])
                .unwrap_or_default();
            let out = sigil(&fx, &args, &env);
            assert_eq!(code(&out), 2, "{args:?} {value:?}: {}", stderr(&out));
            let err = stderr(&out);
            assert!(err.contains("needs a person to confirm"), "{err}");
            assert!(err.contains("no terminal"), "{err}");
            assert!(err.contains("SIGIL_ALLOW_BUILD_SCRIPTS=1"), "{err}");
            assert!(err.contains("Nothing was downloaded or run"), "{err}");
            assert!(ran_nothing(&fx, "pip"), "{args:?} ran pip");
            assert!(ran_nothing(&fx, "npm"), "{args:?} ran npm");
            assert!(
                quarantine_items(&fx).is_empty(),
                "{args:?} {value:?} made a quarantine entry"
            );
        }
    }
}

#[test]
fn the_opt_in_with_the_variable_warns_and_proceeds() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "./local-project", "--allow-build-scripts"],
        &[OPT_IN],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("warning:"), "{err}");
    assert!(err.contains("BEFORE Sigil scans"), "{err}");
    assert!(
        err.contains("SIGIL_ALLOW_BUILD_SCRIPTS=1 is set"),
        "the note says what confirmed it: {err}"
    );
    assert!(recorded(&fx, "pip-download").is_some());
}

/// The variable does nothing for a refused spec, and the confirmation does
/// not replace the spec check's `-` rule.
#[test]
fn the_variable_does_not_lift_the_unusable_spec_refusals() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "--allow-build-scripts", "--", "--index-url=x"],
        &[OPT_IN],
    );
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(ran_nothing(&fx, "pip"));
}

/// pip prints its progress (`Looking in indexes`, `Collecting`, ...) on stdout.
/// With a machine-readable format stdout is the report and nothing else, so
/// pip's goes to stderr, where Sigil's own progress is; in text it is as it
/// was. The same for what `npm pack` prints with the opt-in.
#[test]
fn the_tools_stdout_never_gets_in_front_of_a_json_report() {
    let progress = "Looking in indexes: https://pypi.org/simple\nCollecting wheelok==1.5";
    let fx = fixture();
    let out = sigil(
        &fx,
        &["--format", "json", "pip", "wheelok==1.5"],
        &[("SIGIL_TEST_FAKE_STDOUT", progress)],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("stdout is exactly one JSON document");
    assert_eq!(report["package"], "wheelok==1.5");
    assert!(
        stderr(&out).contains("Collecting wheelok==1.5"),
        "{}",
        stderr(&out)
    );
    assert!(!stdout(&out).contains("Looking in indexes"));

    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "wheelok==1.5"],
        &[("SIGIL_TEST_FAKE_STDOUT", progress)],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("Collecting wheelok==1.5"),
        "{}",
        stdout(&out)
    );

    // npm pack prints the file it wrote.
    let fx = fixture();
    let out = sigil(
        &fx,
        &[
            "--format",
            "json",
            "npm",
            "./local-dir",
            "--allow-build-scripts",
        ],
        &[OPT_IN, ("SIGIL_TEST_FAKE_STDOUT", "local-dir-1.0.0.tgz")],
    );
    assert!(matches!(code(&out), 0 | 2), "stderr: {}", stderr(&out));
    assert!(
        !stdout(&out).contains("local-dir-1.0.0.tgz"),
        "npm pack's output is in stdout: {}",
        stdout(&out)
    );
    assert!(
        recorded(&fx, "npm-pack").is_some(),
        "npm pack ran with the opt-in"
    );
}

// ---------------------------------------------------------------------------
// npm: what the registry's names and versions can make npm do
// ---------------------------------------------------------------------------

/// Sigil never runs `npm pack` by default: not by name (it would ask the
/// registry for the release's metadata a second time) and not by URL (npm 12
/// refuses a URL without `--allow-remote=all`, and npm 10 names the file it
/// writes from the tarball's own manifest). Even a double that fails every
/// `npm pack` changes nothing.
#[test]
fn npm_is_never_asked_to_pack_by_default() {
    let fx = fixture();
    let served = serve_tarball(&fx, "left-pad", "1.3.0");
    let view = npm_view("left-pad", "1.3.0", &served.tarball, &served.integrity);
    let out = sigil(
        &fx,
        &["npm", "left-pad@1.3.0"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &view),
            served.env(),
            ("SIGIL_TEST_FAKE_EXIT", "1"),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(recorded(&fx, "npm-pack").is_none(), "npm pack ran");
    let (argv, _) = recorded(&fx, "npm-view").expect("npm view ran");
    assert!(
        !argv.iter().any(|a| a.contains("://")),
        "no URL is handed to npm: {argv:?}"
    );
}

/// A registry that gives a package a name or version made of path parts or
/// control characters is refused before npm packs it (npm builds the file
/// name from them), and the message cannot write to the terminal.
#[test]
fn npm_refuses_a_registry_name_or_version_that_would_name_a_path() {
    let (_, integrity) = npm_tarball(&fixture(), "plainpkg", "1.0.0");
    let tarball = "https://registry.npmjs.org/plainpkg/-/plainpkg-1.0.0.tgz";
    for (name, version) in [
        ("x/../../../outside/pwn", "1.0.0"),
        ("@s/../../../../outside/pwn", "1.0.0"),
        ("plainpkg", "1.0.0/../../../../outside/v"),
        ("ansi\u{1b}]0;PWNED-TITLE\u{7}\u{1b}[2Jx", "1.0.1"),
        ("plainpkg", "1.0.0\u{1b}[2J"),
    ] {
        let fx = fixture();
        let view = npm_view(name, version, tarball, &integrity);
        let out = sigil(&fx, &["npm", "plainpkg"], &[("SIGIL_TEST_NPM_VIEW", &view)]);
        assert_eq!(code(&out), 2, "{name:?}@{version:?}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("not a valid"), "{err}");
        for text in [&err, &stdout(&out)] {
            assert!(
                !text.chars().any(|c| c.is_control() && c != '\n'),
                "a control character reached the terminal: {text:?}"
            );
        }
        assert!(ran_nothing_but_view(&fx), "{name:?}@{version:?} packed");
        assert!(
            quarantine_items(&fx).is_empty(),
            "{name:?}@{version:?} left a quarantine entry"
        );
        // Nothing was recorded for `sigil list` to print.
        let list = sigil(&fx, &["list"], &[]);
        assert!(
            !stdout(&list).chars().any(|c| c.is_control() && c != '\n'),
            "{:?}",
            stdout(&list)
        );
    }
}

/// `npm pack` did not run (`npm view` did).
fn ran_nothing_but_view(fx: &Fixture) -> bool {
    recorded(fx, "npm-pack").is_none()
}

/// `npm view <name>` and `<name>@*` show the `latest` tag, but npm skips a
/// deprecated `latest` for the highest release that is not deprecated: the
/// release scanned is the one an install gets.
#[test]
fn npm_skips_a_deprecated_latest_for_a_bare_name_as_npm_does() {
    let rel = |tarball: &str, version: &str, deprecated: bool, integrity: &str| {
        let mut o = serde_json::json!({
            "name": "rng2",
            "version": version,
            "dist.tarball": tarball,
            "dist.integrity": integrity,
            "dist-tags.latest": "2.0.0",
        });
        if deprecated {
            o["deprecated"] = "do not use".into();
        }
        o
    };
    for spec in ["rng2", "rng2@*"] {
        let fx = fixture();
        let served = serve_tarball(&fx, "rng2", "1.9.0");
        let latest = rel("http://127.0.0.1:1/x.tgz", "2.0.0", true, "sha512-BBBB").to_string();
        let all = serde_json::json!([
            rel("http://127.0.0.1:1/x.tgz", "1.0.0", false, "sha512-AAAA"),
            rel(&served.tarball, "1.9.0", false, &served.integrity),
            rel("http://127.0.0.1:1/x.tgz", "2.0.0", true, "sha512-BBBB"),
        ])
        .to_string();
        let out = sigil(
            &fx,
            &["npm", spec],
            &[
                ("SIGIL_TEST_NPM_VIEW", &latest),
                ("SIGIL_TEST_NPM_VIEW_ALL", &all),
                served.env(),
            ],
        );
        assert_eq!(code(&out), 0, "{spec}: {}", stderr(&out));
        assert!(
            stdout(&out).contains("resolves to rng2@1.9.0"),
            "{spec}: {}",
            stdout(&out)
        );
        assert!(only_item(&fx).join("rng2-1.9.0").is_dir(), "{spec}");
        let (view, _) = recorded(&fx, "npm-view").expect("npm view ran");
        assert!(
            view.iter().any(|a| a == "rng2@>=0"),
            "the range lookup ran: {view:?}"
        );
    }
    // A tag or a version named is taken as it is, deprecated or not.
    for spec in ["rng2@latest", "rng2@2.0.0"] {
        let fx = fixture();
        let served = serve_tarball(&fx, "rng2", "2.0.0");
        let only = rel(&served.tarball, "2.0.0", true, &served.integrity).to_string();
        let out = sigil(
            &fx,
            &["npm", spec],
            &[
                ("SIGIL_TEST_NPM_VIEW", &only),
                ("SIGIL_TEST_NPM_VIEW_ALL", "[]"),
                served.env(),
            ],
        );
        assert_eq!(code(&out), 0, "{spec}: {}", stderr(&out));
        assert!(only_item(&fx).join("rng2-2.0.0").is_dir(), "{spec}");
        let (view, _) = recorded(&fx, "npm-view").expect("npm view ran");
        assert!(
            !view.iter().any(|a| a.ends_with("@>=0")),
            "{spec}: {view:?}"
        );
    }
    // When the range lookup finds nothing (a package with only
    // pre-releases), the tag stands.
    let fx = fixture();
    let served = serve_tarball(&fx, "rng2", "2.0.0");
    let only = rel(&served.tarball, "2.0.0", true, &served.integrity).to_string();
    let out = sigil(
        &fx,
        &["npm", "rng2"],
        &[
            ("SIGIL_TEST_NPM_VIEW", &only),
            ("SIGIL_TEST_NPM_VIEW_ALL", "{\"error\":{\"code\":\"E404\"}}"),
            served.env(),
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(only_item(&fx).join("rng2-2.0.0").is_dir());
}

// ---------------------------------------------------------------------------
// pip: what to tell the user when the index lookup fails
// ---------------------------------------------------------------------------

#[test]
fn the_index_lookup_failure_says_what_pip_said() {
    for (fail, says, not) in [
        (
            "ERROR: unknown command \"index\"",
            "21.2",
            "Check the spelling",
        ),
        (
            "ERROR: No matching distribution found for no-such-pkg-zzqq",
            "Check the spelling",
            "21.2",
        ),
    ] {
        let fx = fixture();
        let out = sigil(
            &fx,
            &["pip", "no-such-pkg-zzqq"],
            &[("SIGIL_TEST_PIP_INDEX_FAIL", fail)],
        );
        assert_eq!(code(&out), 2, "{fail}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains(says), "{fail}: {err}");
        assert!(!err.contains(not), "{fail}: {err}");
        assert!(recorded(&fx, "pip-download").is_none());
        assert!(quarantine_items(&fx).is_empty());
    }
}

/// A pinned spec with extras is recorded as the release, without them.
#[test]
fn the_release_recorded_has_no_extras() {
    let fx = fixture();
    let out = sigil(&fx, &["pip", "requests[socks]==2.32.3"], &[]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let list = sigil(&fx, &["list"], &[]);
    assert!(
        stdout(&list).contains("requests==2.32.3 (pip)"),
        "{}",
        stdout(&list)
    );
    assert!(!stdout(&list).contains("[socks]"), "{}", stdout(&list));
    let (argv, _) = recorded(&fx, "pip-download").expect("pip ran");
    assert_eq!(
        argv.last().map(String::as_str),
        Some("requests[socks]==2.32.3"),
        "pip is given the spec as typed"
    );
}

// ---------------------------------------------------------------------------
// The real npm against a registry on 127.0.0.1
// ---------------------------------------------------------------------------

fn real_npm_available() -> bool {
    let available = Command::new("npm")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("skipped: npm is not installed");
    }
    available
}

/// A gzip tarball of `package/package.json` (the text given) and
/// `package/index.js`.
fn tarball_bytes(manifest: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let gz = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);
        for (file, body) in [
            ("package/package.json", manifest),
            ("package/index.js", "module.exports = 1;\n"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, file, body.as_bytes()).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
    }
    out
}

fn sri_sha512(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

/// What a [`serve_registry_logged`] registry was asked: each request's
/// path and `Accept` header, in order.
type RequestLog = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// A one-purpose npm registry on 127.0.0.1, served by a thread for as long
/// as the test process lives: `GET /<package>` is a packument and
/// `GET /files/<name>` a file. `build` gets the registry's base URL and
/// returns the packuments (by package name) and the files.
fn serve_registry(
    build: impl FnOnce(&str) -> (Vec<(String, serde_json::Value)>, Vec<(String, Vec<u8>)>),
) -> String {
    serve_registry_logged(build).0
}

/// [`serve_registry`], and what it is asked. A packument named
/// `<package>#abbreviated` is what a request that asks for the abbreviated
/// install document (`Accept: application/vnd.npm.install-v1+json`, as
/// `npm pack` and `npm install` do, where `npm view` asks for full metadata)
/// gets instead of `<package>`.
#[allow(clippy::type_complexity)]
fn serve_registry_logged(
    build: impl FnOnce(&str) -> (Vec<(String, serde_json::Value)>, Vec<(String, Vec<u8>)>),
) -> (String, RequestLog) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let (packuments, files) = build(&base);
    let (packuments, files) = (std::sync::Arc::new(packuments), std::sync::Arc::new(files));
    let log: RequestLog = std::sync::Arc::default();
    let served_log = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (packuments, files, log) = (packuments.clone(), files.clone(), served_log.clone());
            std::thread::spawn(move || {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let path = request
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|p| p.split('?').next())
                    .unwrap_or("/")
                    .replace("%2F", "%2f");
                let accept = request
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("accept")
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_default();
                if let Ok(mut log) = log.lock() {
                    log.push((path.clone(), accept.clone()));
                }
                let abbreviated = accept.contains("application/vnd.npm.install-v1+json");
                let found = match path.strip_prefix("/files/") {
                    Some(name) => files
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, b)| ("application/octet-stream", b.clone())),
                    None => {
                        let wanted = |suffix: &str| {
                            packuments
                                .iter()
                                .find(|(n, _)| path == format!("/{n}{suffix}"))
                                .map(|(_, v)| ("application/json", v.to_string().into_bytes()))
                        };
                        // `/acc#abbreviated` cannot be a request path: the
                        // abbreviated document is stored under that name.
                        packuments
                            .iter()
                            .find(|(n, _)| {
                                abbreviated
                                    && n.strip_suffix("#abbreviated")
                                        .is_some_and(|p| path == format!("/{p}"))
                            })
                            .map(|(_, v)| ("application/json", v.to_string().into_bytes()))
                            .or_else(|| wanted(""))
                    }
                };
                let (status, ctype, body) = match found {
                    Some((ctype, body)) => ("200 OK", ctype, body),
                    None => (
                        "404 Not Found",
                        "application/json",
                        b"{\"error\":\"Not found\"}".to_vec(),
                    ),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
        }
    });
    (base, log)
}

/// A packument with one release whose tarball is `/files/<file>` on `base`.
fn packument(
    base: &str,
    name: &str,
    manifest_name: &str,
    version: &str,
    file: &str,
    bytes: &[u8],
) -> serde_json::Value {
    use sha1::Digest as _;
    serde_json::json!({
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "name": manifest_name,
                "version": version,
                "dist": {
                    "tarball": format!("{base}/files/{file}"),
                    "integrity": sri_sha512(bytes),
                    "shasum": format!("{:x}", sha1::Sha1::digest(bytes)),
                },
            },
        },
    })
}

/// The environment that points the real npm at the registry at `base`,
/// with nothing of the caller's npm or proxy settings.
fn real_npm_env(fx: &Fixture, base: &str) -> Vec<(&'static str, String)> {
    vec![
        ("npm_config_registry", format!("{base}/")),
        (
            "npm_config_cache",
            fx.root.join("npmcache").to_string_lossy().into_owned(),
        ),
        (
            "npm_config_userconfig",
            fx.root.join("user.npmrc").to_string_lossy().into_owned(),
        ),
        (
            "npm_config_globalconfig",
            fx.root.join("global.npmrc").to_string_lossy().into_owned(),
        ),
        ("npm_config_update_notifier", "false".into()),
        ("npm_config_audit", "false".into()),
        ("npm_config_fund", "false".into()),
        ("NO_PROXY", "127.0.0.1,localhost".into()),
        ("no_proxy", "127.0.0.1,localhost".into()),
    ]
}

fn run_with_real_npm(fx: &Fixture, args: &[&str], base: &str) -> Output {
    run_with_npm_in(fx, args, base, None)
}

/// [`run_with_real_npm`], with the `npm` in `npm_dir` (when given) ahead of
/// the one on PATH.
fn run_with_npm_in(fx: &Fixture, args: &[&str], base: &str, npm_dir: Option<&Path>) -> Output {
    let mut path = std::env::var("PATH").unwrap_or_default();
    if let Some(dir) = npm_dir {
        path = format!("{}:{path}", dir.display());
    }
    let env = real_npm_env(fx, base);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut cmd = sigil_command(fx, args, &path, &env);
    for k in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(k);
    }
    cmd.output().expect("run sigil")
}

/// The npm installations the real-npm tests that matter most run under: the
/// one on PATH, and npm 12 when `$SIGIL_TEST_NPM12_BIN` names a directory
/// holding its `npm` (for example `<prefix>/node_modules/.bin` after `npm
/// install --prefix <prefix> npm@12`). `None` is the one on PATH.
fn real_npm_installations() -> Vec<Option<PathBuf>> {
    let mut out = Vec::new();
    if real_npm_available() {
        out.push(None);
    }
    match std::env::var_os("SIGIL_TEST_NPM12_BIN").map(PathBuf::from) {
        Some(dir) if dir.join("npm").exists() => out.push(Some(dir)),
        _ => eprintln!("skipped npm 12: SIGIL_TEST_NPM12_BIN is not set to a directory with npm"),
    }
    out
}

fn git_available() -> bool {
    let available = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("skipped: git is not installed");
    }
    available
}

/// A registry answers `npm view` (which asks for the full metadata) with one
/// tarball URL and `npm pack <name>@<version>` (which asks for the
/// abbreviated install document) with a git or file URL whose `prepare`
/// script creates a marker. Sigil validated the first; if anything handed
/// the second to npm, the marker would appear. Sigil asks the registry about
/// the release once, downloads the checked URL itself, and never runs `npm
/// pack`.
#[test]
fn a_registry_that_answers_the_metadata_requests_differently_cannot_make_sigil_run_package_code() {
    if !git_available() {
        return;
    }
    for npm_dir in real_npm_installations() {
        for kind in ["git", "file"] {
            let which = format!(
                "{} {kind}",
                npm_dir
                    .as_deref()
                    .map_or_else(|| "PATH npm".to_string(), |d| d.display().to_string())
            );
            eprintln!("npm under test: {which}");
            let fx = fixture();
            let marker = fx.root.join("prepare-ran");
            // What a git or directory spec would prepare: a package whose
            // prepare script only creates `marker`.
            let repo = fx.root.join("evil-repo");
            std::fs::create_dir_all(&repo).unwrap();
            std::fs::write(
                repo.join("package.json"),
                serde_json::json!({
                    "name": "acc-split",
                    "version": "1.0.0",
                    "scripts": {"prepare": format!("touch '{}'", marker.display())},
                })
                .to_string(),
            )
            .unwrap();
            std::fs::write(repo.join("index.js"), "module.exports = 1;\n").unwrap();
            let git = |args: &[&str]| {
                let ok = Command::new("git")
                    .args(["-c", "user.email=t@example.invalid", "-c", "user.name=t"])
                    .args(args)
                    .current_dir(&repo)
                    .output()
                    .is_ok_and(|o| o.status.success());
                assert!(ok, "git {args:?}");
            };
            git(&["init", "-q", "."]);
            git(&["add", "-A"]);
            git(&["commit", "-q", "-m", "init"]);
            let evil_url = match kind {
                "git" => format!("git+file://{}", repo.display()),
                _ => format!("file:{}", repo.display()),
            };
            let bytes = tarball_bytes("{\"name\":\"acc-split\",\"version\":\"1.0.0\"}\n");
            let (base, log) = serve_registry_logged(|base| {
                let benign = packument(
                    base,
                    "acc-split",
                    "acc-split",
                    "1.0.0",
                    "acc-split-1.0.0.tgz",
                    &bytes,
                );
                let mut evil = benign.clone();
                evil["versions"]["1.0.0"]["dist"]["tarball"] = evil_url.clone().into();
                (
                    vec![
                        ("acc-split".to_string(), benign),
                        ("acc-split#abbreviated".to_string(), evil),
                    ],
                    vec![("acc-split-1.0.0.tgz".to_string(), bytes.clone())],
                )
            });

            let out = run_with_npm_in(&fx, &["npm", "acc-split"], &base, npm_dir.as_deref());
            assert!(
                !marker.exists(),
                "{which}: package code ran (the prepare script of {evil_url}): {}",
                stderr(&out)
            );
            assert_eq!(code(&out), 0, "{which}: {}", stderr(&out));
            // The benign tarball, the one that was checked, is what was
            // scanned.
            let q = only_item(&fx);
            assert!(
                q.join("acc-split-1.0.0").join("package").is_dir(),
                "{which}"
            );
            // The registry was asked about the release once, for the full
            // metadata, and the tarball fetched once, by Sigil.
            let seen = log.lock().unwrap().clone();
            let metadata: Vec<_> = seen.iter().filter(|(p, _)| p == "/acc-split").collect();
            assert_eq!(metadata.len(), 1, "{which}: {seen:?}");
            assert!(
                !metadata[0].1.contains("install-v1"),
                "{which}: the one metadata request asked for the abbreviated document: {seen:?}"
            );
            assert_eq!(
                seen.iter()
                    .filter(|(p, _)| p.starts_with("/files/"))
                    .count(),
                1,
                "{which}: {seen:?}"
            );
        }
    }
}

/// `npm pack <tarball URL>` names the file `<name>-<version>.tgz` from the
/// package.json inside the tarball, which its author controls: with npm
/// 10.9.7 a version of `1.0.0/../../../../../../outside/v` wrote
/// `outside/v.tgz` beside the quarantine directory, before the scan (npm 12
/// turns the slashes into `-`). That is why Sigil never hands npm the URL: it
/// downloads the tarball itself and names the file from the registry's
/// checked name and version.
#[test]
fn real_npm_cannot_be_made_to_write_outside_quarantine_by_a_tarballs_manifest() {
    for npm_dir in real_npm_installations() {
        let fx = fixture();
        let outside = fx.root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        // Six `..`, for this layout: `<root>/home/.sigil/quarantine/<id>` is
        // where npm would run, `<root>/outside` where the file lands.
        let hostile_version = "1.0.0/../../../../../../outside/v";
        let bytes = tarball_bytes(&format!(
            "{{\"name\":\"hostile\",\"version\":\"{hostile_version}\"}}\n"
        ));
        let base = serve_registry(|base| {
            (
                vec![(
                    "hostile".to_string(),
                    packument(
                        base,
                        "hostile",
                        "hostile",
                        "1.0.0",
                        "hostile-1.0.0.tgz",
                        &bytes,
                    ),
                )],
                vec![("hostile-1.0.0.tgz".to_string(), bytes.clone())],
            )
        });

        // The premise: handed the tarball's URL, this npm may write there (npm
        // 12 has fixed it, in which case the check below is about Sigil
        // only). Only reported, not asserted: it is npm's behaviour.
        let probe = fx.home.join(".sigil").join("quarantine").join("probe");
        std::fs::create_dir_all(&probe).unwrap();
        let mut by_url = Command::new("npm");
        by_url
            .args([
                "pack",
                "--ignore-scripts",
                "--allow-remote=all",
                "--",
                &format!("{base}/files/hostile-1.0.0.tgz"),
            ])
            .current_dir(&probe);
        if let Some(dir) = &npm_dir {
            by_url.env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        }
        for (k, v) in real_npm_env(&fx, &base) {
            by_url.env(k, v);
        }
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            by_url.env_remove(k);
        }
        by_url.env("HOME", &fx.home);
        let _ = by_url.output();
        let premise = outside.join("v.tgz").exists();
        eprintln!("premise (npm writes outside when given the URL): {premise}");
        let _ = std::fs::remove_file(outside.join("v.tgz"));
        std::fs::remove_dir_all(&probe).unwrap();

        let out = run_with_npm_in(&fx, &["npm", "hostile"], &base, npm_dir.as_deref());
        assert!(
            [0, 1].contains(&code(&out)),
            "exit {}: {}",
            code(&out),
            stderr(&out)
        );
        let escaped: Vec<_> = std::fs::read_dir(&outside)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert!(
            escaped.is_empty(),
            "something was written outside quarantine: {escaped:?}"
        );
        let q = only_item(&fx);
        assert!(
            std::fs::read_dir(&q)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| e.file_name().to_string_lossy().starts_with("hostile-1.0.0")),
            "the tarball is in the quarantine entry"
        );
        assert!(stdout(&out).contains("hostile") || stderr(&out).contains("hostile"));
    }
}

/// A registry whose manifest gives the package a name that is a path is
/// refused before npm packs it.
#[test]
fn real_npm_is_not_asked_to_pack_a_registry_name_that_is_a_path() {
    if !real_npm_available() {
        return;
    }
    let fx = fixture();
    let outside = fx.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let bytes = tarball_bytes("{\"name\":\"hostile2\",\"version\":\"1.0.0\"}\n");
    let base = serve_registry(|base| {
        (
            vec![(
                "hostile2".to_string(),
                packument(
                    base,
                    "hostile2",
                    "x/../../../../outside/pwn",
                    "1.0.0",
                    "hostile2-1.0.0.tgz",
                    &bytes,
                ),
            )],
            vec![("hostile2-1.0.0.tgz".to_string(), bytes.clone())],
        )
    });
    let out = run_with_real_npm(&fx, &["npm", "hostile2"], &base);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("not a valid npm package name"),
        "{}",
        stderr(&out)
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert!(quarantine_items(&fx).is_empty());
}

/// The release is resolved by the real npm, downloaded by Sigil and scanned
/// end to end (on every npm: npm 12 included).
#[test]
fn real_npm_resolves_and_sigil_downloads_a_registry_release_and_it_is_scanned() {
    for npm_dir in real_npm_installations() {
        let fx = fixture();
        let bytes = tarball_bytes("{\"name\":\"plainpkg\",\"version\":\"1.0.0\"}\n");
        let base = serve_registry(|base| {
            (
                vec![(
                    "plainpkg".to_string(),
                    packument(
                        base,
                        "plainpkg",
                        "plainpkg",
                        "1.0.0",
                        "plainpkg-1.0.0.tgz",
                        &bytes,
                    ),
                )],
                vec![("plainpkg-1.0.0.tgz".to_string(), bytes.clone())],
            )
        });
        let out = run_with_npm_in(
            &fx,
            &["--format", "json", "npm", "plainpkg@1.0.0"],
            &base,
            npm_dir.as_deref(),
        );
        assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
        let text = stdout(&out);
        let report: serde_json::Value =
            serde_json::from_str(&text[text.find('{').expect("a JSON report")..])
                .expect("JSON report");
        assert_eq!(report["package"], "plainpkg@1.0.0");
        let q = only_item(&fx);
        assert!(q.join("plainpkg-1.0.0").join("package").is_dir());
    }
}

/// A scoped package is checked against its scope's registry
/// (`@scope:registry`), as npm resolves it.
#[test]
fn real_npm_scoped_registry_is_the_one_the_tarball_must_be_on() {
    if !real_npm_available() {
        return;
    }
    let fx = fixture();
    let bytes = tarball_bytes("{\"name\":\"@acme/pkg\",\"version\":\"1.0.0\"}\n");
    let base = serve_registry(|base| {
        (
            vec![(
                "@acme%2fpkg".to_string(),
                packument(
                    base,
                    "@acme/pkg",
                    "@acme/pkg",
                    "1.0.0",
                    "pkg-1.0.0.tgz",
                    &bytes,
                ),
            )],
            vec![("pkg-1.0.0.tgz".to_string(), bytes.clone())],
        )
    });
    // npm's default registry is somewhere else; the scope's is the server.
    std::fs::write(
        fx.root.join("user.npmrc"),
        format!("@acme:registry={base}/\n"),
    )
    .unwrap();
    let env = real_npm_env(&fx, "http://127.0.0.1:1");
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let path = std::env::var("PATH").unwrap_or_default();
    let out = sigil_command(&fx, &["--format", "json", "npm", "@acme/pkg"], &path, &env)
        .output()
        .expect("run sigil");
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(only_item(&fx)
        .join("acme-pkg-1.0.0")
        .join("package")
        .is_dir());
}
