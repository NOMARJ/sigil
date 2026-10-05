//! `sigil pip` / `sigil npm` never let pip or npm run package code by
//! default: end-to-end tests of what the real binary hands to pip and npm.
//!
//! Most tests put test-double `pip` and `npm` executables first on PATH. They
//! only record their argv and working directory and exit; nothing touches a
//! network. `real_pip_never_builds_a_local_sdist_by_default` uses the real
//! pip, offline, against a local source distribution whose build backend
//! would create an empty marker file; it is skipped when pip is not
//! installed. Every run gets its own HOME, so the quarantine is temporary.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Records how it was run, writes nothing else, and exits with
/// `$SIGIL_TEST_FAKE_EXIT` (default 0).
const FAKE_TOOL: &str = r#"#!/bin/sh
tool=$(basename "$0")
for a in "$@"; do printf '%s\n' "$a"; done > "$SIGIL_TEST_LOG_DIR/$tool.argv"
pwd -P > "$SIGIL_TEST_LOG_DIR/$tool.cwd"
exit "${SIGIL_TEST_FAKE_EXIT:-0}"
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

/// The argv and working directory a test double recorded, if it ran.
fn recorded(fx: &Fixture, tool: &str) -> Option<(Vec<String>, PathBuf)> {
    let argv = std::fs::read_to_string(fx.logs.join(format!("{tool}.argv"))).ok()?;
    let cwd = std::fs::read_to_string(fx.logs.join(format!("{tool}.cwd"))).ok()?;
    Some((
        argv.lines().map(str::to_string).collect(),
        PathBuf::from(cwd.trim_end()),
    ))
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

// ---------------------------------------------------------------------------
// pip
// ---------------------------------------------------------------------------

#[test]
fn pip_downloads_wheels_only_from_the_quarantine_directory() {
    let fx = fixture();
    let out = sigil(&fx, &["pip", "requests", "-V", "2.32.3"], &[]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let q = only_item(&fx);
    let (argv, cwd) = recorded(&fx, "pip").expect("pip ran");
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
    assert_eq!(cwd, q, "pip must run in the quarantine directory");
    assert!(!stderr(&out).contains("--allow-build-scripts"));
}

#[test]
fn pip_opt_in_drops_only_binary_and_warns() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "--allow-build-scripts", "./local-project"],
        &[],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let q = only_item(&fx);
    let (argv, cwd) = recorded(&fx, "pip").expect("pip ran");
    // As in 1.3.7: from the caller's directory, so `./local-project` is the
    // one the user meant.
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
    let err = stderr(&out);
    assert!(err.contains("warning:"), "{err}");
    assert!(err.contains("BEFORE Sigil scans"), "{err}");
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
        vec!["pip", "requests>=2", "-V", "2.32.3"],
        vec![
            "pip",
            "requests",
            "-V",
            "2 @ https://example.invalid/x.tar.gz",
        ],
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
        assert!(recorded(&fx, "pip").is_none(), "{args:?} ran pip");
        assert!(
            quarantine_items(&fx).is_empty(),
            "{args:?} created a quarantine entry"
        );
    }
    let out = sigil(&fx, &["pip", "./local-project"], &[]);
    assert!(
        stderr(&out).contains("--allow-build-scripts"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_failed_wheel_only_download_explains_the_opt_in() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["pip", "sdist-only-pkg"],
        &[("SIGIL_TEST_FAKE_EXIT", "1")],
    );
    assert_eq!(code(&out), 2);
    let err = stderr(&out);
    assert!(err.contains("pip download failed"), "{err}");
    assert!(err.contains("--only-binary=:all:"), "{err}");
    assert!(err.contains("--allow-build-scripts"), "{err}");
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

#[test]
fn npm_packs_registry_tarballs_with_scripts_off() {
    let fx = fixture();
    let out = sigil(&fx, &["npm", "@types/node", "-V", "20.1.0"], &[]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let q = only_item(&fx);
    let (argv, cwd) = recorded(&fx, "npm").expect("npm ran");
    assert_eq!(
        argv,
        ["pack", "--ignore-scripts", "--", "@types/node@20.1.0"]
    );
    assert_eq!(cwd, q, "npm must run in the quarantine directory");
}

#[test]
fn npm_opt_in_drops_ignore_scripts_and_warns() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &["npm", "github:owner/repo", "--allow-build-scripts"],
        &[],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let (argv, _) = recorded(&fx, "npm").expect("npm ran");
    assert_eq!(argv, ["pack", "--", "github:owner/repo"]);
    let err = stderr(&out);
    assert!(err.contains("warning:"), "{err}");
    assert!(err.contains("lifecycle scripts"), "{err}");
}

#[test]
fn npm_refusals_run_nothing_and_quarantine_nothing() {
    let fx = fixture();
    for spec in [
        "./local-dir",
        "../local-dir",
        "/abs/dir",
        "owner/repo",
        "github:owner/repo",
        "git+https://example.invalid/owner/repo.git",
        "git+file:///tmp/repo",
        "git@example.invalid:owner/repo.git",
        "https://example.invalid/pkg-1.0.0.tgz",
        "file:../pkg",
        "pkg.tgz",
        "foo@npm:bar",
        "foo@owner/repo",
        "foo#main",
        "@scope/name/sub",
    ] {
        let out = sigil(&fx, &["npm", spec], &[]);
        assert_eq!(code(&out), 2, "{spec}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("will not download"), "{spec}: {err}");
        assert!(err.contains("--allow-build-scripts"), "{spec}: {err}");
        assert!(recorded(&fx, "npm").is_none(), "{spec} ran npm");
        assert!(
            quarantine_items(&fx).is_empty(),
            "{spec} created a quarantine entry"
        );
    }
    let out = sigil(&fx, &["npm", "--", "-g"], &[]);
    assert_eq!(code(&out), 2);
    assert!(recorded(&fx, "npm").is_none());
}

// ---------------------------------------------------------------------------
// The MCP server's scan_package tool takes the same path
// ---------------------------------------------------------------------------

/// One `tools/call scan_package` through `sigil mcp`, with the test doubles
/// first on PATH: the tool's result object.
fn mcp_scan_package(fx: &Fixture, arguments: serde_json::Value) -> serde_json::Value {
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
        );
        assert_eq!(result["isError"], true, "{ecosystem} {name}: {result}");
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("will not download"),
            "{ecosystem} {name}: {text}"
        );
        assert!(recorded(&fx, "npm").is_none(), "{name} ran npm");
        assert!(recorded(&fx, "pip").is_none(), "{name} ran pip");
    }
    // A registry package goes through the wheel-only download.
    let result = mcp_scan_package(
        &fx,
        serde_json::json!({ "ecosystem": "pypi", "name": "requests", "version": "2.32.3" }),
    );
    assert_eq!(result["isError"], false, "{result}");
    let (argv, _) = recorded(&fx, "pip").expect("pip ran");
    assert!(argv.iter().any(|a| a == "--only-binary=:all:"), "{argv:?}");
    assert_eq!(argv.last().map(String::as_str), Some("requests==2.32.3"));
}

// ---------------------------------------------------------------------------
// The real pip, offline, against a local source distribution
// ---------------------------------------------------------------------------

/// A source distribution whose in-tree build backend creates `marker` when
/// pip imports it, i.e. when pip prepares the sdist's metadata. `requires =
/// []` and `backend-path` mean pip needs no network to get that far.
fn write_marker_sdist(links: &Path, marker: &Path) {
    let backend = format!(
        "# Test fixture: its only side effect is an empty marker file.\n\
         open({marker:?}, \"w\").close()\n\
         \n\
         def get_requires_for_build_wheel(config_settings=None):\n    return []\n\
         \n\
         def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):\n\
         \x20   import os\n\
         \x20   d = os.path.join(metadata_directory, \"markerpkg-1.0.dist-info\")\n\
         \x20   os.makedirs(d, exist_ok=True)\n\
         \x20   with open(os.path.join(d, \"METADATA\"), \"w\") as f:\n\
         \x20       f.write(\"Metadata-Version: 2.1\\nName: markerpkg\\nVersion: 1.0\\n\")\n\
         \x20   return \"markerpkg-1.0.dist-info\"\n\
         \n\
         def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n\
         \x20   raise RuntimeError(\"fixture builds no wheels\")\n",
        marker = marker.to_string_lossy()
    );
    let files: [(&str, String); 3] = [
        (
            "pyproject.toml",
            "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n"
                .to_string(),
        ),
        ("backend.py", backend),
        (
            "PKG-INFO",
            "Metadata-Version: 2.1\nName: markerpkg\nVersion: 1.0\n".to_string(),
        ),
    ];
    let f = std::fs::File::create(links.join("markerpkg-1.0.tar.gz")).unwrap();
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for (name, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, format!("markerpkg-1.0/{name}"), body.as_bytes())
            .unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
}

#[test]
fn real_pip_never_builds_a_local_sdist_by_default() {
    let available = Command::new("pip")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("skipped: pip is not installed");
        return;
    }
    let fx = fixture();
    let links = fx.root.join("links");
    std::fs::create_dir_all(&links).unwrap();
    let marker = fx.root.join("marker-backend-ran");
    write_marker_sdist(&links, &marker);
    let path = std::env::var("PATH").unwrap_or_default();
    let links_s = links.to_string_lossy().to_string();
    let offline: [(&str, &str); 5] = [
        ("PIP_CONFIG_FILE", "/dev/null"),
        ("PIP_NO_INDEX", "1"),
        ("PIP_FIND_LINKS", &links_s),
        ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
        ("PIP_NO_CACHE_DIR", "1"),
    ];

    // The index (here: the local find-links directory) has only an sdist.
    let out = run_sigil(&fx, &["pip", "markerpkg"], &path, &offline);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(!marker.exists(), "the sdist's build backend ran by default");
    assert!(
        stderr(&out).contains("--allow-build-scripts"),
        "{}",
        stderr(&out)
    );

    // The same sdist as a local path is refused before pip runs.
    let sdist = links.join("markerpkg-1.0.tar.gz");
    let out = run_sigil(&fx, &["pip", &sdist.to_string_lossy()], &path, &offline);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(!marker.exists(), "a local sdist path was built");

    // The fixture is live: with the opt-in, pip does run its backend.
    let out = run_sigil(
        &fx,
        &["pip", "markerpkg", "--allow-build-scripts"],
        &path,
        &offline,
    );
    assert!(
        marker.exists(),
        "with --allow-build-scripts pip should have prepared the sdist; stderr: {}",
        stderr(&out)
    );
}
