//! End-to-end tests of YARA rule files as custom rules: loading (`--rules`,
//! directories, the organisation policy's `rule_packs`), the exit-code
//! contract, fail-closed refusal, collisions and detached signatures.
//!
//! Every test runs the real binary against a temporary tree with an isolated
//! HOME. The rules match inert synthetic markers (`SIGIL_YARA_TEST_MARKER`,
//! the bytes of "SIGIL"); nothing here describes real malware.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MARKER: &str = "SIGIL_YARA_TEST_MARKER";

/// A High text rule and a Medium byte rule.
const RULES: &str = r#"
rule Sigil_Test_Marker : test
{
    meta:
        description = "Synthetic test marker"
        severity = "high"
        remediation = "Remove the synthetic marker."
    strings:
        $a = "SIGIL_YARA_TEST_MARKER"
    condition:
        $a
}

rule Sigil_Test_Bytes
{
    meta:
        description = "Synthetic byte marker"
        severity = "medium"
    strings:
        $h = { 53 49 47 49 4C 00 }
    condition:
        $h
}
"#;

/// Only the Medium byte rule.
const MEDIUM_ONLY: &str = r#"
rule Sigil_Medium_Bytes
{
    meta:
        severity = "medium"
    strings:
        $h = { 53 49 47 49 4C 00 }
    condition:
        $h
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    proj: PathBuf,
    rules: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    let proj = root.join("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    // Under bin/, where a shipped binary is expected (no PROV-002), so the
    // only thing that can flag it is the YARA byte rule.
    std::fs::create_dir_all(proj.join("bin")).unwrap();
    std::fs::write(
        proj.join("src/app.txt"),
        format!("first line\nvalue = {MARKER}\n"),
    )
    .unwrap();
    std::fs::write(proj.join("bin/blob.dat"), b"\x00\x01SIGIL\x00\xff").unwrap();
    std::fs::write(proj.join("src/readme.txt"), "nothing to see\n").unwrap();
    let rules = root.join("rules.yar");
    std::fs::write(&rules, RULES).unwrap();
    Fixture {
        _dir: dir,
        root,
        home,
        proj,
        rules,
    }
}

fn sigil(fx: &Fixture, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigil"));
    cmd.args(args)
        .current_dir(cwd)
        .env("HOME", &fx.home)
        // No external YARA engine unless a test puts a stub on PATH: what
        // this machine has installed must not change a result.
        .env("PATH", fx.root.join("no-engines"))
        .env_remove("SIGIL_POLICY_FILE")
        .env_remove("SIGIL_PACK_PUBLIC_KEY")
        .env_remove("SIGIL_NO_PROJECT_CONFIG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run sigil")
}

/// Wall-clock ceilings in these tests are set for an optimised build. CI
/// runs `cargo test` unoptimised, where the regex engines are about an order
/// of magnitude slower, so the ceiling scales with the profile: it still
/// catches a search that is not bounded at all (minutes), and no longer fails
/// on a slow runner. The deterministic assertions beside each ceiling (a cut
/// short `not $a` never fires, the budget finding is reported) hold in both.
fn ceiling(release_secs: u64) -> std::time::Duration {
    let factor = if cfg!(debug_assertions) { 8 } else { 1 };
    std::time::Duration::from_secs(release_secs * factor)
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

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document: {e}\n{}",
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

fn findings(o: &Output, rule: &str) -> Vec<serde_json::Value> {
    json(o)["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|f| f["rule"] == rule)
        .cloned()
        .collect()
}

#[test]
fn a_yara_rule_fires_and_gates_on_its_severity() {
    let fx = fixture();
    let rules = fx.rules.to_str().unwrap();

    let clean = sigil(&fx, &fx.proj, &["scan", ".", "--no-cache"], &[]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));

    let flagged = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(
        code(&flagged),
        1,
        "a HIGH YARA finding fails the default gate"
    );

    let raised = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rules,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "critical",
        ],
        &[],
    );
    assert_eq!(code(&raised), 0);

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache", "-f", "json"],
        &[],
    );
    let text = findings(&o, "YARA-SIGIL-TEST-MARKER");
    assert_eq!(text.len(), 1, "{}", stdout(&o));
    assert_eq!(text[0]["severity"], "High");
    assert_eq!(text[0]["line"], 2);
    assert!(text[0]["file"].as_str().unwrap().ends_with("app.txt"));
    assert!(text[0]["snippet"].as_str().unwrap().contains(MARKER));
    assert_eq!(text[0]["remediation"], "Remove the synthetic marker.");
    // The byte rule matches a binary file, which has no line number.
    let bytes = findings(&o, "YARA-SIGIL-TEST-BYTES");
    assert_eq!(bytes.len(), 1, "{}", stdout(&o));
    assert!(bytes[0]["file"].as_str().unwrap().ends_with("blob.dat"));
    assert!(bytes[0]["line"].is_null());

    // A MEDIUM rule passes the default gate and fails --fail-on medium.
    let medium = fx.root.join("medium.yara");
    std::fs::write(&medium, MEDIUM_ONLY).unwrap();
    let medium = medium.to_str().unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["scan", ".", "--no-cache", "--fail-on", "medium"],
        &[],
    );
    assert_eq!(
        code(&o),
        0,
        "nothing else in the tree is MEDIUM: {}",
        stderr(&o)
    );
    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", medium, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            medium,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "medium",
        ],
        &[],
    );
    assert_eq!(code(&o), 1);
}

#[test]
fn directories_policies_and_inline_markers_treat_yara_like_any_rule() {
    let fx = fixture();
    let dir = fx.root.join("ruledir");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("acme.yar"), RULES).unwrap();
    std::fs::write(dir.join("notes.txt"), "not a rule file").unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            dir.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(findings(&o, "YARA-SIGIL-TEST-MARKER").len(), 1);

    // The organisation policy's rule_packs, resolved against its directory.
    let org = fx.root.join("org.yml");
    std::fs::write(&org, "rule_packs: [rules.yar]\n").unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["scan", ".", "--no-cache", "-f", "json"],
        &[("SIGIL_POLICY_FILE", org.to_str().unwrap())],
    );
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(findings(&o, "YARA-SIGIL-TEST-MARKER").len(), 1);

    // Policy globs and severity overrides address YARA ids.
    std::fs::write(
        fx.proj.join(".sigil.yml"),
        "disable_rules: [YARA-SIGIL-TEST-MARKER]\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            fx.rules.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(findings(&o, "YARA-SIGIL-TEST-MARKER").is_empty());
    std::fs::remove_file(fx.proj.join(".sigil.yml")).unwrap();

    // An inline marker on the matched line silences the finding, with its
    // reason kept in the report.
    std::fs::write(
        fx.proj.join("src/app.txt"),
        format!("first line\nvalue = {MARKER}  # sigil:ignore YARA-SIGIL-TEST-MARKER -- fixture\n"),
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            fx.rules.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(findings(&o, "YARA-SIGIL-TEST-MARKER").is_empty());
    assert!(stdout(&o).contains("fixture"));
}

#[test]
fn the_edges_of_an_oversized_files_head_and_tail_are_not_the_files_edges() {
    let fx = fixture();
    // 12 MB of text. The scanned head (the first 2,000,000 bytes) ends in the
    // middle of the word "SIGILab", and the scanned tail (the last 2,000,000)
    // starts in the middle of "zzMARK": neither is a whole word, and neither
    // edge is the start or end of the file.
    let mut data = vec![b'x'; 12 * 1024 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        if i % 64 == 63 {
            *b = b'\n';
        }
    }
    let n = data.len();
    let head_end = 2_000_000;
    data[head_end - 6..head_end + 2].copy_from_slice(b" SIGILab");
    let tail_start = n - 2_000_000;
    data[tail_start - 2..tail_start + 4].copy_from_slice(b"zzMARK");
    std::fs::write(fx.proj.join("big.txt"), &data).unwrap();
    let rule = fx.root.join("edges.yar");
    std::fs::write(
        &rule,
        "rule Edge_Word { strings: $a = \"SIGIL\" fullword condition: $a }\n\
         rule Edge_End { strings: $a = /SIGIL$/ condition: $a }\n\
         rule Edge_Start { strings: $a = /^MARK/ condition: $a }\n\
         rule Edge_Tail_Word { strings: $a = /\\bMARK/ condition: $a }\n\
         rule Edge_Plain { strings: $a = \"SIGIL\" $b = \"MARK\" condition: $a and $b }\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rule.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    // (The fixture's other files carry the markers too; only big.txt counts.)
    let on_big = |id: &str| {
        findings(&o, id)
            .into_iter()
            .filter(|f| f["file"].as_str().unwrap_or("").ends_with("big.txt"))
            .count()
    };
    for id in [
        "YARA-EDGE-WORD",
        "YARA-EDGE-END",
        "YARA-EDGE-START",
        "YARA-EDGE-TAIL-WORD",
    ] {
        assert_eq!(on_big(id), 0, "{id}: {}", stdout(&o));
    }
    // Both markers are in the scanned parts, so the plain rule fires.
    assert_eq!(on_big("YARA-EDGE-PLAIN"), 1, "{}", stdout(&o));
}

#[test]
fn an_oversized_binary_is_evaluated_on_its_head_and_tail_and_says_so() {
    let fx = fixture();
    // 12 MB of zeros with the marker bytes in the head, the middle and the
    // tail: only the head and tail (2 MB each) are read.
    let mut data = vec![0u8; 12 * 1024 * 1024];
    let n = data.len();
    let mid = n / 2;
    data[100..106].copy_from_slice(b"SIGIL\0");
    data[mid..mid + 6].copy_from_slice(b"SIGIL\0");
    data[n - 50..n - 44].copy_from_slice(b"SIGIL\0");
    std::fs::write(fx.proj.join("bin/big.dat"), &data).unwrap();
    let rule = fx.root.join("count.yar");
    std::fs::write(
        &rule,
        "rule Sigil_Count { meta: severity = \"low\" \
         strings: $h = { 53 49 47 49 4C 00 } \
         condition: #h == 2 and filesize > 10MB and $h at 100 }\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rule.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    let hits = findings(&o, "YARA-SIGIL-COUNT");
    assert_eq!(hits.len(), 1, "{}", stdout(&o));
    assert!(hits[0]["file"].as_str().unwrap().ends_with("big.dat"));
    assert!(hits[0]["snippet"]
        .as_str()
        .unwrap()
        .starts_with("[head/tail of oversized file]"));
    let gap = findings(&o, "PROV-INCOMPLETE-001");
    assert!(
        gap.iter()
            .any(|f| f["file"].as_str().unwrap().ends_with("big.dat")
                && f["snippet"].as_str().unwrap().contains("by the YARA rules")),
        "{}",
        stdout(&o)
    );
}

/// Valid YARA, all of it outside the built-in engine's subset.
const NEEDS_ENGINE: &str = "import \"pe\"\n\
     rule Bad_One\n{\n    strings:\n        $a = \"SIGIL\" xor\n    condition:\n        $a and uint16(0) == 1\n}\n";

#[test]
fn invalid_yara_fails_closed_with_every_problem_and_its_line() {
    let fx = fixture();
    let bad = fx.root.join("bad.yar");
    std::fs::write(
        &bad,
        "rule Bad_One\n{\n    strings:\n        $a = \"SIGIL\"\n        $b = \"unused\"\n    \
         condition:\n        $a and $c\n}\n",
    )
    .unwrap();
    let bad = bad.to_str().unwrap();

    // Rules YARA itself refuses stop the scan, whatever the engine.
    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", bad, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(code(&o), 2, "an invalid rule file stops the scan");
    let err = stderr(&o);
    assert!(
        err.contains(&format!("{bad}:7: string $c is not defined")),
        "{err}"
    );

    let o = sigil(&fx, &fx.root, &["rules", "validate", bad], &[]);
    assert_eq!(code(&o), 1);
    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "validate", fx.rules.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(stdout(&o).contains("2 rule(s), yara form"));
    assert!(stdout(&o).contains("engine: built-in"), "{}", stdout(&o));
    let o = sigil(&fx, &fx.root, &["rules", "validate", "missing.yar"], &[]);
    assert_eq!(code(&o), 2);

    // Valid YARA the built-in engine cannot evaluate: `builtin` refuses it
    // as before, naming every construct and its line.
    let module = fx.root.join("module.yar");
    std::fs::write(&module, NEEDS_ENGINE).unwrap();
    let module = module.to_str().unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--yara-engine",
            "builtin",
            "--rules",
            module,
            "scan",
            ".",
            "--no-cache",
        ],
        &[],
    );
    assert_eq!(code(&o), 2);
    let err = stderr(&o);
    for want in [
        format!("{module}:1: `import \"pe\"`"),
        format!("{module}:5: string $a: the `xor` modifier"),
        format!("{module}:7: `uint16()`"),
    ] {
        assert!(err.contains(&want), "missing {want:?} in {err}");
    }
    assert!(err.contains("[needs an external engine]"), "{err}");
    // An explicit external engine that is not installed stops the scan.
    let o = sigil(
        &fx,
        &fx.proj,
        &["--yara-engine", "yara-x", "--rules", module, "scan", "."],
        &[],
    );
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("YARA-X (`yr`) is not installed"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn without_an_engine_rules_that_need_one_are_reported_as_not_evaluated() {
    let fx = fixture();
    let module = fx.root.join("module.yar");
    std::fs::write(&module, NEEDS_ENGINE).unwrap();
    let module = module.to_str().unwrap();
    let args = ["--rules", module, "scan", ".", "--no-cache", "-f", "json"];
    let o = sigil(&fx, &fx.proj, &args, &[]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("these YARA rules need an external engine"),
        "{}",
        stderr(&o)
    );
    let gap = findings(&o, "PROV-INCOMPLETE-001");
    assert!(
        gap.iter().any(|f| {
            let s = f["snippet"].as_str().unwrap();
            s.contains("module.yar") && s.contains("were not evaluated") && s.contains("import")
        }),
        "{}",
        stdout(&o)
    );
    assert_eq!(json(&o)["summary"]["complete"], false);
    // It counts as incomplete coverage: the gate fails closed on it.
    let mut strict = args.to_vec();
    strict.push("--fail-on-incomplete");
    assert_eq!(code(&sigil(&fx, &fx.proj, &strict, &[])), 1);
    // It cannot be called valid either.
    let o = sigil(&fx, &fx.root, &["rules", "validate", module], &[]);
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    assert!(stdout(&o).contains("not checked"), "{}", stdout(&o));
}

/// A stub of YARA-X's `yr` in `dir/bin`: it answers `--version` and `scan
/// --help` as `yr` 1.20.0 does, and scans in its text format, reporting the
/// first rule of each rule file for a target containing
/// `SIGIL_YARA_TEST_MARKER` and the sentinel rule for every target. It logs
/// each invocation to `dir/yr.log`.
#[cfg(unix)]
fn stub_yr(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.join("yr.log");
    let script = format!(
        r#"#!/bin/sh
PATH=/usr/bin:/bin; export PATH
echo "$*" >> '{log}'
if [ "$1" = --version ]; then echo 'yara-x-cli 1.20.0'; exit 0; fi
if [ "$1" = scan ] && [ "$2" = --help ]; then
  echo '-e, --print-namespace -s, --print-strings[=<N>] --scan-list -a, --timeout <SECONDS> --disable-console-logs --relaxed-re-syntax'
  exit 0
fi
shift
rules=""; list=""; scanlist=no
for a in "$@"; do
  case "$a" in
    --scan-list) scanlist=yes ;;
    -*) ;;
    *:*) rules="$rules $a" ;;
    *) list="$a" ;;
  esac
done
[ "$scanlist" = yes ] || exit 0
while IFS= read -r t; do
  if grep -q SIGIL_YARA_TEST_MARKER "$t"; then
    off=$(grep -b -o -a SIGIL_YARA_TEST_MARKER "$t" | head -n 1 | cut -d: -f1)
    for r in $rules; do
      ns=${{r%%:*}}; f=${{r#*:}}
      [ "$ns" = sigil ] && continue
      name=$(sed -n 's/^rule \([A-Za-z0-9_]*\).*/\1/p' "$f" | head -n 1)
      echo "$ns:$name $t"
      printf '0x%x:22:$a: SIGIL_YARA_TEST_MARKER\n' "$off"
    done
  fi
  echo "sigil:sigil_evaluated $t"
done < "$list"
"#,
        log = log.display()
    );
    let path = bin.join("yr");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// A rule only an external engine can evaluate (a module condition).
const MODULE_RULE: &str = r#"import "math"
rule Sigil_Module_Marker
{
    meta:
        description = "Synthetic marker with a module condition"
        severity = "high"
        remediation = "Remove the synthetic marker."
    strings:
        $a = "SIGIL_YARA_TEST_MARKER"
    condition:
        $a and math.entropy(0, filesize) >= 0.0
}
"#;

#[cfg(unix)]
#[test]
fn an_installed_engine_evaluates_rules_the_builtin_engine_cannot() {
    let fx = fixture();
    let bin = stub_yr(&fx.root);
    let path = bin.to_str().unwrap();
    let rules = fx.root.join("module.yar");
    std::fs::write(&rules, MODULE_RULE).unwrap();
    let rules = rules.to_str().unwrap();
    let scan = ["--rules", rules, "scan", ".", "--no-cache", "-f", "json"];
    let o = sigil(&fx, &fx.proj, &scan, &[("PATH", path)]);
    assert_eq!(
        code(&o),
        1,
        "a HIGH YARA finding fails the default gate\n{}",
        stderr(&o)
    );
    let found = findings(&o, "YARA-SIGIL-MODULE-MARKER");
    assert_eq!(found.len(), 1, "{}", stdout(&o));
    let f = &found[0];
    assert_eq!(f["file"], "src/app.txt");
    assert_eq!(f["line"], 2);
    assert_eq!(f["severity"], "High");
    let snippet = f["snippet"].as_str().unwrap();
    assert!(
        snippet.contains("matched $a: SIGIL_YARA_TEST_MARKER"),
        "{snippet}"
    );
    assert!(
        snippet.ends_with("(evaluated by YARA-X 1.20.0)"),
        "{snippet}"
    );
    assert!(
        findings(&o, "PROV-INCOMPLETE-001").is_empty(),
        "{}",
        stdout(&o)
    );
    assert_eq!(json(&o)["summary"]["complete"], true);

    // An inline marker suppresses it like any rule.
    std::fs::write(
        fx.proj.join("src/app.txt"),
        "first line\nvalue = SIGIL_YARA_TEST_MARKER # sigil:ignore YARA-SIGIL-MODULE-MARKER -- test\n",
    )
    .unwrap();
    let o = sigil(&fx, &fx.proj, &scan, &[("PATH", path)]);
    assert!(
        findings(&o, "YARA-SIGIL-MODULE-MARKER").is_empty(),
        "{}",
        stdout(&o)
    );

    // `rules validate`, `show` and `test` name the engine.
    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "validate", rules],
        &[("PATH", path)],
    );
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(
        stdout(&o).contains("engine: YARA-X 1.20.0"),
        "{}",
        stdout(&o)
    );
    let o = sigil(
        &fx,
        &fx.root,
        &[
            "--rules",
            rules,
            "rules",
            "show",
            "YARA-SIGIL-MODULE-MARKER",
        ],
        &[("PATH", path)],
    );
    assert!(stdout(&o).contains("YARA-X 1.20.0"), "{}", stdout(&o));
    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "test", rules, fx.proj.to_str().unwrap()],
        &[("PATH", path)],
    );
    assert!(
        stdout(&o).contains("YARA-SIGIL-MODULE-MARKER"),
        "{}",
        stdout(&o)
    );

    // `builtin` refuses it even with the engine installed.
    let o = sigil(
        &fx,
        &fx.proj,
        &["--yara-engine", "builtin", "--rules", rules, "scan", "."],
        &[("PATH", path)],
    );
    assert_eq!(code(&o), 2, "{}", stderr(&o));

    // So does a policy that says so; `sigil config --policy` shows it.
    std::fs::write(fx.proj.join(".sigil.yml"), "yara_engine: builtin\n").unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", "."],
        &[("PATH", path)],
    );
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    let o = sigil(&fx, &fx.proj, &["config", "--policy"], &[("PATH", path)]);
    assert!(stdout(&o).contains("builtin"), "{}", stdout(&o));
}

#[cfg(unix)]
#[test]
fn an_engine_shipped_inside_the_scanned_tree_is_never_run() {
    let fx = fixture();
    // The tree under scan carries its own `yr`, and PATH points at it.
    let bin = stub_yr(&fx.proj);
    let rules = fx.root.join("module.yar");
    std::fs::write(&rules, MODULE_RULE).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rules.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[("PATH", bin.to_str().unwrap())],
    );
    assert!(!fx.proj.join("yr.log").exists(), "the stub ran");
    let gap = findings(&o, "PROV-INCOMPLETE-001");
    // Said as it is: an engine was found, inside the tree, and not used.
    assert!(
        gap.iter().any(|f| {
            let s = f["snippet"].as_str().unwrap();
            s.contains("were not evaluated") && s.contains("one inside it was not considered")
        }),
        "{}",
        stdout(&o)
    );
}

#[cfg(unix)]
#[test]
fn a_single_file_scanned_beside_the_engine_is_evaluated_by_it() {
    // `sigil scan ~/.cargo/bin/tool` with `yr` installed in the same
    // directory: what is judged is the one file, so the engine beside it
    // runs (before, the file's directory counted as the scanned tree and
    // the rules were reported as not evaluated).
    let fx = fixture();
    let bin = stub_yr(&fx.root);
    let tool = bin.join("tool.txt");
    std::fs::write(&tool, format!("first\n{MARKER}\n")).unwrap();
    let rules = fx.root.join("module.yar");
    std::fs::write(&rules, MODULE_RULE).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rules.to_str().unwrap(),
            "scan",
            tool.to_str().unwrap(),
            "--no-cache",
            "-f",
            "json",
        ],
        &[("PATH", bin.to_str().unwrap())],
    );
    let found = findings(&o, "YARA-SIGIL-MODULE-MARKER");
    assert_eq!(found.len(), 1, "{}\n{}", stdout(&o), stderr(&o));
    assert_eq!(found[0]["line"], 2);
    assert!(
        findings(&o, "PROV-INCOMPLETE-001").is_empty(),
        "{}",
        stdout(&o)
    );
    assert_eq!(json(&o)["summary"]["complete"], true);
}

#[cfg(unix)]
#[test]
fn rules_validate_uses_the_engine_the_scan_policy_selects() {
    let fx = fixture();
    let bin = stub_yr(&fx.root);
    let path = bin.to_str().unwrap();
    let rules = fx.root.join("module.yar");
    std::fs::write(&rules, MODULE_RULE).unwrap();
    let rules = rules.to_str().unwrap();
    // No policy: `auto` hands the file to the installed YARA-X.
    let o = sigil(
        &fx,
        &fx.proj,
        &["rules", "validate", rules],
        &[("PATH", path)],
    );
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(
        stdout(&o).contains("engine: YARA-X 1.20.0"),
        "{}",
        stdout(&o)
    );
    // A project policy here that says `builtin` is what a scan here would
    // use, so validate and sign say what that scan would do: refuse it.
    std::fs::write(fx.proj.join(".sigil.yml"), "yara_engine: builtin\n").unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["rules", "validate", rules],
        &[("PATH", path)],
    );
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    assert!(
        stdout(&o).contains("[needs an external engine]"),
        "{}",
        stdout(&o)
    );
    // The flag overrides an unlocked project file, as for a scan.
    let o = sigil(
        &fx,
        &fx.proj,
        &["--yara-engine", "yara-x", "rules", "validate", rules],
        &[("PATH", path)],
    );
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    // Locked by the organisation, the flag is refused, and said so.
    let org = fx.root.join("org.yml");
    std::fs::write(&org, "yara_engine: builtin\nlocked: [yara_engine]\n").unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &["--yara-engine", "yara-x", "rules", "validate", rules],
        &[("PATH", path), ("SIGIL_POLICY_FILE", org.to_str().unwrap())],
    );
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    assert!(
        stderr(&o).contains("yara_engine") && stderr(&o).contains("locked"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn a_yara_rule_cannot_redefine_an_existing_rule_id() {
    let fx = fixture();
    let copy = fx.root.join("again.yar");
    std::fs::write(&copy, RULES).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            fx.rules.to_str().unwrap(),
            "--rules",
            copy.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
        ],
        &[],
    );
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("YARA-SIGIL-TEST-MARKER is already defined"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn rules_list_show_and_test_include_yara_rules() {
    let fx = fixture();
    let rules = fx.rules.to_str().unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &["--rules", rules, "rules", "list", "--json"],
        &[],
    );
    assert_eq!(code(&o), 0);
    let doc = json(&o);
    let row = doc["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "YARA-SIGIL-TEST-MARKER")
        .cloned()
        .expect("listed");
    assert_eq!(row["kind"], "yara");
    assert_eq!(row["origin"], "custom");
    assert_eq!(row["severity"], "HIGH");

    let o = sigil(
        &fx,
        &fx.root,
        &["--rules", rules, "rules", "show", "yara-sigil-test-marker"],
        &[],
    );
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("rule Sigil_Test_Marker"));

    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "test", rules, fx.proj.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    assert!(out.contains("[YARA-SIGIL-TEST-MARKER]"), "{out}");
    assert!(out.contains("[YARA-SIGIL-TEST-BYTES]"), "{out}");

    // `rules test` keeps the per-file budget: a sample crafted so that every
    // start of `/A.*B/s` is a match just past the 4096-byte limit takes
    // seconds without it, and must be stopped and said so.
    let slow_rule = fx.root.join("slow.yar");
    std::fs::write(
        &slow_rule,
        "rule Slow_Probe { strings: $a = /A.*B/s condition: not $a }\n",
    )
    .unwrap();
    let mut block = vec![b'A'; 4000];
    block.extend(std::iter::repeat_n(b'x', 4097));
    block.push(b'B');
    let samples = fx.root.join("samples");
    std::fs::create_dir_all(&samples).unwrap();
    std::fs::write(samples.join("crafted.bin"), block.repeat(256)).unwrap();
    let started = std::time::Instant::now();
    let o = sigil(
        &fx,
        &fx.root,
        &[
            "rules",
            "test",
            slow_rule.to_str().unwrap(),
            samples.to_str().unwrap(),
        ],
        &[("SIGIL_FILE_BUDGET_SECS", "0.3")],
    );
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    assert!(out.contains("[PROV-BUDGET-001]"), "{out}");
    assert!(!out.contains("[YARA-SLOW-PROBE]"), "{out}");
    assert!(started.elapsed() < ceiling(30), "{:?}", started.elapsed());
}

#[test]
fn signed_yara_files_verify_and_unsigned_ones_are_refused_when_keyed() {
    let fx = fixture();
    let key = fx.root.join("signing.hex");
    std::fs::write(&key, "07".repeat(32)).unwrap();
    let rules = fx.rules.to_str().unwrap();
    let sig = format!("{rules}.sig");

    let o = sigil(
        &fx,
        &fx.root,
        &[
            "rules",
            "sign",
            rules,
            "--key",
            key.to_str().unwrap(),
            "-o",
            &sig,
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let public = stderr(&o)
        .split("SIGIL_PACK_PUBLIC_KEY=")
        .nth(1)
        .map(|s| s.trim().to_string())
        .expect("public key printed");
    let keyed = [("SIGIL_PACK_PUBLIC_KEY", public.as_str())];

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache"],
        &keyed,
    );
    assert_eq!(code(&o), 1, "signed rules load and fire: {}", stderr(&o));

    let unsigned = fx.root.join("unsigned.yar");
    std::fs::write(&unsigned, RULES).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            unsigned.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
        ],
        &keyed,
    );
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("[SECURITY]"), "{}", stderr(&o));

    // Editing a signed file breaks its signature.
    std::fs::write(&fx.rules, RULES.replace("\"high\"", "\"low\"")).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache"],
        &keyed,
    );
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("signature verification failed"),
        "{}",
        stderr(&o)
    );
}
