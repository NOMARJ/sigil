//! Tests for external YARA engines, without the real engines: stub
//! executables written by the tests answer `--version` and `--help` as the
//! real tools do and print scan results in their text format (`ns:rule
//! path`, then `0x<offset>:<length>:<string>: <data>`). The formats, and
//! the recorded lines in the parser tests, come from YARA 4.5.0 (`yara -e -s
//! -L --scan-list`) and YARA-X 1.20.0 (`yr scan -e --print-strings=48
//! --scan-list`) run on synthetic files; only the rule file's temporary name
//! was changed.
//!
//! Every rule matches synthetic, inert markers (`SIGIL_STUB_MARKER`); none
//! describes real malware.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::corpus::yara::{parse_pack_with, FileEngine};
use crate::scanner::Severity;

#[test]
fn engine_modes_parse_and_name_themselves() {
    for name in EngineMode::NAMES {
        let mode = EngineMode::parse(name).expect(name);
        assert_eq!(mode.name(), *name);
    }
    assert_eq!(EngineMode::parse(" YR "), Some(EngineMode::YaraX));
    assert_eq!(EngineMode::parse("libyara"), Some(EngineMode::Yara));
    assert_eq!(EngineMode::parse("built-in"), Some(EngineMode::Builtin));
    assert_eq!(EngineMode::parse("clamav"), None);
}

// ---------------------------------------------------------------------------
// Reading the engines' own output (recorded from the real tools)
// ---------------------------------------------------------------------------

fn parsed(targets: usize, lines: &[&str]) -> Output {
    let mut o = Output::new(targets);
    for l in lines {
        o.line(l.as_bytes());
    }
    o
}

#[test]
fn yara_x_output_is_read_rule_by_rule_and_target_by_target() {
    // YARA-X 1.20.0, `yr scan -e --print-strings=48 --scan-list`.
    let o = parsed(
        3,
        &[
            "f0:Marker_Rule t/0",
            "0x6:12:$a: SIGIL_MARKER",
            "0x1f:12:$a: SIGIL_MARKER",
            "0x13:5:$h: 77 6f 72 6c 64",
            "sigil:sigil_evaluated t/0",
            "sigil:sigil_evaluated t/1",
        ],
    );
    assert_eq!(o.evaluated, vec![true, true, false]);
    assert_eq!(o.hits[0].len(), 1);
    let h = &o.hits[0][0];
    assert_eq!((h.file, h.rule.as_str()), (0, "Marker_Rule"));
    assert_eq!(h.first_offset, Some(0x6));
    let shown: Vec<(&str, &str)> = h
        .shown
        .iter()
        .map(|s| (s.id.as_str(), s.data.as_str()))
        .collect();
    assert_eq!(
        shown,
        vec![("$a", "SIGIL_MARKER"), ("$h", "77 6f 72 6c 64")],
        "each string once, at its first match"
    );
    assert!(o.hits[1].is_empty() && o.hits[2].is_empty());
}

#[test]
fn classic_yara_output_is_read_the_same_way() {
    // YARA 4.5.0, `yara -e -s -L --scan-list`.
    let o = parsed(
        2,
        &[
            "f3:Marker_Rule t/1",
            "0x1f:12:$a: SIGIL_MARKER",
            "0x13:5:$h: 77 6F 72 6C 64",
            "sigil:sigil_evaluated t/1",
        ],
    );
    assert_eq!(o.evaluated, vec![false, true]);
    let h = &o.hits[1][0];
    assert_eq!((h.file, h.first_offset), (3, Some(0x13)), "earliest offset");
}

#[test]
fn the_output_reader_is_robust_to_what_it_does_not_expect() {
    let long = format!("0x0:1:$a: {}", "A".repeat(1000));
    let o = parsed(
        2,
        &[
            // Colour codes are stripped before parsing.
            "\u{1b}[1;36mf0:Colour\u{1b}[0m t/0",
            // A YARA-X xor match names the key after the string id.
            "0x10:4:$x xor(0x5,SIGI): VLBL",
            &long,
            // Not a target Sigil staged, nor a namespace it wrote.
            "f0:Other t/99",
            "f0:Other list/0",
            "bogus line without a colon",
            "0xZZ:1:$a: bad offset",
            "zz:Rule t/1",
            // More distinct strings than a snippet shows.
            "f1:Many t/1",
            "0x1:1:$a: a",
            "0x2:1:$b: b",
            "0x3:1:$c: c",
            "0x4:1:$d: d",
            "0x5:1:$e: e",
            "0x0:1:$a: a again",
        ],
    );
    let colour = &o.hits[0][0];
    assert_eq!(colour.rule, "Colour");
    assert_eq!(
        colour.shown[0].id, "$x",
        "the xor key is not part of the id"
    );
    assert_eq!(colour.first_offset, Some(0));
    assert!(colour.shown[0].data.len() <= SNIPPET_CHARS + 3);
    assert_eq!(o.hits[0].len(), 1, "unknown targets and namespaces ignored");
    let many = &o.hits[1][0];
    assert_eq!(many.rule, "Many");
    assert_eq!(many.shown.len(), SNIPPET_STRINGS);
    assert_eq!(many.more, vec!["$d".to_string(), "$e".to_string()]);
    assert_eq!(many.first_offset, Some(0));
    assert!(!o.evaluated.iter().any(|e| *e));
}

#[test]
fn stream_lines_drops_overlong_lines_without_holding_them() {
    let mut data = Vec::new();
    data.extend_from_slice(b"first\n");
    data.extend(std::iter::repeat_n(b'x', MAX_LINE + 10));
    data.extend_from_slice(b"\nlast");
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&seen);
    let sink: Sink = Arc::new(Mutex::new(move |l: &[u8]| {
        into.lock()
            .unwrap()
            .push(String::from_utf8_lossy(l).into_owned())
    }));
    stream_lines(&data[..], &sink);
    assert_eq!(*seen.lock().unwrap(), vec!["first", "last"]);
}

#[test]
fn per_file_errors_are_attributed_to_their_target() {
    // YARA-X 1.20.0 and YARA 4.5.0 on a file that vanished, and a timeout.
    let e = errors_by_target(
        "error: can't open `t/2`: No such file or directory (os error 2)\n\
         error: scanning \"t/9\": timeout\n\
         error scanning t/4: could not open file\n\
         error scanning t/5: scanning timed out\n\
         warning: rule \"x\" in r/0.yar(1): string \"$a\" may slow down scanning\n\
         error: something about list/7\n",
    );
    assert!(e[&2].contains("can't open"));
    assert!(e[&9].contains("timeout"));
    assert!(e[&4].contains("could not open file"));
    assert!(e[&5].contains("timed out"));
    assert!(!e.contains_key(&7), "`list/7` is not target 7");
    assert!(!e.contains_key(&0));
}

#[test]
fn compile_errors_are_attributed_to_their_rule_file() {
    // YARA-X 1.20.0: a diagnostic block per error, then a count.
    let yr = "warning[invariant_expr]: invariant boolean expression\n \
              --> r/0.yar:1:21\n  |\n\
              error[E025]: unknown pattern `$x`\n \
              --> r/1.yar:1:23\n  |\n1 | rule bad { condition: $x }\n  |                       ^^ \
              this pattern is not declared in the `strings` section\n\
              error: 1 error(s) found\n";
    let by = errors_by_rule_file(yr, 2);
    assert_eq!(by.keys().copied().collect::<Vec<_>>(), vec![1]);
    assert!(by[&1].contains("unknown pattern `$x`"));
    assert!(by[&1].contains("not declared"));
    // YARA 4.5.0.
    let yara = "error: rule \"bad\" in r/3.yar(1): undefined string \"$x\"\n";
    let by = errors_by_rule_file(yara, 4);
    assert!(by[&3].contains("undefined string"));
    let syntax = "r/0.yar(2): error: syntax error, unexpected identifier\n";
    assert!(errors_by_rule_file(syntax, 1)[&0].contains("syntax error"));
    // A file index past the set, or no file at all, names nothing.
    assert!(errors_by_rule_file(yara, 2).is_empty());
    assert!(errors_by_rule_file("error: out of memory\n", 2).is_empty());
}

#[test]
fn engine_output_is_stripped_of_terminal_control() {
    assert_eq!(
        strip_ansi("\u{1b}[31merror\u{1b}[0m: x\u{7}y\tz\n"),
        "error: xy\tz\n"
    );
}

// ---------------------------------------------------------------------------
// Stub engines
// ---------------------------------------------------------------------------

/// A stub engine's behaviour, beyond the recorded format.
#[derive(Clone, Copy, PartialEq)]
enum Variant {
    /// Every flag Sigil uses.
    Full,
    /// An old build without `--scan-list`.
    NoScanList,
    /// `--version` fails: not the engine it is named after.
    NotAnEngine,
}

struct Stub {
    _dir: tempfile::TempDir,
    bin: PathBuf,
    path: PathBuf,
    /// Each invocation's arguments, one line each.
    log: PathBuf,
}

impl Stub {
    fn invocations(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// Write a stub `yr` or `yara`. It refuses a rule file containing
/// `SIGIL_STUB_INVALID` in the engine's own error format; when scanning, it
/// reports the first rule of each rule file for a target containing
/// `SIGIL_STUB_MARKER` (at the marker's offset), marks every target it
/// finished with the sentinel rule, fails a target containing
/// `SIGIL_STUB_FAIL`, times out on one containing `SIGIL_STUB_SLOW`, and
/// hangs on one containing `SIGIL_STUB_HANG` (`exec sleep`) or
/// `SIGIL_STUB_ORPHAN` (a child that keeps the output pipe open).
#[cfg(unix)]
fn stub(kind: EngineKind, variant: Variant) -> Stub {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let log = dir.path().join("invocations.log");
    let (name, version, help) = match kind {
        EngineKind::YaraX => (
            "yr",
            "yara-x-cli 1.20.0",
            "Usage: yr scan [OPTIONS] <[NAMESPACE:]RULES_PATH>... <TARGET_PATH>\n  \
             -e, --print-namespace  -s, --print-strings[=<N>]  --scan-list  \
             -a, --timeout <SECONDS>  --disable-console-logs  \
             -w, --disable-warnings[=<WARNING_ID>...]  --relaxed-re-syntax",
        ),
        EngineKind::Yara => (
            "yara",
            "4.5.0",
            "Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID\n  \
             -e,  --print-namespace  -s,  --print-strings  -L,  --print-string-length  \
             --scan-list  -a,  --timeout=SECONDS  -q,  --disable-console-logs  \
             -w,  --no-warnings",
        ),
    };
    let help = if variant == Variant::NoScanList {
        help.replace("--scan-list", "")
    } else {
        help.to_string()
    };
    let version_line = if variant == Variant::NotAnEngine {
        "echo 'usage: something else' >&2; exit 64".to_string()
    } else {
        format!("echo '{version}'; exit 0")
    };
    let (compile_error, count_line, fail_line, slow_line) = match kind {
        EngineKind::YaraX => (
            r#"printf 'error[E009]: unknown identifier `SIGIL_STUB_INVALID`\n --> %s:3:14\n  |\n' "$f" >&2"#,
            r#"echo 'error: 1 error(s) found' >&2"#,
            r#"echo "error: scanning \"$t\": stub failure" >&2"#,
            r#"echo "error: scanning \"$t\": timeout" >&2"#,
        ),
        EngineKind::Yara => (
            r#"printf 'error: rule "stub" in %s(3): undefined identifier "SIGIL_STUB_INVALID"\n' "$f" >&2"#,
            ":",
            r#"echo "error scanning $t: could not map file into memory" >&2"#,
            r#"echo "error scanning $t: scanning timed out" >&2"#,
        ),
    };
    let skip_scan = if kind == EngineKind::YaraX {
        r#"if [ "$1" = scan ] && [ "$2" = --help ]; then cat <<'EOF'
__HELP__
EOF
exit 0; fi
[ "$1" = scan ] && shift"#
    } else {
        ":"
    };
    let script = format!(
        r#"#!/bin/sh
# Stub of {name} for Sigil's tests (see external/tests.rs).
PATH=/usr/bin:/bin; export PATH
echo "$*" >> '{log}'
case "$1" in
  --version) {version_line} ;;
  --help) cat <<'EOF'
__HELP__
EOF
    exit 0 ;;
esac
{skip_scan}
rules=""; list=""; scanlist=no
for a in "$@"; do
  case "$a" in
    --scan-list) scanlist=yes ;;
    -*) ;;
    *:*) rules="$rules $a" ;;
    *) list="$a" ;;
  esac
done
bad=no
for r in $rules; do
  f=${{r#*:}}
  if grep -q SIGIL_STUB_INVALID "$f"; then
    {compile_error}
    bad=yes
  fi
done
if [ "$bad" = yes ]; then {count_line}; exit 1; fi
[ "$scanlist" = yes ] || exit 0
while IFS= read -r t; do
  if grep -q SIGIL_STUB_HANG "$t"; then exec sleep 30; fi
  if grep -q SIGIL_STUB_ORPHAN "$t"; then sleep 20; fi
  if grep -q SIGIL_STUB_FAIL "$t"; then {fail_line}; continue; fi
  if grep -q SIGIL_STUB_SLOW "$t"; then {slow_line}; continue; fi
  if grep -q SIGIL_STUB_MARKER "$t"; then
    off=$(grep -b -o -a SIGIL_STUB_MARKER "$t" | head -n 1 | cut -d: -f1)
    for r in $rules; do
      ns=${{r%%:*}}; f=${{r#*:}}
      [ "$ns" = sigil ] && continue
      name=$(sed -n 's/^rule \([A-Za-z0-9_]*\).*/\1/p' "$f" | head -n 1)
      echo "$ns:$name $t"
      printf '0x%x:17:$a: SIGIL_STUB_MARKER\n' "$off"
    done
  fi
  echo "sigil:sigil_evaluated $t"
done < "$list"
exit 0
"#,
        log = log.display(),
    )
    .replace("__HELP__", &help);
    let path = bin.join(name);
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    Stub {
        _dir: dir,
        bin,
        path,
        log,
    }
}

/// Probe a stub, retrying the rare `Text file busy` of executing a file
/// another test's fork may still hold open for writing.
#[cfg(unix)]
fn engine(s: &Stub, kind: EngineKind) -> Engine {
    let mut last = String::new();
    for _ in 0..20 {
        match probe(kind, &s.path) {
            Ok(e) => return e,
            Err(e) if e.contains("busy") => {
                last = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("{last}");
}

/// Rules that need an external engine (a module), and one that does not.
const MODULE_RULES: &str = r#"
import "math"
rule Stub_Module_Rule : stub
{
    meta:
        description = "Synthetic marker with a module condition"
        severity = "high"
        phase = "obfuscation"
        remediation = "Remove the synthetic marker."
    strings:
        $a = "SIGIL_STUB_MARKER"
    condition:
        $a and math.entropy(0, filesize) >= 0.0
}

private rule Stub_Private { condition: true }
"#;

const PLAIN_RULE: &str = r#"
rule Stub_Plain
{
    strings:
        $a = "SIGIL_STUB_MARKER"
    condition:
        $a
}
"#;

fn pack(src: &str, sel: &Selection) -> Result<crate::corpus::custom::CustomPack, Vec<String>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.yar");
    parse_pack_with(src.as_bytes(), &path, sel)
}

fn file_of(p: &crate::corpus::custom::CustomPack) -> Arc<YaraFile> {
    p.pack.yara.clone().expect("a YARA pack")
}

// ---------------------------------------------------------------------------
// Finding and probing an engine
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn an_engine_is_found_on_absolute_path_entries_only() {
    let s = stub(EngineKind::YaraX, Variant::Full);
    // Run from the stub's directory, `.` would find it; Sigil skips it.
    let relative = std::env::join_paths([PathBuf::from("."), PathBuf::from("")]).unwrap();
    let e = find(EngineKind::YaraX, Some(relative)).unwrap_err();
    assert!(e.contains("not installed"), "{e}");
    let with_abs = std::env::join_paths([PathBuf::from("relative/bin"), s.bin.clone()]).unwrap();
    let mut found = None;
    for _ in 0..20 {
        match find(EngineKind::YaraX, Some(with_abs.clone())) {
            Ok(e) => {
                found = Some(e);
                break;
            }
            Err(e) if e.contains("busy") => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("{e}"),
        }
    }
    let e = found.expect("found");
    assert_eq!(e.path, s.path);
    assert_eq!(e.version, "1.20.0");
    assert_eq!(e.label(), "YARA-X 1.20.0");
    for f in [
        "--disable-console-logs",
        "--disable-warnings",
        "--relaxed-re-syntax",
    ] {
        assert!(e.has(f), "{f}");
    }
    assert!(
        find(EngineKind::Yara, Some(with_abs)).is_err(),
        "no `yara` there"
    );
    assert!(find(EngineKind::Yara, None).is_err());
}

#[cfg(unix)]
#[test]
fn an_engine_inside_the_tree_to_scan_is_not_even_probed() {
    let s = stub(EngineKind::YaraX, Variant::Full);
    let tree_root = s.bin.parent().unwrap().to_path_buf();
    let path = std::env::join_paths([s.bin.clone()]).unwrap();
    let e = find_excluding(EngineKind::YaraX, Some(path.clone()), Some(&tree_root)).unwrap_err();
    assert!(e.contains("one inside it was not considered"), "{e}");
    assert!(s.invocations().is_empty(), "not run, not even `--version`");
    // Anywhere else it is found.
    let other = tempfile::tempdir().unwrap();
    let mut found = None;
    for _ in 0..20 {
        match find_excluding(EngineKind::YaraX, Some(path.clone()), Some(other.path())) {
            Ok(e) => {
                found = Some(e);
                break;
            }
            Err(e) if e.contains("busy") => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("{e}"),
        }
    }
    assert!(found.is_some());
}

#[cfg(unix)]
#[test]
fn a_program_that_is_not_the_engine_or_lacks_its_flags_is_refused() {
    let old = stub(EngineKind::Yara, Variant::NoScanList);
    let e = probe(EngineKind::Yara, &old.path).unwrap_err();
    assert!(e.contains("lacks --scan-list"), "{e}");
    assert!(e.contains("YARA 4.5.0"), "{e}");
    let other = stub(EngineKind::YaraX, Variant::NotAnEngine);
    let e = probe(EngineKind::YaraX, &other.path).unwrap_err();
    assert!(e.contains("does not look like YARA-X"), "{e}");
    let yara = stub(EngineKind::Yara, Variant::Full);
    let e = engine(&yara, EngineKind::Yara);
    assert_eq!(e.label(), "YARA 4.5.0");
    assert!(e.has("--no-warnings"));
}

// ---------------------------------------------------------------------------
// Choosing an engine at load
// ---------------------------------------------------------------------------

#[test]
fn builtin_refuses_what_it_cannot_evaluate_and_says_an_engine_could() {
    let sel = Selection::with_engines(EngineMode::Builtin, Vec::new());
    let errs = pack(MODULE_RULES, &sel).unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains(":2: `import \"math\"`")
            && e.contains(super::super::parse::NEEDS_ENGINE)),
        "{errs:?}"
    );
    // A file it can evaluate loads as before.
    let p = pack(PLAIN_RULE, &sel).unwrap();
    assert!(file_of(&p).is_builtin());
}

#[test]
fn auto_without_an_engine_loads_the_file_unevaluated_with_its_reasons() {
    let sel = Selection::with_engines(EngineMode::Auto, Vec::new());
    let p = pack(MODULE_RULES, &sel).unwrap();
    let f = file_of(&p);
    let FileEngine::Unevaluated { reasons } = &f.engine else {
        panic!("{:?}", f.engine);
    };
    assert!(
        reasons[0].starts_with("line 2: `import \"math\"`"),
        "{reasons:?}"
    );
    assert!(!reasons[0].contains(super::super::parse::NEEDS_ENGINE));
    // Its rules are known, so ids, severities and policies apply.
    let r = &f.rules[0];
    assert_eq!(r.id, "YARA-STUB-MODULE-RULE");
    assert_eq!((r.severity, r.phase), (Severity::High, Phase::Obfuscation));
    assert!(f.rules[1].private);
    // Every scan says so, in the phases its rules report in.
    let found = unevaluated_findings(&[Arc::clone(&f)], &|_| true);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].rule, crate::scanner::coverage::RULE_PARTIAL);
    assert!(
        found[0].snippet.contains("were not evaluated"),
        "{}",
        found[0].snippet
    );
    assert!(crate::scanner::coverage::is_incomplete(&found));
    assert!(unevaluated_findings(&[f], &|p| p != Phase::Obfuscation).is_empty());
    // A file the built-in engine evaluates is not affected.
    assert!(file_of(&pack(PLAIN_RULE, &sel).unwrap()).is_builtin());
}

#[test]
fn a_rule_yara_itself_refuses_is_refused_whatever_the_engine() {
    let sel = Selection::with_engines(EngineMode::Auto, Vec::new());
    // An undefined string, next to a module: the module alone would load
    // unevaluated; the undefined string refuses the file.
    let src = "import \"pe\"\nrule r {\n strings:\n  $a = \"x\"\n condition:\n  $a and $b\n}\n";
    let errs = pack(src, &sel).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains(":6: string $b is not defined")),
        "{errs:?}"
    );
    // A severity Sigil cannot read is refused for an external file too.
    let src =
        "import \"pe\"\nrule r {\n meta:\n  severity = \"urgent\"\n condition:\n  pe.is_pe\n}\n";
    let errs = pack(src, &sel).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("urgent")), "{errs:?}");
}

#[test]
fn an_explicit_engine_must_be_installed() {
    let sel = Selection::with_engines(EngineMode::YaraX, Vec::new());
    let errs = pack(PLAIN_RULE, &sel).unwrap_err();
    assert!(
        errs[0].contains("--yara-engine yara-x (test): YARA-X (`yr`) is not installed"),
        "{errs:?}"
    );
}

#[cfg(unix)]
#[test]
fn auto_hands_the_file_to_an_installed_engine_and_explicit_modes_send_everything() {
    let yr = stub(EngineKind::YaraX, Variant::Full);
    let yara = stub(EngineKind::Yara, Variant::Full);
    let both = || {
        vec![
            engine(&yr, EngineKind::YaraX),
            engine(&yara, EngineKind::Yara),
        ]
    };
    // auto: YARA-X first; the plain file stays built-in.
    let auto = Selection::with_engines(EngineMode::Auto, both());
    let f = file_of(&pack(MODULE_RULES, &auto).unwrap());
    let FileEngine::External { engine: e, source } = &f.engine else {
        panic!("{:?}", f.engine);
    };
    assert_eq!(e.kind, EngineKind::YaraX);
    assert_eq!(&source[..], MODULE_RULES.as_bytes(), "the exact bytes read");
    assert!(file_of(&pack(PLAIN_RULE, &auto).unwrap()).is_builtin());
    // auto with only classic YARA uses it.
    let only_yara =
        Selection::with_engines(EngineMode::Auto, vec![engine(&yara, EngineKind::Yara)]);
    let f = file_of(&pack(MODULE_RULES, &only_yara).unwrap());
    assert!(
        matches!(&f.engine, FileEngine::External { engine, .. } if engine.kind == EngineKind::Yara)
    );
    // yara: even a file the built-in engine could evaluate.
    let explicit = Selection::with_engines(EngineMode::Yara, both());
    let f = file_of(&pack(PLAIN_RULE, &explicit).unwrap());
    assert!(
        matches!(&f.engine, FileEngine::External { engine, .. } if engine.kind == EngineKind::Yara)
    );
    assert_eq!(f.rules[0].id, "YARA-STUB-PLAIN");
}

#[cfg(unix)]
#[test]
fn the_engine_checks_every_file_of_a_load_and_names_the_bad_one() {
    for kind in [EngineKind::YaraX, EngineKind::Yara] {
        let s = stub(kind, Variant::Full);
        let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, kind)]);
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.yar");
        let bad = dir.path().join("bad.yar");
        // Valid to Sigil's reading (an unknown meta key); the stub refuses
        // the file as the engine would refuse a rule it cannot compile.
        let bad_src = MODULE_RULES.replace(
            "severity = \"high\"",
            "severity = \"high\"\n        note = \"SIGIL_STUB_INVALID\"",
        );
        let a = parse_pack_with(MODULE_RULES.as_bytes(), &good, &sel).unwrap();
        let b = parse_pack_with(bad_src.as_bytes(), &bad, &sel).unwrap();
        let before = s.invocations().len();
        let errs = validate_packs(&[a.clone(), b]).unwrap_err();
        assert_eq!(errs.len(), 1, "{errs:?}");
        let e = &errs[0];
        assert!(
            e.starts_with(&format!("{}: refused by", bad.display())),
            "{e}"
        );
        assert!(e.contains("SIGIL_STUB_INVALID"), "{e}");
        assert!(
            e.contains(&bad.display().to_string()),
            "the real path, not r/<n>.yar: {e}"
        );
        assert!(!e.contains("r/1.yar"), "{e}");
        // One run for the batch, one for the files left once the bad one
        // is out.
        assert_eq!(s.invocations().len() - before, 2, "{:?}", s.invocations());
        assert!(validate_packs(&[a]).is_ok());
    }
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

#[cfg(unix)]
struct Tree {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

#[cfg(unix)]
fn tree(files: &[(&str, &[u8])]) -> Tree {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tree");
    for (name, body) in files {
        let p = root.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    Tree { _dir: dir, root }
}

#[cfg(unix)]
fn disk_units<'a>(t: &Tree, paths: &'a [PathBuf]) -> Vec<Unit<'a>> {
    paths
        .iter()
        .map(|p| Unit {
            rel_path: p
                .strip_prefix(&t.root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            source: Source::Disk(p),
        })
        .collect()
}

#[cfg(unix)]
fn limits() -> Limits {
    Limits {
        total: Some(Duration::from_secs(120)),
        per_file: Some(Duration::from_secs(30)),
        grace: Duration::from_secs(1),
    }
}

#[cfg(unix)]
#[test]
fn matches_become_findings_with_meta_severity_file_and_line() {
    for kind in [EngineKind::YaraX, EngineKind::Yara] {
        let s = stub(kind, Variant::Full);
        let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, kind)]);
        let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
        // Names no shell or line-based output could carry safely.
        let t = tree(&[
            (
                "src/a file; $(touch pwned).txt",
                b"one\ntwo\nthe SIGIL_STUB_MARKER\n",
            ),
            ("line\nbreak.txt", b"SIGIL_STUB_MARKER"),
            ("clean.txt", b"nothing here\n"),
            ("bin/blob.dat", b"\x00\x01SIGIL_STUB_MARKER\x00"),
        ]);
        let mut paths = crate::scanner::collect_files(&t.root);
        paths.sort();
        let mut units = disk_units(&t, &paths);
        let member = b"x\ny\nSIGIL_STUB_MARKER".to_vec();
        units.push(Unit {
            rel_path: "pkg.zip".into(),
            source: Source::Bytes(&member),
        });
        units.push(Unit {
            rel_path: "big.zip".into(),
            source: Source::NotEvaluated("only part of it was kept".into()),
        });
        units.push(Unit {
            rel_path: "consts.pyc".into(),
            source: Source::Excluded,
        });
        let ev = evaluate_with(&[f], &units, &|_| true, None, limits());
        assert!(ev.global.is_empty(), "{:?}", ev.global);
        let by: HashMap<&str, &Vec<crate::scanner::Finding>> = units
            .iter()
            .zip(&ev.per_unit)
            .map(|(u, f)| (u.rel_path.as_str(), f))
            .collect();
        let named = &by["src/a file; $(touch pwned).txt"];
        assert_eq!(named.len(), 1, "{named:?}");
        let x = &named[0];
        assert_eq!(x.rule, "YARA-STUB-MODULE-RULE");
        assert_eq!(x.severity, Severity::High, "from meta");
        assert_eq!(x.phase, Phase::Obfuscation);
        assert_eq!(x.line, Some(3), "line of the earliest match");
        assert!(
            x.snippet.starts_with("Synthetic marker with a module condition: YARA rule Stub_Module_Rule matched $a: SIGIL_STUB_MARKER"),
            "{}",
            x.snippet
        );
        assert!(
            x.snippet.ends_with(&format!(
                "(evaluated by {})",
                match kind {
                    EngineKind::YaraX => "YARA-X 1.20.0",
                    EngineKind::Yara => "YARA 4.5.0",
                }
            )),
            "{}",
            x.snippet
        );
        assert!(!t.root.join("src/pwned").exists() && !Path::new("pwned").exists());
        assert_eq!(by["line\nbreak.txt"][0].line, Some(1));
        assert!(by["clean.txt"].is_empty());
        assert_eq!(by["bin/blob.dat"][0].line, None, "binary: no line");
        assert_eq!(by["pkg.zip"][0].line, Some(3), "an archive member's bytes");
        assert_eq!(
            by["big.zip"][0].rule,
            crate::scanner::coverage::RULE_PARTIAL
        );
        assert!(by["consts.pyc"].is_empty());
        // The private rule never reports; the sentinel never becomes a finding.
        assert!(ev
            .per_unit
            .iter()
            .flatten()
            .all(|f| f.rule != "YARA-STUB-PRIVATE"));
        // How the engine was run: its scan list, namespaces and the
        // sentinel, never a shell.
        let run = s
            .invocations()
            .into_iter()
            .rfind(|l| l.contains("--scan-list"))
            .unwrap();
        assert!(run.contains("f0:r/0.yar sigil:r/sigil.yar list"), "{run}");
        match kind {
            EngineKind::YaraX => {
                assert!(
                    run.starts_with("scan --print-namespace --print-strings=48 --scan-list"),
                    "{run}"
                );
                assert!(run.contains("--timeout=120"), "{run}");
                assert!(run.contains("--relaxed-re-syntax"), "{run}");
            }
            EngineKind::Yara => {
                assert!(run.contains("--print-string-length"), "{run}");
                assert!(run.contains("--timeout=30"), "per-file budget: {run}");
            }
        }
        // Phases a scan filters out are not reported.
        let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
        let ev = evaluate_with(&[f], &units, &|p| p != Phase::Obfuscation, None, limits());
        assert!(ev.per_unit.iter().all(|f| f.is_empty()) && ev.global.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn files_the_engine_did_not_finish_are_reported_not_passed() {
    for kind in [EngineKind::YaraX, EngineKind::Yara] {
        let s = stub(kind, Variant::Full);
        let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, kind)]);
        let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
        let t = tree(&[
            ("fail.txt", b"SIGIL_STUB_FAIL SIGIL_STUB_MARKER"),
            ("ok.txt", b"SIGIL_STUB_MARKER"),
        ]);
        let mut paths = crate::scanner::collect_files(&t.root);
        paths.sort();
        let units = disk_units(&t, &paths);
        let ev = evaluate_with(&[Arc::clone(&f)], &units, &|_| true, None, limits());
        let fail = &ev.per_unit[0];
        assert_eq!(fail.len(), 1, "{fail:?}");
        assert_eq!(fail[0].rule, crate::scanner::coverage::RULE_PARTIAL);
        assert!(fail[0].snippet.contains("fail.txt"), "{}", fail[0].snippet);
        assert!(!fail[0].snippet.contains("t/0"), "{}", fail[0].snippet);
        assert_eq!(ev.per_unit[1][0].rule, "YARA-STUB-MODULE-RULE");
    }
    // Classic YARA's per-file timeout is the scan's per-file budget.
    let s = stub(EngineKind::Yara, Variant::Full);
    let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, EngineKind::Yara)]);
    let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
    let t = tree(&[("slow.txt", b"SIGIL_STUB_SLOW")]);
    let paths = crate::scanner::collect_files(&t.root);
    let ev = evaluate_with(&[f], &disk_units(&t, &paths), &|_| true, None, limits());
    assert_eq!(
        ev.per_unit[0][0].rule,
        crate::scanner::budget::BUDGET_RULE_ID
    );
    // YARA-X's time limit is the whole run's: one finding for the scan.
    let s = stub(EngineKind::YaraX, Variant::Full);
    let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, EngineKind::YaraX)]);
    let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
    let ev = evaluate_with(&[f], &disk_units(&t, &paths), &|_| true, None, limits());
    assert!(ev.per_unit[0].is_empty());
    assert!(
        ev.global[0].snippet.contains("stopped at its time limit"),
        "{}",
        ev.global[0].snippet
    );
}

#[cfg(unix)]
#[test]
fn a_run_past_its_time_limit_is_killed_and_reported_once() {
    let s = stub(EngineKind::YaraX, Variant::Full);
    let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, EngineKind::YaraX)]);
    let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
    for marker in ["SIGIL_STUB_HANG", "SIGIL_STUB_ORPHAN"] {
        let t = tree(&[
            ("a.txt", marker.as_bytes()),
            ("b.txt", b"SIGIL_STUB_MARKER"),
        ]);
        let mut paths = crate::scanner::collect_files(&t.root);
        paths.sort();
        let units = disk_units(&t, &paths);
        let short = Limits {
            total: Some(Duration::from_secs(1)),
            per_file: None,
            grace: Duration::from_secs(1),
        };
        let started = Instant::now();
        let ev = evaluate_with(&[Arc::clone(&f)], &units, &|_| true, None, short);
        // Killed at 2 s; a child left holding the pipe costs at most the
        // drain grace more. Far below the stub's own sleep either way.
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "{marker}: {:?}",
            started.elapsed()
        );
        assert_eq!(ev.global.len(), 1, "{marker}: {:?}", ev.global);
        let g = &ev.global[0];
        assert_eq!(g.rule, crate::scanner::coverage::RULE_PARTIAL);
        assert!(
            g.snippet.contains("not evaluated on 2 of 2 file(s)"),
            "{}",
            g.snippet
        );
        assert!(
            g.snippet.contains("stopped at its time limit of 1 s"),
            "{}",
            g.snippet
        );
        assert!(
            ev.per_unit.iter().all(|f| f.is_empty()),
            "no per-file noise, no partial matches"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_engine_inside_the_scanned_tree_is_never_run() {
    let s = stub(EngineKind::YaraX, Variant::Full);
    let sel = Selection::with_engines(EngineMode::Auto, vec![engine(&s, EngineKind::YaraX)]);
    let f = file_of(&pack(MODULE_RULES, &sel).unwrap());
    let root = s.bin.parent().unwrap().to_path_buf();
    let target = root.join("target.txt");
    std::fs::write(&target, "SIGIL_STUB_MARKER").unwrap();
    let before = s.invocations().len();
    let units = vec![Unit {
        rel_path: "target.txt".into(),
        source: Source::Disk(&target),
    }];
    let ev = evaluate_with(&[f], &units, &|_| true, Some(&root), limits());
    assert_eq!(s.invocations().len(), before, "the stub was not run");
    assert!(
        ev.global[0].snippet.contains("inside the scanned tree"),
        "{}",
        ev.global[0].snippet
    );
}

#[cfg(unix)]
#[test]
fn the_digest_changes_with_the_engine() {
    // A cached result is reused only under the same digest: the same rule
    // under another engine, or under none, is other detection logic.
    let s = stub(EngineKind::Yara, Variant::Full);
    let e = || vec![engine(&s, EngineKind::Yara)];
    let digest = |src: &str, sel: &Selection| {
        let p = pack(src, sel).unwrap();
        crate::corpus::compiled::CompiledCorpus::from_packs(&[p.pack]).digest()
    };
    let builtin = Selection::with_engines(EngineMode::Builtin, Vec::new());
    let external = Selection::with_engines(EngineMode::Yara, e());
    assert_eq!(digest(PLAIN_RULE, &builtin), digest(PLAIN_RULE, &builtin));
    assert_ne!(digest(PLAIN_RULE, &builtin), digest(PLAIN_RULE, &external));
    let none = Selection::with_engines(EngineMode::Auto, Vec::new());
    let auto = Selection::with_engines(EngineMode::Auto, e());
    assert_ne!(digest(MODULE_RULES, &none), digest(MODULE_RULES, &auto));
}

#[test]
fn lines_are_counted_once_for_all_of_a_units_matches() {
    let text = b"a\nb\nc\nd\n";
    let lines = lines_at(&Source::Bytes(text), &[6, 0, 2, 6, 100]);
    assert_eq!(
        (lines[&0], lines[&2], lines[&6], lines[&100]),
        (1, 2, 4, 5),
        "{lines:?}"
    );
    assert!(
        lines_at(&Source::Bytes(b"a\n\x00b"), &[3]).is_empty(),
        "binary"
    );
    // A file over the content-scan size is streamed in 1 MB chunks: lines
    // stay right across chunk boundaries.
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.txt");
    let body: Vec<u8> = b"x\n".repeat(5_500_000);
    std::fs::write(&big, &body).unwrap();
    let offsets = [0u64, 1_048_575, 1_048_576, 1_048_577, 10_999_998];
    let lines = lines_at(&Source::Disk(&big), &offsets);
    for o in offsets {
        assert_eq!(lines[&o], (o / 2) as usize + 1, "offset {o}");
    }
    let small = dir.path().join("small.txt");
    std::fs::write(&small, b"one\ntwo\nthree\n").unwrap();
    assert_eq!(lines_at(&Source::Disk(&small), &[8])[&8], 3);
}
