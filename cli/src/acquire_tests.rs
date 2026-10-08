//! Unit tests for `acquire.rs`: which specs `sigil pip` / `sigil npm` hand
//! to pip and npm, and the exact arguments they run with.

use super::*;
use std::path::PathBuf;

fn kind(r: Result<(), SpecError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(SpecError::Unusable(_)) => "unusable",
        Err(SpecError::NotRegistry(_)) => "not-registry",
        Err(SpecError::LocalPath { .. }) => "local-path",
        Err(SpecError::Alias(_)) => "alias",
        Err(SpecError::Malformed(_)) => "malformed",
    }
}

fn pip(spec: &str) -> &'static str {
    kind(check_spec(Manager::Pip, spec, false))
}

fn npm(spec: &str) -> &'static str {
    kind(check_spec(Manager::Npm, spec, false))
}

fn strings(v: &[OsString]) -> Vec<String> {
    v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
}

// ---------------------------------------------------------------------------
// pip specs
// ---------------------------------------------------------------------------

#[test]
fn pip_accepts_registry_requirements() {
    for spec in [
        "requests",
        "a",
        "Django",
        "zope.interface",
        "foo_bar",
        "foo-bar",
        "requests==2.32.3",
        "requests>=2,<3",
        "requests >= 2 , < 3",
        "requests[socks]",
        "requests[socks,security]>=2.0",
        "requests[ socks ]",
        "requests[]",
        "pkg===1.0",
        "pkg~=1.4",
        "pkg==1.*",
        "pkg!=1.0",
        "pkg==1!2.0",
        "pkg==1.0+local.1",
        "pkg==1.0rc1",
        "pkg==1.0.post1.dev2",
        // PEP 508's parenthesised specifiers, and trailing whitespace (pip
        // strips the requirement).
        "requests (>=2)",
        "foo(>=1)",
        "requests[socks] (>=2, <3)",
        "requests ",
    ] {
        assert_eq!(pip(spec), "ok", "{spec}");
    }
}

#[test]
fn pip_refuses_what_pip_would_build_or_run() {
    for spec in [
        // Local paths: pip builds a project directory or source archive.
        "./pkg",
        "../pkg",
        ".",
        "/abs/pkg",
        "pkg/sub",
        "~/pkg",
        "pkg\\sub",
        // Names pip reads as an archive in the working directory.
        "markerpkg.tgz",
        "pkg.tar.gz",
        "PKG.TAR.GZ",
        "pkg.tar",
        "pkg.tar.bz2",
        "pkg.tar.xz",
        "pkg.zip",
        "pkg.whl",
        "pkg.whl[extra]",
        "pkg==1.0.tar",
        // pip strips the requirement before it looks at the suffix.
        "x==1.zip ",
        "x ==1.tar.gz ",
        "x[e]==1.zip ",
    ] {
        assert_eq!(pip(spec), "local-path", "{spec}");
    }
    for spec in [
        // A drive letter reads as a URL scheme.
        "C:\\pkg",
        // URLs and VCS references.
        "https://example.invalid/pkg-1.0.tar.gz",
        "http://example.invalid/pkg",
        "file:///tmp/pkg-1.0.tar.gz",
        "git+https://github.com/owner/repo",
        "git+ssh://git@github.com/owner/repo.git",
        "hg+https://example.invalid/repo",
        "svn+https://example.invalid/repo",
        "bzr+https://example.invalid/repo",
        // PEP 508 direct references.
        "pkg @ https://example.invalid/pkg-1.0.tar.gz",
        "pkg@file:///tmp/pkg",
        "pkg @ git+https://github.com/owner/repo",
    ] {
        assert_eq!(pip(spec), "not-registry", "{spec}");
    }
}

#[test]
fn pip_refuses_malformed_requirements() {
    for spec in [
        "requests>>2",
        "requests==",
        "requests 2",
        "requests>=2 <3",
        "requests==2.0==3.0",
        "requests; os_name=='nt'",
        "requests==2; python_version<'3.8'",
        "[socks]",
        "_foo",
        "foo-",
        "foo[",
        "foo[bar",
        "foo[-x]",
        " requests",
        "requests,",
        // A version starts with a letter or digit.
        "x==--allow-build-scripts",
        "x== --allow-build-scripts",
        "x>=-1",
        "x==*",
        // Not PEP 440 versions, or not for that operator.
        "pkg==1.0-foo",
        "pkg~=1",
        "pkg==1.0rc1.*",
        // Unbalanced or trailing text around parentheses.
        "foo (>=1",
        "foo (>=1) extra",
        "foo (>=1))",
    ] {
        assert_eq!(pip(spec), "malformed", "{spec}");
    }
}

#[test]
fn never_passes_an_option_or_an_empty_or_control_spec() {
    for m in [Manager::Pip, Manager::Npm] {
        for spec in [
            "",
            "   ",
            "-r",
            "-e.",
            " -e .",
            "--index-url=https://example.invalid/simple",
            "--allow-build-scripts",
            "foo\nbar",
            "foo\0",
            "foo\tbar\r",
        ] {
            for allow in [false, true] {
                assert_eq!(
                    kind(check_spec(m, spec, allow)),
                    "unusable",
                    "{m:?} {spec:?} allow={allow}"
                );
            }
        }
    }
}

#[test]
fn opt_in_accepts_what_the_default_refuses() {
    for spec in [
        "./pkg",
        "git+https://github.com/owner/repo",
        "pkg @ https://example.invalid/pkg.tar.gz",
        "requests>>2",
    ] {
        assert_ne!(pip(spec), "ok", "{spec}");
        assert!(check_spec(Manager::Pip, spec, true).is_ok(), "{spec}");
    }
    for spec in [
        "./dir",
        "owner/repo",
        "github:owner/repo",
        "x.tgz",
        "foo@npm:bar",
    ] {
        assert_ne!(npm(spec), "ok", "{spec}");
        assert!(check_spec(Manager::Npm, spec, true).is_ok(), "{spec}");
    }
}

#[test]
fn pip_version_flag_composes_and_is_checked() {
    assert_eq!(pip_spec("requests", None), "requests");
    assert_eq!(pip_spec("requests", Some("2.32.3")), "requests==2.32.3");
    assert_eq!(pip(&pip_spec("requests", Some("2.32.3"))), "ok");
    assert_eq!(pip(&pip_spec("requests[socks]", Some("2.32.3"))), "ok");
    // A specifier on the name and -V cannot both apply.
    assert_eq!(pip(&pip_spec("requests>=2", Some("2.32.3"))), "malformed");
    // -V cannot smuggle in a direct reference or a marker.
    assert_eq!(
        pip(&pip_spec(
            "requests",
            Some("2 @ https://example.invalid/x.tar.gz")
        )),
        "not-registry"
    );
    assert_eq!(
        pip(&pip_spec("requests", Some("2; os_name=='nt'"))),
        "malformed"
    );
    assert_eq!(pip(&pip_spec("requests", Some(""))), "malformed");
}

// ---------------------------------------------------------------------------
// npm specs
// ---------------------------------------------------------------------------

#[test]
fn npm_accepts_registry_specs() {
    for spec in [
        "left-pad",
        "left-pad@1.3.0",
        "@types/node",
        "@types/node@20.1.0",
        "@scope/foo.bar",
        "foo@latest",
        "foo@next",
        "foo@>=1 <2",
        "foo@^1.2.3",
        "foo@~1.2",
        "foo@1.x || 2.x",
        "foo@1.2.3 - 2.0.0",
        "foo@>=1.0.0-rc.1 <2",
        "foo@*",
        "foo@=1.0.0",
        "foo@1.0.0-rc.1",
        "foo@1.0.0+build.5",
        "JSONStream",
        "lodash.merge",
        "foo_bar",
        "foo~bar",
        // A tag that looks like a host is still a registry tag
        // (npm-package-arg: type "tag").
        "foo@github.com",
        // A scoped name is never read as a tarball path, and `.targz`
        // is one character short of `isFileType`'s `.tar?gz`.
        "@scope/foo.tgz",
        "@scope/foo.tar.gz@1.0.0",
        "foo.targz",
    ] {
        assert_eq!(npm(spec), "ok", "{spec}");
    }
}

#[test]
fn npm_refuses_what_npm_would_build_or_run() {
    for spec in [
        // Local directories and files.
        ".",
        "./dir",
        "../dir",
        "/abs/dir",
        "~/dir",
        ".foo",
        "dir\\sub",
        "file:../dir",
        "file:pkg.tgz",
        "FILE:../dir",
        "npmdir/",
        "foo@.1",
        // Tarball paths, as npm-package-arg's `isFileType` reads them: its
        // `.` in `tar.gz` matches any character.
        "pkg.tgz",
        "pkg.tar.gz",
        "pkg.TAR",
        "foo@1.0.tgz",
        "foo.tar-gz",
        "foo@1.tar-gz",
        "foo@1.tarxgz",
        "FOO.TARXGZ",
        "@scope/foo@1.tgz",
    ] {
        assert_eq!(npm(spec), "local-path", "{spec}");
    }
    for spec in [
        // A drive letter reads as a URL scheme.
        "C:\\dir",
        // Tarball URLs.
        "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
        "http://example.invalid/x.tgz",
        // Git specs and hosted-git shorthands.
        "owner/repo",
        "github:owner/repo",
        "gitlab:owner/repo",
        "bitbucket:owner/repo",
        "gist:abc123",
        "git://github.com/owner/repo.git",
        "git+https://github.com/owner/repo.git",
        "git+ssh://git@github.com/owner/repo.git",
        "git+file:///tmp/repo",
        "git@github.com:owner/repo.git",
        "owner/repo#main",
        "foo#main",
        "foo@github:owner/repo",
        "foo@owner/repo",
        "foo@git+https://github.com/owner/repo.git",
        "foo@./dir",
        "@scope/name/sub",
    ] {
        assert_eq!(npm(spec), "not-registry", "{spec}");
    }
}

#[test]
fn npm_refuses_aliases_and_names_their_target() {
    for (spec, target) in [
        ("foo@npm:bar", "bar"),
        ("foo@npm:bar@1.0.0", "bar@1.0.0"),
        ("foo@NPM:owner/repo", "owner/repo"),
        ("@scope/foo@npm:bar", "bar"),
    ] {
        let err = check_spec(Manager::Npm, spec, false).unwrap_err();
        assert_eq!(err, SpecError::Alias(target.to_string()), "{spec}");
        let msg = refusal(Manager::Npm, spec, &err);
        assert!(msg.contains(&format!("`sigil npm {target}`")), "{msg}");
        assert!(!msg.contains("prepare script"), "{msg}");
        assert!(check_spec(Manager::Npm, spec, true).is_ok(), "{spec}");
    }
}

#[test]
fn npm_refuses_malformed_specs() {
    for spec in [
        "@scope",
        "@/name",
        "@scope/",
        "_foo",
        "foo@",
        "foo@ 1",
        "foo@1@2",
        "foo bar",
        "Foo!",
        "foo@1.0.0!",
        "foo@$(x)",
        // A word of the range that reads as an option is not a range.
        "foo@1 --allow-build-scripts",
        "foo@-1",
        "foo@>=1 -x",
    ] {
        assert_eq!(npm(spec), "malformed", "{spec}");
    }
}

#[test]
fn npm_version_flag_composes_and_is_checked() {
    assert_eq!(npm_spec("left-pad", None), "left-pad");
    assert_eq!(npm_spec("left-pad", Some("1.3.0")), "left-pad@1.3.0");
    assert_eq!(npm_spec("@types/node", Some("20")), "@types/node@20");
    assert_eq!(npm(&npm_spec("@types/node", Some("20"))), "ok");
    assert_eq!(npm(&npm_spec("left-pad@1.3.0", Some("1.3.0"))), "malformed");
    assert_eq!(npm(&npm_spec("foo", Some("npm:bar"))), "alias");
    assert_eq!(
        npm(&npm_spec("foo", Some("github:owner/repo"))),
        "not-registry"
    );
    assert_eq!(npm(&npm_spec("foo", Some("./dir"))), "not-registry");
}

// ---------------------------------------------------------------------------
// The exact argv
// ---------------------------------------------------------------------------

#[test]
fn pip_download_args_default_is_wheel_only_and_ends_options() {
    let dest = PathBuf::from("/q/abc123");
    assert_eq!(
        strings(&pip_download_args(&dest, "requests==2.32.3", false)),
        [
            "download",
            "--no-deps",
            "--only-binary=:all:",
            "--dest",
            "/q/abc123",
            "--",
            "requests==2.32.3",
        ]
    );
}

#[test]
fn pip_download_args_opt_in_drops_only_binary() {
    let dest = PathBuf::from("/q/abc123");
    assert_eq!(
        strings(&pip_download_args(&dest, "./pkg", true)),
        [
            "download",
            "--no-deps",
            "--dest",
            "/q/abc123",
            "--",
            "./pkg"
        ]
    );
}

#[test]
fn npm_pack_args_default_ignores_scripts_and_ends_options() {
    let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    assert_eq!(
        strings(&npm_pack_args(url, false, None)),
        ["pack", "--ignore-scripts", "--", url]
    );
}

#[test]
fn npm_pack_args_opt_in_drops_ignore_scripts_and_packs_into_quarantine() {
    let dest = PathBuf::from("/q/abc123");
    assert_eq!(
        strings(&npm_pack_args("./dir", true, Some(&dest))),
        ["pack", "--pack-destination", "/q/abc123", "--", "./dir"]
    );
}

#[test]
fn resolution_args_end_options_before_the_spec() {
    assert_eq!(
        strings(&pip_index_args("requests")),
        ["index", "versions", "--pre", "--", "requests"]
    );
    assert_eq!(
        strings(&npm_view_args("left-pad@^1")),
        [
            "view",
            "--json",
            "--",
            "left-pad@^1",
            "name",
            "version",
            "dist.tarball",
            "dist.integrity",
            "dist.shasum",
            "deprecated",
            "dist-tags.latest",
        ]
    );
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[test]
fn only_a_registry_refusal_offers_the_opt_in() {
    let npm_git = check_spec(Manager::Npm, "owner/repo", false).unwrap_err();
    let msg = refusal(Manager::Npm, "owner/repo", &npm_git);
    assert!(msg.contains("owner/repo shorthand"), "{msg}");
    assert!(msg.contains("prepare script"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");

    let pip_url = check_spec(Manager::Pip, "git+https://example.invalid/r", false).unwrap_err();
    let msg = refusal(Manager::Pip, "git+https://example.invalid/r", &pip_url);
    assert!(msg.contains("VCS reference"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");

    for (m, spec) in [
        (Manager::Pip, "-r"),
        (Manager::Pip, "requests>>2"),
        (Manager::Npm, "foo@1@2"),
    ] {
        let err = check_spec(m, spec, false).unwrap_err();
        let msg = refusal(m, spec, &err);
        assert!(!msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");
    }
}

#[test]
fn a_local_path_refusal_points_at_sigil_scan() {
    // What pip or npm would read is what `sigil scan` should read: it
    // scans a file or directory where it is and runs nothing from it. The
    // opt-in is not offered: for a pip directory it builds and then saves
    // nothing to scan, and an archive needs no download at all.
    for (m, spec, path) in [
        (Manager::Pip, "./pyproj", "./pyproj"),
        (
            Manager::Pip,
            "pkg-1.0-py3-none-any.whl",
            "pkg-1.0-py3-none-any.whl",
        ),
        (Manager::Pip, "pkg.whl[extra]", "pkg.whl"),
        (Manager::Npm, "./dir", "./dir"),
        (Manager::Npm, "npmdir/", "npmdir/"),
        (Manager::Npm, "pkg-1.0.0.tgz", "pkg-1.0.0.tgz"),
        (Manager::Npm, "foo@1.tgz", "1.tgz"),
        (Manager::Npm, "file:../pkg", "../pkg"),
        (Manager::Npm, "file:///tmp/pkg", "/tmp/pkg"),
    ] {
        let err = check_spec(m, spec, false).unwrap_err();
        let msg = refusal(m, spec, &err);
        assert!(
            msg.contains(&format!("`sigil scan {path}`")),
            "{spec}: {msg}"
        );
        assert!(msg.contains("runs nothing"), "{msg}");
        assert!(!msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");
        assert!(!msg.contains("build backend"), "{msg}");
    }
}

#[test]
fn the_opt_in_warning_says_code_runs_before_the_scan() {
    for m in [Manager::Pip, Manager::Npm] {
        let w = opt_in_warning(m, "x");
        assert!(w.contains("BEFORE Sigil scans"), "{w}");
        assert!(w.contains("on this machine"), "{w}");
    }
    let pinned = pip_wheel_only_hint("docopt==0.6.2", None);
    assert!(pinned.contains(ALLOW_BUILD_SCRIPTS), "{pinned}");
    assert!(pinned.contains("If `docopt==0.6.2` exists"), "{pinned}");
    assert!(!pinned.contains("that version of it"), "{pinned}");
    let resolved = pip_wheel_only_hint("markerpkg", Some("markerpkg==2.0"));
    assert!(
        resolved.contains("`markerpkg==2.0` is the release"),
        "{resolved}"
    );
    assert!(resolved.contains("older release"), "{resolved}");
}

#[test]
fn the_wheel_hint_follows_only_a_missing_distribution() {
    assert!(pip_found_no_distribution(
        "ERROR: Could not find a version that satisfies the requirement x==1 (from versions: none)\n\
         ERROR: No matching distribution found for x==1\n"
    ));
    assert!(!pip_found_no_distribution(
        "ERROR: Could not install packages due to an OSError: [Errno 28] No space left on device"
    ));
}

// ---------------------------------------------------------------------------
// pip: environment, config, resolution
// ---------------------------------------------------------------------------

#[test]
fn pip_env_requirement_settings_are_removed_however_spelled() {
    let vars = [
        ("PIP_CONSTRAINT", "/c.txt"),
        ("PIP_Requirement", "/r.txt"),
        ("PIP_EDITABLE", "."),
        ("PIP___CONSTRAINT", "/c.txt"),
        ("PIP_INDEX_URL", "https://example.invalid/simple"),
        ("PIP_NO_BINARY", ":all:"),
        ("PIP_SRC", "/src"),
        ("pip_constraint", "/c.txt"),
        ("MY_PIP_CONSTRAINT", "/c.txt"),
        ("PIP_CONSTRAINTS", "/c.txt"),
    ]
    .map(|(k, v)| (OsString::from(k), OsString::from(v)));
    let removed: Vec<String> = pip_env_to_remove(vars)
        .into_iter()
        .map(|k| k.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        removed,
        [
            "PIP_CONSTRAINT",
            "PIP_Requirement",
            "PIP_EDITABLE",
            "PIP___CONSTRAINT"
        ]
    );
}

#[test]
fn pip_config_requirement_settings_are_found_where_download_reads_them() {
    let list = "\
:env:.cert='/etc/ssl/ca.pem'
:env:.config-file='/home/u/pip.conf'
download.requirement='/x/req.txt'
global.constraint='/x/c.txt'
global.index-url='https://example.invalid/simple'
install.requirement='/x/only-for-install.txt'
install.editable='.'
global.Editable='/x/proj'
";
    assert_eq!(
        pip_config_added_requirements(list),
        [
            "download.requirement",
            "global.constraint",
            "global.editable"
        ]
    );
    assert!(pip_config_added_requirements(":env:.cert='/etc/ssl/ca.pem'\n").is_empty());
    assert_eq!(
        pip_config_added_requirements(":env:.constraint='/x'\n"),
        [":env:.constraint"]
    );
    let msg = pip_config_refusal(&["download.requirement".into()]);
    assert!(msg.contains("download.requirement"), "{msg}");
    assert!(msg.contains("PIP_CONFIG_FILE=/dev/null"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");
}

#[test]
fn pip_config_pre_lets_prereleases_in() {
    assert!(pip_config_allows_prereleases("global.pre='true'\n"));
    assert!(pip_config_allows_prereleases(":env:.pre='1'\n"));
    assert!(pip_config_allows_prereleases("install.pre='yes'\n"));
    assert!(!pip_config_allows_prereleases("global.pre='false'\n"));
    assert!(!pip_config_allows_prereleases("download.pre='true'\n"));
    assert!(!pip_config_allows_prereleases(""));
}

#[test]
fn pip_index_versions_output_is_read() {
    let out = "markerpkg (2.0)\nAvailable versions: 2.0, 1.0, 1.0rc1\n  INSTALLED: 1.0\n";
    assert_eq!(
        parse_pip_index_versions(out),
        Some(vec!["2.0".to_string(), "1.0".into(), "1.0rc1".into()])
    );
    assert_eq!(parse_pip_index_versions("markerpkg (2.0)\n"), None);
    assert_eq!(parse_pip_index_versions("Available versions: \n"), None);
}

#[test]
fn an_unpinned_spec_resolves_to_what_pip_install_would_pick() {
    let available: Vec<String> = ["2.0", "1.5", "1.0", "3.0b1"].map(String::from).to_vec();
    let pick = |spec: &str| {
        pip_requirement(spec)
            .unwrap()
            .best_match(&available, false)
            .map(str::to_string)
    };
    assert_eq!(pick("markerpkg").as_deref(), Some("2.0"));
    assert_eq!(pick("markerpkg[extra]").as_deref(), Some("2.0"));
    assert_eq!(pick("markerpkg<2").as_deref(), Some("1.5"));
    assert_eq!(pick("markerpkg (>=1, <2)").as_deref(), Some("1.5"));
    assert_eq!(pick("markerpkg>=3.0b1").as_deref(), Some("3.0b1"));
    assert_eq!(pick("markerpkg>4").as_deref(), None);
    let req = pip_requirement("markerpkg").unwrap();
    assert_eq!(req.best_match(&available, true), Some("3.0b1"));
    assert_eq!(req.name, "markerpkg");
    assert!(!req.is_pinned());
    assert!(pip_requirement("markerpkg==1.0").unwrap().is_pinned());
    assert!(pip_requirement("markerpkg===1.0").unwrap().is_pinned());
    assert!(!pip_requirement("markerpkg==1.*").unwrap().is_pinned());
    assert!(!pip_requirement("markerpkg>=1,!=1.5").unwrap().is_pinned());
}

// ---------------------------------------------------------------------------
// npm: resolution and the tarball URL
// ---------------------------------------------------------------------------

fn release(version: &str, deprecated: bool, latest: &str) -> NpmRelease {
    NpmRelease {
        name: "x".into(),
        version: version.into(),
        tarball: format!("https://registry.npmjs.org/x/-/x-{version}.tgz"),
        integrity: None,
        shasum: None,
        deprecated,
        latest: Some(latest.into()),
    }
}

#[test]
fn npm_view_output_is_read() {
    let one = r#"{"name":"is-number","version":"7.0.0","dist.tarball":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","dist.integrity":"sha512-abc==","dist.shasum":"0123","dist-tags.latest":"7.0.0"}"#;
    let r = parse_npm_view(one).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].id(), "is-number@7.0.0");
    assert!(!r[0].deprecated);
    assert_eq!(r[0].latest.as_deref(), Some("7.0.0"));
    assert_eq!(r[0].integrity.as_deref(), Some("sha512-abc=="));
    assert_eq!(r[0].shasum.as_deref(), Some("0123"));

    let many = r#"[
      {"name":"left-pad","version":"1.2.0","dist.tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz","deprecated":"use padStart","dist-tags.latest":"1.3.0"},
      {"name":"left-pad","version":"1.3.0","dist.tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","deprecated":"","dist-tags.latest":"1.3.0"}
    ]"#;
    let r = parse_npm_view(many).unwrap();
    assert_eq!(r.len(), 2);
    assert!(r[0].deprecated);
    assert!(!r[1].deprecated, "an empty deprecation is none");

    for bad in [
        "",
        "not json",
        "[]",
        "\"1.0.0\"",
        r#"{"error":{"code":"E404"}}"#,
        r#"{"name":"x","version":"1.0.0"}"#,
    ] {
        assert!(parse_npm_view(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_range_picks_latest_then_the_highest_non_deprecated() {
    let only = [release("1.0.0", true, "2.0.0")];
    assert_eq!(pick_npm_release(&only).unwrap().version, "1.0.0");

    let with_latest = [
        release("1.0.0", false, "1.1.0"),
        release("1.1.0", false, "1.1.0"),
        release("1.2.0-rc.1", false, "1.1.0"),
    ];
    assert_eq!(pick_npm_release(&with_latest).unwrap().version, "1.1.0");

    let latest_outside = [
        release("1.9.0", false, "2.0.0"),
        release("1.10.0", false, "2.0.0"),
        release("1.11.0", true, "2.0.0"),
    ];
    assert_eq!(pick_npm_release(&latest_outside).unwrap().version, "1.10.0");

    let all_deprecated = [
        release("1.2.0", true, "1.3.0"),
        release("1.3.0", true, "1.3.0"),
    ];
    assert_eq!(pick_npm_release(&all_deprecated).unwrap().version, "1.3.0");
    assert!(pick_npm_release(&[]).is_none());
}

#[test]
fn semver_precedence() {
    use std::cmp::Ordering::*;
    for (a, b, want) in [
        ("1.10.0", "1.9.0", Greater),
        ("1.0.0", "1.0.0-rc.1", Greater),
        ("1.0.0-rc.2", "1.0.0-rc.10", Less),
        ("1.0.0-alpha", "1.0.0-alpha.1", Less),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta", Less),
        ("1.0.0-beta", "1.0.0-alpha", Greater),
        ("1.0.0+build.1", "1.0.0+build.2", Equal),
        ("2.0.0", "not-a-version", Greater),
    ] {
        assert_eq!(semver_cmp(a, b), want, "{a} vs {b}");
    }
}

#[test]
fn only_a_plain_http_tarball_url_is_packed() {
    // Each URL below was classified with npm 10.9.7's own npm-package-arg
    // (`npa(url).type`): `remote` for the first list, `git` for the second
    // except the two plain-http ones marked there.
    for ok in [
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "http://127.0.0.1:4873/x/-/x-1.0.0.tgz",
        "https://npm.pkg.github.com/download/@o/x/1.0.0/abc",
        "https://codeload.github.com/o/r/tar.gz/v1",
        // Hosted-git hosts serve downloads too: hosted-git-info reads these
        // paths as no repository, so npm fetches them as tarballs.
        "https://gitlab.com/api/v4/projects/123/packages/npm/@acme/pkg/-/@acme/pkg-1.0.0.tgz",
        "https://gitlab.com/api/v4/packages/npm/@acme/pkg/-/@acme/pkg-1.0.0.tgz",
        "https://gitlab.com/o/r/repository/archive.tar.gz?ref=v1",
        "https://gitlab.com/onlyone",
        "https://github.com/owner/repo/releases/download/v1.0.0/pkg-1.0.0.tgz",
        "https://github.com/owner/repo/archive/refs/tags/v1.tar.gz",
        "https://github.com/owner",
        "https://github.com/owner/.git",
        "https://bitbucket.org/o/r/get/v1.tar.gz",
        "https://git.sr.ht/~o/r/archive/v1.tar.gz",
        "https://gist.github.com/o/abc/raw/file.tgz",
        "https://gist.github.com/",
        "https://gitlab.com/o/r/",
        "https://gitlab.com/o/-/r",
        "https://github.com/o/r/blob/main/x.tgz",
        "https://github.com//r",
    ] {
        assert!(check_npm_tarball_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "git+file:///tmp/repo",
        "git+https://github.com/o/r.git",
        "git://github.com/o/r.git",
        "ssh://git@example.invalid/o/r.git",
        "file:/tmp/dir",
        "file:///tmp/x.tgz",
        // Repositories, as hosted-git-info reads them.
        "https://github.com/o/r.tgz",
        "https://github.com/o/r",
        "https://github.com/o/r/",
        "https://github.com/o/r.git",
        "https://github.com/o/r/tree/main",
        "https://github.com/o/r#v1.0.0",
        "https://www.github.com/o/r",
        "http://github.com/o/r",
        "https://user:pass@github.com/o/r",
        "https://GitLab.com/o/r.tgz",
        "https://gitlab.com/group/sub/r",
        "https://bitbucket.org/o/r",
        "https://bitbucket.org/o/r/src/main",
        "https://gist.github.com/abc",
        "https://gist.github.com/o/abc",
        "https://git.sr.ht/~o/r",
        "https://gitlab.com/o/r.git",
        "https://www.gitlab.com/o/r",
        "https://gist.github.com/.git",
        "https://bitbucket.org/o/r.git",
        "https://git.sr.ht/~o/r.git",
        "https://github.com/o/r/tree",
        "https://github.com/o/r?x=1",
        // npm downloads these (hosted-git-info takes plain http only for
        // GitHub); refused anyway, which is never less safe.
        "http://gitlab.com/o/r",
        "http://bitbucket.org/o/r",
        "github:o/r",
        "o/r",
        "not a url",
    ] {
        assert!(check_npm_tarball_url(bad).is_err(), "{bad}");
    }
    let why = check_npm_tarball_url("git+file:///tmp/repo").unwrap_err();
    let msg = npm_tarball_refusal("markreg@1.0.0", &why);
    assert!(msg.contains("markreg@1.0.0"), "{msg}");
    assert!(msg.contains("prepare script"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");
    let why = check_npm_tarball_url("https://gitlab.com/o/r.tgz").unwrap_err();
    assert!(why.contains("git repository on gitlab.com"), "{why}");
}

#[test]
fn the_packed_tarball_must_match_the_registry_integrity() {
    let data: &[u8] = b"tarball bytes";
    // Digests of `data` (openssl dgst), as npm writes them.
    let sha512 = "sha512-B8POa95m3GJFaMFp1MsqEvsPvqIJoPCLbH2k06iUbfIjuNSkCqtohW801kLScBVmPs4lTysbJEGKUysB9lnEYw==";
    let sha1_hex = "af2a34236064c58f7672bd0954ec725ad3de6a4e";
    let sha1_sri = "sha1-ryo0I2BkxY92cr0JVOxyWtPeak4=";
    let mismatch = "sha512-AAAA";

    assert!(check_npm_integrity(data, Some(sha512), None).is_ok());
    assert!(check_npm_integrity(data, Some(&format!("{sha512}?opt")), None).is_ok());
    assert!(check_npm_integrity(data, Some(sha1_sri), None).is_ok());
    assert!(check_npm_integrity(data, None, Some(sha1_hex)).is_ok());
    assert!(check_npm_integrity(data, Some(""), Some(&sha1_hex.to_uppercase())).is_ok());
    // Any one hash of the strongest algorithm listed is enough.
    assert!(check_npm_integrity(data, Some(&format!("{mismatch} {sha512}")), None).is_ok());

    for (integrity, shasum) in [
        (Some(mismatch), Some(sha1_hex)),
        // The strongest algorithm decides: a matching sha1 next to a
        // wrong sha512 is not enough.
        (Some(&*format!("{sha1_sri} {mismatch}")), None),
        (None, Some("0000000000000000000000000000000000000000")),
        (Some("md5-abc"), None),
        (None, None),
        (Some(" "), Some("")),
    ] {
        let err = check_npm_integrity(data, integrity, shasum).unwrap_err();
        assert!(!err.is_empty());
    }
    let err = check_npm_integrity(data, Some(mismatch), None).unwrap_err();
    assert!(err.contains(sha512), "{err}");
    let msg = npm_integrity_refusal("plainpkg@1.0.0", &err);
    assert!(msg.contains("plainpkg@1.0.0"), "{msg}");
    assert!(msg.contains("EINTEGRITY"), "{msg}");
}
