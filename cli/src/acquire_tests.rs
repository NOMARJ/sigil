//! Unit tests for `acquire.rs`: which specs `sigil pip` / `sigil npm` hand
//! to pip and npm, and the exact arguments they run with.

use super::*;
use std::path::PathBuf;

fn kind(r: Result<(), SpecError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(SpecError::Unusable(_)) => "unusable",
        Err(SpecError::NotRegistry(_)) => "not-registry",
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
        "C:\\pkg",
        "pkg\\sub",
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
        "C:\\dir",
        "file:../dir",
        "file:pkg.tgz",
        "FILE:../dir",
        // Tarballs, by path or URL.
        "pkg.tgz",
        "pkg.tar.gz",
        "pkg.TAR",
        "foo@1.0.tgz",
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
        "foo@.1",
        "@scope/name/sub",
        "npmdir/",
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
    let not_registry = check_spec(Manager::Pip, "./pkg", false).unwrap_err();
    let msg = refusal(Manager::Pip, "./pkg", &not_registry);
    assert!(msg.contains("local path"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");

    let npm_git = check_spec(Manager::Npm, "owner/repo", false).unwrap_err();
    let msg = refusal(Manager::Npm, "owner/repo", &npm_git);
    assert!(msg.contains("owner/repo shorthand"), "{msg}");
    assert!(msg.contains("prepare script"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");

    // A trailing slash is a directory, not owner/repo.
    let dir = check_spec(Manager::Npm, "npmdir/", false).unwrap_err();
    let msg = refusal(Manager::Npm, "npmdir/", &dir);
    assert!(msg.contains("local path"), "{msg}");
    assert!(!msg.contains("shorthand"), "{msg}");

    // A relative path is read from the caller's directory with the opt-in.
    let rel = check_spec(Manager::Npm, "./dir", false).unwrap_err();
    let msg = refusal(Manager::Npm, "./dir", &rel);
    assert!(msg.contains("current directory"), "{msg}");

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
        deprecated,
        latest: Some(latest.into()),
    }
}

#[test]
fn npm_view_output_is_read() {
    let one = r#"{"name":"is-number","version":"7.0.0","dist.tarball":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","dist-tags.latest":"7.0.0"}"#;
    let r = parse_npm_view(one).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].id(), "is-number@7.0.0");
    assert!(!r[0].deprecated);
    assert_eq!(r[0].latest.as_deref(), Some("7.0.0"));

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
    for ok in [
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "http://127.0.0.1:4873/x/-/x-1.0.0.tgz",
        "https://npm.pkg.github.com/download/@o/x/1.0.0/abc",
        "https://codeload.github.com/o/r/tar.gz/v1",
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
        "https://github.com/o/r.tgz",
        "https://www.github.com/o/r",
        "https://GitLab.com/o/r.tgz",
        "https://bitbucket.org/o/r",
        "https://gist.github.com/abc",
        "https://git.sr.ht/~o/r",
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
}
