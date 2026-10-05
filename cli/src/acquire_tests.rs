//! Unit tests for `acquire.rs`: which specs `sigil pip` / `sigil npm` hand
//! to pip and npm, and the exact arguments they run with.

use super::*;
use std::path::PathBuf;

fn kind(r: Result<(), SpecError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(SpecError::Unusable(_)) => "unusable",
        Err(SpecError::NotRegistry(_)) => "not-registry",
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
        "foo(>=1)",
        " requests",
        "requests,",
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
        // Aliases, whatever they resolve to.
        "foo@npm:bar",
        "foo@npm:bar@1.0.0",
        "foo@NPM:owner/repo",
        "@scope/foo@npm:bar",
    ] {
        assert_eq!(npm(spec), "not-registry", "{spec}");
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
    assert_eq!(npm(&npm_spec("foo", Some("npm:bar"))), "not-registry");
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
    assert_eq!(
        strings(&npm_pack_args("left-pad@1.3.0", false)),
        ["pack", "--ignore-scripts", "--", "left-pad@1.3.0"]
    );
}

#[test]
fn npm_pack_args_opt_in_drops_ignore_scripts() {
    assert_eq!(
        strings(&npm_pack_args("github:owner/repo", true)),
        ["pack", "--", "github:owner/repo"]
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
    assert!(pip_wheel_only_hint("x").contains(ALLOW_BUILD_SCRIPTS));
}
