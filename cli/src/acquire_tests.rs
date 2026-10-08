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

/// Whether `data` hashes to what a registry's `integrity` / `shasum` say.
fn check_npm_integrity(
    data: impl std::io::Read,
    integrity: Option<&str>,
    shasum: Option<&str>,
) -> Result<(), String> {
    NpmDigest::new(integrity, shasum)?.verify(data)
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
        // A Windows drive path looks like a URL scheme, but is a path.
        "C:\\pkg",
        "c:/pkg",
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
fn an_environment_marker_is_named_as_one() {
    for spec in [
        "six; python_version<'3'",
        "six ; os_name=='nt'",
        "six==1.0; python_version<'3'",
        "six==1.0 ; python_version<'3'",
        "six[x]; os_name=='nt'",
        "six (>=1); os_name=='nt'",
        "six>=1,<2; os_name=='nt'",
    ] {
        match check_spec(Manager::Pip, spec, false) {
            Err(SpecError::Malformed(why)) => {
                assert!(why.contains("environment marker"), "{spec}: {why}");
                assert!(
                    !why.contains("expected a version specifier"),
                    "{spec}: {why}"
                );
            }
            other => panic!("{spec}: {other:?}"),
        }
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
        // A Windows drive path looks like a URL scheme, but is a path.
        "C:\\dir",
        "c:/dir",
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

/// Only the opt-in packs: `spec` as typed, into quarantine, options ended
/// before it. By default Sigil downloads the tarball `npm view` named
/// itself.
#[test]
fn npm_pack_args_are_for_the_opt_in_only() {
    let dest = PathBuf::from("/q/abc123");
    assert_eq!(
        strings(&npm_pack_args("./dir", &dest)),
        ["pack", "--pack-destination", "/q/abc123", "--", "./dir"]
    );
}

#[test]
fn npm_config_get_args_name_one_setting() {
    assert_eq!(
        strings(&npm_config_get_args("@scope:registry")),
        ["config", "get", "@scope:registry"]
    );
}

#[test]
fn the_tarball_file_name_follows_npm_pack_and_cannot_name_a_path() {
    assert_eq!(
        npm_tarball_file_name("left-pad", "1.3.0"),
        "left-pad-1.3.0.tgz"
    );
    assert_eq!(
        npm_tarball_file_name("@types/node", "20.1.0"),
        "types-node-20.1.0.tgz"
    );
    assert_eq!(
        npm_tarball_file_name("a", "1.0.0-rc.1+build.5"),
        "a-1.0.0-rc.1_build.5.tgz"
    );
    // Characters of the legacy name rule that a file name should not hold.
    assert_eq!(
        npm_tarball_file_name("a*b!c(d)", "1.0.0"),
        "a_b_c_d_-1.0.0.tgz"
    );
    // Never hidden (the scanner would skip a dot directory).
    assert_eq!(
        npm_tarball_file_name(".hidden", "1.0.0"),
        "_hidden-1.0.0.tgz"
    );
    for name in ["a", "@s/n", "...", "x~y", "._."] {
        let file = npm_tarball_file_name(name, "1.0.0");
        assert!(file.ends_with(".tgz"), "{file}");
        assert!(!file.contains(['/', '\\']), "{file}");
        assert!(!file.starts_with('.'), "{file}");
    }
}

#[test]
fn a_tarball_must_be_on_the_registrys_own_host_and_carry_no_credentials() {
    let host = |tarball: &str, registry: &str| check_npm_tarball_host(tarball, registry);
    // npm's own registry, a mirror on another port, a scoped registry, any
    // scheme (the bytes are checked against the integrity either way).
    // The host and port the download is made to.
    assert_eq!(
        host(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "https://registry.npmjs.org/\n"
        ),
        Ok(("registry.npmjs.org".into(), 443))
    );
    assert_eq!(
        host(
            "http://127.0.0.1:4873/p/-/p-1.tgz",
            "http://127.0.0.1:4873/"
        ),
        Ok(("127.0.0.1".into(), 4873))
    );
    assert_eq!(
        host(
            "https://gitlab.com/api/v4/projects/123/packages/npm/@acme/pkg/-/@acme/pkg-1.0.0.tgz",
            "https://gitlab.com/api/v4/projects/123/packages/npm/"
        ),
        Ok(("gitlab.com".into(), 443))
    );
    assert!(host(
        "http://Registry.Example/p.tgz",
        "https://registry.example/npm/"
    )
    .is_ok());
    assert!(host(
        "https://registry.example:443/p.tgz",
        "https://registry.example/"
    )
    .is_ok());
    for (tarball, registry, says) in [
        // Another host, another port, a host that only ends the same.
        (
            "https://evil.example/p.tgz",
            "https://registry.npmjs.org/",
            "not the host",
        ),
        (
            "https://registry.npmjs.org:8443/p.tgz",
            "https://registry.npmjs.org/",
            "not the host",
        ),
        (
            "https://registry.npmjs.org.evil.example/p.tgz",
            "https://registry.npmjs.org/",
            "not the host",
        ),
        // A mirror whose metadata still names npm's registry.
        (
            "https://registry.npmjs.org/p.tgz",
            "https://mirror.example/",
            "not the host",
        ),
        // Credentials in the URL are never sent.
        (
            "https://user:pw@registry.npmjs.org/p.tgz",
            "https://registry.npmjs.org/",
            "user name or password",
        ),
        // A scheme's default port is not another port.
        (
            "http://registry.example:443/p.tgz",
            "https://registry.example/",
            "not the host",
        ),
        (
            "https://token@registry.npmjs.org/p.tgz",
            "https://registry.npmjs.org/",
            "user name or password",
        ),
        // An unreadable registry setting checks nothing, so it is a refusal.
        ("https://registry.npmjs.org/p.tgz", "", "not a URL"),
        ("https://registry.npmjs.org/p.tgz", "undefined", "not a URL"),
    ] {
        let why = host(tarball, registry).unwrap_err();
        assert!(why.contains(says), "{tarball} vs {registry}: {why}");
        assert!(!why.contains(|c: char| c.is_control()), "{why:?}");
        // Credentials in the URL are never echoed.
        assert!(!why.contains("pw@") && !why.contains("token@"), "{why}");
    }
    let msg = npm_host_refusal("markreg@1.0.0", "the tarball is elsewhere");
    assert!(msg.contains("markreg@1.0.0"), "{msg}");
    assert!(msg.contains("without credentials"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");
}

#[test]
fn credentials_in_a_registrys_url_are_never_echoed() {
    for url in [
        "git+https://user:secret@example.invalid/o/r.git",
        "https://user:secret@github.com/o/r",
        "https://user:secret@github.com/o/r.tgz",
        "ssh://git:secret@example.invalid/o/r.git",
        "https://secret@example.invalid/a b.tgz",
    ] {
        let why = check_npm_tarball_url(url).unwrap_err();
        assert!(!why.contains("secret"), "{url}: {why}");
        let why = check_npm_tarball_host(url, "https://example.invalid/").unwrap_err();
        assert!(!why.contains("secret"), "{url}: {why}");
    }
    assert_eq!(
        redact_url("https://u:p@h.example/x@y"),
        "https://***@h.example/x@y"
    );
    assert_eq!(redact_url("https://h.example/x@y"), "https://h.example/x@y");
    assert_eq!(redact_url("not a url\u{1b}"), "not a url\\u{1b}");
}

#[test]
fn a_download_failure_explains_credentials_and_proxies() {
    let denied = npm_download_failure(
        "pkg@1.0.0",
        "download failed: HTTP 401 Unauthorized from https://r.example/p.tgz",
    );
    assert!(denied.contains("wants credentials"), "{denied}");
    assert!(denied.contains("sigil scan"), "{denied}");
    assert!(denied.contains("HTTPS_PROXY"), "{denied}");
    let other = npm_download_failure("pkg@1.0.0", "download failed: connection refused");
    assert!(!other.contains("wants credentials"), "{other}");
    assert!(other.contains("HTTPS_PROXY"), "{other}");
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

/// pip reads a `global-option` or `build-option` as a request for a legacy
/// `setup.py` build and, before 24.2, discards the command line's
/// `--only-binary`: a source distribution is then built. Like a requirement
/// setting, such a setting is left out of the environment and refused in a
/// config file.
#[test]
fn pip_build_option_settings_are_removed_and_refused_like_requirements() {
    let vars = [
        ("PIP_GLOBAL_OPTION", "--quiet"),
        ("PIP_Build_Option", "--quiet"),
        ("PIP_INSTALL_OPTION", "--quiet"),
        ("PIP___GLOBAL_OPTION", "--quiet"),
        ("PIP_GLOBAL_OPTIONS", "--quiet"),
        ("MY_PIP_GLOBAL_OPTION", "--quiet"),
        ("PIP_NO_BUILD_ISOLATION", "0"),
        ("PIP_CONFIG_SETTINGS", "x"),
    ]
    .map(|(k, v)| (OsString::from(k), OsString::from(v)));
    let removed: Vec<String> = pip_env_to_remove(vars)
        .into_iter()
        .map(|k| k.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        removed,
        [
            "PIP_GLOBAL_OPTION",
            "PIP_Build_Option",
            "PIP_INSTALL_OPTION",
            "PIP___GLOBAL_OPTION"
        ]
    );
    let list = "\
global.global-option='--quiet'
download.build-option='--quiet'
install.global-option='--quiet'
:env:.global-option='--quiet'
global.Install_Option='--quiet'
global.index-url='https://example.invalid/simple'
";
    assert_eq!(
        pip_config_added_requirements(list),
        [
            "global.global-option",
            "download.build-option",
            ":env:.global-option",
            "global.install-option"
        ]
    );
    let msg = pip_config_refusal(&["global.global-option".into()]);
    assert!(msg.contains("global.global-option"), "{msg}");
    assert!(msg.contains("Implying --no-binary=:all:"), "{msg}");
    assert!(msg.contains("PIP_CONFIG_FILE=/dev/null"), "{msg}");
}

#[test]
fn an_npm_release_must_carry_the_name_that_was_asked_for() {
    for (spec, name) in [
        ("left-pad", "left-pad"),
        ("left-pad@^1.3", "left-pad"),
        ("left-pad@latest", "left-pad"),
        ("@types/node", "@types/node"),
        ("@types/node@20.1.0", "@types/node"),
    ] {
        assert_eq!(npm_spec_name(spec), name, "{spec}");
        assert!(!npm_name_mismatch(spec, name), "{spec}");
    }
    // Names compare without regard to case (the registry normalises).
    assert!(!npm_name_mismatch("Left-Pad@1", "left-pad"));
    assert!(!npm_name_mismatch("JSONStream", "jsonstream"));
    // A release of another package is not the one asked for.
    assert!(npm_name_mismatch("nameswap", "othername"));
    assert!(npm_name_mismatch("left-pad@1", "right-pad"));
    assert!(npm_name_mismatch("@acme/pkg", "@other/pkg"));
    assert!(npm_name_mismatch("pkg", "@acme/pkg"));
    let msg = npm_name_refusal("nameswap", "othername@1.0.0");
    assert!(
        msg.starts_with("sigil npm will not scan `othername@1.0.0`: you asked for `nameswap`"),
        "{msg}"
    );
    assert!(
        msg.contains("says the package is named `othername`"),
        "{msg}"
    );
    let scoped = npm_name_refusal("@acme/pkg", "@other/pkg@2.0.0");
    assert!(scoped.contains("is named `@other/pkg`"), "{scoped}");
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
    assert!(msg.contains("no tarball for Sigil to check"), "{msg}");
    assert!(msg.contains(ALLOW_BUILD_SCRIPTS), "{msg}");
    let why = check_npm_tarball_url("https://gitlab.com/o/r.tgz").unwrap_err();
    assert!(why.contains("git repository on gitlab.com"), "{why}");
}

#[test]
fn a_tarball_string_npm_could_read_as_a_path_is_refused() {
    // The URL parser drops a leading space or control character and any tab
    // or line break; npm-package-arg does not, and reads such a string as a
    // relative path (a directory it prepares). What is checked is what npm
    // is given, so each of these is refused as written.
    for bad in [
        " https://x/../../tmp/dir",
        "\u{1}https://x/a.tgz",
        "\thttps://x/a.tgz",
        "\nhttps://x/a.tgz",
        "\u{c}https://x/a.tgz",
        "ht\ttps://x/a.tgz",
        "ht\ntps://x/a.tgz",
        "ht\rtps://x/a.tgz",
        "https\t://x/a.tgz",
        "https://x/a.tgz\n",
        "https://x/a.tgz ",
        "https://x/a b.tgz",
        "https://x/a\u{1}b.tgz",
        "https://x/a\u{7f}b.tgz",
        // A scheme the URL parser accepts without its slashes.
        "http:/x/a.tgz",
        "https:x/a.tgz",
        "https:\\\\x\\a.tgz",
        "\u{feff}https://x/a.tgz",
    ] {
        let why = check_npm_tarball_url(bad).unwrap_err();
        assert!(!why.contains(|c: char| c.is_control()), "{bad:?}: {why:?}");
    }
    let why = check_npm_tarball_url(" https://x/../../tmp/dir").unwrap_err();
    assert!(why.contains("local path"), "{why}");
    // Plain downloads, in either case of the scheme.
    for ok in [
        "https://registry.example/pkg/-/pkg-1.0.0.tgz",
        "HTTPS://registry.example/pkg/-/pkg-1.0.0.tgz",
        "http://127.0.0.1:4873/pkg/-/pkg-1.0.0.tgz",
        "https://registry.example/pkg/-/pkg-1.0.0.tgz?x=%20y",
    ] {
        assert!(check_npm_tarball_url(ok).is_ok(), "{ok}");
    }
}

#[test]
fn the_downloaded_tarball_must_match_the_registry_integrity() {
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
    assert!(err.contains("Sigil downloaded"), "{err}");
    // The digest can be worked out before anything is downloaded.
    assert!(NpmDigest::new(Some(sha512), None).is_ok());
    assert!(NpmDigest::new(None, Some(sha1_hex)).is_ok());
    assert!(NpmDigest::new(Some("md5-abc"), None).is_err());
    assert!(NpmDigest::new(None, None).is_err());
    let msg = npm_integrity_refusal("plainpkg@1.0.0", &err);
    assert!(msg.contains("plainpkg@1.0.0"), "{msg}");
    assert!(msg.contains("EINTEGRITY"), "{msg}");
}

#[test]
fn npm_view_names_and_versions_that_would_name_a_path_are_refused() {
    let view = |name: &str, version: &str| {
        serde_json::json!({
            "name": name,
            "version": version,
            "dist.tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
        })
        .to_string()
    };
    for (name, version) in [
        ("pwn", "1.0.0"),
        ("@types/node", "20.1.0"),
        ("left-pad", "1.3.0-rc.1+build.5"),
        ("Legacy_Name.js", "0.0.1"),
    ] {
        assert!(
            parse_npm_view(&view(name, version)).is_ok(),
            "{name}@{version}"
        );
    }
    for (name, version) in [
        ("x/../../../outside/pwn", "1.0.0"),
        ("@s/../../../outside/pwn", "1.0.0"),
        ("@s/a/b", "1.0.0"),
        ("@s", "1.0.0"),
        ("@/x", "1.0.0"),
        ("..", "1.0.0"),
        ("a\\b", "1.0.0"),
        ("", "1.0.0"),
        ("ansi\u{1b}]0;PWNED\u{7}x", "1.0.1"),
        ("name\u{202e}", "1.0.0"),
        ("pwn", "1.0.0/../../../../outside/v"),
        ("pwn", "1.0.0\\..\\x"),
        ("pwn", "1.0.0 "),
        ("pwn", "1.0.0\u{1b}[2J"),
        ("pwn", ""),
    ] {
        let err = parse_npm_view(&view(name, version)).unwrap_err();
        assert!(err.contains("not a valid"), "{name:?}@{version:?}: {err}");
        assert!(
            !err.chars().any(char::is_control),
            "the message must not carry the control characters: {err:?}"
        );
    }
}

#[test]
fn a_bare_name_or_star_is_asked_about_in_its_range_form_when_latest_is_deprecated() {
    for spec in ["rng2", "@scope/rng2", "rng2@*", "@scope/rng2@*"] {
        let name = npm_name_for_default_pick(spec).unwrap_or_default();
        assert!(spec.starts_with(&name), "{spec} -> {name}");
        assert!(!name.ends_with("@*"));
    }
    assert_eq!(npm_name_for_default_pick("rng2").as_deref(), Some("rng2"));
    assert_eq!(
        npm_name_for_default_pick("@s/rng2@*").as_deref(),
        Some("@s/rng2")
    );
    // A version, a tag or a range names what npm picks as it is.
    for spec in [
        "rng2@1.9.0",
        "rng2@latest",
        "rng2@^1",
        "@s/rng2@1.0.0",
        "rng2@>=1",
    ] {
        assert_eq!(npm_name_for_default_pick(spec), None, "{spec}");
    }
    assert_eq!(npm_all_versions_spec("@s/rng2"), "@s/rng2@>=0");
}

#[test]
fn the_opt_in_confirmation_is_a_person_or_the_variable_set_to_one() {
    use std::ffi::OsStr;
    assert!(opt_in_env_confirms(Some(OsStr::new("1"))));
    for not in ["", "0", "true", "yes", " 1", "1 ", "11"] {
        assert!(!opt_in_env_confirms(Some(OsStr::new(not))), "{not:?}");
    }
    assert!(!opt_in_env_confirms(None));
    for yes in ["yes", "YES\n", " Yes \r\n"] {
        assert!(answer_confirms(yes), "{yes:?}");
    }
    for no in ["", "y", "y\n", "no", "yes please", "yess", "1", "true"] {
        assert!(!answer_confirms(no), "{no:?}");
    }
    let msg = opt_in_unconfirmed(Manager::Npm, "./evil");
    assert!(msg.contains("SIGIL_ALLOW_BUILD_SCRIPTS=1"), "{msg}");
    assert!(msg.contains("no terminal"), "{msg}");
    assert!(msg.contains("Nothing was downloaded or run"), "{msg}");
}

#[test]
fn a_path_in_a_hint_is_one_shell_word() {
    assert_eq!(shell_quote("./my-dir"), "./my-dir");
    assert_eq!(shell_quote("/tmp/a_b-c.d/e"), "/tmp/a_b-c.d/e");
    assert_eq!(shell_quote("./my dir"), "'./my dir'");
    assert_eq!(shell_quote("a;b"), "'a;b'");
    assert_eq!(shell_quote("it's"), "'it'\\''s'");
    assert_eq!(shell_quote("$HOME"), "'$HOME'");
    // A Windows drive path keeps its backslashes, and takes double quotes.
    assert_eq!(shell_quote("C:\\x\\y"), "C:\\x\\y");
    assert_eq!(shell_quote("C:\\my dir\\y"), "\"C:\\my dir\\y\"");
    assert_eq!(shell_quote(""), "''");
    let err = check_spec(Manager::Npm, "./my dir", false).unwrap_err();
    let shown = refusal(Manager::Npm, "./my dir", &err);
    assert!(shown.contains("`sigil scan './my dir'`"), "{shown}");
}

#[test]
fn a_direct_reference_is_called_one_and_a_leading_space_is_trimmed() {
    let reason = |spec: &str| match check_spec(Manager::Pip, spec, false) {
        Err(SpecError::NotRegistry(why)) => why,
        other => panic!("{spec}: {other:?}"),
    };
    assert!(reason("foo @ https://x.invalid/y.whl").contains("direct reference"));
    assert!(reason("foo@https://x.invalid/y.whl").contains("direct reference"));
    assert!(reason("foo @ git+https://x.invalid/y").contains("direct reference"));
    assert!(reason("https://x.invalid/y.whl").contains("URL"));
    assert!(reason("https://user@x.invalid/y.whl").contains("URL"));
    // pip trims the requirement; Sigil reads it as pip does.
    assert_eq!(pip(" six==1.17.0"), "ok");
    assert_eq!(pip("six==1.17.0 "), "ok");
    assert_eq!(pip(" six"), "ok");
}

#[test]
fn a_whole_spec_npm_alias_is_an_alias() {
    match check_spec(Manager::Npm, "npm:left-pad@1.3.0", false) {
        Err(SpecError::Alias(target)) => assert_eq!(target, "left-pad@1.3.0"),
        other => panic!("{other:?}"),
    }
    assert_eq!(npm("NPM:left-pad"), "alias");
    assert_eq!(npm("foo@npm:left-pad@1.3.0"), "alias");
}

#[test]
fn the_release_scanned_is_named_without_extras() {
    assert_eq!(pip_release_name("requests==2.32.3"), "requests==2.32.3");
    assert_eq!(
        pip_release_name("requests[socks]==2.32.3"),
        "requests==2.32.3"
    );
    assert_eq!(
        pip_release_name("requests [socks, security] ==2.32.3"),
        "requests ==2.32.3"
    );
    assert_eq!(pip_release_name(" six==1.17.0 "), "six==1.17.0");
    assert_eq!(pip_release_name("a[b"), "a[b");
}

#[test]
fn the_index_failure_hint_follows_what_pip_said() {
    let old = pip_index_failure_hint("ERROR: unknown command \"index\"\n", "six");
    assert!(old.contains("21.2"), "{old}");
    assert!(old.contains("sigil pip six==<version>"), "{old}");
    let typo = pip_index_failure_hint(
        "ERROR: No matching distribution found for no-such-pkg\n",
        "no-such-pkg",
    );
    assert!(typo.contains("Check the spelling"), "{typo}");
    assert!(!typo.contains("pin a version"), "{typo}");
    let other = pip_index_failure_hint("", "six");
    assert!(other.contains("pip listed no release of `six`"), "{other}");
    assert!(other.contains("pin a version"), "{other}");
}

#[test]
fn the_no_wheel_hint_points_at_scanning_the_source_distribution() {
    let hint = pip_wheel_only_hint("docopt", None);
    assert!(hint.contains("sigil scan <URL of the .tar.gz>"), "{hint}");
    assert!(hint.contains("runs nothing from it"), "{hint}");
    assert!(hint.contains(ALLOW_BUILD_SCRIPTS), "{hint}");
}

/// docs/troubleshooting.md quotes the messages `sigil pip` and `sigil npm`
/// print; each quoted fragment must be one the code produces, and the other
/// way round for the npm lookup errors, so the page cannot drift from the
/// CLI again.
#[test]
fn the_troubleshooting_page_quotes_the_messages_the_cli_prints() {
    let doc = include_str!("../../docs/troubleshooting.md");
    let section = doc
        .split("### `sigil pip` or `sigil npm` refuses a package or fails to download it")
        .nth(1)
        .and_then(|rest| rest.split("\n### ").next())
        .expect("the troubleshooting section for sigil pip and sigil npm");

    // What the registry's name or version can be, as the CLI prints it.
    let bad_name = parse_npm_view(
        r#"{"name":"../evil","version":"1.0.0","dist.tarball":"https://r.example/x.tgz"}"#,
    )
    .unwrap_err();
    let bad_version = parse_npm_view(
        r#"{"name":"ok","version":"1.0.0/../../x","dist.tarball":"https://r.example/x.tgz"}"#,
    )
    .unwrap_err();
    let unreadable = npm_view_unreadable("badname", &bad_name);
    assert!(
        unreadable
            .starts_with("could not read what npm resolves `badname` to: the registry gives `"),
        "{unreadable}"
    );
    assert!(unreadable.ends_with("as a package name, which is not a valid npm package name"));
    assert!(
        npm_view_unreadable("badver", &bad_version).contains("as the version of `ok`, which"),
        "{bad_version}"
    );
    let tarball = npm_tarball_refusal(
        "name@1.0.0",
        &check_npm_tarball_url("git+file:///tmp/repo").unwrap_err(),
    );
    assert!(tarball.starts_with("sigil npm will not download `name@1.0.0`: the registry gives `"));
    assert!(tarball.contains("` as the tarball"), "{tarball}");
    let host = npm_host_refusal(
        "name@1.0.0",
        &check_npm_tarball_host("https://other.example/p.tgz", "https://registry.npmjs.org/")
            .unwrap_err(),
    );
    assert!(host.contains("is not the host of the registry npm resolved the package from"));
    let digest = NpmDigest::new(Some("sha512-AAAA"), None)
        .unwrap()
        .verify(&b"x"[..])
        .unwrap_err();
    assert!(
        digest.starts_with("the tarball Sigil downloaded hashes to "),
        "{digest}"
    );
    let none = NpmDigest::new(None, None).unwrap_err();
    assert!(
        none.contains("the registry gives no integrity or shasum"),
        "{none}"
    );
    let download = npm_download_failure("name@1.0.0", "download failed: HTTP 401 from u");
    assert!(download.starts_with("sigil npm could not download the tarball of `name@1.0.0`: "));
    let twice = version_flag_conflict(Manager::Pip, "requests>=2", Some("2.32.3")).unwrap();
    assert!(
        twice.starts_with("sigil pip was given a version twice: "),
        "{twice}"
    );
    let swapped = npm_name_refusal("nameswap", "othername@1.0.0");
    assert!(
        swapped.contains("says the package is named `othername`"),
        "{swapped}"
    );
    let unconfirmed = opt_in_unconfirmed(Manager::Pip, "./x");
    assert!(
        unconfirmed.contains("so it needs a person to confirm, and there is no terminal to ask on"),
        "{unconfirmed}"
    );
    let build_options = pip_config_refusal(&["global.global-option".into()]);
    assert!(
        build_options.contains("or makes pip build source distributions"),
        "{build_options}"
    );

    // The page quotes each of those, and nothing the CLI does not print.
    for quoted in [
        "could not read what npm resolves",
        "as a package name",
        "as the version of",
        "will not download",
        "as the tarball",
        "is not the host of the registry npm resolved the package from",
        "could not download the tarball of",
        "the tarball Sigil downloaded hashes to",
        "the registry gives no integrity or shasum",
        "was given a version twice",
        "says the package is named",
        "so it needs a person to confirm, and there is no terminal to ask on",
        "or makes pip build source distributions",
        "is pip installed and on PATH?",
    ] {
        assert!(
            section.contains(quoted),
            "troubleshooting.md does not quote `{quoted}`"
        );
    }
    assert!(
        !section.contains("will not download name@version: the registry gives … as a package name"),
        "the package-name error is not printed with a `will not download` prefix"
    );
    assert!(
        !section.contains("the tarball npm downloaded hashes to"),
        "Sigil, not npm, downloads the tarball now"
    );
}
