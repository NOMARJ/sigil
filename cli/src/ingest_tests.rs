//! Unit tests for `ingest.rs` (kept in their own file: they are the
//! attack-shaped fixtures for its detectors — see .sigilignore).

use super::*;
use std::io::Cursor;

fn zip_bytes(entries: &[(&str, &[u8], Option<u32>)]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        for (name, body, mode) in entries {
            let opts = zip::write::FileOptions::default();
            if *mode == Some(S_IFLNK) {
                let target = std::str::from_utf8(body).unwrap();
                w.add_symlink(*name, target, opts).unwrap();
            } else if name.ends_with('/') {
                w.add_directory(*name, opts).unwrap();
            } else {
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

fn tar_with(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    build(&mut b);
    b.into_inner().unwrap()
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

fn regular(b: &mut tar::Builder<Vec<u8>>, name: &str, body: &[u8]) {
    let mut h = tar::Header::new_gnu();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    b.append_data(&mut h, name, body).unwrap();
}

#[test]
fn unpacks_a_skill_zip() {
    let t = tempfile::tempdir().unwrap();
    let src = write(
        t.path(),
        "demo.skill",
        &zip_bytes(&[
            ("demo/", b"", None),
            ("demo/SKILL.md", b"---\nname: demo\n---\n", None),
            ("demo/scripts/run.py", b"print(1)\n", None),
        ]),
    );
    let dest = t.path().join("out");
    fs::create_dir(&dest).unwrap();
    let s = extract(&src, &dest, Limits::default()).unwrap();
    assert_eq!(s.format, "zip");
    assert!(dest.join("demo/SKILL.md").is_file());
    assert!(dest.join("demo/scripts/run.py").is_file());
}

#[test]
fn refuses_zip_slip_absolute_and_symlinks() {
    for (label, entries) in [
        ("dotdot", vec![("../evil.sh", &b"x"[..], None)]),
        ("nested dotdot", vec![("a/../../evil.sh", &b"x"[..], None)]),
        (
            "backslash dotdot",
            vec![("..\\..\\evil.sh", &b"x"[..], None)],
        ),
        ("absolute", vec![("/etc/passwd", &b"x"[..], None)]),
        ("drive", vec![("C:/Windows/evil.dll", &b"x"[..], None)]),
        (
            "symlink",
            vec![("link", &b"/etc/passwd"[..], Some(S_IFLNK))],
        ),
        (
            "duplicate",
            vec![("a.txt", &b"1"[..], None), ("a.txt", &b"2"[..], None)],
        ),
    ] {
        let t = tempfile::tempdir().unwrap();
        let src = write(t.path(), "x.zip", &zip_bytes(&entries));
        let dest = t.path().join("out");
        fs::create_dir(&dest).unwrap();
        let err = extract(&src, &dest, Limits::default());
        assert!(err.is_err(), "{label}: expected refusal, got {err:?}");
        assert!(!t.path().join("evil.sh").exists(), "{label}: wrote outside");
    }
}

#[test]
fn enforces_entry_and_byte_caps_on_real_bytes() {
    let t = tempfile::tempdir().unwrap();
    let many: Vec<(String, Vec<u8>)> = (0..30).map(|i| (format!("f{i}"), vec![b'a'])).collect();
    let refs: Vec<(&str, &[u8], Option<u32>)> = many
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice(), None))
        .collect();
    let src = write(t.path(), "many.zip", &zip_bytes(&refs));
    let dest = t.path().join("a");
    fs::create_dir(&dest).unwrap();
    let limits = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    assert!(extract(&src, &dest, limits)
        .unwrap_err()
        .contains("entries"));

    // A highly compressible body: small on disk, large when expanded.
    let big = vec![b'a'; 64 * 1024];
    let src = write(t.path(), "bomb.zip", &zip_bytes(&[("big.txt", &big, None)]));
    let dest = t.path().join("b");
    fs::create_dir(&dest).unwrap();
    let limits = Limits {
        max_bytes: 4096,
        ..Limits::default()
    };
    assert!(extract(&src, &dest, limits).unwrap_err().contains("MiB"));
    assert!(!dest.join("big.txt").exists(), "partial file left behind");
}

#[test]
fn unpacks_tar_gz_and_refuses_links() {
    let t = tempfile::tempdir().unwrap();
    let ok = gz(&tar_with(|b| {
        regular(b, "pkg/SKILL.md", b"# hi\n");
        regular(b, "pkg/run.sh", b"echo hi\n");
    }));
    let src = write(t.path(), "pkg.tgz", &ok);
    let dest = t.path().join("ok");
    fs::create_dir(&dest).unwrap();
    let s = extract(&src, &dest, Limits::default()).unwrap();
    assert_eq!(s.format, "tar.gz");
    assert_eq!(s.files, 2);
    assert!(dest.join("pkg/run.sh").is_file());

    for kind in [tar::EntryType::Symlink, tar::EntryType::Link] {
        let bad = gz(&tar_with(|b| {
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_entry_type(kind);
            h.set_link_name("/etc/passwd").unwrap();
            h.set_cksum();
            b.append_data(&mut h, "pkg/link", &b""[..]).unwrap();
        }));
        let src = write(t.path(), "bad.tgz", &bad);
        let dest = t.path().join(format!("bad-{kind:?}"));
        fs::create_dir(&dest).unwrap();
        assert!(
            extract(&src, &dest, Limits::default()).is_err(),
            "{kind:?} entry must be refused"
        );
    }
}

#[test]
fn tar_traversal_is_refused() {
    // tar::Builder refuses to write `..` itself, so set the name bytes
    // directly, the way a hostile tool would.
    let t = tempfile::tempdir().unwrap();
    let bad = tar_with(|b| {
        let mut h = tar::Header::new_gnu();
        let name = b"../../escape.sh";
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_size(2);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, &b"x\n"[..]).unwrap();
    });
    for (label, bytes) in [("tar", bad.clone()), ("tar.gz", gz(&bad))] {
        let src = write(t.path(), &format!("bad.{label}"), &bytes);
        let dest = t.path().join(format!("out-{label}"));
        fs::create_dir(&dest).unwrap();
        let err = extract(&src, &dest, Limits::default()).unwrap_err();
        assert!(err.contains("traversal"), "{label}: {err}");
        assert!(!t.path().join("escape.sh").exists());
    }
}

#[test]
fn single_gzip_file_is_decompressed_in_place() {
    let t = tempfile::tempdir().unwrap();
    let src = write(t.path(), "SKILL.md.gz", &gz(b"---\nname: x\n---\n"));
    let dest = t.path().join("out");
    fs::create_dir(&dest).unwrap();
    let s = extract(&src, &dest, Limits::default()).unwrap();
    assert_eq!(s.format, "gzip");
    assert!(dest.join("SKILL.md").is_file());
}

#[test]
fn unsupported_containers_fail_with_a_clear_error() {
    let t = tempfile::tempdir().unwrap();
    let src = write(
        t.path(),
        "x.tar.xz",
        &[0xFD, b'7', b'z', b'X', b'Z', 0, 1, 2],
    );
    let dest = t.path().join("out");
    fs::create_dir(&dest).unwrap();
    let err = extract(&src, &dest, Limits::default()).unwrap_err();
    assert!(
        err.contains("xz") && err.contains("sigil scan <dir>"),
        "{err}"
    );
}

#[test]
fn plan_routes_urls_and_keeps_existing_inputs() {
    use Plan::*;
    // Existing behaviour: repository URLs stay git clones.
    for git_url in [
        "https://github.com/foo/bar",
        "https://github.com/foo/bar.git",
        "https://gitlab.com/group/proj",
        "git@github.com:foo/bar.git",
        // Repository names that end like a file are still repositories.
        "https://github.com/vercel/next.js",
        "https://github.com/mrdoob/three.js/",
        "https://github.com/chartjs/Chart.js.git",
        "https://gitlab.com/group/sub/widget.js",
        "https://codeberg.org/o/notes.md",
    ] {
        assert_eq!(plan(git_url).unwrap(), Passthrough, "{git_url}");
    }
    assert_eq!(plan("/definitely/not/here").unwrap(), Passthrough);

    assert_eq!(
        plan("https://github.com/o/r/blob/main/skills/x/SKILL.md").unwrap(),
        Download("https://raw.githubusercontent.com/o/r/main/skills/x/SKILL.md".into())
    );
    assert_eq!(
        plan("https://gitlab.com/g/p/-/blob/main/SKILL.md").unwrap(),
        Download("https://gitlab.com/g/p/-/raw/main/SKILL.md".into())
    );
    for u in [
        "https://example.com/skills/pdf.skill",
        "https://example.com/a.tar.gz?token=1",
        "https://github.com/o/r/archive/refs/heads/main.zip",
        "https://raw.githubusercontent.com/o/r/main/SKILL.md",
        "https://codeload.github.com/o/r/zip/refs/heads/main",
        "http://example.com/install.sh",
    ] {
        assert!(matches!(plan(u).unwrap(), Download(_)), "{u}");
    }
    assert_eq!(
        plan("https://github.com/anthropics/skills/tree/main/skills/pdf").unwrap(),
        GitHubTree {
            repo: "https://github.com/anthropics/skills.git".into(),
            segments: vec!["main".into(), "skills".into(), "pdf".into()],
        }
    );

    // Extension-less URLs off the known forges are probed with git first.
    for u in [
        "https://get.example.com/",
        "https://git.corp.example/team/repo",
    ] {
        assert!(matches!(plan(u).unwrap(), Probe(_)), "{u}");
    }
    assert_eq!(
        plan("https://git.corp.example/team/repo.git").unwrap(),
        Passthrough
    );
    assert_eq!(
        plan("https://huggingface.co/org/model").unwrap(),
        Passthrough
    );

    let t = tempfile::tempdir().unwrap();
    let md = write(t.path(), "SKILL.md", b"# plain file\n");
    assert_eq!(plan(md.to_str().unwrap()).unwrap(), Passthrough);
    assert_eq!(plan(t.path().to_str().unwrap()).unwrap(), Passthrough);
    let z = write(t.path(), "renamed.bin", &zip_bytes(&[("a", b"1", None)]));
    assert_eq!(plan(z.to_str().unwrap()).unwrap(), LocalArchive(z));
}

#[test]
fn tree_refs_prefer_the_longest_advertised_branch() {
    let refs = parse_ls_remote(
        "a\trefs/heads/main\nb\trefs/heads/feature/x\nc\trefs/tags/v1\nc\trefs/tags/v1^{}\n",
    );
    assert_eq!(refs, vec!["main", "feature/x", "v1"]);
    let segs = |s: &str| s.split('/').map(str::to_string).collect::<Vec<_>>();
    assert_eq!(
        split_tree_ref(&refs, &segs("feature/x/skills/pdf")),
        Some(("feature/x".into(), segs("skills/pdf")))
    );
    assert_eq!(
        split_tree_ref(&refs, &segs("main/skills")),
        Some(("main".into(), segs("skills")))
    );
    assert_eq!(split_tree_ref(&refs, &segs("deadbeef/skills")), None);
}

#[test]
fn non_public_addresses_are_recognised() {
    for ip in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(is_non_public(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
        assert!(!is_non_public(ip.parse().unwrap()), "{ip}");
    }
}

/// Serve `responses` in order on a loopback port, one per connection.
fn serve(responses: Vec<Vec<u8>>) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for body in responses {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&body);
        }
    });
    port
}

fn http_ok(ct: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

#[tokio::test]
async fn download_refuses_loopback_by_default() {
    let t = tempfile::tempdir().unwrap();
    let port = serve(vec![http_ok("text/plain", b"hi")]);
    let policy = DownloadPolicy {
        allow_private: false,
        max_bytes: MAX_DOWNLOAD_BYTES,
    };
    let err = download(
        &format!("http://127.0.0.1:{port}/SKILL.md"),
        &t.path().join("f"),
        &policy,
    )
    .await
    .unwrap_err();
    assert!(err.contains("non-public"), "{err}");
}

#[tokio::test]
async fn download_follows_a_redirect_and_caps_size() {
    let t = tempfile::tempdir().unwrap();
    let policy = DownloadPolicy {
        allow_private: true,
        max_bytes: 1024,
    };
    let port = serve(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /real/SKILL.md\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
        http_ok("text/markdown", b"---\nname: x\n---\n"),
    ]);
    let got = download(
        &format!("http://127.0.0.1:{port}/start"),
        &t.path().join("f"),
        &policy,
    )
    .await
    .unwrap();
    assert!(got.final_url.path().ends_with("/real/SKILL.md"));
    assert_eq!(
        fs::read(t.path().join("f")).unwrap(),
        b"---\nname: x\n---\n"
    );

    let port = serve(vec![http_ok("application/zip", &vec![b'a'; 4096])]);
    let err = download(
        &format!("http://127.0.0.1:{port}/big.zip"),
        &t.path().join("g"),
        &policy,
    )
    .await
    .unwrap_err();
    assert!(err.contains("cap"), "{err}");
    assert!(!t.path().join("g").exists(), "partial download left behind");
}

#[test]
fn downloaded_names_keep_rules_keyed_on_file_names_working() {
    let u = |s: &str| reqwest::Url::parse(s).unwrap();
    assert_eq!(
        downloaded_file_name(&u("https://x.io/a/SKILL.md"), None, b""),
        "SKILL.md"
    );
    assert_eq!(
        downloaded_file_name(&u("https://x.io/skill"), None, b"---\nname"),
        "SKILL.md"
    );
    assert_eq!(
        downloaded_file_name(&u("https://x.io/"), None, b"#!/bin/sh"),
        "script.sh"
    );
    assert_eq!(
        downloaded_file_name(
            &u("https://get.x.io/install"),
            None,
            b"#!/usr/bin/env python3"
        ),
        "install.py"
    );
    assert_eq!(
        downloaded_file_name(&u("https://x.io/"), None, b"hello"),
        "SKILL.md"
    );
    assert_eq!(
        downloaded_file_name(&u("https://x.io/install.sh"), None, b"#!"),
        "install.sh"
    );
    assert_eq!(
        downloaded_file_name(&u("https://x.io/..%2F..%2Fx"), None, b""),
        "_.._x"
    );
    assert_eq!(sanitize_file_name("my skill.md", "x"), "my_skill.md");
    assert_eq!(sanitize_file_name(".hidden", "x"), "hidden");
    assert_eq!(
        sibling_tmp(Path::new("/q/abc123"), "download"),
        Path::new("/q/.abc123.download.tmp")
    );
}
