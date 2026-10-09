//! Expected values come from `packaging` (24.0, and 21.3 as vendored by
//! pip 24.0, which agree on every case here).

use super::*;

fn v(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
}

fn specs(list: &[(&str, &str)]) -> Vec<Specifier> {
    list.iter()
        .map(|(op, ver)| Specifier::new(op, ver).unwrap_or_else(|| panic!("{op}{ver}")))
        .collect()
}

#[test]
fn versions_sort_as_packaging_sorts_them() {
    let order = [
        "1.0.dev0",
        "1.0a1.dev1",
        "1.0a1",
        "1.0a2",
        "1.0b1",
        "1.0rc1",
        "1.0",
        "1.0+abc",
        "1.0+abc.5",
        "1.0+5",
        "1.0.post1.dev1",
        "1.0.post1",
        "1.0.1",
        "1!0.1",
    ];
    for pair in order.windows(2) {
        assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
    }
}

#[test]
fn spellings_normalise() {
    for (a, b) in [
        ("1.0", "1.0.0"),
        ("1.0RC1", "1.0rc1"),
        ("1.0-1", "1.0.post1"),
        ("v1.0", "1.0"),
        ("1.0alpha1", "1.0a1"),
        ("1.0c1", "1.0rc1"),
        ("1.0r", "1.0.post0"),
        ("1.0-dev", "1.0.dev0"),
    ] {
        assert_eq!(v(a), v(b), "{a} == {b}");
    }
}

#[test]
fn non_versions_do_not_parse() {
    for s in [
        "",
        "abc",
        "1.0-",
        "1..0",
        "1.0+",
        "1.0+a..b",
        "--1",
        "1.0 extra",
    ] {
        assert!(Version::parse(s).is_none(), "{s:?}");
    }
    assert!(Version::parse("99999999999999999999999").is_none());
}

#[test]
fn best_match_agrees_with_packaging() {
    let avail: Vec<String> = [
        "1.0",
        "1.1",
        "1.2rc1",
        "2.0.dev1",
        "2.0",
        "2.0.post1",
        "2.1+local",
        "3.0a1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[], "2.1+local"),
        (&[(">=", "1.1")], "2.1+local"),
        (&[("<", "2.0")], "1.1"),
        (&[("<=", "2.0")], "2.0"),
        (&[(">", "2.0")], "2.1+local"),
        (&[("~=", "1.0")], "1.1"),
        (&[("==", "1.*")], "1.1"),
        (&[("!=", "2.0")], "2.1+local"),
        (&[(">=", "2.0rc0")], "3.0a1"),
        (&[("<", "3.0a2")], "2.1+local"),
        (&[(">=", "1"), ("<", "2")], "1.1"),
        (&[("==", "2.0")], "2.0"),
        (&[("~=", "2.0.0")], "2.0.post1"),
        (&[(">=", "3.0a1")], "3.0a1"),
    ];
    for (spec, want) in cases {
        assert_eq!(
            best_match(&avail, &specs(spec), false),
            Some(*want),
            "{spec:?}"
        );
    }
    // pip's --pre lets every pre-release in.
    assert_eq!(best_match(&avail, &[], true), Some("3.0a1"));
}

#[test]
fn prereleases_only_when_nothing_else_and_no_specifier() {
    let only_pre: Vec<String> = vec!["1.0a1".into(), "1.0b2".into()];
    assert_eq!(best_match(&only_pre, &[], false), Some("1.0b2"));
    assert_eq!(best_match(&only_pre, &specs(&[(">=", "0.1")]), false), None);
}

#[test]
fn greater_than_skips_post_and_local_releases_of_the_named_version() {
    let avail: Vec<String> = vec!["3.1.post1".into(), "3.1+local".into()];
    assert_eq!(best_match(&avail, &specs(&[(">", "3.1")]), false), None);
    assert_eq!(
        best_match(&avail, &specs(&[(">", "3.1.post0")]), false),
        Some("3.1.post1")
    );
}

#[test]
fn wildcards_and_compatible_releases() {
    let avail: Vec<String> = vec!["1.4".into(), "1.4.9".into(), "1.5.0".into()];
    assert_eq!(
        best_match(&avail, &specs(&[("==", "1.4.*")]), false),
        Some("1.4.9")
    );
    assert_eq!(
        best_match(&avail, &specs(&[("!=", "1.5.*")]), false),
        Some("1.4.9")
    );
    assert_eq!(
        best_match(&avail, &specs(&[("~=", "1.4")]), false),
        Some("1.5.0")
    );
    assert_eq!(
        best_match(&avail, &specs(&[("~=", "1.4.0")]), false),
        Some("1.4.9")
    );
}

#[test]
fn unparseable_versions_are_skipped() {
    let avail: Vec<String> = vec!["not-a-version".into(), "0.9".into()];
    assert_eq!(best_match(&avail, &[], false), Some("0.9"));
}

#[test]
fn specifier_new_rejects_what_pip_rejects() {
    assert!(Specifier::new("~=", "1").is_none());
    assert!(Specifier::new("==", "1.0rc1.*").is_none());
    assert!(Specifier::new(">=", "abc").is_none());
    assert!(Specifier::new("=>", "1.0").is_none());
    assert!(Specifier::new("===", "anything-goes").is_some());
    assert!(Specifier::new("==", "1.0").unwrap().pins());
    assert!(Specifier::new("===", "1.0").unwrap().pins());
    assert!(!Specifier::new("==", "1.*").unwrap().pins());
    assert!(!Specifier::new(">=", "1.0").unwrap().pins());
}
