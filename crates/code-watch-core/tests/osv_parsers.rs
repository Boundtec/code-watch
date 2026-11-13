use std::fs;
use std::path::{Path, PathBuf};

use code_watch_core::osv::{Discovered, Ecosystem, UnparsedReason, discover};

fn fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/osv")
        .join(case)
}

fn found(case: &str) -> Vec<(String, String)> {
    let d = discover(&fixture(case));
    assert!(d.unparsed.is_empty(), "{case}: {:?}", d.unparsed);
    let mut out: Vec<_> = d
        .packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    out.sort();
    out
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out: Vec<_> = list
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    out.sort();
    out
}

#[test]
fn a_repository_without_lockfiles_has_no_packages() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(discover(dir.path()), Discovered::default());
}

#[test]
fn lockfiles_with_no_packages_give_an_empty_list() {
    for case in [
        "npm-zero",
        "pnpm-zero",
        "yarn-v1-zero",
        "req-zero",
        "poetry-zero",
        "uv-zero",
        "cargo-zero",
        "go-zero",
    ] {
        assert_eq!(found(case), pairs(&[]), "{case}");
    }
}

#[test]
fn npm_with_one_package() {
    assert_eq!(found("npm-one"), pairs(&[("left-pad", "1.3.0")]));
}

#[test]
fn npm_keeps_registry_packages_and_drops_links_files_git_and_private_registries() {
    assert_eq!(
        found("npm-many"),
        pairs(&[
            ("a", "1.0.0"),
            ("@s/b", "2.1.0"),
            ("real", "3.0.0"),
            ("bundled", "4.0.0"),
        ])
    );
}

#[test]
fn npm_lockfile_v1_nested_dependencies_are_listed() {
    assert_eq!(found("npm-v1"), pairs(&[("a", "1.0.0"), ("b", "2.0.0")]));
}

#[test]
fn pnpm_v6_strips_the_peer_suffix_and_drops_tarball_and_directory_sources() {
    assert_eq!(
        found("pnpm-v6"),
        pairs(&[("left-pad", "1.3.0"), ("@scope/pkg", "2.0.0")])
    );
}

#[test]
fn pnpm_v9_keys_have_no_leading_slash_and_git_sources_are_dropped() {
    assert_eq!(
        found("pnpm-v9"),
        pairs(&[("left-pad", "1.3.0"), ("@scope/pkg", "2.0.0")])
    );
}

#[test]
fn yarn_v1_drops_entries_not_resolved_from_the_registry() {
    assert_eq!(
        found("yarn-v1"),
        pairs(&[("left-pad", "1.3.0"), ("@scope/pkg", "2.1.0")])
    );
}

#[test]
fn yarn_berry_reads_npm_resolutions_and_skips_workspace_and_patch_entries() {
    assert_eq!(
        found("yarn-berry"),
        pairs(&[("left-pad", "1.3.0"), ("@scope/pkg", "2.1.0")])
    );
}

#[test]
fn requirements_keep_exact_pins_with_normalised_names_and_first_line_numbers() {
    let d = discover(&fixture("req-many"));
    let got: Vec<_> = d
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str(), p.line))
        .collect();
    assert_eq!(
        got,
        [
            ("django-rest-framework", "3.14.0", Some(3)),
            ("pandas", "2.0.0", Some(14)),
            ("requests", "2.31.0", Some(2)),
            ("urllib3", "2.0.7", Some(10)),
        ]
    );
    assert!(d.packages.iter().all(|p| p.ecosystem == Ecosystem::PyPI));
}

#[test]
fn poetry_drops_packages_with_a_source_table() {
    assert_eq!(
        found("poetry-many"),
        pairs(&[("requests", "2.31.0"), ("typing-extensions", "4.9.0")])
    );
}

#[test]
fn uv_keeps_only_the_public_index_and_never_the_project_itself() {
    assert_eq!(
        found("uv-many"),
        pairs(&[("requests", "2.31.0"), ("typing-extensions", "4.9.0")])
    );
}

#[test]
fn cargo_keeps_only_crates_io_packages() {
    assert_eq!(
        found("cargo-many"),
        pairs(&[("serde", "1.0.229"), ("tokio", "1.40.0")])
    );
}

#[test]
fn go_reads_require_lines_with_replacements_applied_and_their_line_numbers() {
    let d = discover(&fixture("go-many"));
    let got: Vec<_> = d
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str(), p.line))
        .collect();
    assert_eq!(
        got,
        [
            ("github.com/other/fork", "v1.2.3", Some(11)),
            ("github.com/pkg/errors", "v0.9.1", Some(8)),
            ("golang.org/x/net", "v0.20.0", Some(5)),
            ("golang.org/x/text", "v0.14.0", Some(9)),
        ]
    );
    assert!(d.packages.iter().all(|p| p.ecosystem == Ecosystem::Go));
}

#[test]
fn go_sum_is_not_a_package_source() {
    assert_eq!(found("go-sum-only"), pairs(&[]));
}

#[test]
fn ecosystems_use_the_osv_spelling() {
    let names: Vec<_> = [
        Ecosystem::Npm,
        Ecosystem::PyPI,
        Ecosystem::CratesIo,
        Ecosystem::Go,
    ]
    .map(Ecosystem::osv_name)
    .to_vec();
    assert_eq!(names, ["npm", "PyPI", "crates.io", "Go"]);
}

#[test]
fn package_files_are_relative_to_the_scanned_root() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("sub/deeper")).unwrap();
    fs::copy(
        fixture("npm-one").join("package-lock.json"),
        dir.path().join("sub/deeper/package-lock.json"),
    )
    .unwrap();
    let d = discover(dir.path());
    assert_eq!(d.packages[0].file, "sub/deeper/package-lock.json");
}

#[test]
fn nested_lockfiles_in_node_modules_and_git_are_not_read() {
    let dir = tempfile::tempdir().unwrap();
    for sub in ["node_modules/x", ".git/y"] {
        fs::create_dir_all(dir.path().join(sub)).unwrap();
        fs::copy(
            fixture("npm-one").join("package-lock.json"),
            dir.path().join(sub).join("package-lock.json"),
        )
        .unwrap();
    }
    assert_eq!(discover(dir.path()), Discovered::default());
}

fn lockfile_in_tempdir(name: &str, content: &[u8]) -> (tempfile::TempDir, Discovered) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(name), content).unwrap();
    let d = discover(dir.path());
    (dir, d)
}

fn assert_unparsed(d: &Discovered, file: &str, reason: UnparsedReason) {
    assert_eq!(d.packages, []);
    assert_eq!(d.unparsed.len(), 1, "{:?}", d.unparsed);
    assert_eq!(
        (d.unparsed[0].file.as_str(), d.unparsed[0].reason),
        (file, reason)
    );
}

#[test]
fn a_malformed_lockfile_is_reported_for_every_format_that_can_fail() {
    for name in [
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
        "go.mod",
    ] {
        let (_dir, d) = lockfile_in_tempdir(name, b"{{{ this is not a lockfile\n\x00");
        assert_unparsed(&d, name, UnparsedReason::Malformed);
    }
}

#[test]
fn a_truncated_lockfile_is_reported() {
    let full = fs::read(fixture("npm-many").join("package-lock.json")).unwrap();
    let (_dir, d) = lockfile_in_tempdir("package-lock.json", &full[..full.len() / 2]);
    assert_unparsed(&d, "package-lock.json", UnparsedReason::Malformed);
}

#[test]
fn a_lockfile_that_is_not_utf8_is_reported() {
    let (_dir, d) = lockfile_in_tempdir("Cargo.lock", &[0xff, 0xfe, 0x00]);
    assert_unparsed(&d, "Cargo.lock", UnparsedReason::NotUtf8);
}

#[test]
fn a_huge_lockfile_is_reported_without_being_read() {
    let dir = tempfile::tempdir().unwrap();
    let file = fs::File::create(dir.path().join("package-lock.json")).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert_unparsed(
        &discover(dir.path()),
        "package-lock.json",
        UnparsedReason::TooLarge,
    );
}

#[test]
fn a_lockfile_at_the_limit_is_still_read() {
    let dir = tempfile::tempdir().unwrap();
    let pad = " ".repeat(16 * 1024 * 1024 - 2);
    fs::write(dir.path().join("package-lock.json"), format!("{{}}{pad}")).unwrap();
    assert_eq!(discover(dir.path()), Discovered::default());
}

#[cfg(unix)]
#[test]
fn a_symlinked_lockfile_is_reported_and_not_followed() {
    let outside = tempfile::tempdir().unwrap();
    fs::copy(
        fixture("npm-one").join("package-lock.json"),
        outside.path().join("real.json"),
    )
    .unwrap();
    let repo = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("real.json"),
        repo.path().join("package-lock.json"),
    )
    .unwrap();
    assert_unparsed(
        &discover(repo.path()),
        "package-lock.json",
        UnparsedReason::Symlink,
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_lockfile_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Cargo.lock");
    fs::write(&path, "version = 4\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let d = discover(dir.path());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_unparsed(&d, "Cargo.lock", UnparsedReason::Unreadable);
}

fn names(d: &Discovered) -> Vec<&str> {
    let mut out: Vec<_> = d.packages.iter().map(|p| p.name.as_str()).collect();
    out.sort();
    out
}

fn skipped_entries(d: &Discovered) -> Vec<(&str, usize)> {
    d.not_looked_up
        .iter()
        .map(|n| (n.file.as_str(), n.count))
        .collect()
}

#[test]
fn pnpm_v5_keys_are_read_and_the_ones_from_other_sources_are_counted() {
    let lock = r#"lockfileVersion: 5.4
packages:
  /lodash/4.17.20:
    resolution: {integrity: sha512-a}
  /@babel/core/7.0.0:
    resolution: {integrity: sha512-b}
  /react-dom/17.0.0_react@17.0.0:
    resolution: {integrity: sha512-c}
  /gitdep/1.0.0:
    resolution: {tarball: https://example.com/gitdep.tgz}
  registry.example.com/private/1.0.0:
    resolution: {integrity: sha512-d}
"#;
    let (_dir, d) = lockfile_in_tempdir("pnpm-lock.yaml", lock.as_bytes());
    assert_eq!(d.unparsed, []);
    assert_eq!(names(&d), ["@babel/core", "lodash", "react-dom"]);
    let versions: Vec<_> = d.packages.iter().map(|p| p.version.as_str()).collect();
    assert_eq!(versions, ["7.0.0", "4.17.20", "17.0.0"]);
    assert_eq!(skipped_entries(&d), [("pnpm-lock.yaml", 2)]);
}

#[test]
fn npm_entries_resolved_from_a_mirror_are_counted_not_dropped_silently() {
    let lock = r#"{"lockfileVersion":3,"packages":{"":{},
"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
"node_modules/b":{"version":"2.0.0","resolved":"https://artifactory.example.com/api/npm/b/-/b-2.0.0.tgz"},
"node_modules/c":{"version":"3.0.0","resolved":"https://nexus.example.com/repository/npm/c/-/c-3.0.0.tgz"},
"packages/ws":{"version":"1.0.0"},
"node_modules/ws":{"resolved":"packages/ws","link":true}}}"#;
    let (_dir, d) = lockfile_in_tempdir("package-lock.json", lock.as_bytes());
    assert_eq!(names(&d), ["a"]);
    assert_eq!(skipped_entries(&d), [("package-lock.json", 2)]);
}

#[test]
fn an_npm_v1_alias_is_counted_as_not_looked_up() {
    let lock = r#"{"lockfileVersion":1,"dependencies":{
"real":{"version":"1.0.0","resolved":"https://registry.npmjs.org/real/-/real-1.0.0.tgz"},
"alias":{"version":"npm:other@1.0.0","resolved":"https://registry.npmjs.org/other/-/other-1.0.0.tgz"}}}"#;
    let (_dir, d) = lockfile_in_tempdir("package-lock.json", lock.as_bytes());
    assert_eq!(names(&d), ["real"]);
    assert_eq!(skipped_entries(&d), [("package-lock.json", 1)]);
}

#[test]
fn a_cargo_alternative_registry_and_git_entry_are_counted_but_workspace_crates_are_not() {
    let lock = r#"version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "public"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "internal"
version = "2.0.0"
source = "registry+https://crates.example.com/index"

[[package]]
name = "forked"
version = "3.0.0"
source = "git+https://example.com/forked.git#0123456789abcdef0123456789abcdef01234567"
"#;
    let (_dir, d) = lockfile_in_tempdir("Cargo.lock", lock.as_bytes());
    assert_eq!(d.unparsed, []);
    assert_eq!(names(&d), ["public"]);
    assert_eq!(skipped_entries(&d), [("Cargo.lock", 2)]);
}

#[test]
fn a_lockfile_format_version_that_is_not_recognised_is_reported_never_read_as_empty() {
    let cases: [(&str, &str); 6] = [
        (
            "package-lock.json",
            r#"{"lockfileVersion":9,"packages":{}}"#,
        ),
        ("pnpm-lock.yaml", "lockfileVersion: '7.0'\npackages: {}\n"),
        ("pnpm-lock.yaml", "packages: {}\n"),
        ("pnpm-lock.yaml", "lockfileVersion: 4\npackages: {}\n"),
        ("yarn.lock", "__metadata:\n  version: 99\n"),
        ("uv.lock", "version = 7\n"),
    ];
    for (name, text) in cases {
        let (_dir, d) = lockfile_in_tempdir(name, text.as_bytes());
        assert_unparsed(&d, name, UnparsedReason::UnknownFormat);
    }
}

#[test]
fn the_known_format_versions_are_still_read() {
    let cases: [(&str, &str); 5] = [
        (
            "package-lock.json",
            r#"{"lockfileVersion":2,"packages":{}}"#,
        ),
        ("package-lock.json", r#"{"packages":{}}"#),
        ("pnpm-lock.yaml", "lockfileVersion: 5.3\npackages: {}\n"),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ("yarn.lock", "__metadata:\n  version: 6\n"),
    ];
    for (name, text) in cases {
        let (_dir, d) = lockfile_in_tempdir(name, text.as_bytes());
        assert_eq!(d, Discovered::default(), "{name}: {text}");
    }
}

#[test]
fn requirements_files_are_matched_by_one_glob_table() {
    let dir = tempfile::tempdir().unwrap();
    let read = [
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "requirements/prod.txt",
        "svc/requirements.txt",
    ];
    let ignored = [
        "requirements.md",
        "notes.txt",
        "other/base.txt",
        "req.txt",
        "requirements/deeper/x.txt",
    ];
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    fs::create_dir_all(dir.path().join("svc")).unwrap();
    fs::create_dir_all(dir.path().join("other")).unwrap();
    fs::create_dir_all(dir.path().join("requirements/deeper")).unwrap();
    for (i, f) in read.iter().chain(&ignored).enumerate() {
        fs::write(dir.path().join(f), format!("pkg{i}==1.0\n")).unwrap();
    }
    let d = discover(dir.path());
    let mut files: Vec<_> = d.packages.iter().map(|p| p.file.as_str()).collect();
    files.sort();
    let mut want = read.to_vec();
    want.sort();
    assert_eq!(files, want);
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_reported_so_its_lockfiles_are_not_silently_missed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::copy(
        fixture("npm-one").join("package-lock.json"),
        locked.join("package-lock.json"),
    )
    .unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let d = discover(dir.path());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    assert_unparsed(&d, "locked", UnparsedReason::WalkError);
}
