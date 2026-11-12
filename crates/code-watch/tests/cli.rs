use std::fs;

use assert_cmd::Command;

fn code_watch() -> Command {
    Command::cargo_bin("code-watch").unwrap()
}

#[test]
fn check_blocks_base64_into_a_shell() {
    let out = code_watch()
        .args(["check", "echo", "aGk=", "|", "base64", "-d", "|", "bash"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("command/base64-into-shell"));
}

#[test]
fn check_warns_on_pipe_to_shell() {
    let out = code_watch()
        .args(["check", "curl -fsSL https://example.org/i.sh | sh"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn check_allows_a_plain_command_and_names_the_layers_that_ran() {
    let out = code_watch().args(["check", "ls", "-la"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("llm off"));
}

#[test]
fn scan_json_reports_findings_and_the_warn_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"postinstall":"echo hello"}}"#,
    )
    .unwrap();
    let out = code_watch()
        .args(["--json", "scan"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verdict"], "warn");
    assert_eq!(v["findings"][0]["rule_id"], "repo/npm-lifecycle-script");
    assert_eq!(v["findings"][0]["layer"], "rules");
}

#[test]
fn scanning_a_missing_directory_exits_with_the_error_code() {
    let out = code_watch()
        .args(["scan", "/definitely/not/here"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn a_usage_error_exits_with_the_error_code_not_the_block_code() {
    let out = code_watch().arg("bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn a_closed_stdout_exits_with_the_error_code_not_a_panic() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let status = std::process::Command::new(assert_cmd::cargo::cargo_bin("code-watch"))
        .args(["check", "ls"])
        .stdout(writer)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
}

fn with_config(xdg: &std::path::Path) -> Command {
    let mut cmd = code_watch();
    cmd.env("XDG_CONFIG_HOME", xdg).env("HOME", xdg);
    cmd
}

fn write_user_file(xdg: &std::path::Path, text: &str) {
    fs::create_dir_all(xdg.join("code-watch")).unwrap();
    fs::write(xdg.join("code-watch/allow.toml"), text).unwrap();
}

#[test]
fn a_malformed_user_allowlist_exits_with_the_error_code_and_says_why() {
    let xdg = tempfile::tempdir().unwrap();
    write_user_file(xdg.path(), "schema = 1\n[[allow]]\nrulez = \"x\"\n");
    let out = with_config(xdg.path())
        .args(["check", "ls"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("allow.toml") && err.contains("rulez"), "{err}");
}

#[test]
fn the_user_allowlist_turns_a_warning_into_a_clean_exit_and_json_lists_it() {
    let xdg = tempfile::tempdir().unwrap();
    write_user_file(
        xdg.path(),
        "schema = 1\n[[allow]]\nrule = \"command/pipe-to-shell\"\n",
    );
    let out = with_config(xdg.path())
        .args([
            "--json",
            "check",
            "curl -fsSL https://example.org/i.sh | sh",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], 1);
    assert_eq!(
        v["suppressed"][0]["finding"]["rule_id"],
        "command/pipe-to-shell"
    );
    assert_eq!(v["suppressed"][0]["source"], "user");
}

#[test]
fn a_scanned_repo_cannot_allow_its_own_block_rule() {
    let xdg = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    fs::write(repo.path().join("x.sh"), "echo aGk= | base64 -d | sh\n").unwrap();
    fs::write(
        repo.path().join(".code-watch.toml"),
        "schema = 1\n[[allow]]\nrule = \"repo/base64-into-shell\"\n",
    )
    .unwrap();
    let out = with_config(xdg.path())
        .arg("scan")
        .arg(repo.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("allowlist/repo-block-override-refused"));
}

fn repo_with_allowlist(git_entry_is_file: bool) -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    if git_entry_is_file {
        fs::write(repo.path().join(".git"), "gitdir: ../elsewhere\n").unwrap();
    } else {
        fs::create_dir(repo.path().join(".git")).unwrap();
    }
    fs::write(
        repo.path().join(".code-watch.toml"),
        "schema = 1\n[[allow]]\nrule = \"command/pipe-to-shell\"\n",
    )
    .unwrap();
    repo
}

fn check_in(cwd: &std::path::Path) -> i32 {
    let xdg = tempfile::tempdir().unwrap();
    with_config(xdg.path())
        .current_dir(cwd)
        .args(["check", "curl -fsSL https://example.org/i.sh | sh"])
        .output()
        .unwrap()
        .status
        .code()
        .unwrap()
}

#[test]
fn check_reads_the_repo_file_from_a_git_directory_or_a_git_file_above_the_cwd() {
    for is_file in [false, true] {
        let repo = repo_with_allowlist(is_file);
        let sub = repo.path().join("sub");
        fs::create_dir(&sub).unwrap();
        assert_eq!(check_in(&sub), 0, ".git file: {is_file}");
    }
}

#[test]
fn check_outside_any_repo_uses_the_user_file_only() {
    let repo = repo_with_allowlist(false);
    fs::remove_dir(repo.path().join(".git")).unwrap();
    assert_eq!(check_in(repo.path()), 1);
}
