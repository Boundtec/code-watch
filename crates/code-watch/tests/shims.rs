use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;

/// A tempdir world: copies of the binary with their own shim dirs, fake "real" tools that
/// record their argv (NUL-separated) and exit with a chosen code, and a config dir.
struct World {
    root: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let w = Self {
            root: tempfile::tempdir().unwrap(),
        };
        for d in ["bin", "cfg"] {
            fs::create_dir(w.p(d)).unwrap();
        }
        w
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    /// A copy of code-watch named `code-watch` inside `dir`.
    fn copy_of_binary(&self, dir: &str) -> PathBuf {
        fs::create_dir_all(self.p(dir)).unwrap();
        let target = self.p(dir).join("code-watch");
        fs::copy(assert_cmd::cargo::cargo_bin("code-watch"), &target).unwrap();
        target
    }

    fn install_shims(&self, binary: &Path, dir: &str) {
        let out = Command::new(binary)
            .args(["shims", "install"])
            .arg(self.p(dir))
            .env("HOME", self.p("cfg"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A fake tool in `dir` that writes its argv to `<dir>/<name>.argv` and exits with `code`.
    fn fake_tool(&self, dir: &str, name: &str, code: i32) {
        fs::create_dir_all(self.p(dir)).unwrap();
        let path = self.p(dir).join(name);
        let log = self.p(&format!("{dir}/{name}.argv"));
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\0' \"$@\" > '{}'\nexit {code}\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn argv_seen(&self, dir: &str, name: &str) -> Option<Vec<Vec<u8>>> {
        let bytes = fs::read(self.p(&format!("{dir}/{name}.argv"))).ok()?;
        let mut words: Vec<Vec<u8>> = bytes.split(|b| *b == 0).map(<[u8]>::to_vec).collect();
        words.pop();
        Some(words)
    }

    fn path(&self, dirs: &[&str]) -> std::ffi::OsString {
        std::env::join_paths(dirs.iter().map(|d| self.p(d))).unwrap()
    }

    fn run(&self, shim: &str, args: &[&[u8]], path: &[&str], env: &[(&str, &str)]) -> Output {
        use std::os::unix::ffi::OsStrExt;
        let mut cmd = Command::new(self.p(shim));
        cmd.args(args.iter().map(|a| std::ffi::OsStr::from_bytes(a)))
            .env_clear()
            .env("PATH", self.path(path))
            .env("HOME", self.p("cfg"))
            .env("XDG_CONFIG_HOME", self.p("cfg"))
            .current_dir(self.root.path());
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_real_tool_runs_with_the_argv_unchanged_and_its_exit_code_comes_back() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    w.fake_tool("bin", "git", 7);
    let odd: [&[u8]; 6] = [
        b"commit",
        b"-m",
        b"a message with  spaces",
        b"it's \"quoted\"",
        b"line1\nline2",
        "ünï😀".as_bytes(),
    ];
    let out = w.run("shims/git", &odd, &["shims", "bin"], &[]);
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
    let seen = w.argv_seen("bin", "git").expect("the real git ran");
    assert_eq!(seen, odd.iter().map(|a| a.to_vec()).collect::<Vec<_>>());
}

#[test]
fn every_guarded_name_is_a_working_shim() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    for name in ["git", "npm", "pnpm", "yarn", "pip", "brew", "curl"] {
        w.fake_tool("bin", name, 0);
        let out = w.run(
            &format!("shims/{name}"),
            &[b"--version"],
            &["shims", "bin"],
            &[],
        );
        assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
        assert_eq!(
            w.argv_seen("bin", name),
            Some(vec![b"--version".to_vec()]),
            "{name}"
        );
    }
}

#[test]
fn no_real_tool_or_only_shims_is_a_clear_error_never_a_loop() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    for path in [&["bin"][..], &["shims"], &["shims", "shims", "shims"], &[]] {
        let out = w.run("shims/git", &[b"status"], path, &[]);
        assert_eq!(out.status.code(), Some(3), "{path:?}");
        assert!(stderr(&out).contains("no git found on PATH"), "{path:?}");
    }
}

#[test]
fn two_code_watch_copies_with_their_own_shim_dirs_do_not_exec_each_other() {
    let w = World::new();
    let a = w.copy_of_binary("cw-a");
    let b = w.copy_of_binary("cw-b");
    w.install_shims(&a, "shims-a");
    w.install_shims(&b, "shims-b");
    w.fake_tool("bin", "git", 0);
    let out = w.run(
        "shims-a/git",
        &[b"status"],
        &["shims-a", "shims-b", "bin"],
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(w.argv_seen("bin", "git").is_some());
    let out = w.run("shims-a/git", &[b"status"], &["shims-a", "shims-b"], &[]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn a_nested_shim_of_the_same_tool_runs_the_real_one_without_checking_again() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    w.fake_tool("bin", "curl", 0);
    fs::create_dir_all(w.p("cfg/code-watch")).unwrap();
    fs::write(w.p("cfg/code-watch/allow.toml"), "not toml [[").unwrap();
    let path = ["shims", "bin"];
    let checked = w.run("shims/curl", &[b"-V"], &path, &[]);
    assert_eq!(checked.status.code(), Some(3));
    let nested = w.run(
        "shims/curl",
        &[b"-V"],
        &path,
        &[("CODE_WATCH_SHIM", "curl")],
    );
    assert_eq!(nested.status.code(), Some(0), "{}", stderr(&nested));
    let other = w.run("shims/curl", &[b"-V"], &path, &[("CODE_WATCH_SHIM", "git")]);
    assert_eq!(other.status.code(), Some(3));
}

#[test]
fn a_warning_runs_the_real_tool_and_prints_the_report_on_stderr() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    w.fake_tool("bin", "curl", 0);
    let args: [&[u8]; 3] = [b"https://githuh.com/x", b"-o", b"i.sh"];
    let out = w.run("shims/curl", &args, &["shims", "bin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("command/lookalike-download-domain"));
    assert!(w.argv_seen("bin", "curl").is_some());
}

#[test]
fn a_clean_command_runs_without_any_output_from_code_watch() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    w.fake_tool("bin", "git", 0);
    let out = w.run("shims/git", &[b"status"], &["shims", "bin"], &[]);
    assert_eq!(stderr(&out), "");
}

#[test]
fn an_internal_error_stops_the_tool_unless_fail_open_is_set() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    w.fake_tool("bin", "git", 0);
    fs::create_dir_all(w.p("cfg/code-watch")).unwrap();
    fs::write(w.p("cfg/code-watch/allow.toml"), "not toml [[").unwrap();
    let path = ["shims", "bin"];
    let closed = w.run("shims/git", &[b"status"], &path, &[]);
    assert_eq!(closed.status.code(), Some(3));
    assert!(stderr(&closed).contains("CODE_WATCH_FAIL_OPEN"));
    assert_eq!(w.argv_seen("bin", "git"), None);
    let open = w.run(
        "shims/git",
        &[b"status"],
        &path,
        &[("CODE_WATCH_FAIL_OPEN", "1")],
    );
    assert_eq!(open.status.code(), Some(0), "{}", stderr(&open));
    assert!(stderr(&open).contains("running it"));
    assert!(w.argv_seen("bin", "git").is_some());
}

#[test]
fn install_twice_is_fine_and_uninstall_keeps_foreign_files() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    w.install_shims(&bin, "shims");
    w.install_shims(&bin, "shims");
    for n in ["git", "curl"] {
        assert!(
            fs::symlink_metadata(w.p(&format!("shims/{n}")))
                .unwrap()
                .is_symlink()
        );
    }
    fs::write(w.p("shims/notes.txt"), "mine").unwrap();
    fs::remove_file(w.p("shims/npm")).unwrap();
    fs::write(w.p("shims/npm"), "foreign").unwrap();
    let out = Command::new(&bin)
        .args(["shims", "uninstall"])
        .arg(w.p("shims"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("kept npm"));
    assert!(!w.p("shims/git").exists() && fs::symlink_metadata(w.p("shims/git")).is_err());
    assert_eq!(fs::read_to_string(w.p("shims/npm")).unwrap(), "foreign");
    assert_eq!(fs::read_to_string(w.p("shims/notes.txt")).unwrap(), "mine");
}

#[test]
fn install_over_a_foreign_file_or_foreign_link_writes_nothing() {
    let w = World::new();
    let bin = w.copy_of_binary("cw");
    fs::create_dir(w.p("shims")).unwrap();
    fs::write(w.p("shims/yarn"), "foreign").unwrap();
    symlink("/usr/bin/true", w.p("shims/pip")).unwrap();
    let out = Command::new(&bin)
        .args(["shims", "install"])
        .arg(w.p("shims"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("yarn, pip"));
    assert!(fs::symlink_metadata(w.p("shims/git")).is_err());
    assert_eq!(fs::read_to_string(w.p("shims/yarn")).unwrap(), "foreign");
}
