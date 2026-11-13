use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};

use tempfile::TempDir;

/// Held while an executable is written and while a child is spawned: a child forked by another
/// test thread keeps the write fd open until its exec, and exec of that file then fails with
/// ETXTBSY on Linux.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Command::output` with the spawn under the lock and the wait outside it.
fn output_of(cmd: &mut Command) -> Output {
    let child = {
        let _guard = spawn_lock();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child.wait_with_output().unwrap()
}

/// A fake home: every git call and every code-watch call in a test runs inside it, and the
/// real global git config is checked to be untouched when the test ends.
struct Sandbox {
    root: TempDir,
    bin: PathBuf,
    real: Vec<(PathBuf, Option<Vec<u8>>)>,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("home")).unwrap();
        let real_home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let real = [".gitconfig", ".config/git/config"]
            .map(|p| real_home.join(p))
            .into_iter()
            .map(|p| {
                let content = fs::read(&p).ok();
                (p, content)
            })
            .collect();
        let bin = root.path().join("tool dir/it's/code-watch");
        fs::create_dir_all(bin.parent().unwrap()).unwrap();
        {
            let _guard = spawn_lock();
            fs::copy(assert_cmd::cargo::cargo_bin("code-watch"), &bin).unwrap();
        }
        Sandbox { root, bin, real }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn gitconfig(&self) -> PathBuf {
        self.path("gitconfig")
    }

    fn isolate(&self, cmd: &mut Command) {
        cmd.current_dir(self.root.path())
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("xdg"))
            .env("XDG_DATA_HOME", self.path("data"))
            .env("GIT_CONFIG_GLOBAL", self.gitconfig())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_TEMPLATE_DIR")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.org")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.org");
    }

    fn code_watch(&self, args: &[&str]) -> Output {
        self.run(Command::new(&self.bin).args(args))
    }

    fn git(&self, args: &[&str]) -> Output {
        self.run(Command::new("git").args(args))
    }

    fn run(&self, cmd: &mut Command) -> Output {
        self.isolate(cmd);
        output_of(cmd)
    }

    fn config_value(&self, key: &str) -> Option<String> {
        let out = self.git(&["config", "--global", "--get", key]);
        out.status.success().then(|| text(&out.stdout))
    }

    fn template_hook(&self) -> PathBuf {
        self.path("data/code-watch/git-template/hooks/post-checkout")
    }

    /// A repository with one commit holding `files`, ready to be cloned.
    fn source_repo(&self, files: &[(&str, &str)]) -> PathBuf {
        self.source_repo_as(files, "sha1")
    }

    fn source_repo_as(&self, files: &[(&str, &str)], object_format: &str) -> PathBuf {
        let dir = self.path("src");
        fs::create_dir(&dir).unwrap();
        for (name, content) in files {
            fs::write(dir.join(name), content).unwrap();
        }
        let d = dir.to_str().unwrap();
        assert!(
            self.git(&[
                "-C",
                d,
                "init",
                "-q",
                "-b",
                "main",
                &format!("--object-format={object_format}")
            ])
            .status
            .success()
        );
        assert!(self.git(&["-C", d, "add", "."]).status.success());
        assert!(
            self.git(&["-C", d, "commit", "-q", "-m", "i"])
                .status
                .success()
        );
        dir
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        for (path, before) in &self.real {
            assert_eq!(&fs::read(path).ok(), before, "{} changed", path.display());
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end().to_owned()
}

fn both(out: &Output) -> String {
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

const OTHER_KEYS: &str = "# my settings\n[user]\n\tname = someone\n[core]\n\teditor = vi\n";
const LIFECYCLE: (&str, &str) = ("package.json", r#"{"scripts":{"postinstall":"echo hi"}}"#);
const BLOCKER: (&str, &str) = ("setup.sh", "echo aGk= | base64 -d | bash\n");

#[test]
fn install_then_uninstall_restores_a_config_with_other_keys_byte_for_byte() {
    let sb = Sandbox::new();
    fs::write(sb.gitconfig(), OTHER_KEYS).unwrap();
    let out = sb.code_watch(&["install-hook"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(
        sb.config_value("init.templateDir")
            .unwrap()
            .ends_with("code-watch/git-template")
    );
    assert!(sb.template_hook().is_file());
    let out = sb.code_watch(&["uninstall-hook"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert_eq!(fs::read_to_string(sb.gitconfig()).unwrap(), OTHER_KEYS);
    assert!(!sb.path("data/code-watch").exists());
}

#[test]
fn with_no_global_file_uninstall_leaves_an_empty_one_that_git_created() {
    let sb = Sandbox::new();
    assert!(sb.code_watch(&["install-hook"]).status.success());
    assert!(sb.code_watch(&["uninstall-hook"]).status.success());
    assert_eq!(fs::read_to_string(sb.gitconfig()).unwrap(), "");
}

#[test]
fn a_foreign_template_dir_is_refused_and_its_hook_survives() {
    let sb = Sandbox::new();
    let theirs = sb.path("theirs");
    fs::create_dir_all(theirs.join("hooks")).unwrap();
    let hook = theirs.join("hooks/post-checkout");
    fs::write(&hook, "#!/bin/sh\necho mine\n").unwrap();
    let config = format!("{OTHER_KEYS}[init]\n\ttemplateDir = {}\n", theirs.display());
    fs::write(sb.gitconfig(), &config).unwrap();

    let out = sb.code_watch(&["install-hook"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(both(&out).contains("already points at"));
    assert_eq!(fs::read_to_string(sb.gitconfig()).unwrap(), config);
    assert_eq!(fs::read_to_string(&hook).unwrap(), "#!/bin/sh\necho mine\n");
    assert!(!sb.template_hook().exists());

    let out = sb.code_watch(&["uninstall-hook"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(both(&out).contains("nothing to do"));
    assert_eq!(fs::read_to_string(sb.gitconfig()).unwrap(), config);
}

#[test]
fn installing_twice_changes_nothing_the_second_time() {
    let sb = Sandbox::new();
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let config = fs::read(sb.gitconfig()).unwrap();
    let hook = fs::read(sb.template_hook()).unwrap();
    let out = sb.code_watch(&["install-hook"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(both(&out).contains("already installed"));
    assert_eq!(fs::read(sb.gitconfig()).unwrap(), config);
    assert_eq!(fs::read(sb.template_hook()).unwrap(), hook);
    let leftovers: Vec<_> = fs::read_dir(sb.template_hook().parent().unwrap())
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(leftovers, ["post-checkout"]);
}

#[test]
fn uninstall_without_install_changes_nothing_and_says_so() {
    let sb = Sandbox::new();
    fs::write(sb.gitconfig(), OTHER_KEYS).unwrap();
    let out = sb.code_watch(&["uninstall-hook"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(both(&out).contains("nothing to do"));
    assert_eq!(fs::read_to_string(sb.gitconfig()).unwrap(), OTHER_KEYS);
}

#[test]
fn uninstall_after_the_user_changed_the_template_dir_leaves_it_alone() {
    let sb = Sandbox::new();
    assert!(sb.code_watch(&["install-hook"]).status.success());
    assert!(
        sb.git(&["config", "--global", "init.templateDir", "/somewhere/else"])
            .status
            .success()
    );
    let out = sb.code_watch(&["uninstall-hook"]);
    assert!(both(&out).contains("nothing to do"));
    assert_eq!(
        sb.config_value("init.templateDir").as_deref(),
        Some("/somewhere/else")
    );
}

#[test]
fn without_git_on_the_path_install_exits_with_the_error_code() {
    let sb = Sandbox::new();
    let empty = sb.path("empty");
    fs::create_dir(&empty).unwrap();
    for sub in ["install-hook", "uninstall-hook"] {
        let out = sb.run(Command::new(&sb.bin).arg(sub).env("PATH", &empty));
        assert_eq!(out.status.code(), Some(3));
        assert!(both(&out).contains("git was not found"));
    }
}

#[test]
fn core_hooks_path_makes_install_refuse_and_write_nothing() {
    let sb = Sandbox::new();
    fs::write(sb.gitconfig(), "[core]\n\thooksPath = /hooks\n").unwrap();
    let out = sb.code_watch(&["install-hook"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(both(&out).contains("core.hooksPath"));
    assert!(sb.config_value("init.templateDir").is_none());
    assert!(!sb.path("data").exists());
}

#[test]
fn an_environment_template_dir_makes_install_refuse_and_write_nothing() {
    let sb = Sandbox::new();
    let mut cmd = Command::new(&sb.bin);
    cmd.arg("install-hook");
    sb.isolate(&mut cmd);
    let out = output_of(cmd.env("GIT_TEMPLATE_DIR", sb.path("env-tpl")));
    assert_eq!(out.status.code(), Some(3));
    assert!(both(&out).contains("GIT_TEMPLATE_DIR"));
    assert!(sb.config_value("init.templateDir").is_none());
    assert!(!sb.path("data").exists());
}

fn clone(sb: &Sandbox, src: &Path) -> (Output, PathBuf) {
    let dst = sb.path("dst");
    let out = sb.git(&["clone", src.to_str().unwrap(), dst.to_str().unwrap()]);
    (out, dst)
}

#[test]
fn cloning_a_repo_with_warnings_prints_them_and_succeeds() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[LIFECYCLE]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let (out, dst) = clone(&sb, &src);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    let shown = both(&out);
    assert!(shown.contains("repo/npm-lifecycle-script"), "{shown}");
    assert!(shown.contains("review them"), "{shown}");
    assert!(dst.join("package.json").is_file());
}

#[test]
fn cloning_a_blocked_repo_prints_the_verdict_and_leaves_the_clone_on_disk() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[BLOCKER]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let (out, dst) = clone(&sb, &src);
    let shown = both(&out);
    assert!(shown.contains("BLOCK"), "{shown}");
    assert_eq!(
        out.status.code(),
        Some(2),
        "git passes the hook exit code through"
    );
    assert!(dst.join("setup.sh").is_file());
}

#[test]
fn the_hook_runs_a_binary_whose_path_has_a_space_and_a_quote() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[LIFECYCLE]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let script = fs::read_to_string(sb.template_hook()).unwrap();
    assert!(script.contains(r"it'\''s"), "{script}");
    let (out, _) = clone(&sb, &src);
    assert!(both(&out).contains("repo/npm-lifecycle-script"));
}

#[test]
fn a_moved_binary_fails_visibly_without_failing_the_clone() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[BLOCKER]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    fs::remove_file(&sb.bin).unwrap();
    let (out, dst) = clone(&sb, &src);
    assert_eq!(out.status.code(), Some(0));
    assert!(both(&out).contains("binary not found"));
    assert!(dst.is_dir());
}

#[test]
fn a_branch_checkout_does_not_scan() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[LIFECYCLE]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let (_, dst) = clone(&sb, &src);
    let d = dst.to_str().unwrap();
    assert!(
        sb.git(&["-C", d, "checkout", "-q", "-b", "other"])
            .status
            .success()
    );
    let out = sb.git(&["-C", d, "checkout", "main"]);
    assert!(!both(&out).contains("code-watch"), "{}", both(&out));
    assert!(!both(&out).contains("repo/"), "{}", both(&out));
}

/// The part of the output the hook printed after its BLOCK line.
fn after_block(out: &Output) -> Vec<u8> {
    let err = &out.stderr;
    let at = err
        .windows(5)
        .position(|w| w == b"BLOCK")
        .expect("BLOCK line");
    err[at..].to_vec()
}

#[test]
fn the_block_advice_never_builds_a_command_from_the_checkout_path() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[BLOCKER]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let name = "x';touch PWNED;'y$(x)\u{1b}[31m";
    let dst = sb.path(name);
    let out = sb.git(&["clone", src.to_str().unwrap(), dst.to_str().unwrap()]);
    let advice = after_block(&out);
    assert!(
        advice
            .iter()
            .all(|b| *b == b'\n' || (*b >= 0x20 && *b != 0x7f)),
        "raw control bytes in {advice:?}"
    );
    let advice = String::from_utf8(advice).unwrap();
    assert!(!advice.contains("rm -rf"), "{advice}");
    let last = advice.lines().last().unwrap();
    assert!(last.ends_with("x';touch PWNED;'y$(x)[31m"), "{advice}");
    assert!(!sb.path("PWNED").exists() && !dst.join("PWNED").exists());
}

#[test]
fn a_sha256_clone_is_scanned() {
    let sb = Sandbox::new();
    let src = sb.source_repo_as(&[LIFECYCLE], "sha256");
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let (out, _) = clone(&sb, &src);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(
        both(&out).contains("repo/npm-lifecycle-script"),
        "{}",
        both(&out)
    );
}

#[test]
fn an_override_outside_the_global_config_rolls_the_install_back_completely() {
    let sb = Sandbox::new();
    fs::write(sb.gitconfig(), OTHER_KEYS).unwrap();
    let mut cmd = Command::new(&sb.bin);
    cmd.arg("install-hook");
    sb.isolate(&mut cmd);
    let out = output_of(
        cmd.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "init.templateDir")
            .env("GIT_CONFIG_VALUE_0", sb.path("elsewhere")),
    );
    assert_eq!(out.status.code(), Some(3), "{}", both(&out));
    assert!(both(&out).contains("overrides init.templateDir"));
    assert_eq!(fs::read_to_string(sb.gitconfig()).unwrap(), OTHER_KEYS);
    assert!(!sb.path("data/code-watch").exists());
}

#[test]
fn uninstall_keeps_a_hook_the_user_replaced() {
    let sb = Sandbox::new();
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let theirs = "#!/bin/sh\necho theirs\n";
    fs::write(sb.template_hook(), theirs).unwrap();
    assert!(sb.code_watch(&["uninstall-hook"]).status.success());
    assert!(sb.config_value("init.templateDir").is_none());
    assert_eq!(fs::read_to_string(sb.template_hook()).unwrap(), theirs);
}

#[test]
fn a_repo_local_hooks_path_does_not_block_the_install() {
    let sb = Sandbox::new();
    let repo = sb.path("husky-repo");
    fs::create_dir(&repo).unwrap();
    let r = repo.to_str().unwrap();
    assert!(sb.git(&["-C", r, "init", "-q"]).status.success());
    assert!(
        sb.git(&["-C", r, "config", "core.hooksPath", ".husky"])
            .status
            .success()
    );
    let mut cmd = Command::new(&sb.bin);
    cmd.arg("install-hook");
    sb.isolate(&mut cmd);
    let out = output_of(cmd.current_dir(&repo));
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
}

#[test]
fn a_hook_file_we_did_not_write_is_never_overwritten() {
    let sb = Sandbox::new();
    fs::create_dir_all(sb.template_hook().parent().unwrap()).unwrap();
    let theirs = "#!/bin/sh\necho theirs\n";
    fs::write(sb.template_hook(), theirs).unwrap();
    let out = sb.code_watch(&["install-hook"]);
    assert_eq!(out.status.code(), Some(3), "{}", both(&out));
    assert_eq!(fs::read_to_string(sb.template_hook()).unwrap(), theirs);
    assert!(sb.config_value("init.templateDir").is_none());
}

#[test]
fn a_symlinked_hook_is_refused_and_its_target_is_untouched() {
    let sb = Sandbox::new();
    let target = sb.path("target-hook");
    let content = "#!/bin/sh\n# code-watch managed hook\necho target\n";
    fs::write(&target, content).unwrap();
    fs::create_dir_all(sb.template_hook().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, sb.template_hook()).unwrap();
    let out = sb.code_watch(&["install-hook"]);
    assert_eq!(out.status.code(), Some(3), "{}", both(&out));
    assert!(sb.template_hook().is_symlink());
    assert_eq!(fs::read_to_string(&target).unwrap(), content);
}

#[test]
fn a_moved_binary_is_found_again_on_the_path() {
    let sb = Sandbox::new();
    let src = sb.source_repo(&[LIFECYCLE]);
    assert!(sb.code_watch(&["install-hook"]).status.success());
    let on_path = sb.path("on-path");
    fs::create_dir(&on_path).unwrap();
    fs::rename(&sb.bin, on_path.join("code-watch")).unwrap();
    let path = format!("{}:{}", on_path.display(), std::env::var("PATH").unwrap());
    let dst = sb.path("dst");
    let mut cmd = Command::new("git");
    cmd.args(["clone", src.to_str().unwrap(), dst.to_str().unwrap()]);
    sb.isolate(&mut cmd);
    let out = output_of(cmd.env("PATH", path));
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(
        both(&out).contains("repo/npm-lifecycle-script"),
        "{}",
        both(&out)
    );
}
