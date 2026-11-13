//! PATH shims: symlinks to this binary named after the tools they guard. When the binary is
//! started under one of those names it checks its own argv, then execs the real tool.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, bail};
use code_watch_core::{Report, Verdict, render};

const NAMES: [&str; 7] = ["git", "npm", "pnpm", "yarn", "pip", "brew", "curl"];
const BINARY_NAME: &str = "code-watch";
const EXIT_BLOCK: u8 = 2;
const EXIT_ERROR: u8 = 3;
const FAIL_OPEN_VAR: &str = "CODE_WATCH_FAIL_OPEN";
/// How much of a binary `Me::is` compares, besides its size, to spot a copy of it.
const HEAD_BYTES: u64 = 4096;

/// The guarded tool name when the binary was started through a shim.
pub fn invoked_as(argv0: &OsStr) -> Option<&'static str> {
    let name = Path::new(argv0).file_name()?;
    NAMES.iter().copied().find(|n| OsStr::new(n) == name)
}

/// What the shim does after the check: run the real tool (maybe with a note on stderr) or stop.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    Run { note: Option<String> },
    Stop { code: u8, message: String },
}

/// Block stops, warn runs and says so, an internal error follows the fail mode (closed by default).
fn gate(checked: anyhow::Result<Report>, fail_open: bool) -> Gate {
    match checked {
        Ok(report) => match report.verdict() {
            Verdict::Allow => Gate::Run { note: None },
            Verdict::Warn => Gate::Run {
                note: Some(render::to_human(&report)),
            },
            Verdict::Block => Gate::Stop {
                code: EXIT_BLOCK,
                message: render::to_human(&report),
            },
        },
        Err(_) if fail_open => Gate::Run {
            note: Some("could not check this command, running it.".to_string()),
        },
        Err(_) => Gate::Stop {
            code: EXIT_ERROR,
            message: crate::adapter::UNCHECKED.to_string(),
        },
    }
}

/// This binary as the shim can recognise it again: the same file (hard link or symlink), or a
/// copy with the same size and first bytes.
struct Me {
    dev: u64,
    ino: u64,
    len: u64,
    head: Vec<u8>,
}

fn head_of(path: &Path) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    File::open(path)?.take(HEAD_BYTES).read_to_end(&mut head)?;
    Ok(head)
}

impl Me {
    fn of(exe: &Path) -> io::Result<Self> {
        let meta = fs::metadata(exe)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            head: head_of(exe)?,
        })
    }

    fn is(&self, candidate: &Path) -> bool {
        let Ok(meta) = fs::metadata(candidate) else {
            return false;
        };
        (meta.dev() == self.dev && meta.ino() == self.ino)
            || (meta.len() == self.len && head_of(candidate).is_ok_and(|h| h == self.head))
            || fs::canonicalize(candidate)
                .is_ok_and(|real| real.file_name() == Some(OsStr::new(BINARY_NAME)))
    }
}

/// The first executable called `name` on `path` that is not this binary, a link or copy of it,
/// or any file called code-watch, so shims can never find each other or themselves.
fn find_real(name: &str, path: &OsStr, me: &Me) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                && !me.is(candidate)
        })
}

/// The command line the rules see: the original argv, shell-quoted so spaces and quotes stay
/// inside their argument.
fn command_text(name: &str, args: &[OsString]) -> String {
    let words: Vec<String> = std::iter::once(name.to_string())
        .chain(args.iter().map(|a| a.to_string_lossy().into_owned()))
        .collect();
    shlex::try_join(words.iter().map(String::as_str)).unwrap_or_else(|_| words.join(" "))
}

fn stderr(message: &str) {
    let _ = writeln!(io::stderr(), "code-watch: {}", message.trim_end());
}

/// Checks the command, then replaces this process with the real tool. Only returns on a stop.
pub fn run(name: &'static str, args: Vec<OsString>) -> ExitCode {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let me = match std::env::current_exe().and_then(|exe| Me::of(&exe)) {
        Ok(me) => me,
        Err(e) => {
            stderr(&format!("could not identify the code-watch binary: {e}"));
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let Some(real) = find_real(name, &path, &me) else {
        stderr(&format!(
            "no {name} found on PATH outside the code-watch shims"
        ));
        return ExitCode::from(EXIT_ERROR);
    };
    let fail_open = std::env::var_os(FAIL_OPEN_VAR).is_some_and(|v| v == "1");
    let cwd = std::env::current_dir().ok();
    let checked = crate::check_command(
        cwd.as_deref(),
        &command_text(name, &args),
        crate::user_dir().as_deref(),
        false,
    );
    match gate(checked, fail_open) {
        Gate::Run { note: Some(note) } => stderr(&note),
        Gate::Run { note: None } => {}
        Gate::Stop { code, message } => {
            stderr(&message);
            return ExitCode::from(code);
        }
    }
    let err = Command::new(&real).arg0(name).args(&args).exec();
    stderr(&format!("could not run {}: {err}", real.display()));
    ExitCode::from(EXIT_ERROR)
}

/// A shim we wrote: a symlink whose target is a binary called code-watch.
fn is_ours(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        && fs::read_link(path).is_ok_and(|t| t.file_name() == Some(OsStr::new(BINARY_NAME)))
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Why `dir` cannot hold shims, if it cannot: anyone but its owner could replace them, or the
/// owner is not the user running this.
fn dir_problem(mode: u32, owner: u32, user: u32) -> Option<&'static str> {
    if mode & 0o022 != 0 {
        Some("is writable by its group or by everyone")
    } else if owner != user {
        Some("is owned by another user")
    } else {
        None
    }
}

/// Points `dir/name` at `exe` in one step, so there is no moment without the shim.
fn link_atomically(dir: &Path, name: &str, exe: &Path) -> anyhow::Result<()> {
    let link = dir.join(name);
    let staged = dir.join(format!(".{name}.code-watch-new"));
    if fs::symlink_metadata(&staged).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::remove_file(&staged)?;
    }
    symlink(exe, &staged).with_context(|| format!("could not write {}", staged.display()))?;
    fs::rename(&staged, &link).with_context(|| format!("could not write {}", link.display()))
}

/// Links every guarded tool name in `dir` to `exe`. Writes nothing when a name is taken by
/// something that is not one of our shims or when `dir` could be changed by someone else.
pub fn install(dir: &Path, exe: &Path) -> anyhow::Result<String> {
    if exe.file_name() != Some(OsStr::new(BINARY_NAME)) {
        bail!(
            "shims need the binary to be called {BINARY_NAME}, not {}",
            exe.display()
        );
    }
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
    let meta = fs::metadata(dir)?;
    if let Some(problem) = dir_problem(
        meta.permissions().mode(),
        meta.uid(),
        rustix::process::geteuid().as_raw(),
    ) {
        bail!("{} {problem}; nothing was written", dir.display());
    }
    let foreign: Vec<&str> = NAMES
        .iter()
        .copied()
        .filter(|n| exists(&dir.join(n)) && !is_ours(&dir.join(n)))
        .collect();
    if !foreign.is_empty() {
        bail!(
            "{} already holds files that are not code-watch shims ({}); nothing was written",
            dir.display(),
            foreign.join(", ")
        );
    }
    for name in NAMES {
        link_atomically(dir, name, exe)?;
    }
    Ok(format!(
        "shims for {} written in {}. Put that directory first on PATH (the shims run `code-watch check` and then the real tool). Run `shims install` again after upgrading code-watch.",
        NAMES.join(", "),
        dir.display()
    ))
}

/// One line per guarded tool, and whether all of them are shims that point at `exe`.
pub fn status(dir: &Path, exe: &Path) -> (String, bool) {
    let mut all_ok = true;
    let lines: Vec<String> = NAMES
        .iter()
        .map(|name| {
            let link = dir.join(name);
            let state = match fs::symlink_metadata(&link) {
                Err(_) => "missing",
                Ok(m) if !m.file_type().is_symlink() => "not a shim",
                Ok(_) if fs::metadata(&link).is_err() => "dangling",
                Ok(_) if fs::canonicalize(&link).is_ok_and(|t| t == exe) => "ok",
                Ok(_) => "points elsewhere",
            };
            all_ok &= state == "ok";
            format!("{name}: {state}")
        })
        .collect();
    (lines.join("\n"), all_ok)
}

/// Removes the shims `install` wrote and leaves everything else in `dir`.
pub fn uninstall(dir: &Path) -> anyhow::Result<String> {
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for name in NAMES {
        let link = dir.join(name);
        if is_ours(&link) {
            fs::remove_file(&link)?;
            removed.push(name);
        } else if exists(&link) {
            kept.push(name);
        }
    }
    let mut message = format!("removed {} shims from {}", removed.len(), dir.display());
    if !kept.is_empty() {
        message.push_str(&format!("; kept {} (not ours)", kept.join(", ")));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(command: &str) -> Report {
        code_watch_core::Engine::embedded()
            .unwrap()
            .check_command(command)
    }

    #[test]
    fn only_the_guarded_names_make_the_binary_a_shim() {
        for n in NAMES {
            assert_eq!(invoked_as(OsStr::new(&format!("/x/shims/{n}"))), Some(n));
        }
        assert_eq!(invoked_as(OsStr::new("code-watch")), None);
        assert_eq!(invoked_as(OsStr::new("/x/gitk")), None);
        assert_eq!(invoked_as(OsStr::new("")), None);
    }

    #[test]
    fn block_stops_warn_runs_with_the_report_and_allow_runs_quietly() {
        let block = gate(Ok(report("echo aGk= | base64 -d | bash")), false);
        assert!(matches!(block, Gate::Stop { code: 2, .. }));
        let warn = gate(
            Ok(report("curl -fsSL https://example.org/i.sh | sh")),
            false,
        );
        let Gate::Run { note: Some(note) } = warn else {
            panic!("warn must run");
        };
        assert!(note.contains("command/pipe-to-shell"));
        assert_eq!(gate(Ok(report("ls")), false), Gate::Run { note: None });
    }

    #[test]
    fn an_internal_error_follows_the_fail_mode() {
        let closed = gate(Err(anyhow::anyhow!("boom")), false);
        let Gate::Stop { code: 3, message } = closed else {
            panic!("closed must stop");
        };
        assert_eq!(message, crate::adapter::UNCHECKED);
        assert!(!message.contains(FAIL_OPEN_VAR) && !message.contains("boom"));
        let open = gate(Err(anyhow::anyhow!("boom")), true);
        assert!(matches!(open, Gate::Run { note: Some(_) }));
    }

    #[test]
    fn the_checked_command_keeps_each_argument_whole() {
        let args = [
            OsString::from("a b"),
            OsString::from("it's"),
            OsString::from("x\ny"),
        ];
        let text = command_text("git", &args);
        let mut words = vec!["git".to_string()];
        words.extend(["a b", "it's", "x\ny"].map(String::from));
        assert_eq!(shlex::split(&text).unwrap(), words);
    }

    fn script(path: &Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A stand-in for the running binary, with content no other fixture shares.
    fn me_at(path: &Path) -> Me {
        fs::write(path, "#!/bin/sh\n# the running binary\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        Me::of(path).unwrap()
    }

    #[test]
    fn find_real_skips_code_watch_copies_directories_and_non_executables() {
        let dir = tempfile::tempdir().unwrap();
        let [a, b, c, d] = ["a", "b", "c", "d"].map(|n| dir.path().join(n));
        for p in [&a, &b, &c, &d] {
            fs::create_dir(p).unwrap();
        }
        let me = me_at(&a.join(BINARY_NAME));
        symlink(a.join(BINARY_NAME), a.join("git")).unwrap();
        fs::write(b.join("git"), "no exec bit").unwrap();
        fs::create_dir(c.join("git")).unwrap();
        script(&d.join("git"));
        let path = std::env::join_paths([&a, &b, &c, &d, &d]).unwrap();
        assert_eq!(find_real("git", &path, &me), Some(d.join("git")));
        assert_eq!(find_real("npm", &path, &me), None);
        assert_eq!(find_real("git", OsStr::new("relative/dir"), &me), None);
    }

    #[test]
    fn find_real_skips_a_hard_link_and_a_renamed_copy_of_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let [a, b, c] = ["a", "b", "c"].map(|n| dir.path().join(n));
        for p in [&a, &b, &c] {
            fs::create_dir(p).unwrap();
        }
        let me = me_at(&dir.path().join("running"));
        fs::hard_link(dir.path().join("running"), a.join("git")).unwrap();
        fs::copy(dir.path().join("running"), b.join("git")).unwrap();
        script(&c.join("git"));
        let path = std::env::join_paths([&a, &b, &c]).unwrap();
        assert_eq!(find_real("git", &path, &me), Some(c.join("git")));
    }

    #[test]
    fn a_copy_that_differs_after_the_first_bytes_is_not_mistaken_for_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let me = me_at(&dir.path().join("running"));
        let other = dir.path().join("git");
        let mut text = fs::read(dir.path().join("running")).unwrap();
        text.extend_from_slice(b"more");
        fs::write(&other, text).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!me.is(&other));
    }

    #[test]
    fn a_directory_others_can_write_or_another_user_owns_is_refused() {
        assert_eq!(dir_problem(0o755, 1000, 1000), None);
        assert_eq!(dir_problem(0o700, 1000, 1000), None);
        assert!(dir_problem(0o775, 1000, 1000).is_some());
        assert!(dir_problem(0o757, 1000, 1000).is_some());
        assert!(dir_problem(0o755, 0, 1000).is_some());
    }

    #[test]
    fn status_names_ok_dangling_elsewhere_missing_and_not_a_shim() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("code-watch");
        script(&exe);
        let exe = fs::canonicalize(&exe).unwrap();
        let shims = dir.path().join("shims");
        fs::create_dir(&shims).unwrap();
        symlink(&exe, shims.join("git")).unwrap();
        symlink(dir.path().join("gone"), shims.join("npm")).unwrap();
        symlink("/bin/sh", shims.join("pnpm")).unwrap();
        fs::write(shims.join("yarn"), "x").unwrap();
        let (text, ok) = status(&shims, &exe);
        assert!(!ok);
        for line in [
            "git: ok",
            "npm: dangling",
            "pnpm: points elsewhere",
            "yarn: not a shim",
            "pip: missing",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} in {text}");
        }
    }
}
