//! PATH shims: symlinks to this binary named after the tools they guard. When the binary is
//! started under one of those names it checks its own argv, then execs the real tool.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
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
/// Set to the tool name on the exec, so a shim of the same tool met further down the chain
/// runs the real tool without checking the same command twice. Other tools are still checked.
const NESTED_VAR: &str = "CODE_WATCH_SHIM";

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
        Err(e) if fail_open => Gate::Run {
            note: Some(format!("could not check this command, running it: {e:#}")),
        },
        Err(e) => Gate::Stop {
            code: EXIT_ERROR,
            message: format!(
                "could not check this command: {e:#}. Set {FAIL_OPEN_VAR}=1 to run commands it cannot check."
            ),
        },
    }
}

/// The first executable called `name` on `path` that is not a code-watch binary or a link to
/// one (any copy), so shims can never find each other.
fn find_real(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| {
            let executable = fs::metadata(candidate)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
            executable
                && fs::canonicalize(candidate)
                    .is_ok_and(|real| real.file_name() != Some(OsStr::new(BINARY_NAME)))
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
    let Some(real) = find_real(name, &path) else {
        stderr(&format!(
            "no {name} found on PATH outside the code-watch shims"
        ));
        return ExitCode::from(EXIT_ERROR);
    };
    let nested = std::env::var_os(NESTED_VAR).is_some_and(|v| v == name);
    if !nested {
        let fail_open = std::env::var_os(FAIL_OPEN_VAR).is_some_and(|v| v == "1");
        let cwd = std::env::current_dir().ok();
        let checked = crate::check_command(
            cwd.as_deref(),
            &command_text(name, &args),
            crate::user_dir().as_deref(),
        );
        match gate(checked, fail_open) {
            Gate::Run { note: Some(note) } => stderr(&note),
            Gate::Run { note: None } => {}
            Gate::Stop { code, message } => {
                stderr(&message);
                return ExitCode::from(code);
            }
        }
    }
    let err = Command::new(&real)
        .arg0(name)
        .args(&args)
        .env(NESTED_VAR, name)
        .exec();
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

/// Links every guarded tool name in `dir` to `exe`. Writes nothing when a name is taken by
/// something that is not one of our shims.
pub fn install(dir: &Path, exe: &Path) -> anyhow::Result<String> {
    if exe.file_name() != Some(OsStr::new(BINARY_NAME)) {
        bail!(
            "shims need the binary to be called {BINARY_NAME}, not {}",
            exe.display()
        );
    }
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
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
        let link = dir.join(name);
        if exists(&link) {
            fs::remove_file(&link)?;
        }
        symlink(exe, &link).with_context(|| format!("could not write {}", link.display()))?;
    }
    Ok(format!(
        "shims for {} written in {}. Put that directory first on PATH (the shims run `code-watch check` and then the real tool).",
        NAMES.join(", "),
        dir.display()
    ))
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
        assert!(message.contains(FAIL_OPEN_VAR));
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

    #[test]
    fn find_real_skips_code_watch_copies_directories_and_non_executables() {
        let dir = tempfile::tempdir().unwrap();
        let [a, b, c, d] = ["a", "b", "c", "d"].map(|n| dir.path().join(n));
        for p in [&a, &b, &c, &d] {
            fs::create_dir(p).unwrap();
        }
        script(&a.join(BINARY_NAME));
        symlink(a.join(BINARY_NAME), a.join("git")).unwrap();
        fs::write(b.join("git"), "no exec bit").unwrap();
        fs::create_dir(c.join("git")).unwrap();
        script(&d.join("git"));
        let path = std::env::join_paths([&a, &b, &c, &d, &d]).unwrap();
        assert_eq!(find_real("git", &path), Some(d.join("git")));
        assert_eq!(find_real("npm", &path), None);
        assert_eq!(find_real("git", OsStr::new("relative/dir")), None);
    }
}
