use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MARKER: &str = "# code-watch managed hook";
const KEY: &str = "init.templateDir";

/// Failure that stops install or uninstall; the message is printed as is and the exit code is 3.
#[derive(Debug)]
pub struct HookError(pub String);

type Result<T> = std::result::Result<T, HookError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(HookError(message.into()))
}

/// Directory that holds our template (and nothing of the user's).
fn template_dir() -> Result<PathBuf> {
    let var = |name| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let data = var("XDG_DATA_HOME")
        .or_else(|| var("HOME").map(|h| h.join(".local/share")))
        .ok_or_else(|| HookError("neither XDG_DATA_HOME nor HOME is set".into()))?;
    Ok(data.join("code-watch/git-template"))
}

/// Runs git and returns its stdout, or None when it exits non-zero (an unset key does).
fn git(args: &[&str]) -> Result<Option<String>> {
    match Command::new("git").args(args).output() {
        Ok(out) if out.status.success() => Ok(Some(
            String::from_utf8_lossy(&out.stdout).trim_end().to_owned(),
        )),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == ErrorKind::NotFound => err("git was not found on PATH"),
        Err(e) => err(format!("could not run git: {e}")),
    }
}

fn global_template_dir() -> Result<Option<String>> {
    git(&["config", "--global", "--get", KEY])
}

fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The post-checkout script. It scans only when the previous HEAD is all zeros (a clone or
/// `worktree add`), whatever the hash length, and fails visibly when the binary is gone.
fn hook_script(binary: &Path) -> String {
    let bin = single_quote(&binary.to_string_lossy());
    format!(
        r#"#!/bin/sh
{MARKER}
case "$1" in ''|*[!0]*) exit 0 ;; esac
bin={bin}
if [ ! -x "$bin" ]; then bin=$(command -v code-watch) || bin=; fi
if [ -z "$bin" ]; then
  echo "code-watch: binary not found; run 'code-watch install-hook' again" >&2
  exit 0
fi
"$bin" scan .
status=$?
case $status in
  0) exit 0 ;;
  1) echo "code-watch: warnings above; review them before running anything in $PWD" >&2; exit 0 ;;
  2) printf "code-watch: BLOCK. Do not open or run anything here. Delete it: rm -rf '%s'\n" "$PWD" >&2; exit 2 ;;
  *) echo "code-watch: the scan failed (exit $status); the clone was not checked" >&2; exit 0 ;;
esac
"#
    )
}

/// Installs the hook into our own template dir and points the global `init.templateDir` at it.
/// Refuses, writing nothing, whenever git would not run the hook or the key is not ours.
pub fn install(binary: &Path) -> Result<String> {
    let dir = template_dir()?;
    let ours = dir.to_string_lossy().into_owned();
    if git(&["config", "--get", "core.hooksPath"])?.is_some() {
        return err(
            "core.hooksPath is set: git ignores template hooks while it is, so the hook would never run",
        );
    }
    if std::env::var_os("GIT_TEMPLATE_DIR").is_some() {
        return err(
            "GIT_TEMPLATE_DIR is set in the environment and overrides init.templateDir, so the hook would never run",
        );
    }
    let current = global_template_dir()?;
    if let Some(other) = current.as_deref().filter(|c| *c != ours) {
        return err(format!(
            "init.templateDir already points at {other}; not changing it. Add `code-watch scan .` to a post-checkout hook there yourself"
        ));
    }

    let hooks = dir.join("hooks");
    fs::create_dir_all(&hooks)
        .map_err(|e| HookError(format!("cannot create {}: {e}", hooks.display())))?;
    let hook = hooks.join("post-checkout");
    fs::write(&hook, hook_script(binary))
        .map_err(|e| HookError(format!("cannot write {}: {e}", hook.display())))?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))
        .map_err(|e| HookError(format!("cannot make {} executable: {e}", hook.display())))?;

    if current.is_none() {
        git(&["config", "--global", KEY, &ours])?;
    }
    if git(&["config", "--get", KEY])?.as_deref() != Some(ours.as_str()) {
        if current.is_none() {
            git(&["config", "--global", "--unset", KEY])?;
        }
        return err(
            "a setting outside the global git config overrides init.templateDir, so the hook would never run; nothing was changed",
        );
    }
    Ok(if current.is_some() {
        "already installed; hook refreshed".into()
    } else {
        format!(
            "installed: new clones are scanned (hook in {})",
            hook.display()
        )
    })
}

/// Undoes install, and only that: nothing happens unless `init.templateDir` is exactly ours.
pub fn uninstall() -> Result<String> {
    let dir = template_dir()?;
    if global_template_dir()?.as_deref() != Some(&*dir.to_string_lossy()) {
        return Ok("init.templateDir is not code-watch's (or not set); nothing to do".into());
    }
    git(&["config", "--global", "--unset", KEY])?;
    let hooks = dir.join("hooks");
    let hook = hooks.join("post-checkout");
    if fs::read_to_string(&hook).is_ok_and(|s| s.lines().any(|l| l == MARKER)) {
        let _ = fs::remove_file(&hook);
    }
    let _ = fs::remove_dir(&hooks);
    let _ = fs::remove_dir(&dir);
    Ok("uninstalled".into())
}
