use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Every hook we wrote starts its marker line with this; `MARKER` adds the script's version.
const MARKER_PREFIX: &str = "# code-watch managed hook";
const MARKER: &str = "# code-watch managed hook v2";
const KEY: &str = "init.templateDir";

/// Directory that holds our template (and nothing of the user's).
fn template_dir() -> Result<PathBuf> {
    let var = |name| std::env::var_os(name).map(PathBuf::from);
    template_dir_from(var("XDG_DATA_HOME"), var("HOME"))
}

/// A relative `XDG_DATA_HOME` or `HOME` is ignored: the template would land in whatever
/// directory the command happened to run in.
fn template_dir_from(xdg: Option<PathBuf>, home: Option<PathBuf>) -> Result<PathBuf> {
    let data = xdg
        .filter(|p| p.is_absolute())
        .or_else(|| {
            home.filter(|h| h.is_absolute())
                .map(|h| h.join(".local/share"))
        })
        .context("neither an absolute XDG_DATA_HOME nor an absolute HOME is set")?;
    Ok(data.join("code-watch/git-template"))
}

/// Runs git outside any repository, so a repo-local config never leaks into the answer, and
/// returns its stdout, or None when it exits non-zero (an unset key does).
fn git(args: &[&str]) -> Result<Option<String>> {
    match Command::new("git").args(args).current_dir("/").output() {
        Ok(out) if out.status.success() => Ok(Some(
            String::from_utf8_lossy(&out.stdout).trim_end().to_owned(),
        )),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == ErrorKind::NotFound => bail!("git was not found on PATH"),
        Err(e) => Err(e).context("could not run git"),
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
/// The checkout path is attacker-chosen, so it is printed with control characters removed and
/// never inside a command someone could paste.
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
dir=$(printf '%s' "$PWD" | tr -d '\000-\037\177')
"$bin" scan --user-allow-only .
status=$?
case $status in
  0) exit 0 ;;
  1) printf 'code-watch: warnings above; review them before running anything in:\n%s\n' "$dir" >&2; exit 0 ;;
  2) printf 'code-watch: BLOCK. Do not open or run anything in this directory. Delete this directory:\n%s\n' "$dir" >&2; exit 2 ;;
  *) echo "code-watch: the scan failed (exit $status); the clone was not checked" >&2; exit 0 ;;
esac
"#
    )
}

fn is_ours(hook: &Path) -> bool {
    fs::read_to_string(hook).is_ok_and(|s| s.lines().any(|l| l.starts_with(MARKER_PREFIX)))
}

fn is_current(hook: &Path) -> bool {
    fs::read_to_string(hook).is_ok_and(|s| s.lines().any(|l| l == MARKER))
}

/// Removes our hook (only if it still carries the marker) and then every directory above it
/// that is left empty.
fn remove_template(dir: &Path) {
    let hooks = dir.join("hooks");
    let hook = hooks.join("post-checkout");
    if is_ours(&hook) {
        let _ = fs::remove_file(&hook);
    }
    let _ = fs::remove_dir(&hooks);
    let _ = fs::remove_dir(dir);
    if let Some(parent) = dir.parent() {
        let _ = fs::remove_dir(parent);
    }
}

/// Installs the hook into our own template dir and points the global `init.templateDir` at it.
/// Refuses, writing nothing, whenever git would not run the hook or a file there is not ours.
pub fn install(binary: &Path) -> Result<String> {
    let dir = template_dir()?;
    let ours = dir.to_string_lossy().into_owned();
    if git(&["config", "--get", "core.hooksPath"])?.is_some() {
        bail!(
            "core.hooksPath is set: git ignores template hooks while it is, so the hook would never run"
        );
    }
    if std::env::var_os("GIT_TEMPLATE_DIR").is_some() {
        bail!(
            "GIT_TEMPLATE_DIR is set in the environment and overrides init.templateDir, so the hook would never run"
        );
    }
    let current = global_template_dir()?;
    if let Some(other) = current.as_deref().filter(|c| *c != ours) {
        bail!(
            "init.templateDir already points at {other}; not changing it. Add `code-watch scan .` to a post-checkout hook there yourself"
        );
    }

    let hook = dir.join("hooks/post-checkout");
    let existed = hook.symlink_metadata().is_ok();
    let outdated = existed && !hook.is_symlink() && is_ours(&hook) && !is_current(&hook);
    if existed && (hook.is_symlink() || !is_ours(&hook)) {
        bail!(
            "{} exists and was not written by code-watch; not touching it",
            hook.display()
        );
    }
    fs::create_dir_all(hook.parent().unwrap_or(&dir))
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let staged = hook.with_extension("new");
    let _ = fs::remove_file(&staged);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&staged)
        .and_then(|mut f| f.write_all(hook_script(binary).as_bytes()))
        .and_then(|()| fs::rename(&staged, &hook))
        .with_context(|| format!("cannot write {}", hook.display()))?;

    if current.is_none() {
        git(&["config", "--global", KEY, &ours])?;
    }
    if git(&["config", "--get", KEY])?.as_deref() != Some(ours.as_str()) {
        if current.is_none() {
            git(&["config", "--global", "--unset", KEY])?;
        }
        if !existed {
            remove_template(&dir);
        }
        bail!(
            "a setting outside the global git config overrides init.templateDir, so the hook would never run; nothing was left behind"
        );
    }
    Ok(if outdated {
        "updated from an older version; the hook was rewritten".into()
    } else if current.is_some() {
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
    remove_template(&dir);
    Ok("uninstalled".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_data_home_or_home_is_ignored() {
        let dir = |xdg: Option<&str>, home: Option<&str>| {
            template_dir_from(xdg.map(PathBuf::from), home.map(PathBuf::from)).ok()
        };
        let want = |p: &str| Some(PathBuf::from(p).join("code-watch/git-template"));
        assert_eq!(dir(Some("/x"), Some("/h")), want("/x"));
        assert_eq!(dir(Some("rel"), Some("/h")), want("/h/.local/share"));
        assert_eq!(dir(Some(""), Some("/h")), want("/h/.local/share"));
        assert_eq!(dir(None, Some("rel")), None);
        assert_eq!(dir(Some("rel"), None), None);
    }
}
