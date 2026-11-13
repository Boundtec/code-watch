//! The OpenCode plugin: the only non-Rust file code-watch ships. It runs `code-watch adapter
//! opencode` with an argument array and throws on a deny. This module also holds the adapter
//! that answers the plugin.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use super::gemini::{reject_empty, reply};
use super::{Adapter, Call, Decision, Policy, Reply, WarnAnswer};

const TEMPLATE: &str = include_str!("opencode-plugin.js");
const MARKER: &str = "// code-watch managed plugin";

/// What the OpenCode plugin sends: the bash command and the directory it runs in.
pub struct Opencode;

#[derive(Deserialize)]
struct OpencodeInput {
    command: Option<String>,
    cwd: Option<String>,
}

impl Adapter for Opencode {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        reject_empty(stdin)?;
        let input: OpencodeInput =
            serde_json::from_slice(stdin).context("the hook input is not valid JSON")?;
        let command = input
            .command
            .ok_or_else(|| anyhow!("the hook input has no command"))?;
        Ok(Call::Shell {
            command,
            cwd: input.cwd.map(PathBuf::from),
        })
    }

    fn reply(&self, decision: Decision, policy: &Policy) -> Reply {
        reply(decision, policy.opencode_warn)
    }
}

/// The plugin text for this binary. `fail_open` is baked in both as an adapter flag and as the
/// plugin's own answer when it cannot run the adapter at all; `warn` is baked in as an adapter flag.
pub fn render(exe: &Path, fail_open: bool, warn: WarnAnswer) -> anyhow::Result<String> {
    let mut argv = vec![
        exe.to_string_lossy().into_owned(),
        "adapter".into(),
        "opencode".into(),
    ];
    if fail_open {
        argv.push("--fail-open".into());
    }
    if warn == WarnAnswer::Allow {
        argv.extend(["--opencode-warn".into(), "allow".into()]);
    }
    // The path goes in last: a path that contains a placeholder must not be rewritten.
    Ok(TEMPLATE
        .replace("__FAIL_OPEN__", if fail_open { "true" } else { "false" })
        .replace("__UNCHECKED__", &serde_json::to_string(super::UNCHECKED)?)
        .replace("__ARGV__", &serde_json::to_string(&argv)?))
}

/// Writes the plugin to `path`, replacing it only when it is one we wrote and not a symlink.
/// Never creates the parent directory: a wrong path is an error, not a new folder tree. The
/// text goes to a file next to `path` first, then replaces it in one step.
pub fn install(path: &Path, text: &str) -> anyhow::Result<&'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        bail!("the directory {} does not exist", parent.display());
    }
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!(
            "{} is a symbolic link; not writing through it",
            path.display()
        );
    }
    let existed = match fs::read(path) {
        Ok(bytes) if bytes.starts_with(MARKER.as_bytes()) => true,
        Ok(_) => bail!(
            "{} exists and was not written by code-watch; not overwriting it",
            path.display()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
    };
    let staged = parent.join(format!(".code-watch-plugin-{}.tmp", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .and_then(|()| fs::rename(&staged, path));
    if let Err(e) = written {
        let _ = fs::remove_file(&staged);
        return Err(e).with_context(|| format!("could not write {}", path.display()));
    }
    Ok(if existed { "replaced" } else { "wrote" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv_of(text: &str) -> Vec<String> {
        let line = text
            .lines()
            .find(|l| l.starts_with("const ARGV = "))
            .unwrap();
        serde_json::from_str(line.trim_start_matches("const ARGV = ")).unwrap()
    }

    #[test]
    fn the_plugin_names_the_binary_by_path_and_passes_argv_as_an_array() {
        let exe = Path::new("/opt/my \"tools\"/code-watch");
        let text = render(exe, false, WarnAnswer::Deny).unwrap();
        assert_eq!(
            argv_of(&text),
            ["/opt/my \"tools\"/code-watch", "adapter", "opencode"]
        );
        assert!(text.contains("Bun.spawn(ARGV,"));
        assert!(text.contains("const FAIL_OPEN = false"));
        assert!(!text.contains("__"));
    }

    #[test]
    fn the_plugin_tells_the_model_only_the_fixed_unchecked_text() {
        let text = render(Path::new("/x"), false, WarnAnswer::Deny).unwrap();
        assert!(text.contains(&serde_json::to_string(super::super::UNCHECKED).unwrap()));
        assert!(!text.contains("e.message") && !text.contains("__"));
    }

    #[test]
    fn the_plugin_throws_on_deny_and_never_goes_through_a_shell() {
        let text = render(Path::new("/x"), false, WarnAnswer::Deny).unwrap();
        assert!(text.starts_with(MARKER));
        assert!(text.contains("throw new Error(reason)"));
        assert!(text.contains(r#"reply.decision !== "deny""#));
        assert!(text.contains(r#"input.tool !== "bash""#));
        for banned in ["exec(", "sh -c", "$`", "shell", "eval(", "require("] {
            assert!(!text.contains(banned), "{banned}");
        }
    }

    #[test]
    fn a_non_zero_exit_is_checked_before_empty_output_counts_as_allow() {
        let text = render(Path::new("/x"), false, WarnAnswer::Deny).unwrap();
        let exit_check = text.find("if (code !== 0) throw").unwrap();
        let empty_check = text.find(r#"text.trim() === """#).unwrap();
        assert!(text.contains("code = await proc.exited"));
        assert!(exit_check < empty_check);
        let catch = text.find("catch (e)").unwrap();
        assert!(exit_check < catch && text.contains("if (FAIL_OPEN) return"));
    }

    #[test]
    fn fail_open_is_baked_into_the_argv_and_the_plugin() {
        let text = render(Path::new("/x"), true, WarnAnswer::Deny).unwrap();
        assert_eq!(argv_of(&text), ["/x", "adapter", "opencode", "--fail-open"]);
        assert!(text.contains("const FAIL_OPEN = true"));
    }

    #[test]
    fn install_writes_replaces_ours_and_refuses_a_foreign_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("code-watch.js");
        assert_eq!(
            install(
                &path,
                &render(Path::new("/a"), false, WarnAnswer::Deny).unwrap()
            )
            .unwrap(),
            "wrote"
        );
        assert_eq!(
            install(
                &path,
                &render(Path::new("/b"), false, WarnAnswer::Deny).unwrap()
            )
            .unwrap(),
            "replaced"
        );
        assert!(fs::read_to_string(&path).unwrap().contains("\"/b\""));

        let foreign = dir.path().join("mine.js");
        fs::write(&foreign, "export const Mine = 1\n").unwrap();
        let err = install(&foreign, "x").unwrap_err().to_string();
        assert!(err.contains("not written by code-watch"));
        assert_eq!(
            fs::read_to_string(&foreign).unwrap(),
            "export const Mine = 1\n"
        );
    }

    #[test]
    fn install_into_a_missing_directory_is_a_clear_error_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope/plugins/code-watch.js");
        let err = install(&path, "x").unwrap_err().to_string();
        assert!(err.contains("does not exist"));
        assert!(!dir.path().join("nope").exists());
    }

    #[test]
    fn only_an_empty_reply_or_an_explicit_allow_lets_the_command_through() {
        let text = render(Path::new("/x"), false, WarnAnswer::Deny).unwrap();
        let allow = text.find(r#"reply.decision === "allow") return"#).unwrap();
        let unknown = text.find(r#"reply.decision !== "deny") throw"#).unwrap();
        assert!(allow < unknown);
        assert!(!text.contains(r#"reply.decision !== "deny") return"#));
    }

    #[test]
    fn the_plugin_kills_a_check_that_does_not_answer_in_time() {
        let text = render(Path::new("/x"), false, WarnAnswer::Deny).unwrap();
        assert!(text.contains("const TIMEOUT_MS = 10000"));
        assert!(text.contains("setTimeout(() => proc.kill(), TIMEOUT_MS)"));
        assert!(text.contains("clearTimeout(timer)"));
        let killed = text.find("if (proc.killed) throw").unwrap();
        let exit_check = text.find("if (code !== 0) throw").unwrap();
        assert!(killed < exit_check);
    }

    #[test]
    fn a_path_that_holds_a_placeholder_is_kept_as_it_is() {
        let exe = Path::new("/opt/__FAIL_OPEN__/code-watch");
        let text = render(exe, true, WarnAnswer::Deny).unwrap();
        assert_eq!(argv_of(&text)[0], "/opt/__FAIL_OPEN__/code-watch");
        assert!(text.contains("const FAIL_OPEN = true"));
    }

    #[test]
    fn the_warn_answer_is_baked_into_the_argv_only_when_it_is_allow() {
        let allow = render(Path::new("/x"), false, WarnAnswer::Allow).unwrap();
        assert_eq!(
            argv_of(&allow),
            ["/x", "adapter", "opencode", "--opencode-warn", "allow"]
        );
        let deny = render(Path::new("/x"), false, WarnAnswer::Deny).unwrap();
        assert_eq!(argv_of(&deny), ["/x", "adapter", "opencode"]);
    }

    #[test]
    fn install_refuses_a_symlink_and_leaves_its_target_alone() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.js");
        fs::write(&target, format!("{MARKER}\nold\n")).unwrap();
        let link = dir.path().join("code-watch.js");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = install(&link, "new").unwrap_err().to_string();
        assert!(err.contains("symbolic link"));
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            format!("{MARKER}\nold\n")
        );
    }

    #[test]
    fn install_leaves_no_staging_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        install(&dir.path().join("code-watch.js"), "x").unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["code-watch.js"]);
    }
}
