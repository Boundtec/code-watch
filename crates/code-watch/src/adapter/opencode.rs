//! The OpenCode plugin: the only non-Rust file code-watch ships. It runs `code-watch adapter
//! opencode` with an argument array and throws on a deny.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, bail};

const TEMPLATE: &str = include_str!("opencode-plugin.js");
const MARKER: &str = "// code-watch managed plugin";

/// The plugin text for this binary. `fail_open` is baked in both as an adapter flag and as the
/// plugin's own answer when it cannot run the adapter at all.
pub fn render(exe: &Path, fail_open: bool) -> anyhow::Result<String> {
    let mut argv = vec![
        exe.to_string_lossy().into_owned(),
        "adapter".into(),
        "opencode".into(),
    ];
    if fail_open {
        argv.push("--fail-open".into());
    }
    Ok(TEMPLATE
        .replace("__ARGV__", &serde_json::to_string(&argv)?)
        .replace("__FAIL_OPEN__", if fail_open { "true" } else { "false" }))
}

/// Writes the plugin to `path`, replacing it only when it is one we wrote. Never creates the
/// parent directory: a wrong path is an error, not a new folder tree.
pub fn install(path: &Path, text: &str) -> anyhow::Result<&'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        bail!("the directory {} does not exist", parent.display());
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
    fs::write(path, text).with_context(|| format!("could not write {}", path.display()))?;
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
        let text = render(exe, false).unwrap();
        assert_eq!(
            argv_of(&text),
            ["/opt/my \"tools\"/code-watch", "adapter", "opencode"]
        );
        assert!(text.contains("Bun.spawn(ARGV,"));
        assert!(text.contains("const FAIL_OPEN = false"));
        assert!(!text.contains("__"));
    }

    #[test]
    fn the_plugin_throws_on_deny_and_never_goes_through_a_shell() {
        let text = render(Path::new("/x"), false).unwrap();
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
        let text = render(Path::new("/x"), false).unwrap();
        let exit_check = text.find("if (code !== 0) throw").unwrap();
        let empty_check = text.find(r#"text.trim() === """#).unwrap();
        assert!(text.contains("const code = await proc.exited"));
        assert!(exit_check < empty_check);
        let catch = text.find("catch (e)").unwrap();
        assert!(exit_check < catch && text.contains("if (FAIL_OPEN) return"));
    }

    #[test]
    fn fail_open_is_baked_into_the_argv_and_the_plugin() {
        let text = render(Path::new("/x"), true).unwrap();
        assert_eq!(argv_of(&text), ["/x", "adapter", "opencode", "--fail-open"]);
        assert!(text.contains("const FAIL_OPEN = true"));
    }

    #[test]
    fn install_writes_replaces_ours_and_refuses_a_foreign_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("code-watch.js");
        assert_eq!(
            install(&path, &render(Path::new("/a"), false).unwrap()).unwrap(),
            "wrote"
        );
        assert_eq!(
            install(&path, &render(Path::new("/b"), false).unwrap()).unwrap(),
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
}
