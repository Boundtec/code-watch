//! The settings snippet each agent needs. Printed, never written into the agent's own files.

use std::path::Path;

use serde_json::{Value, json};

use super::Agent;

/// The JSON to merge into the agent's settings file, and where that file lives.
pub fn snippet(agent: Agent, exe: &Path) -> anyhow::Result<(Value, &'static str)> {
    let exe_text = exe.to_string_lossy().into_owned();
    let line = |name: &str| shlex::try_join([exe_text.as_str(), "adapter", name]);
    Ok(match agent {
        Agent::ClaudeCode => (
            json!({"hooks": {"PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": exe_text,
                    "args": ["adapter", "claude-code"],
                    "onFailure": "block",
                }],
            }]}}),
            "~/.claude/settings.json",
        ),
        Agent::Cursor => (
            json!({"version": 1, "hooks": {"beforeShellExecution": [{
                "command": line("cursor")?,
                "failClosed": true,
            }]}}),
            "~/.cursor/hooks.json",
        ),
        Agent::Codex => (
            json!({"hooks": {"PreToolUse": [{
                "matcher": "^Bash$",
                "hooks": [{"type": "command", "command": line("codex")?}],
            }]}}),
            "~/.codex/hooks.json",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_snippet_names_the_binary_and_the_agent() {
        let exe = Path::new("/opt/my tools/code-watch");
        for (agent, name) in [
            (Agent::ClaudeCode, "claude-code"),
            (Agent::Cursor, "cursor"),
            (Agent::Codex, "codex"),
        ] {
            let (value, file) = snippet(agent, exe).unwrap();
            let text = value.to_string();
            assert!(text.contains("/opt/my tools/code-watch"), "{name}");
            assert!(text.contains(name), "{name}");
            assert!(file.starts_with("~/."));
        }
    }

    #[test]
    fn a_shell_style_command_quotes_a_path_with_spaces() {
        let (value, _) = snippet(Agent::Cursor, Path::new("/opt/my tools/code-watch")).unwrap();
        let cmd = value["hooks"]["beforeShellExecution"][0]["command"]
            .as_str()
            .unwrap();
        assert_eq!(
            shlex::split(cmd).unwrap(),
            ["/opt/my tools/code-watch", "adapter", "cursor"]
        );
    }
}
