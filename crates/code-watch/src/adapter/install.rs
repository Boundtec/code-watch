//! The settings snippet each agent needs. Printed, never written into the agent's own files.

use std::path::Path;

use anyhow::bail;
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
                    "command": line("claude-code")?,
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
        Agent::Gemini => (
            json!({"hooks": {"BeforeTool": [{
                "matcher": "run_shell_command",
                "hooks": [{"type": "command", "name": "code-watch", "command": line("gemini")?}],
            }]}}),
            "~/.gemini/settings.json",
        ),
        Agent::Opencode => bail!(
            "opencode has no settings snippet: use `code-watch install-adapter opencode <path>` or --print"
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
            (Agent::Gemini, "gemini"),
        ] {
            let (value, file) = snippet(agent, exe).unwrap();
            let text = value.to_string();
            assert!(text.contains("/opt/my tools/code-watch"), "{name}");
            assert!(!text.contains("\"args\""), "{name}");
            assert!(text.contains(name), "{name}");
            assert!(file.starts_with("~/."));
        }
    }

    #[test]
    fn the_command_is_one_shell_quoted_string_with_the_agent_name() {
        let exe = Path::new("/opt/my tools/code-watch");
        let command = |agent, name: &str| {
            let (value, _) = snippet(agent, exe).unwrap();
            let node = match agent {
                Agent::Cursor => &value["hooks"]["beforeShellExecution"][0],
                Agent::Gemini => &value["hooks"]["BeforeTool"][0]["hooks"][0],
                _ => &value["hooks"]["PreToolUse"][0]["hooks"][0],
            };
            (
                shlex::split(node["command"].as_str().unwrap()).unwrap(),
                name.to_string(),
            )
        };
        for (agent, name) in [
            (Agent::ClaudeCode, "claude-code"),
            (Agent::Cursor, "cursor"),
            (Agent::Codex, "codex"),
            (Agent::Gemini, "gemini"),
        ] {
            let (words, name) = command(agent, name);
            assert_eq!(
                words,
                ["/opt/my tools/code-watch", "adapter", name.as_str()]
            );
        }
    }

    #[test]
    fn the_claude_code_snippet_keeps_on_failure_block() {
        let (value, _) = snippet(Agent::ClaudeCode, Path::new("/x")).unwrap();
        assert_eq!(
            value["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "block"
        );
    }
}
