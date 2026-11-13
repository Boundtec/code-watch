//! The PreToolUse hook shape shared by Claude Code and Codex CLI.

use std::path::PathBuf;

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Call;

const SHELL_TOOL: &str = "Bash";

#[derive(Deserialize)]
struct Input {
    tool_name: Option<String>,
    tool_input: Option<Value>,
    cwd: Option<String>,
}

pub fn parse(stdin: &[u8]) -> anyhow::Result<Call> {
    if stdin.iter().all(u8::is_ascii_whitespace) {
        return Err(anyhow!("the hook input is empty"));
    }
    let input: Input = serde_json::from_slice(stdin).context("the hook input is not valid JSON")?;
    let tool = input
        .tool_name
        .ok_or_else(|| anyhow!("the hook input has no tool_name"))?;
    if tool != SHELL_TOOL {
        return Ok(Call::Skip);
    }
    let command = input
        .tool_input
        .as_ref()
        .and_then(|t| t.get("command"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the hook input has no tool_input.command"))?;
    Ok(Call::Shell {
        command: command.to_string(),
        cwd: input.cwd.map(PathBuf::from),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    hook_specific_output: Specific,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Specific {
    hook_event_name: &'static str,
    permission_decision: &'static str,
    permission_decision_reason: String,
}

/// The reply that makes the agent ask the user (`ask`) or refuse (`deny`).
pub fn decision(permission: &'static str, reason: String) -> Value {
    json!(Output {
        hook_specific_output: Specific {
            hook_event_name: "PreToolUse",
            permission_decision: permission,
            permission_decision_reason: reason,
        },
    })
}
