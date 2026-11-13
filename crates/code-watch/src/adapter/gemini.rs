//! Gemini CLI `BeforeTool` and the OpenCode plugin share one reply: JSON with `decision` and
//! `reason` on stdout, nothing for "no opinion". Gemini has no ask, so a warning is a deny that
//! says what lets it through, or, with `--gemini-warn allow`, a run with the reason on stderr.

use std::path::PathBuf;

use anyhow::{Context, anyhow};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Adapter, Call, Decision, Policy, Reply, WarnAnswer};

const SHELL_TOOL: &str = "run_shell_command";

pub struct Gemini;

/// What the OpenCode plugin sends: the bash command and the directory it runs in.
pub struct Opencode;

#[derive(Deserialize)]
struct GeminiInput {
    tool_name: Option<String>,
    tool_input: Option<Value>,
    cwd: Option<String>,
}

#[derive(Deserialize)]
struct OpencodeInput {
    command: Option<String>,
    cwd: Option<String>,
}

fn reject_empty(stdin: &[u8]) -> anyhow::Result<()> {
    if stdin.iter().all(u8::is_ascii_whitespace) {
        return Err(anyhow!("the hook input is empty"));
    }
    Ok(())
}

fn reply(decision: Decision, policy: &Policy) -> Reply {
    let deny = |reason: String| Some(json!({"decision": "deny", "reason": reason}));
    let (stdout, stderr) = match decision {
        Decision::Allow => (None, None),
        Decision::Deny(reason) => (deny(reason), None),
        Decision::Ask { reason, allow_hint } => match policy.gemini_warn {
            WarnAnswer::Deny => (deny(format!("{reason} {allow_hint}")), None),
            WarnAnswer::Allow => (None, Some(reason)),
        },
    };
    Reply { stdout, stderr }
}

impl Adapter for Gemini {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        reject_empty(stdin)?;
        let input: GeminiInput =
            serde_json::from_slice(stdin).context("the hook input is not valid JSON")?;
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

    fn reply(&self, decision: Decision, policy: &Policy) -> Reply {
        reply(decision, policy)
    }
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
        reply(decision, policy)
    }
}
