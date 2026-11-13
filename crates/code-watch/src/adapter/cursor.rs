use std::path::PathBuf;

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Adapter, Call, Decision, Policy, Reply};

pub struct Cursor;

#[derive(Deserialize)]
struct Input {
    command: Option<String>,
    cwd: Option<String>,
}

#[derive(Serialize)]
struct Output {
    permission: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_message: Option<String>,
}

fn output(permission: &'static str, message: Option<String>) -> Value {
    json!(Output {
        permission,
        user_message: message.clone(),
        agent_message: message,
    })
}

impl Adapter for Cursor {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        if stdin.iter().all(u8::is_ascii_whitespace) {
            return Err(anyhow!("the hook input is empty"));
        }
        let input: Input =
            serde_json::from_slice(stdin).context("the hook input is not valid JSON")?;
        let command = input
            .command
            .ok_or_else(|| anyhow!("the hook input has no command"))?;
        Ok(Call::Shell {
            command,
            cwd: input.cwd.map(PathBuf::from),
        })
    }

    /// Cursor has no "no opinion" reply (anything but a valid permission blocks), so a clean
    /// result is an explicit allow; see docs/adapters.md.
    fn reply(&self, decision: Decision, _: &Policy) -> Reply {
        let stdout = match decision {
            Decision::Allow => output("allow", None),
            Decision::Ask { reason, .. } => output("ask", Some(reason)),
            Decision::Deny(reason) => output("deny", Some(reason)),
        };
        Reply {
            stdout: Some(stdout),
            stderr: None,
        }
    }
}
