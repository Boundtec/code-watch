use std::path::PathBuf;

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Adapter, Call, CursorClean, Decision, Policy, Reply, UNCHECKED, UNCHECKED_ALLOWED};

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

/// `user_message` is shown to the user and `agent_message` goes to the model, so only the
/// former may say how to allow a command.
fn output(permission: &'static str, user: Option<String>, agent: Option<String>) -> Value {
    json!(Output {
        permission,
        user_message: user,
        agent_message: agent,
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

    /// Cursor has no "no opinion" reply (anything but a valid permission blocks), and an allow
    /// may skip its own approval prompt, so a clean result is an ask unless `--cursor-clean allow`.
    fn reply(&self, decision: Decision, policy: &Policy) -> Reply {
        let clean = |user: Option<String>| match policy.cursor_clean {
            CursorClean::Ask => output("ask", user, None),
            CursorClean::Allow => output("allow", user, None),
        };
        let stdout = match decision {
            Decision::Unchecked {
                detail,
                closed: true,
            } => output(
                "deny",
                Some(format!(
                    "{detail}. Use --fail-open to allow commands code-watch cannot check."
                )),
                Some(UNCHECKED.into()),
            ),
            Decision::Unchecked {
                detail,
                closed: false,
            } => clean(Some(format!("{UNCHECKED_ALLOWED} {detail}."))),
            Decision::Allow => match policy.cursor_clean {
                CursorClean::Ask => output("ask", None, None),
                CursorClean::Allow => output("allow", None, None),
            },
            Decision::Ask { reason, allow_hint } => {
                output("ask", Some(format!("{reason} {allow_hint}")), Some(reason))
            }
            Decision::Deny(reason) => output("deny", Some(reason.clone()), Some(reason)),
        };
        Reply::new(Some(stdout), None)
    }
}
