use super::{Adapter, Call, CodexWarn, Decision, Policy, Reply, UNCHECKED, pretool};

pub struct Codex;

const USER_CAN_ALLOW: &str = "Ask the user before trying again.";

impl Adapter for Codex {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        pretool::parse(stdin)
    }

    /// Codex does not support `ask` yet, so a warn is a deny, or, with `--codex-warn allow`, the
    /// empty reply plus the reason on stderr. Its one channel is read by the model, so the deny
    /// never says how to allow the command: that is for the user's own settings only.
    fn reply(&self, decision: Decision, policy: &Policy) -> Reply {
        let (stdout, stderr) = match decision {
            Decision::Allow => (None, None),
            Decision::Deny(reason) => (Some(pretool::decision("deny", reason)), None),
            Decision::Unchecked { closed, .. } => (
                closed.then(|| pretool::decision("deny", UNCHECKED.into())),
                None,
            ),
            Decision::Ask { reason, .. } => match policy.codex_warn {
                CodexWarn::Deny => (
                    Some(pretool::decision(
                        "deny",
                        format!("{reason} {USER_CAN_ALLOW}"),
                    )),
                    None,
                ),
                CodexWarn::Allow => (None, Some(reason)),
            },
        };
        Reply::new(stdout, stderr)
    }
}
