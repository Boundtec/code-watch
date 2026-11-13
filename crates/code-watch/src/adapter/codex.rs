use super::{Adapter, Call, CodexWarn, Decision, Policy, Reply, pretool};

pub struct Codex;

const USER_CAN_ALLOW: &str = "The user can allow this command in their code-watch settings.";

impl Adapter for Codex {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        pretool::parse(stdin)
    }

    /// Codex does not support `ask` yet, so a warn is a deny, or, with `--codex-warn allow`, the
    /// empty reply plus the reason on stderr. Its one channel is read by the model, so the deny
    /// never carries the allow entry or the file: that is for the user's own settings only.
    fn reply(&self, decision: Decision, policy: &Policy) -> Reply {
        let (stdout, stderr) = match decision {
            Decision::Allow => (None, None),
            Decision::Deny(reason) => (Some(pretool::decision("deny", reason)), None),
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
