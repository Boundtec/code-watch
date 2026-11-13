use super::{ASK_USER, Adapter, Call, Decision, Policy, Reply, UNCHECKED, WarnAnswer, pretool};

pub struct Codex;

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
                WarnAnswer::Deny => (
                    Some(pretool::decision("deny", format!("{reason} {ASK_USER}"))),
                    None,
                ),
                WarnAnswer::Allow => (None, Some(reason)),
            },
        };
        Reply::new(stdout, stderr)
    }
}
