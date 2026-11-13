use super::{Adapter, Call, Decision, Policy, Reply, WarnAnswer, pretool};

pub struct Codex;

impl Adapter for Codex {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        pretool::parse(stdin)
    }

    /// Codex does not support `ask` yet, so a warn is a deny that says what lets it through,
    /// or, with `--codex-warn allow`, the empty reply plus the reason on stderr.
    fn reply(&self, decision: Decision, policy: &Policy) -> Reply {
        let (stdout, stderr) = match decision {
            Decision::Allow => (None, None),
            Decision::Deny(reason) => (Some(pretool::decision("deny", reason)), None),
            Decision::Ask { reason, allow_hint } => match policy.codex_warn {
                WarnAnswer::Deny => (
                    Some(pretool::decision("deny", format!("{reason} {allow_hint}"))),
                    None,
                ),
                WarnAnswer::Allow => (None, Some(reason)),
            },
        };
        Reply { stdout, stderr }
    }
}
