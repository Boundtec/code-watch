use super::{Adapter, Call, Decision, Policy, Reply, pretool};

pub struct ClaudeCode;

impl Adapter for ClaudeCode {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call> {
        pretool::parse(stdin)
    }

    /// Allow is the empty reply, so Claude Code's own permission flow still decides.
    fn reply(&self, decision: Decision, _: &Policy) -> Reply {
        let stdout = match decision {
            Decision::Allow => None,
            Decision::Ask { reason, .. } => Some(pretool::decision("ask", reason)),
            Decision::Deny(reason) => Some(pretool::decision("deny", reason)),
        };
        Reply {
            stdout,
            stderr: None,
        }
    }
}
