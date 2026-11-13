//! What counts as a script reader and a decoder: the one table the download rule and the
//! base64 rule both use.

use super::parse::{ProcKind, Simple, Stage, basename};

pub const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash",
];
pub const FETCHERS: &[&str] = &["curl", "wget"];

/// Interpreters that run what they read on stdin: name (any version suffix) and the letters of the flags that
/// take inline code (`python -c`, `perl -pe`, `node -e`).
const INTERPRETERS: &[(&str, &str)] = &[
    ("python", "c"),
    ("perl", "eE"),
    ("ruby", "e"),
    ("node", "ep"),
];

/// Files that stand for the script on stdin.
const STDIN_FILES: &[&str] = &["-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"];

pub fn is_shell(program: &str) -> bool {
    SHELLS.contains(&program)
}

/// Whether a stage runs what is piped into it: a shell, an interpreter without a script file
/// or with inline code, `source` of stdin, a command that feeds a `>(...)` holding a reader, or
/// a group with a reader inside.
pub fn stage_reads_script(stage: &Stage) -> bool {
    match stage {
        Stage::Simple(simple) => simple_reads_script(simple),
        Stage::Group(group) => group
            .pipelines
            .iter()
            .any(|p| p.stages.iter().any(stage_reads_script)),
    }
}

pub fn simple_reads_script(simple: &Simple) -> bool {
    let feeds_a_reader = simple.attached.procs.iter().any(|p| {
        p.kind == ProcKind::Write
            && p.body
                .iter()
                .any(|pl| pl.stages.iter().any(stage_reads_script))
    });
    feeds_a_reader || program_reads_script(simple)
}

fn program_reads_script(simple: &Simple) -> bool {
    let Some(index) = simple.program_index() else {
        return false;
    };
    if simple.words[index].text.contains(['$', '`']) {
        return true;
    }
    let program = basename(&simple.words[index].text);
    if is_shell(program) {
        return true;
    }
    if matches!(program, "source" | ".") {
        return simple
            .arg_texts()
            .next()
            .is_some_and(|a| STDIN_FILES.contains(&a));
    }
    INTERPRETERS
        .iter()
        .find(|(name, _)| is_version_of(program, name))
        .is_some_and(|(_, code_flags)| {
            simple.arg_texts().all(|a| a.starts_with('-'))
                || simple.arg_texts().next().is_some_and(|a| a == "-")
                || simple
                    .arg_texts()
                    .any(|a| is_inline_code_flag(a, code_flags))
        })
}

/// `python`, `python3`, `python3.12`; not `pythonista`.
fn is_version_of(program: &str, name: &str) -> bool {
    program
        .strip_prefix(name)
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn is_inline_code_flag(arg: &str, code_flags: &str) -> bool {
    arg.strip_prefix('-')
        .filter(|rest| !rest.starts_with('-') && !rest.is_empty())
        .is_some_and(|cluster| {
            cluster.chars().all(|c| c.is_ascii_alphabetic())
                && cluster
                    .chars()
                    .last()
                    .is_some_and(|c| code_flags.contains(c))
        })
        || arg == "--eval"
}

/// The shell text of a git alias definition: `!cmd` as the value of `git config alias.x` or
/// the part after `=` in `git -c alias.x=!cmd`.
pub fn git_alias_script(arg: &str) -> Option<&str> {
    arg.strip_prefix('!').or_else(|| {
        let (name, value) = arg.split_once('=')?;
        name.starts_with("alias.")
            .then_some(value)?
            .strip_prefix('!')
    })
}

/// A program that runs text it is given: a shell with `-c`, or `eval`.
pub fn runs_text(program: &str) -> bool {
    is_shell(program) || program == "eval"
}

/// A program that runs a file or process substitution named in its arguments as a script.
pub fn reads_script_files(program: &str) -> bool {
    is_shell(program) || matches!(program, "source" | ".")
}

pub fn is_dash_c(arg: &str) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.ends_with('c')
}

/// A command that turns an encoded payload back into bytes.
struct Decoder {
    program: &'static str,
    /// The first argument that selects the mode (`openssl enc`).
    subcommand: Option<&'static str>,
    /// The short flags may be clustered (`base64 -di`).
    clustered: bool,
    /// Every group needs one of its flags.
    flags: &'static [&'static [&'static str]],
}

const DECODERS: &[Decoder] = &[
    Decoder {
        program: "base64",
        subcommand: None,
        clustered: true,
        flags: &[&["-d", "-D", "--decode"]],
    },
    Decoder {
        program: "base32",
        subcommand: None,
        clustered: true,
        flags: &[&["-d", "--decode"]],
    },
    Decoder {
        program: "b64decode",
        subcommand: None,
        clustered: true,
        flags: &[&["-r"]],
    },
    Decoder {
        program: "xxd",
        subcommand: None,
        clustered: true,
        flags: &[&["-r", "-revert"]],
    },
    Decoder {
        program: "openssl",
        subcommand: Some("base64"),
        clustered: false,
        flags: &[&["-d", "-decode"]],
    },
    Decoder {
        program: "openssl",
        subcommand: Some("enc"),
        clustered: false,
        flags: &[&["-d", "-decode"], &["-base64", "-a", "-A"]],
    },
];

pub fn is_decoder(simple: &Simple) -> bool {
    let Some(program) = simple.program() else {
        return false;
    };
    let args: Vec<&str> = simple.arg_texts().collect();
    DECODERS
        .iter()
        .filter(|d| d.program == program)
        .filter(|d| d.subcommand.is_none_or(|sub| args.first() == Some(&sub)))
        .any(|d| {
            d.flags
                .iter()
                .all(|group| args.iter().any(|a| matches_flag(a, group, d.clustered)))
        })
}

fn matches_flag(arg: &str, group: &[&str], clustered: bool) -> bool {
    group.iter().any(|flag| {
        arg == *flag
            || clustered
                && flag.len() == 2
                && arg
                    .strip_prefix('-')
                    .filter(|cluster| !cluster.starts_with('-'))
                    .is_some_and(|cluster| cluster.contains(&flag[1..]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::parse::{Stage, parse};

    fn first_stage(text: &str) -> Stage {
        parse(text).unwrap()[0].stages[0].clone()
    }

    #[test]
    fn each_reader_form_reads_a_script() {
        for cmd in [
            "sh",
            "/bin/bash -s",
            "busybox sh",
            "doas sh",
            "sudo -u root bash",
            "env -i FOO=1 bash",
            "xargs sh -c 'x'",
            "python3",
            "python3.12 -",
            "python3 - arg",
            "python3 -c 'x'",
            "perl -pe 's/a/b/'",
            "perl -E 'say 1'",
            "ruby -e 'x'",
            "node -e 'x'",
            "node --eval x",
            "source /dev/stdin",
            ". /dev/stdin",
            "tee >(sh)",
            "(sh)",
            "{ true; sh; }",
            "if true; then sh; fi",
        ] {
            assert!(stage_reads_script(&first_stage(cmd)), "{cmd}");
        }
    }

    #[test]
    fn things_that_only_look_like_readers_do_not() {
        for cmd in [
            "pythonista",
            "node-sass",
            "python3 tool.py",
            "python3 -m http.server",
            "perl script.pl",
            "source ./file",
            "tee out",
            "tee >(wc)",
            "(cat)",
            "busybox ls",
            "echo sh",
        ] {
            assert!(!stage_reads_script(&first_stage(cmd)), "{cmd}");
        }
    }

    #[test]
    fn git_alias_values_starting_with_a_bang_are_shell_text() {
        assert_eq!(git_alias_script("!sh -c x"), Some("sh -c x"));
        assert_eq!(git_alias_script("alias.x=!sh"), Some("sh"));
        assert_eq!(git_alias_script("alias.x=status"), None);
        assert_eq!(git_alias_script("core.pager=!x"), None);
        assert_eq!(git_alias_script("status"), None);
    }

    #[test]
    fn decoders_are_found_by_their_flags() {
        for cmd in [
            "base64 -d",
            "base64 -D",
            "base64 -di",
            "base64 --decode",
            "xxd -r -p",
            "xxd -r",
            "base32 -d",
            "b64decode -r",
            "openssl base64 -d",
            "openssl enc -d -base64",
            "openssl enc -a -d -aes-256-cbc",
            "openssl enc -base64 -d",
        ] {
            let Stage::Simple(s) = first_stage(cmd) else {
                panic!("{cmd}")
            };
            assert!(is_decoder(&s), "{cmd}");
        }
        for cmd in [
            "base64",
            "base64 file",
            "xxd -p",
            "echo -d",
            "openssl enc -aes-256-cbc -pbkdf2",
            "openssl enc -d -aes-256-cbc",
            "openssl base64",
            "openssl dgst -sha256 -d",
        ] {
            let Stage::Simple(s) = first_stage(cmd) else {
                panic!("{cmd}")
            };
            assert!(!is_decoder(&s), "{cmd}");
        }
    }
}
