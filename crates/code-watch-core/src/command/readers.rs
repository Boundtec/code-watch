//! What counts as a script reader and a decoder: the one table the download rule and the
//! base64 rule both use.

use super::parse::{ProcKind, Simple, Stage};

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
    let Some(program) = simple.program() else {
        return false;
    };
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

/// A command that turns an encoded payload back into bytes: `base64 -d`/`-D`/`--decode`
/// (also in a cluster such as `-di`) and `xxd -r`.
pub fn is_decoder(simple: &Simple) -> bool {
    let flag_letters = |letters: &str| {
        simple.arg_texts().any(|a| {
            a.strip_prefix('-')
                .filter(|c| !c.starts_with('-'))
                .is_some_and(|cluster| cluster.chars().any(|c| letters.contains(c)))
        })
    };
    match simple.program() {
        Some("base64") => flag_letters("dD") || simple.arg_texts().any(|a| a == "--decode"),
        Some("xxd") => flag_letters("r") || simple.arg_texts().any(|a| a == "-revert"),
        _ => false,
    }
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
    fn decoders_are_found_by_their_flags() {
        for cmd in [
            "base64 -d",
            "base64 -D",
            "base64 -di",
            "base64 --decode",
            "xxd -r -p",
            "xxd -r",
        ] {
            let Stage::Simple(s) = first_stage(cmd) else {
                panic!("{cmd}")
            };
            assert!(is_decoder(&s), "{cmd}");
        }
        for cmd in ["base64", "base64 file", "xxd -p", "echo -d"] {
            let Stage::Simple(s) = first_stage(cmd) else {
                panic!("{cmd}")
            };
            assert!(!is_decoder(&s), "{cmd}");
        }
    }
}
