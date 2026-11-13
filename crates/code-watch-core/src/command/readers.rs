//! What counts as a script reader and a decoder: the one table the download rule and the
//! base64 rule both use.

use super::parse::{self, ProcKind, Simple, Stage, Word, basename};

pub const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "mksh", "rbash",
];
pub const FETCHERS: &[&str] = &[
    "curl",
    "wget",
    "http",
    "https",
    "aria2c",
    "fetch",
    "lwp-download",
];

/// Interpreters that run what they read on stdin: name (any version suffix) and the letters of the flags that
/// take inline code (`python -c`, `perl -pe`, `node -e`).
const INTERPRETERS: &[(&str, &str)] = &[
    ("python", "c"),
    ("perl", "eE"),
    ("ruby", "e"),
    ("node", "ep"),
    ("php", "r"),
    ("lua", "e"),
    ("tclsh", ""),
    ("osascript", "e"),
];

/// Interpreters whose program is an argument and runs commands only through `system(...)` or a
/// pipe to a command.
const AWKS: &[&str] = &["awk", "gawk", "mawk", "nawk"];

/// Flags of an interpreter that consume the following word, which is then not its script.
const INTERPRETER_VALUE_FLAGS: &[(&str, &[&str])] = &[("osascript", &["-l"])];

/// Programs that print their arguments: piped into a reader they are the script.
pub const EMITTERS: &[&str] = &["echo", "printf"];

/// The arguments of an emitter that are the text it prints: `printf`'s format is not.
pub fn emitted_args(simple: &Simple) -> &[Word] {
    let args = simple.args();
    match args.first() {
        Some(format) if simple.program() == Some("printf") && format.text.contains('%') => {
            &args[1..]
        }
        _ => args,
    }
}

/// Files that stand for the script on stdin.
const STDIN_FILES: &[&str] = &["-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"];

/// Flags of `ssh` that consume the following word.
const SSH_VALUE_FLAGS: &[&str] = &[
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q",
    "-R", "-S", "-W", "-w",
];

/// A program that starts another program inside a container: the first reader after one of its
/// subcommands is what runs.
pub struct Launcher {
    pub name: &'static str,
    pub subcommands: &'static [&'static str],
}

pub const LAUNCHERS: &[Launcher] = &[
    Launcher {
        name: "docker",
        subcommands: &["run", "exec"],
    },
    Launcher {
        name: "podman",
        subcommands: &["run", "exec"],
    },
    Launcher {
        name: "nerdctl",
        subcommands: &["run", "exec"],
    },
    Launcher {
        name: "kubectl",
        subcommands: &["run", "exec"],
    },
    Launcher {
        name: "lxc",
        subcommands: &["exec"],
    },
    Launcher {
        name: "find",
        subcommands: &["-exec", "-execdir", "-ok", "-okdir"],
    },
];

pub fn is_shell(program: &str) -> bool {
    SHELLS.contains(&program)
}

/// The inline-code flag letters of an interpreter, by program name.
fn interpreter_flags(program: &str) -> Option<&'static str> {
    INTERPRETERS
        .iter()
        .find(|(name, _)| is_version_of(program, name))
        .map(|(_, flags)| *flags)
}

/// A program a launcher or `ssh` can start that then reads a script.
pub fn is_inner_program(program: &str) -> bool {
    is_shell(program) || AWKS.contains(&program) || interpreter_flags(program).is_some()
}

/// Index of the word after the host of the `ssh` at `at`: where the remote command starts.
pub fn ssh_command_start(words: &[Word], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while let Some(word) = words.get(i) {
        match word.text.as_str() {
            "--" => return Some(i + 2),
            flag if flag.starts_with('-') => {
                i += if SSH_VALUE_FLAGS.contains(&flag) {
                    2
                } else {
                    1
                }
            }
            _ => return Some(i + 1),
        }
    }
    None
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
    writes_into_reader(simple) || program_reads_script(simple)
}

/// The command's own output goes to a `>(...)` that holds a reader: `tee >(sh)`, `curl > >(sh)`.
pub fn writes_into_reader(simple: &Simple) -> bool {
    simple.attached.procs.iter().any(|p| {
        p.kind == ProcKind::Write
            && p.body
                .iter()
                .any(|pl| pl.stages.iter().any(stage_reads_script))
    })
}

/// Names of the programs that decode or decompress, for the token-level check.
pub fn decoder_programs() -> impl Iterator<Item = &'static str> {
    DECODERS.iter().map(|d| d.program)
}

/// The shell and interpreter names, for the token-level check.
pub fn reader_programs() -> impl Iterator<Item = &'static str> {
    SHELLS
        .iter()
        .copied()
        .chain(INTERPRETERS.iter().map(|(name, _)| *name))
        .chain(AWKS.iter().copied())
        .chain(["su", "ssh", "eval", "source"])
}

fn program_reads_script(simple: &Simple) -> bool {
    let Some(index) = simple.program_index() else {
        return starts_login_shell(simple);
    };
    if simple.words[index]
        .text
        .contains(['$', '`', '*', '?', '[', '{'])
    {
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
    match program {
        "ssh" => return ssh_reads_script(simple, index),
        "su" => {
            let command = script_words(simple, Some(program));
            return command.is_empty() || text_holds_reader(&command);
        }
        _ => {}
    }
    if AWKS.contains(&program) {
        return simple.arg_texts().any(awk_runs_commands);
    }
    interpreter_flags(program).is_some_and(|code_flags| {
        let operands = interpreter_operands(simple, program);
        operands.iter().all(|a| a.starts_with('-'))
            || operands.iter().any(|a| STDIN_FILES.contains(a))
            || operands.iter().any(|a| is_inline_code_flag(a, code_flags))
    })
}

/// The arguments of an interpreter that are not the value of one of its flags.
fn interpreter_operands<'a>(simple: &'a Simple, program: &str) -> Vec<&'a str> {
    let value_flags = INTERPRETER_VALUE_FLAGS
        .iter()
        .find(|(name, _)| *name == program)
        .map_or(&[][..], |(_, flags)| *flags);
    let mut operands = Vec::new();
    let mut args = simple.arg_texts();
    while let Some(arg) = args.next() {
        if value_flags.contains(&arg) {
            args.next();
        } else {
            operands.push(arg);
        }
    }
    operands
}

/// `sudo -i` and `sudo -s` start the user's shell, which reads stdin.
pub const LOGIN_WRAPPERS: &[&str] = &["sudo", "doas"];
pub const LOGIN_FLAGS: &[&str] = &["-i", "-s", "--login", "--shell"];

fn starts_login_shell(simple: &Simple) -> bool {
    let Some((first, rest)) = simple.words.split_first() else {
        return false;
    };
    LOGIN_WRAPPERS.contains(&basename(&first.text))
        && rest.iter().any(|w| LOGIN_FLAGS.contains(&w.text.as_str()))
}

/// `ssh host` with no command opens a login shell that reads stdin; with a command, the remote
/// shell reads a script when the command text holds a reader.
fn ssh_reads_script(simple: &Simple, at: usize) -> bool {
    let command = script_words(simple, Some("ssh"));
    command.is_empty() && ssh_command_start(&simple.words, at).is_some()
        || text_holds_reader(&command)
}

/// Whether the shell command line made of these words has a stage that reads a script.
fn text_holds_reader(words: &[&Word]) -> bool {
    let text = words
        .iter()
        .map(|w| w.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    parse::parse(&text).is_ok_and(|p| p.iter().any(|pl| pl.stages.iter().any(stage_reads_script)))
}

fn awk_runs_commands(program: &str) -> bool {
    program.contains("system(") || program.contains("| \"") || program.contains("|\"")
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

/// A program that runs text it is given as a shell command line.
pub fn runs_text(program: &str) -> bool {
    is_shell(program) || matches!(program, "eval" | "su" | "ssh" | "watch")
}

/// A program that runs the script file named by its first operand.
pub fn reads_script_operand(program: &str) -> bool {
    reads_script_files(program) || interpreter_flags(program).is_some()
}

/// A program that runs a file or process substitution named in its arguments as a script.
pub fn reads_script_files(program: &str) -> bool {
    is_shell(program) || matches!(program, "source" | ".")
}

pub fn is_dash_c(arg: &str) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.ends_with('c')
}

/// The words a text runner takes as a command line: the argument of `-c` (after an optional
/// `--`), all arguments of `eval`, the remote command of `ssh`.
pub fn script_words<'a>(simple: &'a Simple, program: Option<&str>) -> Vec<&'a Word> {
    let args = simple.args();
    let after_dash_c = |is_flag: fn(&str) -> bool| -> Vec<&'a Word> {
        let Some(at) = args.iter().position(|w| is_flag(&w.text)) else {
            return Vec::new();
        };
        let mut rest = args[at + 1..].iter().peekable();
        while rest
            .next_if(|w| w.text.starts_with('-') && w.text.len() > 1 && w.text != "--")
            .is_some()
        {}
        rest.next_if(|w| w.text == "--");
        rest.next().into_iter().collect()
    };
    match program {
        Some("eval") => args.iter().collect(),
        Some("su") => after_dash_c(|a| a == "-c" || a == "--command"),
        Some("watch") => {
            let mut rest = args.iter();
            while let Some(word) = rest.next() {
                if word.text.starts_with('-') {
                    if matches!(word.text.as_str(), "-n" | "--interval") {
                        rest.next();
                    }
                } else {
                    return std::iter::once(word).chain(rest).collect();
                }
            }
            Vec::new()
        }
        Some("ssh") => {
            let at = simple.program_index().unwrap_or(0);
            ssh_command_start(&simple.words, at)
                .map(|start| {
                    simple.words[start.min(simple.words.len())..]
                        .iter()
                        .collect()
                })
                .unwrap_or_default()
        }
        Some(p) if is_shell(p) => after_dash_c(is_dash_c),
        _ => Vec::new(),
    }
}

/// The code of an interpreter given on its command line: the argument of `-c`/`-e`, an awk
/// program.
pub fn inline_code(simple: &Simple) -> Vec<&str> {
    let Some(program) = simple.program() else {
        return Vec::new();
    };
    let args = simple.args();
    if AWKS.contains(&program) {
        return args
            .iter()
            .map(|w| w.text.as_str())
            .filter(|a| !a.starts_with('-'))
            .collect();
    }
    let Some(code_flags) = interpreter_flags(program) else {
        return Vec::new();
    };
    args.windows(2)
        .filter(|pair| is_inline_code_flag(&pair[0].text, code_flags))
        .map(|pair| pair[1].text.as_str())
        .collect()
}

/// Whether the program is an interpreter of its own language, not a shell: what it reads on
/// stdin is code whose string literals may hold shell commands.
pub fn runs_code(program: &str) -> bool {
    !is_shell(program) && is_inner_program(program)
}

/// The quoted strings of a program in another language (`'..'`, `".."`, `` `..` ``), with a
/// backslash taking the next character literally. Each may be a shell command line.
pub fn string_literals(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = code.chars();
    while let Some(c) = chars.next() {
        if !matches!(c, '\'' | '"' | '`') {
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(n) = chars.next() {
            if n == c {
                closed = true;
                break;
            }
            if n == '\\' {
                literal.extend(chars.next());
            } else {
                literal.push(n);
            }
        }
        if closed {
            out.push(literal);
        }
    }
    out
}

/// A command that turns an encoded or compressed payload back into bytes.
struct Decoder {
    program: &'static str,
    /// The program may carry a version suffix (`python3`).
    versioned: bool,
    /// Arguments that must come first (`openssl enc`, `python -m base64`).
    prefix: &'static [&'static str],
    /// The short flags may be clustered (`base64 -di`).
    clustered: bool,
    /// Every group needs one of its flags.
    flags: &'static [&'static [&'static str]],
}

const fn decoder(
    program: &'static str,
    prefix: &'static [&'static str],
    clustered: bool,
    flags: &'static [&'static [&'static str]],
) -> Decoder {
    Decoder {
        program,
        versioned: false,
        prefix,
        clustered,
        flags,
    }
}

const DECODERS: &[Decoder] = &[
    decoder("base64", &[], true, &[&["-d", "-D", "--decode"]]),
    decoder("base32", &[], true, &[&["-d", "--decode"]]),
    decoder("b64decode", &[], true, &[&["-r"]]),
    decoder("xxd", &[], true, &[&["-r", "-revert"]]),
    decoder("openssl", &["base64"], false, &[&["-d", "-decode"]]),
    decoder(
        "openssl",
        &["enc"],
        false,
        &[&["-d", "-decode"], &["-base64", "-a", "-A"]],
    ),
    Decoder {
        versioned: true,
        ..decoder("python", &["-m", "base64"], false, &[&["-d", "-D"]])
    },
    decoder(
        "basenc",
        &[],
        true,
        &[
            &["-d", "--decode"],
            &[
                "--base64",
                "--base64url",
                "--base32",
                "--base32hex",
                "--base16",
            ],
        ],
    ),
    decoder(
        "gzip",
        &[],
        true,
        &[&["-d", "--decompress", "--uncompress"]],
    ),
    decoder("xz", &[], true, &[&["-d", "--decompress", "--uncompress"]]),
    decoder("bzip2", &[], true, &[&["-d", "--decompress"]]),
    decoder("zstd", &[], true, &[&["-d", "--decompress"]]),
    decoder("gunzip", &[], false, &[]),
    decoder("zcat", &[], false, &[]),
    decoder("gzcat", &[], false, &[]),
    decoder("unxz", &[], false, &[]),
    decoder("xzcat", &[], false, &[]),
    decoder("lzcat", &[], false, &[]),
    decoder("bunzip2", &[], false, &[]),
    decoder("bzcat", &[], false, &[]),
    decoder("unzstd", &[], false, &[]),
    decoder("zstdcat", &[], false, &[]),
];

pub fn is_decoder(simple: &Simple) -> bool {
    let Some(program) = simple.program() else {
        return false;
    };
    let args: Vec<&str> = simple.arg_texts().collect();
    DECODERS
        .iter()
        .filter(|d| {
            if d.versioned {
                is_version_of(program, d.program)
            } else {
                d.program == program
            }
        })
        .filter(|d| args.starts_with(d.prefix))
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

    fn simple(text: &str) -> Simple {
        let Stage::Simple(s) = first_stage(text) else {
            panic!("{text}")
        };
        s
    }

    #[test]
    fn launchers_and_remote_commands_resolve_to_the_program_that_runs() {
        for (cmd, program) in [
            ("docker run --rm -e A=1 img sh -c x", "sh"),
            ("docker exec -it c bash", "bash"),
            ("kubectl exec p -- sh", "sh"),
            ("ssh host sh", "sh"),
            ("ssh -p 22 -i k host sudo bash", "bash"),
            ("pkexec sh", "sh"),
            ("chroot /r sh", "sh"),
            ("docker run img ls", "docker"),
            ("docker build -t sh .", "docker"),
            ("ssh host ls sh", "ssh"),
            ("ssh host 'sh -s'", "ssh"),
        ] {
            assert_eq!(simple(cmd).program(), Some(program), "{cmd}");
        }
    }

    #[test]
    fn script_words_come_from_the_text_runner_that_owns_them() {
        let texts = |cmd: &str| {
            let s = simple(cmd);
            script_words(&s, s.program())
                .iter()
                .map(|w| w.text.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(texts("sh -c 'a b'"), ["a b"]);
        assert_eq!(texts("sh -c -- 'a b'"), ["a b"]);
        assert_eq!(texts("bash -lc 'a b'"), ["a b"]);
        assert_eq!(texts("eval a b"), ["a", "b"]);
        assert_eq!(texts("su -c 'a b' root"), ["a b"]);
        assert_eq!(texts("su --command 'a b'"), ["a b"]);
        assert_eq!(texts("ssh -p 1 host 'a b'"), ["a b"]);
        assert_eq!(texts("ssh host a b"), ["a", "b"]);
        assert!(texts("ssh host").is_empty());
        assert!(texts("sh script.sh").is_empty());
    }

    #[test]
    fn inline_code_is_the_argument_of_the_code_flag_or_the_awk_program() {
        let code = |cmd: &str| {
            let s = simple(cmd);
            inline_code(&s)
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(code("python3 -c 'x y'"), ["x y"]);
        assert_eq!(code("perl -pe 'x y'"), ["x y"]);
        assert_eq!(code("php -r 'x y'"), ["x y"]);
        assert_eq!(code("lua -e 'x y'"), ["x y"]);
        assert_eq!(code("osascript -e 'a' -e 'b'"), ["a", "b"]);
        assert_eq!(code("awk -F: 'x y' f"), ["x y", "f"]);
        assert!(code("python3 tool.py").is_empty());
        assert!(code("sh -c x").is_empty());
    }

    #[test]
    fn string_literals_take_each_quoted_string_and_honour_backslashes() {
        assert_eq!(
            string_literals(r#"os.system('a b'); x = "c \" d"; `e f`"#),
            ["a b", "c \" d", "e f"]
        );
        assert_eq!(string_literals(r#"print("it's")"#), ["it's"]);
        assert!(string_literals("print(1)").is_empty());
        assert!(string_literals("print('open").is_empty());
    }

    #[test]
    fn awk_reads_a_script_only_when_its_program_runs_commands() {
        for cmd in [
            "awk '{system($0)}'",
            "gawk 'BEGIN{ print | \"sh\" }'",
            "mawk '{ print|\"sh\" }'",
        ] {
            assert!(stage_reads_script(&first_stage(cmd)), "{cmd}");
        }
        for cmd in ["awk '{print $1}'", "awk -f prog.awk", "awk 'BEGIN{x=1}' f"] {
            assert!(!stage_reads_script(&first_stage(cmd)), "{cmd}");
        }
    }

    #[test]
    fn ssh_and_su_read_a_script_when_their_command_does() {
        for cmd in [
            "ssh host",
            "ssh -t host",
            "ssh host sh",
            "ssh host 'sh -s'",
            "ssh host 'a; sh'",
            "su -c sh",
            "su",
            "su -",
            "su root",
        ] {
            assert!(stage_reads_script(&first_stage(cmd)), "{cmd}");
        }
        for cmd in ["ssh host ls", "ssh host 'cd /app && git pull'", "su -c ls"] {
            assert!(!stage_reads_script(&first_stage(cmd)), "{cmd}");
        }
    }

    #[test]
    fn printf_formats_are_not_printed_text() {
        let s = simple("printf '%s\\n' a b");
        let words: Vec<_> = emitted_args(&s).iter().map(|w| w.text.as_str()).collect();
        assert_eq!(words, ["a", "b"]);
        let s = simple("echo '%s' a");
        assert_eq!(emitted_args(&s).len(), 2);
    }
}
