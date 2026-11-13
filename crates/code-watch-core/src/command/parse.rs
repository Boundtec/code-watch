/// One simple command of a pipeline or command list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub words: Vec<String>,
    /// The segment's output goes into the next segment (`|`, `|&`).
    pub piped_into_next: bool,
}

const OPERATORS: &[&str] = &["|", "|&", ";", "&&", "||", "&"];

/// Programs that run another program given as their arguments, with the flags that consume the
/// following word. Matching the real program through them is what keeps `sudo -u root bash`
/// from hiding the shell behind the user name.
const WRAPPERS: &[(&str, &[&str])] = &[
    (
        "sudo",
        &[
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
        ],
    ),
    ("env", &["-u", "-C", "-S"]),
    ("xargs", &["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"]),
    ("nice", &["-n"]),
    ("nohup", &[]),
    ("exec", &[]),
    ("command", &[]),
    ("time", &[]),
];

/// Tokenises with shlex, then splits on operator tokens. Operators glued to a word (`a|b`) are
/// not split; the regex rules cover that spelling. Redirections are split from their target
/// first, so `echo x>file` has the target as its own word. An unbalanced quote falls back to
/// whitespace splitting so a stray quote cannot hide a command from the rules.
pub fn segments(command: &str) -> Vec<Segment> {
    let spaced = space_redirects(command);
    let words = shlex::split(&spaced)
        .unwrap_or_else(|| spaced.split_whitespace().map(String::from).collect());
    let mut out = Vec::new();
    let mut current = Vec::new();
    for word in words {
        if OPERATORS.contains(&word.as_str()) {
            if !current.is_empty() {
                out.push(Segment {
                    words: std::mem::take(&mut current),
                    piped_into_next: word.starts_with('|'),
                });
            }
        } else {
            current.push(word);
        }
    }
    if !current.is_empty() {
        out.push(Segment {
            words: current,
            piped_into_next: false,
        });
    }
    out
}

/// Puts a space on both sides of every unquoted `>` or `>>`, keeping an `&` or a file
/// descriptor glued to it (`2>`, `&>`), so the target becomes a word of its own.
fn space_redirects(command: &str) -> String {
    let mut out = String::with_capacity(command.len() + 8);
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, '\\') | (Some('"'), '\\') => {
                out.push(c);
                out.extend(chars.next());
            }
            (None, '\'' | '"') => {
                quote = Some(c);
                out.push(c);
            }
            (Some(q), _) if c == q => {
                quote = None;
                out.push(c);
            }
            (None, '>') => {
                let fd_start = out
                    .trim_end_matches(|d: char| d.is_ascii_digit() || d == '&')
                    .len();
                let preceded_by_space = out[..fd_start]
                    .chars()
                    .last()
                    .is_none_or(char::is_whitespace);
                let split_at = if preceded_by_space {
                    fd_start
                } else {
                    out.len()
                };
                out.insert(split_at, ' ');
                out.push('>');
                if chars.peek() == Some(&'>') {
                    out.extend(chars.next());
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

/// The text the shell would run: each segment's words joined by spaces, segments joined by
/// ` | ` or ` ; `. A word with whitespace and an operator character can only come from quotes,
/// so its operators are replaced and cannot form a pipeline.
pub fn unquoted_text(segments: &[Segment]) -> String {
    let mut out = String::new();
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            out.push_str(if segments[i - 1].piped_into_next {
                " | "
            } else {
                " ; "
            });
        }
        let words: Vec<String> = seg.words.iter().map(|w| defuse_operators(w)).collect();
        out.push_str(&words.join(" "));
    }
    out
}

fn defuse_operators(word: &str) -> String {
    if word.contains(char::is_whitespace) {
        word.replace(['|', ';', '&'], "_")
    } else {
        word.to_string()
    }
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

impl Segment {
    /// Index of the program that really runs: after wrappers such as `sudo -u root`,
    /// `/usr/bin/env`, `nohup`, their flags and `VAR=value` prefixes.
    pub fn program_index(&self) -> Option<usize> {
        let mut arg_flags: Option<&[&str]> = None;
        let mut i = 0;
        while i < self.words.len() {
            let word = self.words[i].as_str();
            if let Some(flags) = arg_flags.filter(|_| word.starts_with('-')) {
                i += if flags.contains(&word) { 2 } else { 1 };
            } else if is_assignment(word) {
                i += 1;
            } else if let Some((_, flags)) = WRAPPERS.iter().find(|(n, _)| *n == basename(word)) {
                arg_flags = Some(flags);
                i += 1;
            } else {
                return Some(i);
            }
        }
        None
    }

    /// The program name without its directory.
    pub fn program(&self) -> Option<&str> {
        self.program_index().map(|i| basename(&self.words[i]))
    }

    /// The words after the program.
    pub fn args(&self) -> &[String] {
        self.program_index()
            .map_or(&[][..], |i| &self.words[i + 1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(command: &str) -> Vec<(Vec<String>, bool)> {
        segments(command)
            .into_iter()
            .map(|s| (s.words, s.piped_into_next))
            .collect()
    }

    #[test]
    fn splits_on_spaced_operators_and_marks_pipes() {
        let got = words("curl x | sh ; ls && echo hi");
        assert_eq!(got.len(), 4);
        assert!(got[0].1 && !got[1].1);
        assert_eq!(got[1].0, ["sh"]);
    }

    #[test]
    fn quoted_operators_are_not_operators() {
        assert_eq!(words("echo '|' \";\"").len(), 1);
    }

    #[test]
    fn glued_operators_stay_in_one_segment() {
        assert_eq!(words("curl x|sh").len(), 1);
    }

    #[test]
    fn an_unbalanced_quote_still_yields_words() {
        assert_eq!(words("curl 'oops | sh").len(), 2);
    }

    #[test]
    fn empty_input_has_no_segments() {
        assert!(segments("  ").is_empty());
    }

    #[test]
    fn program_skips_sudo_env_flags_and_directories() {
        let seg = &segments("sudo -E FOO=1 /bin/bash -s")[0];
        assert_eq!(seg.program(), Some("bash"));
    }

    #[test]
    fn program_skips_wrappers_with_their_flag_arguments() {
        for cmd in [
            "sudo -u root bash",
            "/usr/bin/env -u X FOO=1 bash",
            "nohup bash",
            "exec bash",
            "command bash",
            "xargs -n 1 bash",
            "time nice -n 5 bash",
            "FOO=1 /bin/bash",
        ] {
            assert_eq!(segments(cmd)[0].program(), Some("bash"), "{cmd}");
        }
        assert_eq!(segments("sudo -E")[0].program(), None);
    }

    #[test]
    fn args_follow_the_real_program() {
        assert_eq!(segments("sudo -u root curl -s x")[0].args(), ["-s", "x"]);
    }

    #[test]
    fn redirects_are_split_from_their_targets() {
        assert_eq!(words("echo x>f")[0].0, ["echo", "x", ">", "f"]);
        assert_eq!(words("echo x 2>>f")[0].0, ["echo", "x", "2>>", "f"]);
        assert_eq!(words("echo x &>f")[0].0, ["echo", "x", "&>", "f"]);
        assert_eq!(
            words("echo 'a>b' \"c>d\" e\\>f")[0].0,
            ["echo", "a>b", "c>d", "e>f"]
        );
    }
}
