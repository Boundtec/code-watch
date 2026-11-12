/// One simple command of a pipeline or command list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub words: Vec<String>,
    /// The segment's output goes into the next segment (`|`, `|&`).
    pub piped_into_next: bool,
}

const OPERATORS: &[&str] = &["|", "|&", ";", "&&", "||", "&"];

/// Tokenises with shlex, then splits on operator tokens. Operators glued to a word (`a|b`) are
/// not split; the regex rules cover that spelling. An unbalanced quote falls back to
/// whitespace splitting so a stray quote cannot hide a command from the rules.
pub fn segments(command: &str) -> Vec<Segment> {
    let words = shlex::split(command)
        .unwrap_or_else(|| command.split_whitespace().map(String::from).collect());
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

impl Segment {
    /// The program name, skipping `sudo`, `env`, their flags and `VAR=value` prefixes, without
    /// its directory.
    pub fn program(&self) -> Option<&str> {
        self.words
            .iter()
            .find(|w| {
                !(matches!(w.as_str(), "sudo" | "env") || w.starts_with('-') || w.contains('='))
            })
            .map(|w| w.rsplit('/').next().unwrap_or(w))
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
}
