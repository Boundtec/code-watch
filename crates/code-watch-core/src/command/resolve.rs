//! Variables and the working directory as the command text itself sets them. A name is bound
//! only to what the text shows: a literal, or a command substitution. Anything else (the
//! environment, `read`, arithmetic) leaves the name unbound and a use of it unresolved, so an
//! unknown value is never guessed.

use std::collections::{HashMap, HashSet};

use super::parse::{Sub, Word};

#[derive(Debug, Clone, Default)]
pub struct Env {
    vars: HashMap<String, Var>,
    pub cwd: Option<String>,
    /// Names the text defines as functions: a call may run anything, a reader included.
    pub functions: HashSet<String>,
}

#[derive(Debug, Clone)]
enum Var {
    Literal(String),
    /// Holds the output of a command: `x=$(...)`. `source` is the substitution as written and
    /// `pending` the id the analysis uses to know the body was reached through a use.
    Command {
        source: String,
        body: String,
        pending: usize,
    },
}

/// A word with its known variables replaced, and the command variables it now holds.
pub struct Resolved {
    pub word: Word,
    pub used: Vec<usize>,
}

impl Env {
    pub fn set_literal(&mut self, name: &str, value: String) {
        self.vars.insert(name.to_string(), Var::Literal(value));
    }

    pub fn set_command(&mut self, name: &str, source: String, body: String, pending: usize) {
        self.vars.insert(
            name.to_string(),
            Var::Command {
                source,
                body,
                pending,
            },
        );
    }

    pub fn unbind(&mut self, name: &str) {
        self.vars.remove(name);
    }

    /// A relative path is made absolute against a known working directory; anything else is
    /// only normalised.
    pub fn absolute(&self, path: &str) -> String {
        let path = path.strip_prefix("./").unwrap_or(path);
        match &self.cwd {
            Some(cwd) if !path.starts_with(['/', '~']) && !path.contains('$') => {
                format!("{cwd}/{path}")
            }
            _ => path.to_string(),
        }
    }

    /// Replaces `$NAME` and `${NAME}` that are bound. A command variable becomes its
    /// substitution, so a word that is only that variable is a whole substitution.
    pub fn resolve(&self, word: &Word) -> Resolved {
        let mut used = Vec::new();
        if self.vars.is_empty() || !word.text.contains('$') {
            return Resolved {
                word: word.clone(),
                used,
            };
        }
        let mut text = String::new();
        let mut subs = word.subs.clone();
        let mut from_command = None;
        let mut rest = word.text.as_str();
        while let Some(at) = rest.find('$') {
            text.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let Some((name, len)) = reference(after) else {
                text.push('$');
                rest = after;
                continue;
            };
            match self.vars.get(name) {
                Some(Var::Literal(value)) => text.push_str(value),
                Some(Var::Command {
                    source,
                    body,
                    pending,
                }) => {
                    text.push_str(source);
                    subs.push(Sub { body: body.clone() });
                    used.push(*pending);
                    from_command = Some(source.as_str());
                }
                None => {
                    text.push('$');
                    text.push_str(&after[..len]);
                }
            }
            rest = &after[len..];
        }
        text.push_str(rest);
        let whole_substitution = word.whole_substitution
            || (word.subs.is_empty() && subs.len() == 1 && from_command == Some(text.as_str()));
        Resolved {
            word: Word {
                text,
                subs,
                whole_substitution,
            },
            used,
        }
    }

    pub fn resolve_text(&self, text: &str) -> String {
        let word = Word {
            text: text.to_string(),
            subs: Vec::new(),
            whole_substitution: false,
        };
        self.resolve(&word).word.text
    }
}

/// The name after a `$` and how many characters it takes: `NAME` or `{NAME}`.
fn reference(after: &str) -> Option<(&str, usize)> {
    let name_end = |s: &str| {
        s.char_indices()
            .find(|(i, c)| {
                !(c.is_ascii_alphabetic() || *c == '_' || (*i > 0 && c.is_ascii_digit()))
            })
            .map_or(s.len(), |(i, _)| i)
    };
    if let Some(inner) = after.strip_prefix('{') {
        let end = name_end(inner);
        (end > 0 && inner[end..].starts_with('}')).then(|| (&inner[..end], end + 2))
    } else {
        let end = name_end(after);
        (end > 0).then(|| (&after[..end], end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(text: &str) -> Word {
        Word {
            text: text.to_string(),
            subs: Vec::new(),
            whole_substitution: false,
        }
    }

    #[test]
    fn a_bound_literal_replaces_both_spellings() {
        let mut env = Env::default();
        env.set_literal("U", "evil.io".into());
        assert_eq!(
            env.resolve(&word("https://$U/x")).word.text,
            "https://evil.io/x"
        );
        assert_eq!(env.resolve(&word("${U}/x")).word.text, "evil.io/x");
    }

    #[test]
    fn an_unbound_or_special_form_is_left_alone() {
        let mut env = Env::default();
        env.set_literal("U", "evil.io".into());
        for text in ["$V", "${V}", "${U:-x}", "$(U)", "$", "$1", "cost$"] {
            assert_eq!(env.resolve(&word(text)).word.text, text, "{text}");
        }
    }

    #[test]
    fn a_command_variable_becomes_its_substitution() {
        let mut env = Env::default();
        env.set_command(
            "x",
            "$(curl y | base64 -d)".into(),
            "curl y | base64 -d".into(),
            7,
        );
        let whole = env.resolve(&word("$x"));
        assert!(whole.word.whole_substitution);
        assert_eq!(whole.word.subs[0].body, "curl y | base64 -d");
        assert_eq!(whole.used, [7]);
        let part = env.resolve(&word("a$x"));
        assert!(!part.word.whole_substitution);
        assert_eq!(part.word.subs.len(), 1);
    }

    #[test]
    fn a_relative_path_follows_a_known_directory_only() {
        let mut env = Env::default();
        assert_eq!(env.absolute("./a.plist"), "a.plist");
        env.cwd = Some("/x/y".into());
        assert_eq!(env.absolute("./a.plist"), "/x/y/a.plist");
        assert_eq!(env.absolute("/abs/a"), "/abs/a");
        assert_eq!(env.absolute("~/a"), "~/a");
        assert_eq!(env.absolute("$D/a"), "$D/a");
    }
}
