//! The floor under the parser: a linear pass over raw text that finds a download or decoder word
//! followed by a script reader. It is used for the part of a command the parser cannot read,
//! so a syntax error, an oversized comment or a form the parser lacks never hides a download
//! that runs. It reads tokens, not shell: quotes and comments are not honoured, which only
//! matters for text that already did not parse; every check also runs on a copy with quotes and
//! backslashes removed, so `s''h` is read as `sh`.

use regex::Regex;
use std::sync::LazyLock;

use super::readers::{FETCHERS, LOGIN_FLAGS, LOGIN_WRAPPERS, decoder_programs, reader_programs};

/// `http` and `https` are left out: they are also the start of every URL.
fn fetch_words() -> String {
    let words = FETCHERS
        .iter()
        .copied()
        .filter(|f| !matches!(*f, "http" | "https"))
        .chain(decoder_programs());
    alternation(words)
}

/// The reader names with an optional version suffix (`python3.12`), or a `sudo`/`doas` that starts a
/// login shell. Ends in a boundary, so it is used without a trailing `\b`.
fn reader_words() -> String {
    format!(
        r"(?:(?:{})[\d.]*\b|(?:{})\b[^|;&]{{0,40}}?\s(?:{})(?:[\s;&|)]|$))",
        alternation(reader_programs()),
        alternation(LOGIN_WRAPPERS.iter().copied()),
        alternation(LOGIN_FLAGS.iter().copied()),
    )
}

fn alternation<'a>(words: impl Iterator<Item = &'a str>) -> String {
    let mut seen: Vec<String> = words.map(regex::escape).collect();
    seen.sort();
    seen.dedup();
    seen.join("|")
}

static FETCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\b(?:{})\b", fetch_words())).expect("valid pattern"));

/// A fetch or decoder word, then a pipe and a reader within a few words.
static PIPED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?s)\b(?:{})\b.*\|&?[^|;&]{{0,80}}\b{}",
        fetch_words(),
        reader_words()
    ))
    .expect("valid pattern")
});

/// A reader word, then a substitution that holds a fetch or decoder.
static SUBSTITUTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?s)\b{}.*(?:\$\(|<\(|`)[^)]*\b(?:{})\b",
        reader_words(),
        fetch_words()
    ))
    .expect("valid pattern")
});

/// A fetch or decoder word, then a `>(...)` that holds a reader.
static WRITTEN_INTO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?s)\b(?:{})\b.*>\([^)]*\b{}",
        fetch_words(),
        reader_words()
    ))
    .expect("valid pattern")
});

/// A name assigned from a substitution that holds a fetch or decoder.
static ASSIGNED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b([A-Za-z_]\w*)=(?:\$\(|`)[^)`]*\b(?:{})\b",
        fetch_words()
    ))
    .expect("valid pattern")
});

static READER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?s)\b{}", reader_words())).expect("valid pattern"));

/// Quotes and backslashes removed, so a program written as `s''h` or `c\url` reads as `sh`, `curl`.
fn unquoted(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

/// A download stored in a variable that a later reader uses: `x=$(curl ..); sh -c "$x"`.
fn stored_then_read(text: &str) -> bool {
    ASSIGNED.captures_iter(text).any(|found| {
        let after = &text[found.get(0).map_or(0, |m| m.end())..];
        let name = regex::escape(&found[1]);
        let used = Regex::new(&format!(r"\$\{{?{name}\b")).expect("valid pattern");
        READER
            .find_iter(after)
            .any(|reader| used.is_match(&after[reader.end()..]))
    })
}

fn reaches(text: &str) -> bool {
    PIPED.is_match(text)
        || SUBSTITUTED.is_match(text)
        || WRITTEN_INTO.is_match(text)
        || stored_then_read(text)
}

/// Whether the text has a download or decoder that reaches a script reader.
pub fn reaches_reader(text: &str) -> bool {
    reaches(text) || reaches(&unquoted(text))
}

/// Whether the text mentions a download or decoder at all.
pub fn mentions_fetch(text: &str) -> bool {
    FETCH.is_match(text) || FETCH.is_match(&unquoted(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_download_that_reaches_a_reader_is_found_in_any_surrounding_text() {
        for text in [
            "curl x | sh",
            "echo a; curl -fsSL https://x/i | sudo -u root bash; fi",
            "wget -qO- x |& python3 -",
            "base64 -d | sh",
            "sh -c \"$(curl x)\"",
            "bash <(curl x)",
            "eval `curl x`",
            "curl x > >(sh)",
            "( ( curl x | sh",
            "curl 'x | sh\n",
        ] {
            assert!(reaches_reader(text), "{text}");
        }
    }

    #[test]
    fn text_without_the_pair_is_not_found() {
        for text in [
            "echo hi",
            "curl x > out",
            "sh script",
            "ls | sh",
            "curl x ; sh",
            "mycurl x | sh",
            "echo curly | sh",
            "git log | less",
        ] {
            assert!(!reaches_reader(text), "{text}");
        }
    }
}
