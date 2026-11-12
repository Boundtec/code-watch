use unicode_security::confusable_detection::skeleton;

/// Registrable domains people run installers from. A host that imitates one of these without
/// being it is a lookalike.
const KNOWN: &[&str] = &[
    "brew.sh",
    "github.com",
    "githubusercontent.com",
    "npmjs.com",
    "pypi.org",
    "pythonhosted.org",
    "rustup.rs",
    "rust-lang.org",
    "docker.com",
    "nodesource.com",
    "python-poetry.org",
    "bun.sh",
    "deno.land",
    "helm.sh",
];

/// Real domains that share a name with a known one (another suffix, one letter apart) and must
/// never be reported as imitations of it.
const SIBLINGS: &[&str] = &[
    "gitlab.com",
    "github.io",
    "docker.io",
    "npmjs.org",
    "deno.com",
];

/// Registrable domains shorter than this collide with unrelated names at edit distance 1
/// (`gun.sh` against `bun.sh`).
const MIN_FUZZY_LEN: usize = 7;

/// Labels shorter than this are not compared across suffixes (`brew.com`).
const MIN_LABEL_LEN: usize = 5;

/// Labels shorter than this are not compared by edit distance.
const MIN_FUZZY_LABEL_LEN: usize = 6;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Imitates(&'static str),
    /// The host is not a valid domain name, so no comparison was possible.
    Unreadable,
}

/// Splits an argument into the userinfo and host it would fetch, with or without a scheme
/// (`curl brew.sh/install` works). The host is what is after the last `@`.
fn authority_of(arg: &str) -> Option<(Option<&str>, String)> {
    let arg = arg.strip_prefix("--url=").unwrap_or(arg);
    if arg.starts_with('-') {
        return None;
    }
    let rest = arg.split_once("://").map_or(arg, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, authority),
    };
    let host = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    // A trailing dot is the absolute spelling of the same name.
    let host = host.trim_end_matches('.');
    host.contains('.').then(|| (userinfo, host.to_lowercase()))
}

/// The verdict on the host an argument would fetch, with that host. The userinfo is checked as
/// well: `https://github.com@evil.example/` reads as the known site in a quick look.
pub(super) fn inspect(arg: &str) -> Option<(String, Verdict)> {
    let (userinfo, host) = authority_of(arg)?;
    let verdict = match imitates(&host) {
        Verdict::Clean => spoofed_by_userinfo(userinfo, &host),
        other => other,
    };
    Some((host, verdict))
}

/// The host a `curl` or `wget` argument fetches, only for arguments that are clearly an address
/// (a scheme or a path), so `-o out.sh` is not read as a host.
pub(super) fn fetched_host(arg: &str) -> Option<String> {
    let bare = arg.strip_prefix("--url=").unwrap_or(arg);
    if !bare.contains('/') {
        return None;
    }
    authority_of(arg).map(|(_, host)| host)
}

fn spoofed_by_userinfo(userinfo: Option<&str>, host: &str) -> Verdict {
    let user = userinfo
        .and_then(|u| u.split(':').next())
        .map(str::to_lowercase)
        .filter(|u| !u.is_empty());
    let named = user.as_deref().and_then(|u| {
        known_domain(u).or_else(|| match imitates(u) {
            Verdict::Imitates(k) => Some(k),
            _ => None,
        })
    });
    match named {
        Some(named) if known_domain(host) != Some(named) => Verdict::Imitates(named),
        _ => Verdict::Clean,
    }
}

fn known_domain(host: &str) -> Option<&'static str> {
    KNOWN.iter().copied().find(|k| is_or_under(host, k))
}

fn is_or_under(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Whether `host` imitates a known domain. A known domain, its subdomains and the known
/// siblings are the real thing.
pub fn imitates(host: &str) -> Verdict {
    let host = host.trim_end_matches('.');
    match idna::domain_to_ascii(host) {
        Ok(ascii) => classify(host, &ascii),
        Err(_) => {
            let flat: String = skeleton(host).collect();
            match known_domain(&flat) {
                Some(known) => Verdict::Imitates(known),
                None => idna::domain_to_ascii(&flat)
                    .map(|ascii| classify(&flat, &ascii))
                    .ok()
                    .filter(|v| *v != Verdict::Clean)
                    .unwrap_or(Verdict::Unreadable),
            }
        }
    }
}

fn classify(raw: &str, ascii: &str) -> Verdict {
    // A real known host is plain ASCII; an invisible or foreign character that idna mapped
    // away would otherwise make an imitation look like the real thing.
    if known_domain(ascii).is_some() && !raw.is_ascii() {
        return Verdict::Imitates(known_domain(ascii).expect("checked"));
    }
    // Checked on the host, not the registrable domain: the public suffix list treats
    // githubusercontent.com as a suffix, so raw.githubusercontent.com is its own registrable domain.
    if known_domain(ascii).is_some() || SIBLINGS.iter().any(|s| is_or_under(ascii, s)) {
        return Verdict::Clean;
    }
    let Some(registrable) = psl::domain_str(ascii) else {
        return Verdict::Clean;
    };
    let (unicode, _) = idna::domain_to_unicode(registrable);
    let leftmost = format!(".{ascii}.");
    let found = KNOWN.iter().copied().find(|known| {
        leftmost.contains(&format!(".{known}."))
            || same_name(&unicode, known)
            || (unicode.len() >= MIN_FUZZY_LEN && strsim::damerau_levenshtein(&unicode, known) == 1)
            || label_imitates(&unicode, known)
    });
    found.map_or(Verdict::Clean, Verdict::Imitates)
}

fn same_name(a: &str, b: &str) -> bool {
    skeleton(a).eq(skeleton(b))
}

/// The name without its suffix, for both sides: `github.org` has the label of `github.com`.
fn label_of(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

fn label_imitates(candidate: &str, known: &str) -> bool {
    let (label, known_label) = (label_of(candidate), label_of(known));
    label.chars().count() >= MIN_LABEL_LEN
        && (same_name(label, known_label)
            || (label.chars().count() >= MIN_FUZZY_LABEL_LEN
                && strsim::damerau_levenshtein(label, known_label) == 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imitated(host: &str) -> Option<&'static str> {
        match imitates(host) {
            Verdict::Imitates(known) => Some(known),
            _ => None,
        }
    }

    fn host(arg: &str) -> Option<String> {
        inspect(arg).map(|(host, _)| host)
    }

    #[test]
    fn real_domains_and_their_subdomains_are_not_lookalikes() {
        for host in ["brew.sh", "raw.githubusercontent.com", "www.github.com"] {
            assert_eq!(imitates(host), Verdict::Clean, "{host}");
        }
    }

    #[test]
    fn a_trailing_dot_is_the_same_name() {
        assert_eq!(imitates("brew.sh."), Verdict::Clean);
        assert_eq!(host("https://brew.sh./install").as_deref(), Some("brew.sh"));
        assert_eq!(imitated("githuh.com."), Some("github.com"));
    }

    #[test]
    fn real_sibling_sites_are_not_lookalikes() {
        for host in [
            "gitlab.com",
            "docker.io",
            "github.io",
            "npmjs.org",
            "deno.com",
        ] {
            assert_eq!(imitates(host), Verdict::Clean, "{host}");
        }
    }

    #[test]
    fn no_sibling_is_also_a_known_domain() {
        for sibling in SIBLINGS {
            assert_eq!(known_domain(sibling), None, "{sibling}");
        }
    }

    #[test]
    fn unrelated_domains_are_not_lookalikes() {
        assert_eq!(imitates("example.org"), Verdict::Clean);
    }

    #[test]
    fn a_name_with_another_suffix_is_flagged() {
        assert_eq!(imitated("github.org"), Some("github.com"));
        assert_eq!(imitated("docker.dev"), Some("docker.com"));
        assert_eq!(imitated("brew.com"), None);
    }

    #[test]
    fn a_short_name_one_letter_off_is_not_flagged() {
        assert_eq!(imitated("gun.sh"), None);
        assert_eq!(imitated("bu.sh"), None);
        assert_eq!(imitated("brev.sh"), Some("brew.sh"));
    }

    #[test]
    fn a_typo_is_found_by_edit_distance_one() {
        assert_eq!(imitated("githuh.com"), Some("github.com"));
        assert_eq!(imitated("gihtub.com"), Some("github.com"));
        assert_eq!(
            imitated("raw.githubusercontent.co"),
            Some("githubusercontent.com")
        );
        assert_eq!(imitated("gitlab.org"), None);
    }

    #[test]
    fn a_cyrillic_lookalike_is_found_by_its_skeleton() {
        // Four look-alike letters: too far from github.com for the edit distance, so only the
        // skeleton comparison can find it.
        assert_eq!(
            imitated("\u{261}\u{456}t\u{4bb}ub.c\u{43e}m"),
            Some("github.com")
        );
    }

    #[test]
    fn punycode_is_decoded_before_comparing() {
        let ascii = idna::domain_to_ascii("g\u{456}thub.com").unwrap();
        assert!(ascii.starts_with("xn--"));
        assert_eq!(imitated(&ascii), Some("github.com"));
    }

    #[test]
    fn a_known_domain_as_the_leftmost_labels_of_another_registrable_domain_is_flagged() {
        assert_eq!(imitated("github.com.attacker.io"), Some("github.com"));
        assert_eq!(
            imitated("raw.githubusercontent.com.attacker.io"),
            Some("githubusercontent.com")
        );
    }

    #[test]
    fn an_invisible_character_does_not_hide_the_imitation() {
        assert_eq!(imitated("git\u{200b}hub.com"), Some("github.com"));
        assert_eq!(imitated("gi\u{ad}thub.com"), Some("github.com"));
    }

    #[test]
    fn a_host_that_cannot_be_read_is_reported_as_such() {
        assert_eq!(imitates("exa\u{2028}mple..com"), Verdict::Unreadable);
    }

    #[test]
    fn hosts_are_read_with_or_without_a_scheme() {
        assert_eq!(host("https://Brew.sh/install").as_deref(), Some("brew.sh"));
        assert_eq!(host("brew.sh/install").as_deref(), Some("brew.sh"));
        assert_eq!(host("localhost:8080/x"), None);
        assert_eq!(host("-fsSL"), None);
    }

    #[test]
    fn the_url_flag_spelling_is_read() {
        assert_eq!(
            host("--url=https://githuh.com/x").as_deref(),
            Some("githuh.com")
        );
    }

    #[test]
    fn userinfo_cannot_hide_the_real_host() {
        let spoof = |arg| inspect(arg).map(|(_, v)| v);
        assert_eq!(
            host("https://github.com@evil.example/x").as_deref(),
            Some("evil.example")
        );
        assert_eq!(
            spoof("https://github.com@evil.example/x"),
            Some(Verdict::Imitates("github.com"))
        );
        assert_eq!(
            spoof("https://github.com:443@evil.io/"),
            Some(Verdict::Imitates("github.com"))
        );
        assert_eq!(
            spoof("https://github.com@github.com/x"),
            Some(Verdict::Clean)
        );
        assert_eq!(spoof("https://user@evil.example/x"), Some(Verdict::Clean));
    }

    #[test]
    fn a_port_is_not_part_of_the_host() {
        assert_eq!(host("https://brew.sh:443/x").as_deref(), Some("brew.sh"));
    }
}
