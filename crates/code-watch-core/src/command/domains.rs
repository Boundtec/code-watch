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

/// Names shorter than this collide with unrelated domains at edit distance 1.
const MIN_FUZZY_LEN: usize = 6;

/// Splits an argument into the userinfo and host it would fetch, with or without a scheme
/// (`curl brew.sh/install` works). The host is what is after the last `@`.
fn authority_of(arg: &str) -> Option<(Option<&str>, String)> {
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
    host.contains('.').then(|| (userinfo, host.to_lowercase()))
}

pub fn host_of(arg: &str) -> Option<String> {
    authority_of(arg).map(|(_, host)| host)
}

/// The known domain an argument names in its userinfo while fetching from another host
/// (`https://github.com@evil.example/`), which reads as the known site in a quick look.
pub fn spoofed_by_userinfo(arg: &str) -> Option<&'static str> {
    let (userinfo, host) = authority_of(arg)?;
    let user = userinfo?.to_lowercase();
    let named = known_domain(&user).or_else(|| imitates(&user))?;
    (known_domain(&host) != Some(named)).then_some(named)
}

fn known_domain(host: &str) -> Option<&'static str> {
    KNOWN
        .iter()
        .copied()
        .find(|k| host == *k || host.ends_with(&format!(".{k}")))
}

/// The known domain `host` imitates, or `None` when it is unrelated or is the known domain
/// itself (or one of its subdomains).
pub fn imitates(host: &str) -> Option<&'static str> {
    let ascii = idna::domain_to_ascii(host).ok()?;
    // Checked on the host, not the registrable domain: the public suffix list treats
    // githubusercontent.com as a suffix, so raw.githubusercontent.com is its own registrable domain.
    if known_domain(&ascii).is_some() {
        return None;
    }
    let registrable = psl::domain_str(&ascii)?;
    let (unicode, _) = idna::domain_to_unicode(registrable);
    let labels = format!(".{ascii}.");
    KNOWN.iter().copied().find(|known| {
        labels.contains(&format!(".{known}."))
            || skeleton(&unicode).eq(skeleton(known))
            || close(&unicode, known)
    })
}

fn close(candidate: &str, known: &str) -> bool {
    let limit = if known.len() < 10 { 1 } else { 2 };
    candidate.len() >= MIN_FUZZY_LEN && strsim::damerau_levenshtein(candidate, known) <= limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_domains_and_their_subdomains_are_not_lookalikes() {
        for host in ["brew.sh", "raw.githubusercontent.com", "www.github.com"] {
            assert_eq!(imitates(host), None, "{host}");
        }
    }

    #[test]
    fn unrelated_domains_are_not_lookalikes() {
        assert_eq!(imitates("example.org"), None);
    }

    #[test]
    fn a_typo_is_found_by_edit_distance() {
        assert_eq!(imitates("githuh.com"), Some("github.com"));
        assert_eq!(
            imitates("raw.githubusercontent.co"),
            Some("githubusercontent.com")
        );
    }

    #[test]
    fn a_cyrillic_lookalike_is_found_by_its_skeleton() {
        // Four look-alike letters: too far from github.com for the edit distance, so only the
        // skeleton comparison can find it.
        assert_eq!(
            imitates("\u{261}\u{456}t\u{4bb}ub.c\u{43e}m"),
            Some("github.com")
        );
    }

    #[test]
    fn punycode_is_decoded_before_comparing() {
        let ascii = idna::domain_to_ascii("g\u{456}thub.com").unwrap();
        assert!(ascii.starts_with("xn--"));
        assert_eq!(imitates(&ascii), Some("github.com"));
    }

    #[test]
    fn a_known_domain_as_the_leftmost_labels_of_another_registrable_domain_is_flagged() {
        assert_eq!(imitates("github.com.attacker.io"), Some("github.com"));
        assert_eq!(
            imitates("raw.githubusercontent.com.attacker.io"),
            Some("githubusercontent.com")
        );
    }

    #[test]
    fn hosts_are_read_with_or_without_a_scheme() {
        assert_eq!(
            host_of("https://Brew.sh/install").as_deref(),
            Some("brew.sh")
        );
        assert_eq!(host_of("brew.sh/install").as_deref(), Some("brew.sh"));
        assert_eq!(host_of("localhost:8080/x"), None);
        assert_eq!(host_of("-fsSL"), None);
    }

    #[test]
    fn userinfo_cannot_hide_the_real_host() {
        let arg = "https://github.com@evil.example/x";
        assert_eq!(host_of(arg).as_deref(), Some("evil.example"));
        assert_eq!(spoofed_by_userinfo(arg), Some("github.com"));
        assert_eq!(spoofed_by_userinfo("https://github.com@github.com/x"), None);
        assert_eq!(spoofed_by_userinfo("https://user@evil.example/x"), None);
    }

    #[test]
    fn a_port_is_not_part_of_the_host() {
        assert_eq!(host_of("https://brew.sh:443/x").as_deref(), Some("brew.sh"));
    }
}
