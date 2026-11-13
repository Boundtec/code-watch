use std::cmp::Ordering;
use std::str::FromStr;

use pep508_rs::pep440_rs::Version as Pep440;

use super::package::Ecosystem;

/// Orders two versions of one ecosystem, or `None` when either does not parse: PEP 440 for
/// PyPI, semver (Go's leading `v` and `+incompatible` dropped) for the rest.
pub(crate) fn compare(ecosystem: Ecosystem, a: &str, b: &str) -> Option<Ordering> {
    match ecosystem {
        Ecosystem::PyPI => Some(Pep440::from_str(a).ok()?.cmp(&Pep440::from_str(b).ok()?)),
        _ => Some(semver(a)?.cmp(&semver(b)?)),
    }
}

fn semver(v: &str) -> Option<cargo_lock::Version> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = v.split_once('+').map_or(v, |(head, _)| head);
    cargo_lock::Version::parse(v).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_orders_numerically_and_ignores_go_decoration() {
        let go = |a, b| compare(Ecosystem::Go, a, b);
        assert_eq!(go("v0.9.0", "v0.10.0"), Some(Ordering::Less));
        assert_eq!(go("v2.0.0+incompatible", "2.0.0"), Some(Ordering::Equal));
        assert_eq!(
            compare(Ecosystem::Npm, "1.0.0-beta.1", "1.0.0"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn pep440_orders_python_versions() {
        let py = |a, b| compare(Ecosystem::PyPI, a, b);
        assert_eq!(py("4.2", "4.10"), Some(Ordering::Less));
        assert_eq!(py("2.0.0rc1", "2.0.0"), Some(Ordering::Less));
    }

    #[test]
    fn a_version_that_does_not_parse_has_no_order() {
        assert_eq!(compare(Ecosystem::Npm, "not-a-version", "1.0.0"), None);
        assert_eq!(compare(Ecosystem::PyPI, "1.0.0", "???"), None);
    }
}
