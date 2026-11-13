use std::cmp::Ordering;
use std::collections::BTreeSet;

use super::advisory::Vuln;
use super::layer::{RULE_KNOWN, RULE_MALICIOUS};
use super::package::{Ecosystem, Package};
use super::version::compare;
use crate::finding::{Advisory, Evidence, Finding, Layer, Severity, clean_text};

/// Ids listed in the human text; `--json` carries them all.
const NAMED_IDS: usize = 3;

/// Joins the advisories that are one vulnerability under several ids (a Go advisory and its
/// GitHub alias): two advisories merge when their id sets, id plus aliases, intersect.
pub(crate) fn merge_aliases(vulns: &[Vuln]) -> Vec<Vuln> {
    let mut groups: Vec<(BTreeSet<String>, Vec<&Vuln>)> = Vec::new();
    for v in vulns {
        let mut ids: BTreeSet<String> = v.aliases.iter().cloned().collect();
        ids.insert(v.id.clone());
        let mut members = vec![v];
        let mut rest = Vec::new();
        for (set, group) in groups {
            if set.is_disjoint(&ids) {
                rest.push((set, group));
            } else {
                ids.extend(set);
                members.extend(group);
            }
        }
        rest.push((ids, members));
        groups = rest;
    }
    let mut merged: Vec<Vuln> = groups
        .into_iter()
        .map(|(ids, members)| one(ids, &members))
        .collect();
    merged.sort_by(|a, b| a.id.cmp(&b.id));
    merged
}

fn one(ids: BTreeSet<String>, members: &[&Vuln]) -> Vuln {
    let id = ids.iter().next().cloned().unwrap_or_default();
    let fixed = members.iter().flat_map(|v| v.fixed.clone()).collect();
    let primary = members.iter().find(|v| v.id == id).unwrap_or(&members[0]);
    Vuln {
        aliases: ids.into_iter().filter(|i| *i != id).collect(),
        summary: primary.summary.clone(),
        severity: members
            .iter()
            .map(|v| v.severity)
            .max()
            .unwrap_or(Severity::Warn),
        malicious: members.iter().any(|v| v.malicious),
        fixed,
        id,
    }
}

enum Fix {
    Version(String),
    NoSingle,
    /// Every fix of some advisory is a Go pseudo-version: a commit, not a release.
    Untagged,
    Unknown,
}

/// A Go pseudo-version ends in a 14-digit timestamp and a 12-hex-digit commit, as in
/// `0.0.0-20230101120000-0123456789ab`.
fn is_pseudo_version(v: &str) -> bool {
    let mut parts = v.rsplitn(3, '-');
    let (Some(commit), Some(stamp)) = (parts.next(), parts.next()) else {
        return false;
    };
    commit.len() == 12
        && commit.bytes().all(|b| b.is_ascii_hexdigit())
        && stamp
            .rsplit('.')
            .next()
            .is_some_and(|t| t.len() == 14 && t.bytes().all(|b| b.is_ascii_digit()))
}

/// Go modules are installed as `v1.2.3`; OSV writes the version without the `v`.
fn display_version(ecosystem: Ecosystem, v: &str) -> String {
    if ecosystem == Ecosystem::Go && !v.starts_with('v') {
        format!("v{v}")
    } else {
        v.to_owned()
    }
}

/// The lowest version above the installed one that is past a fix of every advisory: per
/// advisory the first fixed version above it, then the highest of those. It assumes a version
/// past a fix stays fixed, which is how OSV ranges are written in practice. Go pseudo-versions
/// are skipped while a tagged release fixes the advisory.
fn common_fix(ecosystem: Ecosystem, installed: &str, vulns: &[Vuln]) -> Fix {
    let mut needed: Option<&str> = None;
    for v in vulns {
        let mut first: Option<&str> = None;
        let mut untagged = false;
        for f in &v.fixed {
            match compare(ecosystem, f, installed) {
                None => return Fix::Unknown,
                Some(Ordering::Greater) if ecosystem == Ecosystem::Go && is_pseudo_version(f) => {
                    untagged = true;
                }
                Some(Ordering::Greater) => {
                    let lower =
                        first.is_none_or(|c| compare(ecosystem, f, c) == Some(Ordering::Less));
                    if lower {
                        first = Some(f);
                    }
                }
                Some(_) => {}
            }
        }
        let Some(first) = first else {
            return if untagged {
                Fix::Untagged
            } else {
                Fix::NoSingle
            };
        };
        if needed.is_none_or(|n| compare(ecosystem, first, n) == Some(Ordering::Greater)) {
            needed = Some(first);
        }
    }
    needed.map_or(Fix::NoSingle, |v| Fix::Version(v.to_owned()))
}

/// The findings for one package in one lockfile: one for its vulnerabilities and, only when
/// advisories say it is malicious, a separate one for that, so an allowlist entry for one can
/// never hide the other.
pub(crate) fn findings(pkg: &Package, vulns: &[Vuln]) -> Vec<Finding> {
    let (malicious, plain): (Vec<Vuln>, Vec<Vuln>) =
        merge_aliases(vulns).into_iter().partition(|v| v.malicious);
    [malicious, plain]
        .into_iter()
        .filter(|g| !g.is_empty())
        .map(|g| finding(pkg, &g))
        .collect()
}

fn finding(pkg: &Package, vulns: &[Vuln]) -> Finding {
    let name = clean_text(&pkg.name);
    let version = clean_text(&pkg.version);
    let malicious = vulns[0].malicious;
    let n = vulns.len();
    let first = clean_text(&vulns[0].id);
    let named: Vec<String> = vulns
        .iter()
        .take(NAMED_IDS)
        .map(|v| clean_text(&v.id))
        .collect();
    let more = n.saturating_sub(NAMED_IDS);
    let id_list = if more > 0 {
        format!("{} and {more} more", named.join(", "))
    } else {
        named.join(", ")
    };
    let (title, excerpt) = match (n, malicious) {
        (1, true) => (
            format!("{name} {version} is flagged as malicious by {first}"),
            format!("{name}@{version}: {first}{}", also(&vulns[0])),
        ),
        (_, true) => (
            format!("{name} {version} is flagged as malicious by {n} advisories"),
            format!("{name}@{version}: {id_list}"),
        ),
        (1, false) => (
            format!("{name} {version} is affected by {first}"),
            format!(
                "{name}@{version}: {first}{}: {}",
                also(&vulns[0]),
                vulns[0].summary
            ),
        ),
        (_, false) => (
            format!("{name} {version} has {n} known vulnerabilities"),
            format!("{name}@{version}: {id_list}"),
        ),
    };
    let remediation = if malicious {
        format!("Remove {name} and anything that installed it; treat this machine as exposed.")
    } else {
        match (common_fix(pkg.ecosystem, &pkg.version, vulns), n) {
            (Fix::Version(v), 1) => format!(
                "Upgrade {name} to {} and re-lock.",
                clean_text(&display_version(pkg.ecosystem, &v))
            ),
            (Fix::Version(v), _) => format!(
                "Upgrade {name} to {}, the lowest version that fixes all {n}, and re-lock.",
                clean_text(&display_version(pkg.ecosystem, &v))
            ),
            (Fix::Untagged, _) => format!(
                "It is fixed in an untagged commit, not in a release. Replace {name} or read the advisory at https://osv.dev/{first}."
            ),
            (Fix::NoSingle, 1) => format!(
                "No fixed version is listed. Replace {name} or read the advisory at https://osv.dev/{first}."
            ),
            (Fix::NoSingle, _) => format!(
                "No single version fixes all {n}. Replace {name} or read the advisories, starting at https://osv.dev/{first}."
            ),
            (Fix::Unknown, _) => format!(
                "The fixed versions could not be compared. Read the advisories, starting at https://osv.dev/{first}."
            ),
        }
    };
    Finding {
        rule_id: if malicious {
            RULE_MALICIOUS
        } else {
            RULE_KNOWN
        }
        .into(),
        severity: vulns
            .iter()
            .map(|v| v.severity)
            .max()
            .unwrap_or(Severity::Warn),
        layer: Layer::Osv,
        title,
        evidence: Evidence::new(Some(pkg.file.clone()), pkg.line, &excerpt),
        remediation,
        domain: None,
        package: Some(pkg.name.clone()),
        advisories: vulns
            .iter()
            .map(|v| Advisory {
                id: clean_text(&v.id),
                aliases: v.aliases.iter().map(|a| clean_text(a)).collect(),
            })
            .collect(),
    }
}

fn also(v: &Vuln) -> String {
    if v.aliases.is_empty() {
        String::new()
    } else {
        let aliases: Vec<String> = v.aliases.iter().map(|a| clean_text(a)).collect();
        format!(" (also {})", aliases.join(", "))
    }
}
