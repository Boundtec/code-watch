use std::collections::{BTreeMap, BTreeSet};

use super::advisory::{OsvRecord, Vuln};
use super::cache::Cache;
use super::client::{MAX_BATCH, OsvClient, OsvError, Query};
use super::discover::{Discovered, Unparsed};
use super::group;
use super::package::{Ecosystem, Package};
use crate::finding::{Evidence, Finding, Layer, Severity};

/// Follow-up requests per batch when OSV pages a package's advisory list.
const MAX_PAGES: usize = 5;
const NAMED_UNCHECKED: usize = 3;

pub const RULE_KNOWN: &str = "osv/known-vulnerability";
pub const RULE_MALICIOUS: &str = "osv/malicious-package";
pub const RULE_UNPARSED: &str = "osv/unparsed-lockfile";
pub const RULE_UNCHECKED: &str = "osv/unchecked-packages";
pub const RULE_IDS: [&str; 4] = [RULE_KNOWN, RULE_MALICIOUS, RULE_UNPARSED, RULE_UNCHECKED];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsvMode {
    /// Ask OSV for whatever the cache does not hold fresh.
    Live,
    /// Use only fresh cache entries and never touch the network.
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvStatus {
    Ran,
    /// Nothing could be looked up; the text says why.
    Skipped(String),
}

#[derive(Debug)]
pub struct OsvOutcome {
    pub findings: Vec<Finding>,
    pub status: OsvStatus,
}

type Key = (Ecosystem, String, String);

/// Checks the discovered packages against OSV and the cache. A package that could not be
/// looked up is never treated as clean: it is named in a `warn` finding, and when nothing
/// could be looked up the layer is `Skipped`.
pub fn run(found: Discovered, mode: OsvMode, client: &dyn OsvClient, cache: &Cache) -> OsvOutcome {
    let mut findings: Vec<Finding> = found.unparsed.iter().map(unparsed_finding).collect();
    let mut groups: BTreeMap<Key, Vec<Package>> = BTreeMap::new();
    for p in found.packages {
        let key = (p.ecosystem, p.name.clone(), p.version.clone());
        groups.entry(key).or_default().push(p);
    }
    let mut resolved: BTreeMap<Key, Vec<Vuln>> = BTreeMap::new();
    let mut missing: Vec<Key> = Vec::new();
    for (key, pkgs) in &groups {
        match cache.get(&pkgs[0]) {
            Some(vulns) => {
                resolved.insert(key.clone(), vulns);
            }
            None => missing.push(key.clone()),
        }
    }
    let mut why = (!missing.is_empty() && mode == OsvMode::Offline)
        .then(|| "offline and no fresh cache".to_owned());
    if mode == OsvMode::Live && !missing.is_empty() {
        let (fetched, err) = lookup(client, &missing);
        for (key, vulns) in fetched {
            cache.put(&groups[&key][0], &vulns);
            resolved.insert(key, vulns);
        }
        why = err.map(|e| e.to_string());
    }
    for (key, vulns) in &resolved {
        for pkg in &groups[key] {
            findings.extend(group::findings(pkg, vulns));
        }
    }
    let unchecked: Vec<&Key> = groups
        .keys()
        .filter(|k| !resolved.contains_key(*k))
        .collect();
    let why = why.unwrap_or_else(|| "not looked up".to_owned());
    if !unchecked.is_empty() {
        findings.push(unchecked_finding(&unchecked, &why));
    }
    let status = if resolved.is_empty() && !groups.is_empty() {
        OsvStatus::Skipped(why)
    } else {
        OsvStatus::Ran
    };
    OsvOutcome { findings, status }
}

/// Looks up `keys` and returns the advisories of every package that was fully answered, plus
/// the first error that stopped the rest. Packages missing from the result are unchecked.
fn lookup(client: &dyn OsvClient, keys: &[Key]) -> (BTreeMap<Key, Vec<Vuln>>, Option<OsvError>) {
    let mut ids: BTreeMap<Key, BTreeSet<String>> = BTreeMap::new();
    let mut done: BTreeSet<Key> = BTreeSet::new();
    let mut error = None;
    for chunk in keys.chunks(MAX_BATCH) {
        if let Err(e) = query_chunk(client, chunk, &mut ids, &mut done) {
            error = Some(e);
            break;
        }
    }
    let mut records: BTreeMap<String, OsvRecord> = BTreeMap::new();
    let wanted: BTreeSet<&String> = done.iter().flat_map(|k| &ids[k]).collect();
    for id in wanted {
        if error.as_ref().is_some_and(|e| *e != OsvError::Partial) {
            break;
        }
        match client.record(id) {
            Ok(r) => {
                records.insert(id.clone(), r);
            }
            Err(e) => error = Some(e),
        }
    }
    let mut out = BTreeMap::new();
    for key in done {
        if ids[&key].iter().all(|id| records.contains_key(id)) {
            let mut vulns: Vec<Vuln> = ids[&key]
                .iter()
                .map(|id| records[id].for_package(key.0, &key.1))
                .collect();
            vulns.sort_by(|a, b| a.id.cmp(&b.id));
            out.insert(key, vulns);
        }
    }
    (out, error)
}

/// Runs one batch plus its follow-up pages. Keys whose answer is complete go into `done`.
fn query_chunk(
    client: &dyn OsvClient,
    chunk: &[Key],
    ids: &mut BTreeMap<Key, BTreeSet<String>>,
    done: &mut BTreeSet<Key>,
) -> Result<(), OsvError> {
    let mut pending: Vec<(&Key, Option<String>)> = chunk.iter().map(|k| (k, None)).collect();
    for _ in 0..MAX_PAGES {
        if pending.is_empty() {
            return Ok(());
        }
        let queries: Vec<Query> = pending
            .iter()
            .map(|(k, token)| Query {
                ecosystem: k.0,
                name: k.1.clone(),
                version: k.2.clone(),
                page_token: token.clone(),
            })
            .collect();
        let answers = client.query_batch(&queries)?;
        if answers.len() > queries.len() {
            return Err(OsvError::BadResponse);
        }
        let answered = answers.len();
        let mut next = Vec::new();
        for ((key, _), answer) in pending.iter().zip(answers) {
            ids.entry((*key).clone()).or_default().extend(answer.ids);
            match answer.next_page_token {
                Some(token) => next.push((*key, Some(token))),
                None => {
                    done.insert((*key).clone());
                }
            }
        }
        if answered < queries.len() {
            return Err(OsvError::Partial);
        }
        pending = next;
    }
    if pending.is_empty() {
        Ok(())
    } else {
        Err(OsvError::Partial)
    }
}

fn unparsed_finding(u: &Unparsed) -> Finding {
    Finding {
        rule_id: RULE_UNPARSED.into(),
        severity: Severity::Warn,
        layer: Layer::Osv,
        title: "A lockfile could not be checked for known vulnerabilities".into(),
        evidence: Evidence::new(Some(u.file.clone()), None, u.reason.describe()),
        remediation: "Read the lockfile by hand before installing from it.".into(),
        domain: None,
        package: None,
        advisories: Vec::new(),
    }
}

fn unchecked_finding(keys: &[&Key], why: &str) -> Finding {
    let named: Vec<String> = keys
        .iter()
        .take(NAMED_UNCHECKED)
        .map(|(_, n, v)| format!("{n}@{v}"))
        .collect();
    let more = keys.len().saturating_sub(NAMED_UNCHECKED);
    let tail = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    Finding {
        rule_id: RULE_UNCHECKED.into(),
        severity: Severity::Warn,
        layer: Layer::Osv,
        title: "Some packages were not checked for known vulnerabilities".into(),
        evidence: Evidence::new(
            None,
            None,
            &format!(
                "{} not checked ({why}): {}{tail}",
                keys.len(),
                named.join(", ")
            ),
        ),
        remediation: "Run the scan again with network access, or review these packages by hand."
            .into(),
        domain: None,
        package: None,
        advisories: Vec::new(),
    }
}
