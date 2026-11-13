use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use super::advisory::MALICIOUS_PREFIX;
use super::advisory::{OsvRecord, Vuln};
use super::cache::{Cache, Clock, SystemClock};
use super::client::{MAX_BATCH, OsvClient, OsvError, Query};
use super::discover::{Discovered, NotLookedUp, Unparsed};
use super::group;
use super::package::{Ecosystem, Package};
use crate::finding::{Evidence, Finding, Layer, Severity};

/// Follow-up requests per batch when OSV pages a package's advisory list.
const MAX_PAGES: usize = 5;
const NAMED_UNCHECKED: usize = 3;

/// How long the whole layer may spend on the network. One request in flight can run past it by
/// the client's own timeout; whatever is left is reported as unchecked.
pub const TIME_BUDGET: Duration = Duration::from_secs(30);

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

/// Checks the discovered packages against OSV and the cache within `TIME_BUDGET`. A package that
/// could not be looked up is never treated as clean: it is named in a `warn` finding, and when
/// nothing could be looked up the layer is `Skipped`.
pub fn run(found: Discovered, mode: OsvMode, client: &dyn OsvClient, cache: &Cache) -> OsvOutcome {
    run_within(found, mode, client, cache, &SystemClock, TIME_BUDGET)
}

/// `run` with the clock and the time budget given, so the deadline is testable without waiting.
pub fn run_within(
    found: Discovered,
    mode: OsvMode,
    client: &dyn OsvClient,
    cache: &Cache,
    clock: &dyn Clock,
    budget: Duration,
) -> OsvOutcome {
    let deadline = Deadline {
        clock,
        at: clock.now() + budget,
    };
    let mut findings: Vec<Finding> = found.unparsed.iter().map(unparsed_finding).collect();
    findings.extend(found.not_looked_up.iter().map(not_looked_up_finding));
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
    let mut malicious_only: BTreeMap<Key, Vec<Vuln>> = BTreeMap::new();
    if mode == OsvMode::Live && !missing.is_empty() {
        let looked_up = lookup(client, cache, &deadline, &missing);
        for (key, vulns) in looked_up.resolved {
            cache.put(&groups[&key][0], &vulns);
            resolved.insert(key, vulns);
        }
        malicious_only = looked_up.malicious_only;
        why = looked_up.error.map(|e| e.to_string());
    }
    for (key, vulns) in &resolved {
        for pkg in &groups[key] {
            findings.extend(group::findings(pkg, vulns));
        }
    }
    for (key, vulns) in &malicious_only {
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

struct Deadline<'a> {
    clock: &'a dyn Clock,
    at: SystemTime,
}

impl Deadline<'_> {
    fn check(&self) -> Result<(), OsvError> {
        if self.clock.now() >= self.at {
            Err(OsvError::OutOfTime)
        } else {
            Ok(())
        }
    }
}

struct Lookup {
    resolved: BTreeMap<Key, Vec<Vuln>>,
    /// For packages whose answer is incomplete: the malicious advisories the batch named, known
    /// from the id alone when their record could not be fetched.
    malicious_only: BTreeMap<Key, Vec<Vuln>>,
    error: Option<OsvError>,
}

/// Looks up `keys` and returns the advisories of every package that was fully answered, plus
/// the first error that stopped the rest. Packages missing from `resolved` are unchecked, but
/// a `MAL-` id in a batch answer still blocks without its record.
fn lookup(client: &dyn OsvClient, cache: &Cache, deadline: &Deadline, keys: &[Key]) -> Lookup {
    let mut ids: BTreeMap<Key, BTreeSet<String>> = BTreeMap::new();
    let mut done: BTreeSet<Key> = BTreeSet::new();
    let mut error = None;
    for chunk in keys.chunks(MAX_BATCH) {
        if let Err(e) = query_chunk(client, deadline, chunk, &mut ids, &mut done) {
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
        if let Some(r) = cache.get_record(id) {
            records.insert(id.clone(), r);
            continue;
        }
        match deadline.check().and_then(|()| client.record(id)) {
            Ok(r) => {
                cache.put_record(&r);
                records.insert(id.clone(), r);
            }
            Err(e) => error = Some(e),
        }
    }
    let mut resolved = BTreeMap::new();
    let mut malicious_only = BTreeMap::new();
    for key in done {
        let vulns_of = |wanted: &mut dyn Iterator<Item = &String>| -> Vec<Vuln> {
            let mut vulns: Vec<Vuln> = wanted
                .map(|id| match records.get(id) {
                    Some(r) => r.for_package(key.0, &key.1),
                    None => Vuln::malicious_id(id),
                })
                .collect();
            vulns.sort_by(|a, b| a.id.cmp(&b.id));
            vulns
        };
        if ids[&key].iter().all(|id| records.contains_key(id)) {
            let vulns = vulns_of(&mut ids[&key].iter());
            resolved.insert(key, vulns);
        } else {
            let vulns = vulns_of(
                &mut ids[&key]
                    .iter()
                    .filter(|id| id.starts_with(MALICIOUS_PREFIX)),
            );
            if !vulns.is_empty() {
                malicious_only.insert(key, vulns);
            }
        }
    }
    Lookup {
        resolved,
        malicious_only,
        error,
    }
}

/// Runs one batch plus its follow-up pages. Keys whose answer is complete go into `done`.
fn query_chunk(
    client: &dyn OsvClient,
    deadline: &Deadline,
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
        deadline.check()?;
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

fn not_looked_up_finding(n: &NotLookedUp) -> Finding {
    Finding {
        rule_id: RULE_UNCHECKED.into(),
        severity: Severity::Warn,
        layer: Layer::Osv,
        title: "Some lockfile entries were not checked for known vulnerabilities".into(),
        evidence: Evidence::new(
            Some(n.file.clone()),
            None,
            &format!(
                "{} {} not looked up (non-public source or unrecognised entry)",
                n.count,
                if n.count == 1 { "entry" } else { "entries" }
            ),
        ),
        remediation:
            "Review these entries by hand: OSV only knows packages from the public registry.".into(),
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
