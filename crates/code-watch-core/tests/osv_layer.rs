use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use code_watch_core::osv::{
    Cache, Clock, DEFAULT_TTL, Discovered, Ecosystem, MAX_BATCH, OsvClient, OsvError, OsvMode,
    OsvRecord, OsvStatus, Package, Query, QueryAnswer, Unparsed, UnparsedReason, run,
};
use code_watch_core::{Allowlists, Engine, Finding, LayerStatus, OsvSetup, Severity, render};

#[derive(Clone)]
struct FakeClock(Rc<Cell<u64>>);

impl FakeClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(1_700_000_000)))
    }
    fn advance(&self, by: Duration) {
        self.0.set(self.0.get() + by.as_secs());
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.get())
    }
}

type BatchFn = Box<dyn Fn(&[Query]) -> Result<Vec<QueryAnswer>, OsvError>>;

struct FakeOsv {
    batch: BatchFn,
    records: BTreeMap<String, Result<OsvRecord, OsvError>>,
    batches: RefCell<Vec<Vec<Query>>>,
    record_calls: RefCell<Vec<String>>,
}

impl FakeOsv {
    fn new(batch: BatchFn) -> Self {
        Self {
            batch,
            records: BTreeMap::new(),
            batches: RefCell::default(),
            record_calls: RefCell::default(),
        }
    }

    /// Answers every query with the given advisory ids.
    fn answering(ids: &[&str]) -> Self {
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        Self::new(Box::new(move |qs| {
            Ok(qs
                .iter()
                .map(|_| QueryAnswer {
                    ids: ids.clone(),
                    next_page_token: None,
                })
                .collect())
        }))
    }

    fn failing(err: OsvError) -> Self {
        Self::new(Box::new(move |_| Err(err.clone())))
    }

    fn with_record(mut self, r: OsvRecord) -> Self {
        self.records.insert(r.id.clone(), Ok(r));
        self
    }

    fn with_record_error(mut self, id: &str, err: OsvError) -> Self {
        self.records.insert(id.into(), Err(err));
        self
    }

    fn queries(&self) -> usize {
        self.batches.borrow().iter().map(Vec::len).sum()
    }
}

impl OsvClient for FakeOsv {
    fn query_batch(&self, queries: &[Query]) -> Result<Vec<QueryAnswer>, OsvError> {
        self.batches.borrow_mut().push(queries.to_vec());
        (self.batch)(queries)
    }

    fn record(&self, id: &str) -> Result<OsvRecord, OsvError> {
        self.record_calls.borrow_mut().push(id.to_owned());
        self.records
            .get(id)
            .cloned()
            .unwrap_or(Err(OsvError::Status(404)))
    }
}

fn record(id: &str, severity: Option<&str>, name: &str, fixed: &[&str]) -> OsvRecord {
    let events: Vec<_> = fixed
        .iter()
        .map(|f| serde_json::json!({ "fixed": f }))
        .collect();
    serde_json::from_value(serde_json::json!({
        "id": id,
        "summary": format!("summary of {id}"),
        "database_specific": { "severity": severity },
        "affected": [{
            "package": { "ecosystem": "npm", "name": name },
            "ranges": [{ "type": "SEMVER", "events": events }],
        }],
    }))
    .unwrap()
}

fn pkg(name: &str, version: &str, file: &str, line: Option<usize>) -> Package {
    Package {
        ecosystem: Ecosystem::Npm,
        name: name.into(),
        version: version.into(),
        file: file.into(),
        line,
    }
}

fn packages(list: Vec<Package>) -> Discovered {
    Discovered {
        packages: list,
        unparsed: vec![],
    }
}

fn cache(dir: &Path, clock: &FakeClock) -> Cache {
    Cache::new(dir.to_path_buf(), DEFAULT_TTL, Box::new(clock.clone()))
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

#[test]
fn a_vulnerable_package_becomes_a_finding_with_everything_the_allowlist_needs() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::answering(&["GHSA-1"]).with_record(record(
        "GHSA-1",
        Some("HIGH"),
        "lodash",
        &["4.17.21"],
    ));
    let out = run(
        packages(vec![pkg("lodash", "4.17.4", "package-lock.json", Some(7))]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(out.status, OsvStatus::Ran);
    let f = &out.findings[0];
    assert_eq!(f.rule_id, "osv/known-vulnerability");
    assert_eq!(f.severity, Severity::Warn);
    assert_eq!(f.package.as_deref(), Some("lodash"));
    assert_eq!(f.evidence.file.as_deref(), Some("package-lock.json"));
    assert_eq!(f.evidence.line, Some(7));
    assert!(f.title.contains("GHSA-1") && f.title.contains("lodash 4.17.4"));
    assert!(f.remediation.contains("4.17.21"));
    assert_eq!(out.findings.len(), 1);
}

#[test]
fn an_advisory_without_a_fixed_version_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let client =
        FakeOsv::answering(&["GHSA-1"]).with_record(record("GHSA-1", Some("LOW"), "x", &[]));
    let out = run(
        packages(vec![pkg("x", "1.0.0", "f", None)]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert!(out.findings[0].remediation.contains("No fixed version"));
}

#[test]
fn severity_follows_the_database_label_and_unknown_is_never_downgraded() {
    let cases = [
        ("MAL-2024-1", None, Severity::Block, "osv/malicious-package"),
        (
            "GHSA-a",
            Some("CRITICAL"),
            Severity::Warn,
            "osv/known-vulnerability",
        ),
        (
            "GHSA-b",
            Some("high"),
            Severity::Warn,
            "osv/known-vulnerability",
        ),
        (
            "GHSA-c",
            Some("MODERATE"),
            Severity::Info,
            "osv/known-vulnerability",
        ),
        (
            "GHSA-d",
            Some("LOW"),
            Severity::Info,
            "osv/known-vulnerability",
        ),
        ("GHSA-e", None, Severity::Warn, "osv/known-vulnerability"),
        (
            "GHSA-f",
            Some("surprising"),
            Severity::Warn,
            "osv/known-vulnerability",
        ),
    ];
    for (id, label, severity, rule) in cases {
        let dir = tempfile::tempdir().unwrap();
        let client = FakeOsv::answering(&[id]).with_record(record(id, label, "x", &[]));
        let out = run(
            packages(vec![pkg("x", "1.0.0", "f", None)]),
            OsvMode::Live,
            &client,
            &cache(dir.path(), &FakeClock::new()),
        );
        assert_eq!(
            (out.findings[0].severity, out.findings[0].rule_id.as_str()),
            (severity, rule),
            "{id}"
        );
    }
}

#[test]
fn a_package_with_no_advisories_is_clean_and_remembered() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let live = FakeOsv::answering(&[]);
    let list = || packages(vec![pkg("x", "1.0.0", "f", None)]);
    let first = run(list(), OsvMode::Live, &live, &cache(dir.path(), &clock));
    assert!(first.findings.is_empty() && first.status == OsvStatus::Ran);
    let second = run(list(), OsvMode::Offline, &live, &cache(dir.path(), &clock));
    assert!(second.findings.is_empty() && second.status == OsvStatus::Ran);
    assert_eq!(live.queries(), 1);
}

#[test]
fn no_packages_means_the_layer_ran_with_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::failing(OsvError::Network);
    let out = run(
        packages(vec![]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert!(out.findings.is_empty() && out.status == OsvStatus::Ran);
    assert_eq!(client.queries(), 0);
}

#[test]
fn a_failing_lookup_is_never_a_clean_result() {
    let errors = [
        OsvError::Status(404),
        OsvError::Status(429),
        OsvError::Status(503),
        OsvError::Timeout,
        OsvError::Network,
        OsvError::BadResponse,
    ];
    for err in errors {
        let dir = tempfile::tempdir().unwrap();
        let client = FakeOsv::failing(err.clone());
        let out = run(
            packages(vec![pkg("x", "1.0.0", "f", None)]),
            OsvMode::Live,
            &client,
            &cache(dir.path(), &FakeClock::new()),
        );
        assert_eq!(ids(&out.findings), ["osv/unchecked-packages"], "{err}");
        assert_eq!(out.findings[0].severity, Severity::Warn);
        assert_eq!(out.status, OsvStatus::Skipped(err.to_string()), "{err}");
    }
}

#[test]
fn a_failing_advisory_lookup_leaves_that_package_unchecked() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::answering(&["GHSA-1"]).with_record_error("GHSA-1", OsvError::Timeout);
    let out = run(
        packages(vec![pkg("x", "1.0.0", "f", None)]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(ids(&out.findings), ["osv/unchecked-packages"]);
    assert!(matches!(out.status, OsvStatus::Skipped(_)));
}

#[test]
fn a_partial_batch_uses_the_answered_packages_and_names_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::new(Box::new(|qs| {
        Ok(vec![
            QueryAnswer {
                ids: vec!["GHSA-1".into()],
                next_page_token: None,
            };
            qs.len() - 1
        ])
    }))
    .with_record(record("GHSA-1", Some("HIGH"), "a", &[]));
    let out = run(
        packages(vec![
            pkg("a", "1.0.0", "f", None),
            pkg("b", "1.0.0", "f", None),
        ]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(out.status, OsvStatus::Ran);
    assert_eq!(ids(&out.findings).len(), 2);
    let unchecked = out
        .findings
        .iter()
        .find(|f| f.rule_id == "osv/unchecked-packages")
        .unwrap();
    assert!(
        unchecked.evidence.excerpt.contains("b@1.0.0"),
        "{}",
        unchecked.evidence.excerpt
    );
    assert!(unchecked.evidence.excerpt.contains("only part of a batch"));
}

#[test]
fn the_unchecked_finding_names_a_few_packages_and_counts_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let list = (0..6)
        .map(|i| pkg(&format!("p{i}"), "1.0.0", "f", None))
        .collect();
    let out = run(
        packages(list),
        OsvMode::Offline,
        &FakeOsv::failing(OsvError::Network),
        &cache(dir.path(), &FakeClock::new()),
    );
    let text = &out.findings[0].evidence.excerpt;
    assert!(
        text.starts_with(
            "6 not checked (offline and no fresh cache): p0@1.0.0, p1@1.0.0, p2@1.0.0 and 3 more"
        ),
        "{text}"
    );
}

#[test]
fn the_same_package_in_two_lockfiles_is_one_query_and_two_findings() {
    let dir = tempfile::tempdir().unwrap();
    let client =
        FakeOsv::answering(&["GHSA-1"]).with_record(record("GHSA-1", Some("HIGH"), "x", &[]));
    let out = run(
        packages(vec![
            pkg("x", "1.0.0", "a/package-lock.json", None),
            pkg("x", "1.0.0", "b/yarn.lock", None),
        ]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(client.queries(), 1);
    let files: Vec<_> = out
        .findings
        .iter()
        .map(|f| f.evidence.file.clone().unwrap())
        .collect();
    assert_eq!(files, ["a/package-lock.json", "b/yarn.lock"]);
}

#[test]
fn an_advisory_shared_by_two_packages_is_fetched_once() {
    let dir = tempfile::tempdir().unwrap();
    let client =
        FakeOsv::answering(&["GHSA-1"]).with_record(record("GHSA-1", Some("HIGH"), "x", &[]));
    run(
        packages(vec![
            pkg("x", "1.0.0", "f", None),
            pkg("y", "2.0.0", "f", None),
        ]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(client.record_calls.borrow().as_slice(), ["GHSA-1"]);
}

#[test]
fn more_than_the_batch_limit_is_split_into_several_requests() {
    let dir = tempfile::tempdir().unwrap();
    let list = (0..MAX_BATCH + 1)
        .map(|i| pkg(&format!("p{i:05}"), "1.0.0", "f", None))
        .collect();
    let client = FakeOsv::answering(&[]);
    let out = run(
        packages(list),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    let sizes: Vec<_> = client.batches.borrow().iter().map(Vec::len).collect();
    assert_eq!(sizes, [MAX_BATCH, 1]);
    assert!(out.findings.is_empty() && out.status == OsvStatus::Ran);
}

#[test]
fn a_paged_answer_is_followed_and_merged() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::new(Box::new(|qs| {
        Ok(qs
            .iter()
            .map(|q| match &q.page_token {
                None => QueryAnswer {
                    ids: vec!["GHSA-1".into()],
                    next_page_token: Some("t2".into()),
                },
                Some(t) if t == "t2" => QueryAnswer {
                    ids: vec!["GHSA-2".into()],
                    next_page_token: None,
                },
                Some(_) => panic!("unexpected token"),
            })
            .collect())
    }))
    .with_record(record("GHSA-1", Some("HIGH"), "x", &[]))
    .with_record(record("GHSA-2", Some("LOW"), "x", &[]));
    let out = run(
        packages(vec![pkg("x", "1.0.0", "f", None)]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(out.findings.len(), 2);
    assert_eq!(client.batches.borrow().len(), 2);
}

#[test]
fn an_endless_paged_answer_ends_as_unchecked() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::new(Box::new(|qs| {
        Ok(qs
            .iter()
            .map(|_| QueryAnswer {
                ids: vec![],
                next_page_token: Some("again".into()),
            })
            .collect())
    }));
    let out = run(
        packages(vec![pkg("x", "1.0.0", "f", None)]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(client.batches.borrow().len(), 5);
    assert_eq!(ids(&out.findings), ["osv/unchecked-packages"]);
}

#[test]
fn offline_uses_a_fresh_cache_and_skips_when_it_is_stale_or_missing() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let client =
        FakeOsv::answering(&["GHSA-1"]).with_record(record("GHSA-1", Some("HIGH"), "x", &[]));
    let list = || packages(vec![pkg("x", "1.0.0", "f", None)]);
    let offline = |c: &FakeClock| run(list(), OsvMode::Offline, &client, &cache(dir.path(), c));

    let missing = offline(&clock);
    assert_eq!(
        missing.status,
        OsvStatus::Skipped("offline and no fresh cache".into())
    );
    assert_eq!(ids(&missing.findings), ["osv/unchecked-packages"]);

    run(list(), OsvMode::Live, &client, &cache(dir.path(), &clock));
    clock.advance(DEFAULT_TTL - Duration::from_secs(1));
    let fresh = offline(&clock);
    assert_eq!(fresh.status, OsvStatus::Ran);
    assert_eq!(ids(&fresh.findings), ["osv/known-vulnerability"]);

    clock.advance(Duration::from_secs(1));
    let stale = offline(&clock);
    assert!(matches!(stale.status, OsvStatus::Skipped(_)));
    assert_eq!(ids(&stale.findings), ["osv/unchecked-packages"]);
    assert_eq!(client.queries(), 1, "offline never asks OSV");
}

#[test]
fn offline_with_some_packages_cached_runs_and_names_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let client = FakeOsv::answering(&[]);
    run(
        packages(vec![pkg("a", "1.0.0", "f", None)]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &clock),
    );
    let out = run(
        packages(vec![
            pkg("a", "1.0.0", "f", None),
            pkg("b", "1.0.0", "f", None),
        ]),
        OsvMode::Offline,
        &client,
        &cache(dir.path(), &clock),
    );
    assert_eq!(out.status, OsvStatus::Ran);
    assert!(out.findings[0].evidence.excerpt.contains("b@1.0.0"));
}

#[test]
fn a_cache_entry_dated_in_the_future_is_not_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let client = FakeOsv::answering(&[]);
    clock.advance(Duration::from_secs(10_000));
    run(
        packages(vec![pkg("a", "1.0.0", "f", None)]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &clock),
    );
    let earlier = FakeClock(Rc::new(Cell::new(1_700_000_000)));
    let out = run(
        packages(vec![pkg("a", "1.0.0", "f", None)]),
        OsvMode::Offline,
        &client,
        &cache(dir.path(), &earlier),
    );
    assert!(matches!(out.status, OsvStatus::Skipped(_)));
}

fn cache_files(dir: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}

#[test]
fn a_damaged_or_foreign_cache_file_is_ignored_and_refetched() {
    let bad_files: [&str; 5] = [
        "not json at all",
        "",
        r#"{"schema":99,"ecosystem":"npm","name":"x","version":"1.0.0","fetched_at":1700000000,"vulns":[]}"#,
        r#"{"schema":1,"ecosystem":"npm","name":"other","version":"1.0.0","fetched_at":1700000000,"vulns":[]}"#,
        r#"{"schema":1,"ecosystem":"npm","name":"x","version":"1.0.0","fetched_at":"soon","vulns":[]}"#,
    ];
    for bad in bad_files {
        let dir = tempfile::tempdir().unwrap();
        let clock = FakeClock::new();
        let client =
            FakeOsv::answering(&["GHSA-1"]).with_record(record("GHSA-1", Some("HIGH"), "x", &[]));
        let list = || packages(vec![pkg("x", "1.0.0", "f", None)]);
        run(list(), OsvMode::Live, &client, &cache(dir.path(), &clock));
        for f in cache_files(dir.path()) {
            fs::write(f, bad).unwrap();
        }
        let offline = run(
            list(),
            OsvMode::Offline,
            &client,
            &cache(dir.path(), &clock),
        );
        assert!(matches!(offline.status, OsvStatus::Skipped(_)), "{bad}");
        let live = run(list(), OsvMode::Live, &client, &cache(dir.path(), &clock));
        assert_eq!(ids(&live.findings), ["osv/known-vulnerability"], "{bad}");
        let healed = run(
            list(),
            OsvMode::Offline,
            &client,
            &cache(dir.path(), &clock),
        );
        assert_eq!(healed.status, OsvStatus::Ran, "{bad}");
    }
}

#[test]
fn a_hostile_package_name_cannot_write_outside_the_cache_directory() {
    let root = tempfile::tempdir().unwrap();
    let cache_dir = root.path().join("cache");
    let client = FakeOsv::answering(&[]);
    let list = vec![
        pkg("../../escape", "1.0.0", "f", None),
        pkg("a/b\\c", "../../v", "f", None),
        pkg("x\0y", "1", "f", None),
    ];
    run(
        packages(list),
        OsvMode::Live,
        &client,
        &cache(&cache_dir, &FakeClock::new()),
    );
    let mut top: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    top.sort();
    assert_eq!(top, ["cache"]);
    for f in cache_files(&cache_dir) {
        assert_eq!(f.parent().unwrap(), cache_dir);
        assert!(f.extension().is_some_and(|e| e == "json"));
    }
    assert_eq!(cache_files(&cache_dir).len(), 3);
}

#[cfg(unix)]
#[test]
fn a_symlinked_cache_file_is_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let client = FakeOsv::answering(&[]);
    let list = || packages(vec![pkg("x", "1.0.0", "f", None)]);
    run(list(), OsvMode::Live, &client, &cache(dir.path(), &clock));
    let file = cache_files(dir.path()).remove(0);
    let real = dir.path().join("elsewhere");
    fs::rename(&file, &real).unwrap();
    std::os::unix::fs::symlink(&real, &file).unwrap();
    let out = run(
        list(),
        OsvMode::Offline,
        &client,
        &cache(dir.path(), &clock),
    );
    assert!(matches!(out.status, OsvStatus::Skipped(_)));
}

#[test]
fn an_unreadable_lockfile_is_a_warning_and_the_rest_still_runs() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::answering(&[]);
    let out = run(
        Discovered {
            packages: vec![pkg("x", "1.0.0", "f", None)],
            unparsed: vec![Unparsed {
                file: "yarn.lock".into(),
                reason: UnparsedReason::Malformed,
            }],
        },
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    assert_eq!(ids(&out.findings), ["osv/unparsed-lockfile"]);
    assert_eq!(out.findings[0].severity, Severity::Warn);
    assert_eq!(out.findings[0].evidence.file.as_deref(), Some("yarn.lock"));
    assert_eq!(out.status, OsvStatus::Ran);
}

fn write_user_allow(dir: &Path, body: &str) -> Allowlists {
    fs::create_dir(dir.join("code-watch")).unwrap();
    fs::write(
        dir.join("code-watch/allow.toml"),
        format!("schema = 1\n{body}"),
    )
    .unwrap();
    Allowlists::load(Some(dir), None).unwrap()
}

fn lockfile_repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    fs::write(
        repo.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.4","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz"}}}"#,
    )
    .unwrap();
    repo
}

fn scan(
    repo: &Path,
    allow: &Allowlists,
    mode: OsvMode,
    client: &FakeOsv,
    cache: &Cache,
) -> code_watch_core::Report {
    let setup = OsvSetup {
        mode,
        client,
        cache,
    };
    Engine::embedded()
        .unwrap()
        .scan_dir_osv(repo, allow, Some(&setup))
        .unwrap()
}

#[test]
fn an_allowlist_entry_with_the_package_suppresses_and_another_package_does_not() {
    let repo = lockfile_repo();
    let client =
        FakeOsv::answering(&["GHSA-1"]).with_record(record("GHSA-1", Some("HIGH"), "lodash", &[]));
    for (package, hidden) in [("lodash", true), ("express", false)] {
        let user = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let allow = write_user_allow(
            user.path(),
            &format!("[[allow]]\nrule = \"osv/known-vulnerability\"\npackage = \"{package}\"\n"),
        );
        let report = scan(
            repo.path(),
            &allow,
            OsvMode::Live,
            &client,
            &cache(cache_dir.path(), &FakeClock::new()),
        );
        assert_eq!(report.findings().is_empty(), hidden, "{package}");
        assert_eq!(report.suppressed().len(), usize::from(hidden), "{package}");
        assert!(
            report.allowlist_warnings().is_empty(),
            "osv rule ids are known"
        );
    }
}

#[test]
fn the_unchecked_and_unparsed_warnings_can_never_be_allowed() {
    let repo = lockfile_repo();
    fs::write(repo.path().join("Cargo.lock"), "{{{").unwrap();
    let user = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let allow = write_user_allow(
        user.path(),
        "[[allow]]\nrule = \"osv/unchecked-packages\"\n[[allow]]\nrule = \"osv/unparsed-lockfile\"\n",
    );
    let client = FakeOsv::failing(OsvError::Network);
    let report = scan(
        repo.path(),
        &allow,
        OsvMode::Live,
        &client,
        &cache(cache_dir.path(), &FakeClock::new()),
    );
    assert!(ids(report.findings()).contains(&"osv/unchecked-packages"));
    assert!(ids(report.findings()).contains(&"osv/unparsed-lockfile"));
    assert!(report.suppressed().is_empty());
}

#[test]
fn a_repo_file_cannot_allow_a_malicious_package_on_its_own() {
    let repo = lockfile_repo();
    fs::write(
        repo.path().join(".code-watch.toml"),
        "schema = 1\n[[allow]]\nrule = \"osv/malicious-package\"\n",
    )
    .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::answering(&["MAL-1"]).with_record(record("MAL-1", None, "lodash", &[]));
    let allow = Allowlists::load(None, Some(repo.path())).unwrap();
    let report = scan(
        repo.path(),
        &allow,
        OsvMode::Live,
        &client,
        &cache(cache_dir.path(), &FakeClock::new()),
    );
    assert_eq!(report.verdict(), code_watch_core::Verdict::Block);
    assert!(ids(report.findings()).contains(&"allowlist/repo-block-override-refused"));
}

#[test]
fn the_layer_status_is_ran_skipped_with_a_reason_or_off_in_both_outputs() {
    let repo = lockfile_repo();
    let engine = Engine::embedded().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let client = FakeOsv::answering(&[]);

    let off = engine
        .scan_dir_with(repo.path(), &Allowlists::empty())
        .unwrap();
    assert_eq!(off.layers()[&code_watch_core::Layer::Osv], LayerStatus::Off);
    let json: serde_json::Value = serde_json::from_str(&render::to_json(&off).unwrap()).unwrap();
    assert_eq!(json["layers"]["osv"], "off");
    assert_eq!(json["schema"], 1);

    let skipped = scan(
        repo.path(),
        &Allowlists::empty(),
        OsvMode::Offline,
        &client,
        &cache(cache_dir.path(), &clock),
    );
    let json: serde_json::Value =
        serde_json::from_str(&render::to_json(&skipped).unwrap()).unwrap();
    assert_eq!(json["layers"]["osv"], "skipped");
    assert_eq!(json["skipped_layers"]["osv"], "offline and no fresh cache");
    assert!(render::to_human(&skipped).contains("osv skipped (offline and no fresh cache)"));

    let ran = scan(
        repo.path(),
        &Allowlists::empty(),
        OsvMode::Live,
        &client,
        &cache(cache_dir.path(), &clock),
    );
    let json: serde_json::Value = serde_json::from_str(&render::to_json(&ran).unwrap()).unwrap();
    assert_eq!(json["layers"]["osv"], "ran");
    assert_eq!(json["skipped_layers"], serde_json::json!({}));
}

#[test]
fn ecosystem_names_in_queries_are_the_osv_spellings() {
    let dir = tempfile::tempdir().unwrap();
    let client = FakeOsv::answering(&[]);
    let mk = |e, n: &str| Package {
        ecosystem: e,
        name: n.into(),
        version: "1".into(),
        file: "f".into(),
        line: None,
    };
    run(
        packages(vec![
            mk(Ecosystem::Npm, "a"),
            mk(Ecosystem::PyPI, "b"),
            mk(Ecosystem::CratesIo, "c"),
            mk(Ecosystem::Go, "d"),
        ]),
        OsvMode::Live,
        &client,
        &cache(dir.path(), &FakeClock::new()),
    );
    let names: Vec<_> = client.batches.borrow()[0]
        .iter()
        .map(|q| q.ecosystem.osv_name())
        .collect();
    assert_eq!(names, ["npm", "PyPI", "crates.io", "Go"]);
}
