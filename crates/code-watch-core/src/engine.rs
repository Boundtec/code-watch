use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use ignore::WalkBuilder;

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
            if !binary_rules.is_empty() {
                let head = read_head(entry.path());
                let executable = entry.metadata().is_ok_and(|m| is_executable(&m));
                findings.extend(
                    binary_rules
                        .iter()
                        .flat_map(|r| r.check_head(rel, &head, executable)),
                );
                if binary_rules.iter().any(|r| r.claims_binary(&head)) {
                    continue;
                }
            }
            if text_rules.is_empty() {
                continue;
            }
            match read_target(entry.path()) {
                Ok(content) => {
                    findings.extend(text_rules.iter().flat_map(|r| r.check_file(rel, &content)));
                }
                Err(reason) => skipped.push(Skipped {
                    path: rel.to_string_lossy().into_owned(),
                    reason,
                }),
            }
        }
        Ok(Report::from_scan(findings, skipped))
    }

    pub fn check_command(&self, command: &str) -> Report {
        let findings = self
            .rules
            .rules()
            .iter()
            .filter(|r| r.target() == Target::Command)
            .flat_map(|r| r.check_command(command))
            .collect();
        Report::from_rules(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn each_binary_format_is_recognised_and_not_reported_as_skipped() {
        let dir = tempfile::tempdir().unwrap();
        for (name, magic) in [
            ("elf.py", &b"\x7fELF\x00"[..]),
            ("macho.js", &[0xcf, 0xfa, 0xed, 0xfe, 0][..]),
            ("macho32.js", &[0xfe, 0xed, 0xfa, 0xce, 0][..]),
            ("pe.rb", &b"MZ\x90\x00"[..]),
        ] {
            fs::write(dir.path().join(name), magic).unwrap();
        }
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        let hits = report
            .findings()
            .iter()
            .filter(|f| f.rule_id == "repo/committed-binary")
            .count();
        assert_eq!(hits, 4);
        assert!(report.skipped().is_empty());
    }

    #[test]
    fn unreadable_text_is_still_skipped_when_it_is_not_a_known_binary() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("setup.py"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        assert_eq!(report.skipped().len(), 1);
    }
}
