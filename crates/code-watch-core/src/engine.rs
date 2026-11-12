use std::fs;
use std::path::Path;

use ignore::WalkBuilder;

use crate::report::Report;
use crate::rules::{RuleError, RuleSet, Target};

/// Files above this size are not read: rules look at manifests and scripts, and a hostile repo
/// must not be able to make a scan allocate without bound.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{0} is not a directory")]
    NotADirectory(String),
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
    /// machine) and only `.git` is skipped. Unreadable and non-UTF-8 files are skipped.
    pub fn scan_dir(&self, dir: &Path) -> Result<Report, ScanError> {
        if !dir.is_dir() {
            return Err(ScanError::NotADirectory(dir.display().to_string()));
        }
        let walker = WalkBuilder::new(dir)
            .standard_filters(false)
            .filter_entry(|e| e.file_name() != ".git")
            .build();
        let mut findings = Vec::new();
        for entry in walker.flatten() {
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
            if wanted.is_empty() || entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES) {
                continue;
            }
            let Ok(content) = fs::read_to_string(entry.path()) else {
                continue;
            };
            findings.extend(wanted.iter().flat_map(|r| r.check_file(rel, &content)));
        }
        Ok(Report::from_rules(findings))
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

    #[test]
    fn oversized_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let pad = " ".repeat(MAX_FILE_BYTES as usize);
        fs::write(
            dir.path().join("package.json"),
            format!(r#"{{"scripts":{{"postinstall":"echo hi"}}}}{pad}"#),
        )
        .unwrap();
        let report = Engine::embedded().unwrap().scan_dir(dir.path()).unwrap();
        assert!(report.findings().is_empty());
    }
}
