use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path};

use ignore::WalkBuilder;

use crate::finding::Finding;

/// Most files, bytes per file and bytes in total a request may carry.
pub const MAX_FILES: usize = 12;
pub const MAX_FILE_BYTES: usize = 16 * 1024;
pub const MAX_TOTAL_BYTES: usize = 96 * 1024;
const MAX_DEPTH: usize = 6;

const MANIFESTS: [&str; 8] = [
    "package.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Makefile",
    "build.rs",
    "Cargo.toml",
    "Dockerfile",
];

/// A file as it was sent: relative path, the text (cut at `MAX_FILE_BYTES`) and whether it was cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentFile {
    pub path: String,
    pub text: String,
    pub truncated: bool,
}

/// Exactly what a request carries. Evidence in a reply is checked against this, never against
/// the disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sent {
    pub files: Vec<SentFile>,
}

impl Sent {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Picks the files to send: those that already have a finding first, then manifests and install
/// or CI scripts. Only regular files, never through a symlink, never binary.
pub fn select(root: &Path, findings: &[Finding]) -> Sent {
    let mut paths: Vec<String> = Vec::new();
    for file in findings.iter().filter_map(|f| f.evidence.file.as_deref()) {
        if !paths.iter().any(|p| p == file) {
            paths.push(file.to_owned());
        }
    }
    for name in named_files(root) {
        if !paths.contains(&name) {
            paths.push(name);
        }
    }
    let mut sent = Sent::default();
    let mut total = 0;
    for rel in paths {
        if sent.files.len() == MAX_FILES || total >= MAX_TOTAL_BYTES {
            break;
        }
        let Some(file) = read_text(root, &rel, MAX_FILE_BYTES.min(MAX_TOTAL_BYTES - total)) else {
            continue;
        };
        total += file.text.len();
        sent.files.push(file);
    }
    sent
}

fn named_files(root: &Path) -> Vec<String> {
    let walker = WalkBuilder::new(root)
        .standard_filters(false)
        .follow_links(false)
        .max_depth(Some(MAX_DEPTH))
        .filter_entry(|e| e.file_name() != ".git" && e.file_name() != "node_modules")
        .build();
    let mut names: Vec<String> = walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .filter_map(|e| {
            let rel = e.path().strip_prefix(root).ok()?.to_str()?.to_owned();
            is_wanted(&rel).then_some(rel)
        })
        .collect();
    names.sort();
    names
}

fn is_wanted(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let lower = name.to_ascii_lowercase();
    let in_workflows = rel.starts_with(".github/workflows/")
        && (lower.ends_with(".yml") || lower.ends_with(".yaml"));
    let in_vscode = rel.starts_with(".vscode/") && name == "tasks.json";
    let manifest = MANIFESTS.contains(&name);
    let script = lower.ends_with(".sh")
        || ["install", "preinstall", "postinstall"]
            .iter()
            .any(|p| lower.starts_with(p));
    in_workflows || in_vscode || manifest || script
}

/// Reads at most `limit` bytes of a regular, non-symlink, UTF-8 file under `root`.
fn read_text(root: &Path, rel: &str, limit: usize) -> Option<SentFile> {
    let path = Path::new(rel);
    if limit == 0 || !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return None;
    }
    let full = root.join(path);
    let meta = fs::symlink_metadata(&full).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    File::open(&full)
        .ok()?
        .take(limit as u64)
        .read_to_end(&mut buf)
        .ok()?;
    let truncated = meta.len() > buf.len() as u64;
    let text = match std::str::from_utf8(&buf) {
        Ok(text) => text,
        Err(e) if truncated && e.error_len().is_none() => {
            std::str::from_utf8(&buf[..e.valid_up_to()]).ok()?
        }
        Err(_) => return None,
    };
    if text.contains('\0') {
        return None;
    }
    Some(SentFile {
        path: rel.to_owned(),
        text: text.to_owned(),
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Evidence, Layer, Severity};

    fn finding_in(file: &str) -> Finding {
        Finding {
            rule_id: "r/x".into(),
            severity: Severity::Warn,
            layer: Layer::Rules,
            title: String::new(),
            evidence: Evidence::new(Some(file.into()), None, ""),
            remediation: String::new(),
            domain: None,
            package: None,
            advisories: vec![],
        }
    }

    fn repo(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let full = dir.path().join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, content).unwrap();
        }
        dir
    }

    fn paths(sent: &Sent) -> Vec<&str> {
        sent.files.iter().map(|f| f.path.as_str()).collect()
    }

    #[test]
    fn files_with_findings_come_first_then_manifests_and_scripts() {
        let dir = repo(&[
            ("package.json", b"{}"),
            ("src/main.rs", b"fn main() {}"),
            ("src/odd.txt", b"x"),
            ("scripts/run.sh", b"echo"),
            ("README.md", b"hi"),
            (".github/workflows/ci.yaml", b"on: push"),
        ]);
        let sent = select(dir.path(), &[finding_in("src/odd.txt")]);
        assert_eq!(
            paths(&sent),
            [
                "src/odd.txt",
                ".github/workflows/ci.yaml",
                "package.json",
                "scripts/run.sh"
            ]
        );
    }

    #[test]
    fn binary_and_non_utf8_files_are_not_sent() {
        let dir = repo(&[
            ("package.json", b"{}"),
            ("a.sh", b"echo\0hi"),
            ("b.sh", &[0xff, 0xfe, 0x41]),
        ]);
        assert_eq!(paths(&select(dir.path(), &[])), ["package.json"]);
    }

    #[test]
    fn a_file_is_cut_at_the_per_file_cap_without_splitting_a_character() {
        let big = "é".repeat(MAX_FILE_BYTES);
        let dir = repo(&[("setup.py", big.as_bytes())]);
        let sent = select(dir.path(), &[]);
        let file = &sent.files[0];
        assert!(file.truncated);
        assert!(file.text.len() <= MAX_FILE_BYTES);
        assert!(file.text.chars().all(|c| c == 'é'));
    }

    fn many_scripts(size: usize) -> Sent {
        let many: Vec<(String, Vec<u8>)> = (0..30)
            .map(|i| (format!("s{i:02}.sh"), vec![b'a'; size]))
            .collect();
        let refs: Vec<(&str, &[u8])> = many.iter().map(|(p, c)| (p.as_str(), &c[..])).collect();
        select(repo(&refs).path(), &[])
    }

    #[test]
    fn the_file_count_is_capped() {
        assert_eq!(many_scripts(10).files.len(), MAX_FILES);
    }

    #[test]
    fn the_total_size_is_capped() {
        let sent = many_scripts(MAX_FILE_BYTES);
        let total: usize = sent.files.iter().map(|f| f.text.len()).sum();
        assert_eq!(total, MAX_TOTAL_BYTES);
        assert_eq!(sent.files.len(), MAX_TOTAL_BYTES / MAX_FILE_BYTES);
    }

    #[test]
    fn a_symlink_and_a_path_that_leaves_the_repo_are_not_read() {
        let outside = repo(&[("secret.txt", b"outside")]);
        let dir = repo(&[("package.json", b"{}")]);
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("link.sh"),
        )
        .unwrap();
        let sent = select(
            dir.path(),
            &[
                finding_in("link.sh"),
                finding_in("../secret.txt"),
                finding_in("/etc/hosts"),
            ],
        );
        assert_eq!(paths(&sent), ["package.json"]);
    }

    #[test]
    fn node_modules_and_git_are_not_walked() {
        let dir = repo(&[
            ("node_modules/x/install.sh", b"x"),
            (".git/hooks/post.sh", b"x"),
        ]);
        assert!(select(dir.path(), &[]).is_empty());
    }
}
