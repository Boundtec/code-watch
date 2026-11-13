use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::read::{MAX_TEXT_BYTES, read_optional, read_text};
use super::{Judge, finding, shown, unchecked};
use crate::finding::{Finding, Severity};

/// Nested `-r` files followed.
const MAX_DEPTH: usize = 3;
/// Requirement lines read in all.
const MAX_LINES: usize = 5000;

const VALUE_FLAGS: &[&str] = &[
    "-c",
    "--constraint",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
    "--platform",
    "--abi",
    "--implementation",
    "--python-version",
    "--config-settings",
    "-C",
    "--proxy",
    "--cert",
    "--trusted-host",
    "--src",
    "--upgrade-strategy",
    "--report",
    "--exists-action",
    "--progress-bar",
    "--root-user-action",
    "--use-feature",
    "--log",
    "--retries",
    "--timeout",
    "--cache-dir",
    "--global-option",
    "--install-option",
    "--hash",
];

#[derive(Default)]
struct Scan {
    only_binary_all: bool,
    no_binary: bool,
    targets: BTreeSet<Target>,
    problems: Vec<(String, String)>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    /// A directory that is built with its own backend, shown as typed.
    Directory(String),
    /// A VCS address or a source archive.
    Source(String),
}

enum Kind {
    Directory,
    Source,
    Other,
}

/// `pip install` args (after `install`) of one command. Only files on disk are read: a bare
/// package name gets no finding because whether pip builds it depends on what the index
/// offers, and that is never fetched here.
pub(super) fn analyze(args: &[String], here: &Path, cwd: &Path, judge: &Judge) -> Vec<Finding> {
    let mut words = args.iter().filter(|a| !a.starts_with('-') || a.len() > 1);
    // The subcommand is the first word that is not a flag; pip's global flags take no value here.
    let Some(sub) = words.find(|a| !a.starts_with('-')) else {
        return Vec::new();
    };
    if sub != "install" {
        return Vec::new();
    }
    let rest: Vec<String> = args
        .iter()
        .skip_while(|a| *a != "install")
        .skip(1)
        .cloned()
        .collect();
    let mut scan = Scan::default();
    read_args(&rest, here, cwd, 0, &mut scan);
    let mut out = Vec::new();
    for (file, why) in &scan.problems {
        out.push(unchecked(file, why));
    }
    if scan.only_binary_all {
        out.push(finding(
            "install/pip-wheels-only",
            Severity::Info,
            None,
            None,
            "--only-binary :all:",
            None,
        ));
        return out;
    }
    if scan.no_binary {
        out.push(finding(
            "install/pip-build-code",
            Severity::Warn,
            None,
            None,
            "--no-binary makes pip build packages from source",
            None,
        ));
    }
    for target in &scan.targets {
        match target {
            Target::Source(what) => out.push(finding(
                "install/pip-build-code",
                Severity::Warn,
                None,
                None,
                &format!("pip builds {what} from source"),
                None,
            )),
            Target::Directory(dir) => out.extend(directory(dir, here, cwd, judge)),
        }
    }
    out
}

/// A local project builds with its own backend: setup.py or the pyproject.toml `build-backend`.
fn directory(dir: &str, here: &Path, cwd: &Path, judge: &Judge) -> Vec<Finding> {
    let path: PathBuf = here.join(dir);
    let name = shown(&path, cwd);
    if !path.is_dir() {
        return vec![unchecked(&name, "is not a directory")];
    }
    let mut parts = Vec::new();
    let mut out = Vec::new();
    match read_optional(&path.join("pyproject.toml"), MAX_TEXT_BYTES) {
        Ok(Some(text)) => match text.parse::<toml::Table>() {
            Ok(t) => match t
                .get("build-system")
                .and_then(|b| b.get("build-backend"))
                .and_then(|b| b.as_str())
            {
                Some(backend) => parts.push(format!("build backend {backend}")),
                None => parts.push("pyproject.toml without a build backend (setuptools)".into()),
            },
            Err(_) => out.push(unchecked(
                &format!("{name}/pyproject.toml"),
                "is not valid TOML",
            )),
        },
        Ok(None) => {}
        Err(e) => out.push(unchecked(&format!("{name}/pyproject.toml"), e.describe())),
    }
    match read_text(&path.join("setup.py"), MAX_TEXT_BYTES) {
        Ok(text) if (judge.setup_py_flagged)(&text) => {
            parts.push("setup.py runs code at install time".into())
        }
        Ok(_) => parts.push("setup.py".into()),
        Err(super::read::ReadError::Missing) => {}
        Err(e) => out.push(unchecked(&format!("{name}/setup.py"), e.describe())),
    }
    if parts.is_empty() {
        parts.push("no pyproject.toml or setup.py read".into());
    }
    out.push(finding(
        "install/pip-build-code",
        Severity::Warn,
        Some(name),
        None,
        &format!("pip builds this directory: {}", parts.join(", ")),
        None,
    ));
    out
}

fn classify(spec: &str) -> Kind {
    let lower = spec.to_ascii_lowercase();
    let archive = [".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".tar"]
        .iter()
        .any(|e| lower.split(['#', '?']).next().unwrap_or("").ends_with(e));
    if ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|p| lower.starts_with(p))
        || archive
    {
        Kind::Source
    } else if lower.contains(".whl") {
        Kind::Other
    } else if spec == "." || spec == ".." || spec.starts_with(['.', '/', '~']) {
        Kind::Directory
    } else {
        Kind::Other
    }
}

fn add_spec(spec: &str, scan: &mut Scan) {
    match classify(spec) {
        Kind::Directory => {
            scan.targets.insert(Target::Directory(spec.to_string()));
        }
        Kind::Source => {
            scan.targets.insert(Target::Source(spec.to_string()));
        }
        Kind::Other => {}
    }
}

fn binary_flag(flag: &str, value: Option<&str>, scan: &mut Scan) {
    let value = value.unwrap_or("");
    match flag {
        "--only-binary" if value.split(',').any(|v| v == ":all:") => scan.only_binary_all = true,
        "--no-binary" if value.split(',').any(|v| v != ":none:") => scan.no_binary = true,
        _ => {}
    }
}

fn read_args(args: &[String], here: &Path, cwd: &Path, depth: usize, scan: &mut Scan) {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if arg.starts_with("--") => (f, Some(v)),
            _ => (arg, None),
        };
        let mut value = || {
            inline.or_else(|| {
                i += 1;
                args.get(i).map(String::as_str)
            })
        };
        match flag {
            "-r" | "--requirement" => {
                if let Some(file) = value() {
                    requirements(file, here, cwd, depth, scan);
                }
            }
            "-e" | "--editable" => {
                if let Some(target) = value() {
                    if matches!(classify(target), Kind::Source) {
                        add_spec(target, scan);
                    } else {
                        scan.targets.insert(Target::Directory(target.to_string()));
                    }
                }
            }
            "--only-binary" | "--no-binary" => {
                let v = value();
                binary_flag(flag, v, scan);
            }
            f if VALUE_FLAGS.contains(&f) => {
                let _ = value();
            }
            f if f.starts_with('-') => {}
            _ => add_spec(arg, scan),
        }
        i += 1;
    }
}

/// A requirements file's lines are options or specs; nested `-r` is relative to that file.
fn requirements(file: &str, here: &Path, cwd: &Path, depth: usize, scan: &mut Scan) {
    let path = here.join(file);
    let name = shown(&path, cwd);
    if depth >= MAX_DEPTH {
        scan.problems
            .push((name, "is nested deeper than the limit".into()));
        return;
    }
    let text = match read_text(&path, MAX_TEXT_BYTES) {
        Ok(t) => t,
        Err(e) => {
            scan.problems.push((name, e.describe().into()));
            return;
        }
    };
    let base = path.parent().unwrap_or(here).to_path_buf();
    for line in text.lines().take(MAX_LINES) {
        let line = line.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            let words: Vec<String> = line
                .split_once(char::is_whitespace)
                .map(|(f, v)| vec![f.to_string(), v.trim().to_string()])
                .unwrap_or_else(|| vec![line.to_string()]);
            read_args(&words, &base, cwd, depth + 1, scan);
        } else {
            let spec = line.split(" ;").next().unwrap_or(line).trim();
            let spec = spec.split(" @ ").nth(1).unwrap_or(spec).trim();
            add_spec(spec, scan);
        }
    }
}
