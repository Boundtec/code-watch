use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use super::read::{MAX_TEXT_BYTES, read_optional, read_text};
use super::{Judge, finding, list, redact, shown, unchecked};
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
    "--client-cert",
    "--keyring-provider",
];

/// Short flags whose value may be glued to them (`-rreq.txt`).
const GLUED_SHORT: &[char] = &['r', 'e', 'c', 'i', 'f', 't', 'C'];

struct Scan {
    /// Where the install runs: local paths are resolved against it.
    root: PathBuf,
    only_binary_all: bool,
    /// Names given to `--no-binary` (and `:all:`), after the later `--only-binary` flags.
    no_binary: BTreeSet<String>,
    targets: BTreeSet<Target>,
    /// Index packages named on the command line or in requirements files.
    names: BTreeSet<String>,
    /// Options that point pip at a source other than PyPI, by name (their values can hold credentials).
    other_index: BTreeSet<String>,
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
    Index(String),
    Wheel,
}

/// Where `install` is among pip's args: the first word that is neither a flag nor a flag's value.
fn install_position(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg.starts_with('-') && arg.len() > 1 {
            if VALUE_FLAGS.contains(&arg) {
                i += 1;
            }
            i += 1;
            continue;
        }
        return (arg == "install").then_some(i);
    }
    None
}

/// `pip ...` args of one command (after the program). `pip install name` cannot be judged
/// offline: whether pip builds a package depends on what the index offers, so named packages
/// are reported as "may build".
pub(super) fn analyze(args: &[String], here: &Path, cwd: &Path, judge: &Judge) -> Vec<Finding> {
    let Some(at) = install_position(args) else {
        return Vec::new();
    };
    let mut scan = Scan {
        root: here.to_path_buf(),
        only_binary_all: false,
        no_binary: BTreeSet::new(),
        targets: BTreeSet::new(),
        names: BTreeSet::new(),
        other_index: BTreeSet::new(),
        problems: Vec::new(),
    };
    read_args(&args[at + 1..], here, cwd, 0, &mut scan);
    let mut out = Vec::new();
    for (file, why) in &scan.problems {
        out.push(unchecked(file, why));
    }
    if !scan.no_binary.is_empty() {
        let names: BTreeSet<String> = scan.no_binary.iter().cloned().collect();
        out.push(finding(
            "install/pip-build-code",
            Severity::Warn,
            None,
            None,
            &format!("--no-binary makes pip build from source: {}", list(&names)),
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
                &format!("pip builds {} from source", redact(what)),
                None,
            )),
            Target::Directory(dir) => out.extend(directory(&redact(dir), here, cwd, judge)),
        }
    }
    let wheels_only = scan.only_binary_all && scan.no_binary.is_empty();
    if !scan.only_binary_all && !scan.no_binary.contains(":all:") && !scan.names.is_empty() {
        // From an index alone, pip builds only when no wheel fits: worth saying, not worth a warn.
        let index_only =
            scan.targets.is_empty() && scan.no_binary.is_empty() && scan.other_index.is_empty();
        out.push(finding(
            "install/pip-build-code",
            if index_only {
                Severity::Info
            } else {
                Severity::Warn
            },
            None,
            None,
            &format!(
                "pip may build these from source if no wheel fits; not checked offline: {}{}",
                list(&scan.names),
                if scan.other_index.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; {} point pip at a source other than PyPI, where a package can be a source distribution that builds",
                        list(&scan.other_index)
                    )
                }
            ),
            None,
        ));
    }
    if wheels_only && scan.targets.is_empty() {
        out.push(finding(
            "install/pip-wheels-only",
            Severity::Info,
            None,
            None,
            "--only-binary :all:",
            None,
        ));
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

/// The spec as pip would read it: a PEP 508 `name @ url` is its url, anything else as written.
fn direct_reference(spec: &str) -> String {
    match pep508_rs::Requirement::<pep508_rs::VerbatimUrl>::from_str(spec) {
        Ok(req) => match req.version_or_url {
            Some(pep508_rs::VersionOrUrl::Url(url)) => url.to_string(),
            _ => spec.to_string(),
        },
        Err(_) => spec.to_string(),
    }
}

fn package_name(spec: &str) -> String {
    pep508_rs::Requirement::<pep508_rs::VerbatimUrl>::from_str(spec)
        .map(|r| r.name.to_string())
        .unwrap_or_else(|_| redact(spec))
}

fn classify(spec: &str, root: &Path) -> Kind {
    let target = direct_reference(spec);
    let lower = target.to_ascii_lowercase();
    let path = lower.split(['#', '?']).next().unwrap_or("");
    if path.ends_with(".whl") {
        return Kind::Wheel;
    }
    let archive = [".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".tar"]
        .iter()
        .any(|e| path.ends_with(e));
    if lower.contains("://") || lower.starts_with("file:") || archive {
        Kind::Source
    } else if target == "."
        || target == ".."
        || target.starts_with(['.', '/', '~'])
        || (target.contains('/') && root.join(&target).is_dir())
    {
        Kind::Directory
    } else {
        Kind::Index(package_name(spec))
    }
}

fn add_spec(spec: &str, scan: &mut Scan) {
    let spec = spec.split(" --").next().unwrap_or(spec).trim();
    let spec = spec.split(" ;").next().unwrap_or(spec).trim();
    let shown = direct_reference(spec);
    match classify(spec, &scan.root) {
        Kind::Directory => {
            scan.targets.insert(Target::Directory(shown));
        }
        Kind::Source => {
            scan.targets.insert(Target::Source(shown));
        }
        Kind::Index(name) => {
            scan.names.insert(name);
        }
        Kind::Wheel => {}
    }
}

/// pip's format control: a later flag overrides an earlier one for the names it mentions, and
/// `:all:` resets the other flag.
fn binary_flag(flag: &str, value: Option<&str>, scan: &mut Scan) {
    for name in value.unwrap_or("").split(',').map(str::to_ascii_lowercase) {
        match (flag, name.as_str()) {
            ("--only-binary", ":all:") => {
                scan.only_binary_all = true;
                scan.no_binary.clear();
            }
            ("--only-binary", ":none:") => scan.only_binary_all = false,
            ("--only-binary", _) => {
                scan.no_binary.remove(&name);
            }
            ("--no-binary", ":all:") => {
                scan.only_binary_all = false;
                scan.no_binary.clear();
                scan.no_binary.insert(name);
            }
            ("--no-binary", ":none:") => scan.no_binary.clear(),
            ("--no-binary", _) => {
                scan.no_binary.insert(name);
            }
            _ => {}
        }
    }
}

/// The options that make pip look for packages somewhere else than PyPI, in their long spelling.
fn other_index_flag(flag: &str) -> Option<&'static str> {
    match flag {
        "-i" | "--index-url" => Some("--index-url"),
        "--extra-index-url" => Some("--extra-index-url"),
        "-f" | "--find-links" => Some("--find-links"),
        "--trusted-host" => Some("--trusted-host"),
        _ => None,
    }
}

/// `-rreq.txt` as (`-r`, `req.txt`); anything else as (flag, inline value of `--flag=value`).
fn split_flag(arg: &str) -> (&str, Option<&str>) {
    if let Some(long) = arg.strip_prefix("--") {
        return match long.split_once('=') {
            Some((_, v)) => (&arg[..arg.len() - v.len() - 1], Some(v)),
            None => (arg, None),
        };
    }
    let mut chars = arg.chars();
    if chars.next() == Some('-')
        && let Some(short) = chars.next()
        && GLUED_SHORT.contains(&short)
        && arg.len() > 2
    {
        return (&arg[..2], Some(&arg[2..]));
    }
    (arg, None)
}

/// Reads install options and specs from CLI words; requirements-file option lines are
/// tokenised and read through here too, so both take the same forms.
fn read_args(args: &[String], here: &Path, cwd: &Path, depth: usize, scan: &mut Scan) {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let (flag, inline) = split_flag(arg);
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
                    if matches!(classify(target, &scan.root), Kind::Source) {
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
            f if other_index_flag(f).is_some() => {
                let _ = value();
                scan.other_index
                    .extend(other_index_flag(f).map(str::to_string));
            }
            f if VALUE_FLAGS.contains(&f) => {
                let _ = value();
            }
            f if f.starts_with('-') && f.len() > 1 => {}
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
            match shlex::split(line) {
                Some(words) => read_args(&words, &base, cwd, depth + 1, scan),
                None => scan
                    .problems
                    .push((name.clone(), "has a line that cannot be read".into())),
            }
        } else {
            add_spec(line, scan);
        }
    }
}
