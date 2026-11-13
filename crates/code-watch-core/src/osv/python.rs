use std::str::FromStr;

use pep508_rs::pep440_rs::Operator;
use pep508_rs::{PackageName, Requirement, VersionOrUrl};
use serde::Deserialize;

use super::package::{Ecosystem, FormatVersion, Package, PackageSource, ParseError, Parsed};

const PYPI_INDEX: &str = "https://pypi.org/simple";

/// PEP 503 normalised name, so the same package spelled two ways is one package.
pub(crate) fn normalise(name: &str) -> Option<String> {
    PackageName::from_str(name).ok().map(|n| n.to_string())
}

fn pypi(file: &str, name: &str, version: &str) -> Option<Package> {
    Some(Package::new(
        Ecosystem::PyPI,
        &normalise(name)?,
        version,
        file,
    ))
}

/// Requirements files: `requirements.txt`, `requirements-dev.txt`, `dev-requirements.txt` and
/// anything under a `requirements/` directory. Only exact `==` pins are packages; ranges, URLs, editable installs and
/// option lines name no single version.
pub struct Requirements;

impl PackageSource for Requirements {
    fn globs(&self) -> &'static [&'static str] {
        &[
            "**/requirements*.txt",
            "**/*requirements.txt",
            "**/requirements/*.txt",
        ]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        Ok(Parsed::new(
            logical_lines(text)
                .into_iter()
                .filter_map(|(line_no, line)| {
                    let req = Requirement::<pep508_rs::VerbatimUrl>::from_str(&line).ok()?;
                    let Some(VersionOrUrl::VersionSpecifier(specs)) = &req.version_or_url else {
                        return None;
                    };
                    let mut specs = specs.iter();
                    let (Some(spec), None) = (specs.next(), specs.next()) else {
                        return None;
                    };
                    if *spec.operator() != Operator::Equal {
                        return None;
                    }
                    let version = spec.version().to_string();
                    pypi(file, req.name.as_ref(), &version).map(|p| p.at_line(line_no))
                })
                .collect(),
            0,
        ))
    }
}

/// Joins `\` continuations (hash lines) and drops comments and option lines, keeping the
/// first physical line number of each requirement.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let (start, mut acc) = pending.take().unwrap_or((i + 1, String::new()));
        let line = raw.trim_end();
        let (body, continued) = match line.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (line, false),
        };
        acc.push_str(body);
        acc.push(' ');
        if continued {
            pending = Some((start, acc));
            continue;
        }
        let stripped = strip_comment(&acc).trim().to_owned();
        if !stripped.is_empty() && !stripped.starts_with('-') {
            out.push((start, stripped));
        }
    }
    if let Some((start, acc)) = pending {
        let stripped = strip_comment(&acc).trim().to_owned();
        if !stripped.is_empty() && !stripped.starts_with('-') {
            out.push((start, stripped));
        }
    }
    out
}

/// Drops a trailing comment and per-requirement options such as `--hash=...`.
fn strip_comment(line: &str) -> &str {
    let cut = [" #", " --"]
        .iter()
        .filter_map(|marker| line.find(marker))
        .chain(line.starts_with('#').then_some(0))
        .min();
    cut.map_or(line, |i| &line[..i])
}

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<LockPackage>,
    metadata: Option<PoetryMetadata>,
    version: Option<FormatVersion>,
}

#[derive(Deserialize)]
struct PoetryMetadata {
    #[serde(rename = "lock-version")]
    lock_version: Option<FormatVersion>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: Option<String>,
    source: Option<toml::Value>,
}

/// `poetry.lock`: a package with a `[package.source]` table is git, local or from a private
/// index, so only source-less entries (PyPI) are kept; the ones that are not a local directory
/// are counted as not looked up.
pub struct PoetryLock;

impl PackageSource for PoetryLock {
    fn globs(&self) -> &'static [&'static str] {
        &["**/poetry.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        let lock: Lock = toml::from_str(text).map_err(ParseError::of)?;
        if let Some(v) = lock.metadata.as_ref().and_then(|m| m.lock_version.as_ref()) {
            FormatVersion::require(Some(v), &[1, 2], "poetry lockfile")?;
        }
        let mut out = Parsed::default();
        for p in &lock.package {
            match &p.source {
                None => out
                    .packages
                    .extend(p.version.as_deref().and_then(|v| pypi(file, &p.name, v))),
                Some(s) if s.get("type").and_then(toml::Value::as_str) == Some("directory") => {}
                Some(_) => out.not_looked_up += 1,
            }
        }
        Ok(out)
    }
}

/// `uv.lock`: only packages whose source is the public PyPI index. The project itself is
/// `virtual` or `editable`; git, URL and other-index packages are counted as not looked up.
pub struct UvLock;

impl PackageSource for UvLock {
    fn globs(&self) -> &'static [&'static str] {
        &["**/uv.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        let lock: Lock = toml::from_str(text).map_err(ParseError::of)?;
        FormatVersion::require(lock.version.as_ref(), &[1], "uv lockfile")?;
        let mut out = Parsed::default();
        for p in &lock.package {
            let Some(source) = p.source.as_ref() else {
                continue;
            };
            match source.get("registry").and_then(toml::Value::as_str) {
                Some(r) if r.trim_end_matches('/') == PYPI_INDEX => out
                    .packages
                    .extend(p.version.as_deref().and_then(|v| pypi(file, &p.name, v))),
                Some(_) => out.not_looked_up += 1,
                None if ["git", "url"].iter().any(|k| source.get(k).is_some()) => {
                    out.not_looked_up += 1;
                }
                None => {}
            }
        }
        Ok(out)
    }
}
