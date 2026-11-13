use std::str::FromStr;

use pep508_rs::pep440_rs::Operator;
use pep508_rs::{PackageName, Requirement, VersionOrUrl};
use serde::Deserialize;

use super::package::{Ecosystem, Package, PackageSource, ParseError};

const PYPI_INDEX: &str = "https://pypi.org/simple";

/// PEP 503 normalised name, so the same package spelled two ways is one package.
fn normalise(name: &str) -> Option<String> {
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

/// `requirements.txt`: only exact `==` pins are packages; ranges, URLs, editable installs and
/// option lines name no single version.
pub struct Requirements;

impl PackageSource for Requirements {
    fn file_names(&self) -> &'static [&'static str] {
        &["requirements.txt"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        Ok(logical_lines(text)
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
            .collect())
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
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: Option<String>,
    source: Option<toml::Value>,
}

/// `poetry.lock`: a package with a `[package.source]` table is git, local or from a private
/// index, so only source-less entries (PyPI) are kept.
pub struct PoetryLock;

impl PackageSource for PoetryLock {
    fn file_names(&self) -> &'static [&'static str] {
        &["poetry.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        let lock: Lock = toml::from_str(text).map_err(ParseError::of)?;
        Ok(lock
            .package
            .iter()
            .filter(|p| p.source.is_none())
            .filter_map(|p| pypi(file, &p.name, p.version.as_deref()?))
            .collect())
    }
}

/// `uv.lock`: only packages whose source is the public PyPI index. The project itself is
/// `virtual` or `editable`, so it never matches.
pub struct UvLock;

impl PackageSource for UvLock {
    fn file_names(&self) -> &'static [&'static str] {
        &["uv.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        let lock: Lock = toml::from_str(text).map_err(ParseError::of)?;
        Ok(lock
            .package
            .iter()
            .filter(|p| {
                p.source
                    .as_ref()
                    .and_then(|s| s.get("registry"))
                    .and_then(toml::Value::as_str)
                    .is_some_and(|r| r.trim_end_matches('/') == PYPI_INDEX)
            })
            .filter_map(|p| pypi(file, &p.name, p.version.as_deref()?))
            .collect())
    }
}
