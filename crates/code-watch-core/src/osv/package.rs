use std::fmt;

use serde::{Deserialize, Serialize};

/// The ecosystems OSV knows, named exactly as the OSV API spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "PyPI")]
    PyPI,
    #[serde(rename = "crates.io")]
    CratesIo,
    #[serde(rename = "Go")]
    Go,
}

impl Ecosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Go => "Go",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.osv_name())
    }
}

/// A package a lockfile pins, from the public registry of its ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// The lockfile, relative to the scanned root.
    pub file: String,
    pub line: Option<usize>,
}

impl Package {
    pub(crate) fn new(ecosystem: Ecosystem, name: &str, version: &str, file: &str) -> Self {
        Self {
            ecosystem,
            name: name.to_owned(),
            version: version.to_owned(),
            file: file.to_owned(),
            line: None,
        }
    }

    pub(crate) fn at_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("{0}")]
    Malformed(String),
    /// The file parses as a lockfile but declares a format version this build does not know.
    #[error("{0}")]
    UnknownFormat(String),
}

impl ParseError {
    pub(crate) fn of(err: impl fmt::Display) -> Self {
        Self::Malformed(err.to_string())
    }

    pub(crate) fn unknown_format(what: impl fmt::Display) -> Self {
        Self::UnknownFormat(what.to_string())
    }
}

/// What one lockfile gave: the packages to look up, and how many entries were left out because
/// their source is not the public registry or the entry was not recognised.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub packages: Vec<Package>,
    pub not_looked_up: usize,
}

impl Parsed {
    pub(crate) fn new(packages: Vec<Package>, not_looked_up: usize) -> Self {
        Self {
            packages,
            not_looked_up,
        }
    }
}

/// A lockfile format version written as a number (`5.4`) or a string (`'6.0'`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum FormatVersion {
    Number(f64),
    Text(String),
}

impl FormatVersion {
    pub(crate) fn major(&self) -> Option<u64> {
        match self {
            FormatVersion::Number(n) if *n >= 0.0 => Some(*n as u64),
            FormatVersion::Number(_) => None,
            FormatVersion::Text(s) => s.split('.').next()?.trim().parse().ok(),
        }
    }

    /// Fails with an unknown-format error unless the major version is in `known`.
    pub(crate) fn require(
        version: Option<&Self>,
        known: &[u64],
        what: &str,
    ) -> Result<(), ParseError> {
        match version.and_then(Self::major) {
            Some(m) if known.contains(&m) => Ok(()),
            Some(m) => Err(ParseError::unknown_format(format!(
                "{what} format version {m} is not recognised"
            ))),
            None => Err(ParseError::unknown_format(format!(
                "{what} format version is missing or unreadable"
            ))),
        }
    }
}

/// One lockfile format. `parse` returns only packages that come from the public registry:
/// local, workspace, git and private-registry entries are dropped so they can never match a
/// published package of the same name; the ones that are not local are counted in
/// `not_looked_up` so the report can say they were skipped. A format version the parser does not
/// know is an error, never an empty list.
pub trait PackageSource {
    /// Globs over the path relative to the scanned root, `/`-separated.
    fn globs(&self) -> &'static [&'static str];
    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError>;
}

/// The npm family of lockfiles resolve public packages from these hosts.
pub(crate) fn is_public_npm_url(url: &str) -> bool {
    [
        "https://registry.npmjs.org/",
        "https://registry.yarnpkg.com/",
    ]
    .iter()
    .any(|p| url.starts_with(p))
}

/// A plain version number, as opposed to `file:`, `link:`, `git+...` or a range.
pub(crate) fn looks_like_version(v: &str) -> bool {
    v.starts_with(|c: char| c.is_ascii_digit()) && !v.contains(['/', ':', ' '])
}
