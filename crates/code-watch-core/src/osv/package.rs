use std::fmt;

use serde::Serialize;

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
#[error("{0}")]
pub struct ParseError(pub String);

impl ParseError {
    pub(crate) fn of(err: impl fmt::Display) -> Self {
        Self(err.to_string())
    }
}

/// One lockfile format. `parse` returns only packages that come from the public registry:
/// local, workspace, git and private-registry entries are dropped so they can never match a
/// published package of the same name.
pub trait PackageSource {
    fn file_names(&self) -> &'static [&'static str];
    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError>;
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
