use std::fs;
use std::io;
use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

use super::cargo::CargoLock;
use super::go::GoModFile;
use super::npm::NpmLock;
use super::package::{Package, PackageSource, ParseError};
use super::pnpm::PnpmLock;
use super::python::{PoetryLock, Requirements, UvLock};
use super::yarn::YarnLock;
use crate::engine::error_path;

/// Lockfiles outgrow manifests, so the cap is higher than the scan's; it still bounds memory
/// against a hostile repository.
const MAX_LOCKFILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnparsedReason {
    Symlink,
    TooLarge,
    Unreadable,
    NotUtf8,
    Malformed,
    UnknownFormat,
    WalkError,
}

impl UnparsedReason {
    pub fn describe(self) -> &'static str {
        match self {
            UnparsedReason::Symlink => "a symlink, not followed",
            UnparsedReason::TooLarge => "larger than the 16 MiB limit",
            UnparsedReason::Unreadable => "could not be read",
            UnparsedReason::NotUtf8 => "not valid UTF-8",
            UnparsedReason::Malformed => "could not be parsed",
            UnparsedReason::UnknownFormat => "format version not recognised",
            UnparsedReason::WalkError => "could not be listed",
        }
    }
}

/// A lockfile the layer could not read, so its packages were not checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unparsed {
    pub file: String,
    pub reason: UnparsedReason,
}

/// Entries of a lockfile that were not looked up: from a non-public source, or not recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotLookedUp {
    pub file: String,
    pub count: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Discovered {
    pub packages: Vec<Package>,
    pub unparsed: Vec<Unparsed>,
    pub not_looked_up: Vec<NotLookedUp>,
}

fn sources() -> Vec<Box<dyn PackageSource>> {
    vec![
        Box::new(NpmLock),
        Box::new(PnpmLock),
        Box::new(YarnLock),
        Box::new(Requirements),
        Box::new(PoetryLock),
        Box::new(UvLock),
        Box::new(CargoLock),
        Box::new(GoModFile),
    ]
}

/// One glob set per source, matched against the path relative to the scanned root.
fn glob_table(sources: &[Box<dyn PackageSource>]) -> Vec<GlobSet> {
    sources
        .iter()
        .map(|s| {
            let mut builder = GlobSetBuilder::new();
            for pattern in s.globs() {
                let glob = GlobBuilder::new(pattern)
                    .literal_separator(true)
                    .build()
                    .expect("the built-in lockfile globs are valid");
                builder.add(glob);
            }
            builder
                .build()
                .expect("the built-in lockfile globs are valid")
        })
        .collect()
}

fn read_lockfile(path: &Path) -> Result<String, UnparsedReason> {
    let len = fs::metadata(path)
        .map_err(|_| UnparsedReason::Unreadable)?
        .len();
    if len > MAX_LOCKFILE_BYTES {
        return Err(UnparsedReason::TooLarge);
    }
    fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => UnparsedReason::NotUtf8,
        _ => UnparsedReason::Unreadable,
    })
}

/// Finds and parses every lockfile under `dir`. Like the scan it never follows symlinks and
/// skips `.git`; it also skips `node_modules`, whose nested lockfiles belong to other projects.
/// A lockfile that cannot be read or parsed is reported, never dropped silently.
pub fn discover(dir: &Path) -> Discovered {
    let sources = sources();
    let table = glob_table(&sources);
    let walker = WalkBuilder::new(dir)
        .standard_filters(false)
        .filter_entry(|e| e.file_name() != ".git" && e.file_name() != "node_modules")
        .build();
    let mut out = Discovered::default();
    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                out.unparsed.push(Unparsed {
                    file: error_path(&err, dir),
                    reason: UnparsedReason::WalkError,
                });
                continue;
            }
        };
        let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
        let Some(source) = table
            .iter()
            .position(|set| set.is_match(rel))
            .map(|i| &sources[i])
        else {
            continue;
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        let file = rel.to_string_lossy().into_owned();
        if file_type.is_symlink() {
            out.unparsed.push(Unparsed {
                file,
                reason: UnparsedReason::Symlink,
            });
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        match read_lockfile(entry.path()) {
            Err(reason) => out.unparsed.push(Unparsed { file, reason }),
            Ok(text) => match source.parse(&file, &text) {
                Ok(parsed) => {
                    out.packages.extend(parsed.packages);
                    if parsed.not_looked_up > 0 {
                        out.not_looked_up.push(NotLookedUp {
                            file,
                            count: parsed.not_looked_up,
                        });
                    }
                }
                Err(err) => out.unparsed.push(Unparsed {
                    file,
                    reason: match err {
                        ParseError::Malformed(_) => UnparsedReason::Malformed,
                        ParseError::UnknownFormat(_) => UnparsedReason::UnknownFormat,
                    },
                }),
            },
        }
    }
    out.packages.sort();
    out.unparsed.sort_by(|a, b| a.file.cmp(&b.file));
    out.not_looked_up.sort_by(|a, b| a.file.cmp(&b.file));
    out
}
