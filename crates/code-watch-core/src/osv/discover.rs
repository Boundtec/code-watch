use std::fs;
use std::io;
use std::path::Path;

use ignore::WalkBuilder;

use super::cargo::CargoLock;
use super::go::GoModFile;
use super::npm::NpmLock;
use super::package::{Package, PackageSource};
use super::pnpm::PnpmLock;
use super::python::{PoetryLock, Requirements, UvLock};
use super::yarn::YarnLock;

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
}

impl UnparsedReason {
    pub fn describe(self) -> &'static str {
        match self {
            UnparsedReason::Symlink => "a symlink, not followed",
            UnparsedReason::TooLarge => "larger than the 16 MiB limit",
            UnparsedReason::Unreadable => "could not be read",
            UnparsedReason::NotUtf8 => "not valid UTF-8",
            UnparsedReason::Malformed => "could not be parsed",
        }
    }
}

/// A lockfile the layer could not read, so its packages were not checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unparsed {
    pub file: String,
    pub reason: UnparsedReason,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Discovered {
    pub packages: Vec<Package>,
    pub unparsed: Vec<Unparsed>,
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
    let walker = WalkBuilder::new(dir)
        .standard_filters(false)
        .filter_entry(|e| e.file_name() != ".git" && e.file_name() != "node_modules")
        .build();
    let mut out = Discovered::default();
    for entry in walker.flatten() {
        let name = entry.file_name().to_string_lossy();
        let Some(source) = sources.iter().find(|s| s.file_names().contains(&&*name)) else {
            continue;
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
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
                Ok(packages) => out.packages.extend(packages),
                Err(_) => out.unparsed.push(Unparsed {
                    file,
                    reason: UnparsedReason::Malformed,
                }),
            },
        }
    }
    out.packages.sort();
    out.unparsed.sort_by(|a, b| a.file.cmp(&b.file));
    out
}
