use std::collections::BTreeMap;

use serde::Deserialize;

use super::package::{
    Ecosystem, FormatVersion, Package, PackageSource, ParseError, Parsed, is_public_npm_url,
    looks_like_version,
};

/// `package-lock.json` and `npm-shrinkwrap.json`, lockfile versions 1 to 3.
pub struct NpmLock;

#[derive(Deserialize)]
struct Lock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<FormatVersion>,
    #[serde(default)]
    packages: BTreeMap<String, Entry>,
    #[serde(default)]
    dependencies: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, Entry>,
}

impl PackageSource for NpmLock {
    fn globs(&self) -> &'static [&'static str] {
        &["**/package-lock.json", "**/npm-shrinkwrap.json"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        let lock: Lock =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(ParseError::of)?;
        // Lockfiles written before npm 7 may omit the field; they are version 1.
        if lock.lockfile_version.is_some() {
            FormatVersion::require(lock.lockfile_version.as_ref(), &[1, 2, 3], "npm lockfile")?;
        }
        let mut out = Parsed::default();
        for (key, entry) in &lock.packages {
            let Some((_, tail)) = key.rsplit_once("node_modules/") else {
                continue;
            };
            let name = entry.name.as_deref().unwrap_or(tail);
            push_if_public(&mut out, file, name, entry);
        }
        collect_v1(&mut out, file, &lock.dependencies);
        Ok(out)
    }
}

fn collect_v1(out: &mut Parsed, file: &str, deps: &BTreeMap<String, Entry>) {
    for (name, entry) in deps {
        push_if_public(out, file, name, entry);
        collect_v1(out, file, &entry.dependencies);
    }
}

/// An entry without `resolved` is a bundled dependency and is kept; one that resolves outside
/// the public registry (a mirror, a tarball, git, `file:`) or whose version is an alias is
/// counted as not looked up. An entry with no version is a workspace link or the root and is
/// not an install.
fn push_if_public(out: &mut Parsed, file: &str, name: &str, entry: &Entry) {
    let Some(version) = entry.version.as_deref() else {
        return;
    };
    let public = entry.resolved.as_deref().is_none_or(is_public_npm_url);
    if public && looks_like_version(version) && !name.is_empty() {
        out.packages
            .push(Package::new(Ecosystem::Npm, name, version, file));
    } else {
        out.not_looked_up += 1;
    }
}
