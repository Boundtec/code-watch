use std::collections::BTreeMap;

use serde::Deserialize;

use super::package::{
    Ecosystem, Package, PackageSource, ParseError, is_public_npm_url, looks_like_version,
};

/// `package-lock.json` and `npm-shrinkwrap.json`, lockfile versions 1 to 3.
pub struct NpmLock;

#[derive(Deserialize)]
struct Lock {
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
    link: bool,
    #[serde(default)]
    dependencies: BTreeMap<String, Entry>,
}

impl PackageSource for NpmLock {
    fn file_names(&self) -> &'static [&'static str] {
        &["package-lock.json", "npm-shrinkwrap.json"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        let lock: Lock =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(ParseError::of)?;
        let mut out = Vec::new();
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

fn collect_v1(out: &mut Vec<Package>, file: &str, deps: &BTreeMap<String, Entry>) {
    for (name, entry) in deps {
        push_if_public(out, file, name, entry);
        collect_v1(out, file, &entry.dependencies);
    }
}

/// An entry without `resolved` is a bundled dependency and is kept; one that resolves outside
/// the public registry (a tarball, git, `file:`) is not.
fn push_if_public(out: &mut Vec<Package>, file: &str, name: &str, entry: &Entry) {
    let Some(version) = entry.version.as_deref().filter(|v| looks_like_version(v)) else {
        return;
    };
    let public = entry.resolved.as_deref().is_none_or(is_public_npm_url);
    if entry.link || !public || name.is_empty() {
        return;
    }
    out.push(Package::new(Ecosystem::Npm, name, version, file));
}
