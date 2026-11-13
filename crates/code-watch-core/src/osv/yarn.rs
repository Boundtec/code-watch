use std::collections::BTreeMap;

use serde::Deserialize;

use super::package::{
    Ecosystem, Package, PackageSource, ParseError, is_public_npm_url, looks_like_version,
};

/// `yarn.lock`, both the v1 text format and the berry YAML format.
pub struct YarnLock;

impl PackageSource for YarnLock {
    fn file_names(&self) -> &'static [&'static str] {
        &["yarn.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        if text.contains("\n__metadata:") || text.starts_with("__metadata:") {
            berry(file, text)
        } else {
            classic(file, text)
        }
    }
}

fn classic(file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
    let lock = yarn_lock_parser::parse_str(text).map_err(ParseError::of)?;
    Ok(lock
        .entries
        .iter()
        .filter(|e| is_public_npm_url(e.resolved) && looks_like_version(e.version))
        .map(|e| Package::new(Ecosystem::Npm, e.name, e.version, file))
        .collect())
}

#[derive(Deserialize)]
struct BerryEntry {
    version: Option<String>,
    resolution: Option<String>,
}

/// Berry resolutions read `name@npm:version`; `workspace:`, `patch:` and `github:` ones do not
/// match and are dropped.
fn berry(file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
    let lock: BTreeMap<String, serde_norway::Value> =
        serde_norway::from_str(text).map_err(ParseError::of)?;
    let mut out = Vec::new();
    for (key, value) in lock {
        if key == "__metadata" {
            continue;
        }
        let Ok(entry) = serde_norway::from_value::<BerryEntry>(value) else {
            continue;
        };
        let (Some(resolution), Some(version)) = (entry.resolution, entry.version) else {
            continue;
        };
        let Some((name, resolved)) = resolution.split_once("@npm:") else {
            continue;
        };
        if !name.is_empty() && resolved == version && looks_like_version(&version) {
            out.push(Package::new(Ecosystem::Npm, name, &version, file));
        }
    }
    Ok(out)
}
