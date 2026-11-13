use std::collections::BTreeMap;

use serde::Deserialize;

use super::package::{
    Ecosystem, FormatVersion, Package, PackageSource, ParseError, Parsed, is_public_npm_url,
    looks_like_version,
};

/// `yarn.lock`, both the v1 text format and the berry YAML format.
pub struct YarnLock;

impl PackageSource for YarnLock {
    fn globs(&self) -> &'static [&'static str] {
        &["**/yarn.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        if text.contains("\n__metadata:") || text.starts_with("__metadata:") {
            berry(file, text)
        } else {
            classic(file, text)
        }
    }
}

fn classic(file: &str, text: &str) -> Result<Parsed, ParseError> {
    if let Some(v) = text
        .lines()
        .find_map(|l| l.strip_prefix("# yarn lockfile v"))
        .filter(|v| v.trim() != "1")
    {
        return Err(ParseError::unknown_format(format!(
            "yarn lockfile format version {} is not recognised",
            v.trim()
        )));
    }
    let lock = yarn_lock_parser::parse_str(text).map_err(ParseError::of)?;
    let (public, other): (Vec<_>, Vec<_>) = lock
        .entries
        .iter()
        .partition(|e| is_public_npm_url(e.resolved) && looks_like_version(e.version));
    Ok(Parsed::new(
        public
            .iter()
            .map(|e| Package::new(Ecosystem::Npm, e.name, e.version, file))
            .collect(),
        other.len(),
    ))
}

#[derive(Deserialize)]
struct BerryEntry {
    version: Option<String>,
    resolution: Option<String>,
}

#[derive(Deserialize)]
struct Metadata {
    version: Option<FormatVersion>,
}

/// Berry resolutions read `name@npm:version`; `patch:`, `github:` and alias ones do not match
/// and are counted as not looked up. `workspace:` entries are the project's own packages.
fn berry(file: &str, text: &str) -> Result<Parsed, ParseError> {
    let lock: BTreeMap<String, serde_norway::Value> =
        serde_norway::from_str(text).map_err(ParseError::of)?;
    let metadata: Metadata = lock
        .get("__metadata")
        .cloned()
        .and_then(|v| serde_norway::from_value(v).ok())
        .unwrap_or(Metadata { version: None });
    FormatVersion::require(metadata.version.as_ref(), &[4, 5, 6, 7, 8], "yarn lockfile")?;
    let mut out = Parsed::default();
    for (key, value) in lock {
        if key == "__metadata" {
            continue;
        }
        let entry = serde_norway::from_value::<BerryEntry>(value).ok();
        let Some((resolution, version)) = entry.and_then(|e| Some((e.resolution?, e.version?)))
        else {
            out.not_looked_up += 1;
            continue;
        };
        if resolution.contains("@workspace:") {
            continue;
        }
        match resolution.split_once("@npm:") {
            Some((name, resolved))
                if !name.is_empty() && resolved == version && looks_like_version(&version) =>
            {
                out.packages
                    .push(Package::new(Ecosystem::Npm, name, &version, file));
            }
            _ => out.not_looked_up += 1,
        }
    }
    Ok(out)
}
