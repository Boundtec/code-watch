use std::collections::BTreeMap;

use serde::Deserialize;

use super::package::{Ecosystem, Package, PackageSource, ParseError, looks_like_version};

/// `pnpm-lock.yaml`: package keys are `/name@ver(peers)` in v6 and `name@ver(peers)` in v9.
pub struct PnpmLock;

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    packages: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
struct Entry {
    resolution: Option<Resolution>,
}

/// Registry packages carry only an `integrity`; every other key marks a local, git or
/// tarball source.
#[derive(Deserialize)]
struct Resolution {
    #[serde(flatten)]
    fields: BTreeMap<String, serde_norway::Value>,
}

impl Resolution {
    fn is_registry(&self) -> bool {
        self.fields.keys().all(|k| k == "integrity")
    }
}

impl PackageSource for PnpmLock {
    fn file_names(&self) -> &'static [&'static str] {
        &["pnpm-lock.yaml"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        let lock: Lock = serde_norway::from_str(text).map_err(ParseError::of)?;
        Ok(lock
            .packages
            .iter()
            .filter(|(_, e)| e.resolution.as_ref().is_some_and(Resolution::is_registry))
            .filter_map(|(key, _)| split_key(key))
            .map(|(name, version)| Package::new(Ecosystem::Npm, name, version, file))
            .collect())
    }
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split_once('(').map_or(key, |(head, _)| head);
    let (name, version) = key.rsplit_once('@')?;
    let plain_name = !name.is_empty() && !name[1..].contains('@');
    (plain_name && looks_like_version(version)).then_some((name, version))
}
