use std::collections::BTreeMap;

use serde::Deserialize;

use super::package::{
    Ecosystem, FormatVersion, Package, PackageSource, ParseError, Parsed, looks_like_version,
};

/// `pnpm-lock.yaml`: package keys are `/name/ver_peers` in v5, `/name@ver(peers)` in v6 and
/// `name@ver(peers)` in v9.
pub struct PnpmLock;

#[derive(Deserialize)]
struct Lock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<FormatVersion>,
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
    fn globs(&self) -> &'static [&'static str] {
        &["**/pnpm-lock.yaml"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        let lock: Lock = serde_norway::from_str(text).map_err(ParseError::of)?;
        FormatVersion::require(lock.lockfile_version.as_ref(), &[5, 6, 9], "pnpm lockfile")?;
        let v5 = lock
            .lockfile_version
            .as_ref()
            .and_then(FormatVersion::major)
            == Some(5);
        let split = if v5 { split_key_v5 } else { split_key };
        let mut out = Parsed::default();
        for (key, entry) in &lock.packages {
            let registry = entry
                .resolution
                .as_ref()
                .is_some_and(Resolution::is_registry);
            match split(key).filter(|_| registry) {
                Some((name, version)) => {
                    out.packages
                        .push(Package::new(Ecosystem::Npm, name, version, file))
                }
                None => out.not_looked_up += 1,
            }
        }
        Ok(out)
    }
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split_once('(').map_or(key, |(head, _)| head);
    let (name, version) = key.rsplit_once('@')?;
    let plain_name = !name.is_empty() && !name[1..].contains('@');
    (plain_name && looks_like_version(version)).then_some((name, version))
}

/// v5 keys are `/name/version` with an optional `_peers` suffix on the version; a key that
/// does not start with `/` names another registry.
fn split_key_v5(key: &str) -> Option<(&str, &str)> {
    let (name, version) = key.strip_prefix('/')?.rsplit_once('/')?;
    let version = version.split_once('_').map_or(version, |(head, _)| head);
    let bare = name.strip_prefix('@').unwrap_or(name);
    if bare.is_empty() || bare.contains('@') {
        return None;
    }
    looks_like_version(version).then_some((name, version))
}
