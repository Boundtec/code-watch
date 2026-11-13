use cargo_lock::Lockfile;

use super::package::{Ecosystem, Package, PackageSource, ParseError};

/// `Cargo.lock`. Path and git packages (the workspace's own crates among them) have no
/// crates.io source and are dropped, as are packages from other registries.
pub struct CargoLock;

impl PackageSource for CargoLock {
    fn file_names(&self) -> &'static [&'static str] {
        &["Cargo.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Vec<Package>, ParseError> {
        let lock: Lockfile = text.parse().map_err(ParseError::of)?;
        Ok(lock
            .packages
            .iter()
            .filter(|p| p.source.as_ref().is_some_and(|s| s.is_default_registry()))
            .map(|p| {
                Package::new(
                    Ecosystem::CratesIo,
                    p.name.as_str(),
                    &p.version.to_string(),
                    file,
                )
            })
            .collect())
    }
}
