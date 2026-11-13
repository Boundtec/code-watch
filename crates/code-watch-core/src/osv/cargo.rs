use cargo_lock::Lockfile;

use super::package::{Ecosystem, Package, PackageSource, ParseError, Parsed};

/// `Cargo.lock`. Path packages (the workspace's own crates) are not dependencies; git packages
/// and those from other registries have no crates.io source and are counted as not looked up.
pub struct CargoLock;

impl PackageSource for CargoLock {
    fn globs(&self) -> &'static [&'static str] {
        &["**/Cargo.lock"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        let lock: Lockfile = text.parse().map_err(ParseError::of)?;
        let mut out = Parsed::default();
        for p in &lock.packages {
            match p.source.as_ref() {
                None => {}
                Some(s) if s.is_default_registry() => out.packages.push(Package::new(
                    Ecosystem::CratesIo,
                    p.name.as_str(),
                    &p.version.to_string(),
                    file,
                )),
                Some(s) if s.is_path() => {}
                Some(_) => out.not_looked_up += 1,
            }
        }
        Ok(out)
    }
}
