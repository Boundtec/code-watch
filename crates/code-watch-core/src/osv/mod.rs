//! The known-vulnerabilities layer: lockfile parsers that list the public-registry packages a
//! repository depends on.

mod cargo;
mod discover;
mod go;
mod npm;
mod package;
mod pnpm;
mod python;
mod yarn;

pub use discover::{Discovered, Unparsed, UnparsedReason, discover};
pub use package::{Ecosystem, Package, PackageSource, ParseError};
