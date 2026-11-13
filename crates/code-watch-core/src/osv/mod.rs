//! The known-vulnerabilities layer: lockfile parsers that list the public-registry packages a
//! repository depends on.

mod advisory;
mod cache;
mod cargo;
mod client;
mod discover;
mod go;
mod group;
mod layer;
mod npm;
mod package;
mod pnpm;
mod python;
mod version;
mod yarn;

pub use advisory::{OsvRecord, Vuln};
pub use cache::{Cache, Clock, DEFAULT_TTL, SystemClock};
pub use client::{MAX_BATCH, OsvClient, OsvError, Query, QueryAnswer, UreqOsv};
pub use discover::{Discovered, Unparsed, UnparsedReason, discover};
pub use layer::{OsvMode, OsvOutcome, OsvStatus, RULE_IDS, RULE_UNCHECKED, RULE_UNPARSED, run};
pub use package::{Ecosystem, Package, PackageSource, ParseError};
