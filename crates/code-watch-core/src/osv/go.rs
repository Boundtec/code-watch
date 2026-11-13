use std::str::FromStr;

use gomod_parser::{GoMod, Replacement};

use super::package::{Ecosystem, Package, PackageSource, ParseError, Parsed};

/// `go.mod` require lines, direct and indirect. `go.sum` is not a source: it keeps versions
/// the build does not use and would raise findings for code that never runs.
pub struct GoModFile;

impl PackageSource for GoModFile {
    fn globs(&self) -> &'static [&'static str] {
        &["**/go.mod"]
    }

    fn parse(&self, file: &str, text: &str) -> Result<Parsed, ParseError> {
        let go_mod = GoMod::from_str(text).map_err(ParseError::of)?;
        let mut out = Vec::new();
        for dep in &go_mod.require {
            let path = &dep.module.module_path;
            let replaced = go_mod.replace.iter().find(|r| {
                r.module_path == *path
                    && r.version.as_ref().is_none_or(|v| *v == dep.module.version)
            });
            let (name, version) = match replaced.map(|r| &r.replacement) {
                None => (path.as_str(), dep.module.version.as_str()),
                Some(Replacement::FilePath(_)) => continue,
                Some(Replacement::Module(m)) => (m.module_path.as_str(), m.version.as_str()),
            };
            let line = text[..dep.module.path_span.start].matches('\n').count() + 1;
            out.push(Package::new(Ecosystem::Go, name, version, file).at_line(line));
        }
        Ok(Parsed::new(out, 0))
    }
}
