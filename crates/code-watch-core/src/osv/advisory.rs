use serde::{Deserialize, Serialize};

use super::package::Ecosystem;
use super::python::normalise;
use crate::finding::Severity;

/// The parts of an OSV record the layer reads. Unknown fields are ignored: the schema grows.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub database_specific: DatabaseSpecific,
    #[serde(default)]
    pub affected: Vec<Affected>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DatabaseSpecific {
    pub severity: Option<String>,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Affected {
    pub package: Option<AffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<Range>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AffectedPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Range {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Event {
    pub fixed: Option<String>,
}

/// An advisory as it applies to one package version: what the finding and the cache keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vuln {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Severity,
    pub malicious: bool,
    pub fixed: Vec<String>,
}

pub const MALICIOUS_PREFIX: &str = "MAL-";

/// CWE-506, "Embedded Malicious Code": how GitHub's advisories mark a backdoored package.
const MALICIOUS_CWE: &str = "CWE-506";

/// Range types whose `fixed` events are versions; a `GIT` range lists commit hashes.
const VERSION_RANGES: [&str; 2] = ["ECOSYSTEM", "SEMVER"];

impl OsvRecord {
    pub fn for_package(&self, ecosystem: Ecosystem, name: &str) -> Vuln {
        let mut fixed: Vec<String> = Vec::new();
        for a in &self.affected {
            let Some(p) = a.package.as_ref() else {
                continue;
            };
            if p.ecosystem != ecosystem.osv_name() || !same_name(ecosystem, &p.name, name) {
                continue;
            }
            for v in a
                .ranges
                .iter()
                .filter(|r| VERSION_RANGES.contains(&r.kind.as_str()))
                .flat_map(|r| &r.events)
                .filter_map(|e| e.fixed.as_ref())
            {
                if !fixed.contains(v) {
                    fixed.push(v.clone());
                }
            }
        }
        Vuln {
            id: self.id.clone(),
            aliases: self.aliases.clone(),
            summary: self.summary.clone(),
            severity: self.severity(),
            malicious: self.is_malicious(),
            fixed,
        }
    }

    /// Malicious when the id or any alias is a `MAL-` id, or the record's own CWE list says
    /// embedded malicious code. Only fields are read, never the summary text.
    fn is_malicious(&self) -> bool {
        std::iter::once(&self.id)
            .chain(&self.aliases)
            .any(|id| id.starts_with(MALICIOUS_PREFIX))
            || self
                .database_specific
                .cwe_ids
                .iter()
                .any(|c| c == MALICIOUS_CWE)
    }

    /// A malicious-package advisory blocks. Otherwise the database's own label decides:
    /// CRITICAL and HIGH warn, MODERATE and LOW inform. An advisory with no label (only a CVSS
    /// vector, which this build does not score) warns: unknown is never downgraded.
    fn severity(&self) -> Severity {
        if self.is_malicious() {
            return Severity::Block;
        }
        match self
            .database_specific
            .severity
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("MODERATE" | "MEDIUM" | "LOW") => Severity::Info,
            _ => Severity::Warn,
        }
    }
}

fn same_name(ecosystem: Ecosystem, advisory: &str, ours: &str) -> bool {
    match ecosystem {
        Ecosystem::PyPI => normalise(advisory).is_some_and(|n| n == ours),
        _ => advisory == ours,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(json: serde_json::Value) -> OsvRecord {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn fixed_versions_come_only_from_the_matching_package_and_version_ranges() {
        let r = record(serde_json::json!({
            "id": "GHSA-1",
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "other"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9"}]}]},
                {"package": {"ecosystem": "PyPI", "name": "Typing_Extensions"},
                 "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1"}, {"fixed": "2"}, {"fixed": "1"}, {"fixed": "3"}, {"fixed": "4"}]},
                    {"type": "GIT", "events": [{"fixed": "0123456789abcdef0123456789abcdef01234567"}]}]},
                {"package": {"ecosystem": "npm", "name": "typing-extensions"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "8"}]}]},
                {"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "7"}]}]},
            ],
        }));
        assert_eq!(
            r.for_package(Ecosystem::PyPI, "typing-extensions").fixed,
            ["1", "2", "3", "4"]
        );
    }

    #[test]
    fn a_malicious_advisory_blocks_whatever_its_label_says() {
        let r = record(
            serde_json::json!({"id": "MAL-2024-1", "database_specific": {"severity": "LOW"}}),
        );
        assert_eq!(r.for_package(Ecosystem::Npm, "x").severity, Severity::Block);
    }

    #[test]
    fn malicious_means_a_mal_id_a_mal_alias_or_the_embedded_malicious_code_cwe() {
        let flagged = [
            serde_json::json!({"id": "MAL-2024-1"}),
            serde_json::json!({"id": "GHSA-x", "aliases": ["CVE-1", "MAL-2024-2"]}),
            serde_json::json!({"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-79", "CWE-506"], "severity": "LOW"}}),
        ];
        for r in flagged {
            let v = record(r.clone()).for_package(Ecosystem::Npm, "x");
            assert!(v.malicious && v.severity == Severity::Block, "{r}");
        }
        let plain = record(serde_json::json!({
            "id": "GHSA-x", "summary": "Malicious code in x", "aliases": ["CVE-1"],
            "database_specific": {"cwe_ids": ["CWE-79"]},
        }));
        assert!(
            !plain.for_package(Ecosystem::Npm, "x").malicious,
            "the summary text is never read"
        );
    }

    #[test]
    fn unknown_fields_in_an_osv_record_are_ignored() {
        let r = record(
            serde_json::json!({"id": "A", "details": "long", "severity": [{"type": "CVSS_V3", "score": "x"}], "new_field": 1}),
        );
        assert_eq!(r.for_package(Ecosystem::Go, "m").severity, Severity::Warn);
    }
}
