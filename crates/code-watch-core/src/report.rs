use std::collections::BTreeMap;

use serde::Serialize;

use crate::finding::{Evidence, Finding, Layer, Severity};
use crate::names::display_as_wire_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerStatus {
    Ran,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

/// Why a file a rule wanted to read was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    TooLarge,
    Unreadable,
    NotUtf8,
    WalkError,
}

display_as_wire_name!(LayerStatus, Verdict, SkipReason);

/// A path the scan could not read, so the verdict says nothing about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: SkipReason,
}

impl Verdict {
    /// 0 clean, 1 warn, 2 block. Exit code 3 is reserved for errors and never comes from a verdict.
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Allow => 0,
            Verdict::Warn => 1,
            Verdict::Block => 2,
        }
    }
}

/// The result of a check. The verdict is always derived from the findings, never stored, and
/// the findings are private so the only way to change a report is to build it from findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    findings: Vec<Finding>,
    layers: BTreeMap<Layer, LayerStatus>,
    skipped: Vec<Skipped>,
}

impl Report {
    /// Builds a report from the rules layer. The OSV and LLM layers are off until they exist.
    pub fn from_rules(findings: Vec<Finding>) -> Self {
        Self::from_scan(findings, Vec::new())
    }

    /// Builds a report from a directory scan. Every skipped path adds a `warn` finding, so a
    /// file that could not be read never produces a clean verdict.
    pub fn from_scan(mut findings: Vec<Finding>, skipped: Vec<Skipped>) -> Self {
        findings.extend(skipped.iter().map(unscanned_finding));
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.evidence.file.cmp(&b.evidence.file))
                .then_with(|| a.evidence.line.cmp(&b.evidence.line))
        });
        let layers = BTreeMap::from([
            (Layer::Rules, LayerStatus::Ran),
            (Layer::Osv, LayerStatus::Off),
            (Layer::Llm, LayerStatus::Off),
        ]);
        Self {
            findings,
            layers,
            skipped,
        }
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn layers(&self) -> &BTreeMap<Layer, LayerStatus> {
        &self.layers
    }

    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    pub fn verdict(&self) -> Verdict {
        match self.findings.iter().map(|f| f.severity).max() {
            Some(Severity::Block) => Verdict::Block,
            Some(Severity::Warn) => Verdict::Warn,
            Some(Severity::Info) | None => Verdict::Allow,
        }
    }
}

fn unscanned_finding(s: &Skipped) -> Finding {
    Finding {
        rule_id: "repo/unscanned-target".into(),
        severity: Severity::Warn,
        layer: Layer::Rules,
        title: "A file the rules target could not be scanned".into(),
        evidence: Evidence::new(
            Some(s.path.clone()),
            None,
            &format!("not scanned: {}", s.reason),
        ),
        remediation: "Read the file by hand before running anything in this repository.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Evidence;

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: id.into(),
            severity,
            layer: Layer::Rules,
            title: String::new(),
            evidence: Evidence::new(None, None, ""),
            remediation: String::new(),
        }
    }

    #[test]
    fn verdict_is_the_highest_severity() {
        assert_eq!(Report::from_rules(vec![]).verdict(), Verdict::Allow);
        let info = Report::from_rules(vec![finding("a", Severity::Info)]);
        assert_eq!(info.verdict(), Verdict::Allow);
        let warn = Report::from_rules(vec![
            finding("a", Severity::Info),
            finding("b", Severity::Warn),
        ]);
        assert_eq!(warn.verdict(), Verdict::Warn);
        let block = Report::from_rules(vec![
            finding("a", Severity::Warn),
            finding("b", Severity::Block),
        ]);
        assert_eq!(block.verdict(), Verdict::Block);
    }

    #[test]
    fn findings_come_out_most_severe_first() {
        let r = Report::from_rules(vec![
            finding("a", Severity::Warn),
            finding("b", Severity::Block),
        ]);
        assert_eq!(r.findings()[0].rule_id, "b");
    }

    #[test]
    fn exit_codes_never_use_the_error_code() {
        assert_eq!(
            [Verdict::Allow, Verdict::Warn, Verdict::Block].map(Verdict::exit_code),
            [0, 1, 2]
        );
    }

    #[test]
    fn llm_and_osv_layers_report_off() {
        let r = Report::from_rules(vec![]);
        assert_eq!(r.layers()[&Layer::Rules], LayerStatus::Ran);
        assert_eq!(r.layers()[&Layer::Llm], LayerStatus::Off);
    }
}
