use std::fmt::Write;

use serde::Serialize;

use crate::allow::Suppressed;
use crate::finding::{Finding, Layer};
use crate::report::{LayerStatus, Report, Skipped, Verdict};

/// Version of the `--json` shape; bump it on any breaking change to the output.
pub const JSON_SCHEMA: u32 = 1;

#[derive(Serialize)]
struct JsonReport<'a> {
    schema: u32,
    verdict: Verdict,
    layers: &'a std::collections::BTreeMap<Layer, LayerStatus>,
    findings: &'a [Finding],
    skipped: &'a [Skipped],
    skipped_rules: &'a [String],
    skipped_layers: &'a std::collections::BTreeMap<Layer, String>,
    suppressed: &'a [Suppressed],
    allowlist_warnings: &'a [String],
}

pub fn to_json(report: &Report) -> serde_json::Result<String> {
    let view = JsonReport {
        schema: JSON_SCHEMA,
        verdict: report.verdict(),
        layers: report.layers(),
        findings: report.findings(),
        skipped: report.skipped(),
        skipped_rules: report.skipped_rules(),
        skipped_layers: report.layer_notes(),
        suppressed: report.suppressed(),
        allowlist_warnings: report.allowlist_warnings(),
    };
    serde_json::to_string_pretty(&view)
}

pub fn to_human(report: &Report) -> String {
    let mut out = String::new();
    for f in report.findings() {
        let place = match (&f.evidence.file, f.evidence.line) {
            (Some(file), Some(line)) => format!(" {file}:{line}"),
            (Some(file), None) => format!(" {file}"),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "{:<5} {}{place}: {}",
            f.severity.to_string().to_uppercase(),
            f.rule_id,
            f.title
        );
        let _ = writeln!(out, "      evidence: {}", f.evidence.excerpt);
        let _ = writeln!(out, "      fix: {}", f.remediation);
    }
    let layers: Vec<String> = report
        .layers()
        .iter()
        .map(|(layer, status)| match report.layer_notes().get(layer) {
            Some(why) => format!("{layer} {status} ({why})"),
            None => format!("{layer} {status}"),
        })
        .collect();
    let _ = writeln!(out, "layers: {}", layers.join(", "));
    if !report.skipped_rules().is_empty() {
        let _ = writeln!(
            out,
            "rules skipped on this platform: {}",
            report.skipped_rules().join(", ")
        );
    }
    for w in report.allowlist_warnings() {
        let _ = writeln!(out, "allowlist: {w}");
    }
    let hidden = report.suppressed().len();
    if hidden > 0 {
        let noun = if hidden == 1 { "finding" } else { "findings" };
        let _ = writeln!(out, "{hidden} {noun} suppressed by allowlists");
    }
    let skipped = report.skipped().len();
    if skipped > 0 {
        let noun = if skipped == 1 { "file" } else { "files" };
        let _ = writeln!(out, "{skipped} {noun} not scanned");
    }
    let _ = writeln!(out, "verdict: {}", report.verdict());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allow::Suppressed;

    #[test]
    fn clean_report_says_which_layers_are_off() {
        let text = to_human(&Report::from_rules(vec![]));
        assert_eq!(
            text,
            "layers: rules ran, osv off, llm off\nverdict: allow\n"
        );
    }

    #[test]
    fn human_footer_counts_files_that_were_not_scanned() {
        let skipped = vec![Skipped {
            path: "package.json".into(),
            reason: crate::report::SkipReason::TooLarge,
        }];
        let text = to_human(&Report::from_scan(vec![], skipped));
        assert!(text.contains("1 file not scanned\n"));
        assert!(text.contains("WARN  repo/unscanned-target package.json"));
        assert!(text.contains("verdict: warn"));
    }

    #[test]
    fn json_carries_schema_verdict_and_layers() {
        let v: serde_json::Value =
            serde_json::from_str(&to_json(&Report::from_rules(vec![])).unwrap()).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["verdict"], "allow");
        assert_eq!(v["layers"]["llm"], "off");
        assert_eq!(v["findings"], serde_json::json!([]));
        assert_eq!(v["skipped"], serde_json::json!([]));
        assert_eq!(v["skipped_rules"], serde_json::json!([]));
    }

    fn report_with_one_suppressed() -> Report {
        let f = Finding {
            rule_id: "r/x".into(),
            severity: crate::finding::Severity::Warn,
            layer: Layer::Rules,
            title: "t".into(),
            evidence: crate::finding::Evidence::new(None, None, "e"),
            remediation: String::new(),
            domain: Some("example.org".into()),
            package: None,
            advisories: Vec::new(),
        };
        let s = Suppressed {
            finding: f,
            source: crate::allow::Source::Repo,
            reason: None,
        };
        Report::from_rules(vec![])
            .with_allowlist(vec![s], vec!["unknown rule id \"q\" in x".into()])
    }

    #[test]
    fn json_lists_suppressed_findings_additively_and_keeps_schema_one() {
        let v: serde_json::Value =
            serde_json::from_str(&to_json(&report_with_one_suppressed()).unwrap()).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["verdict"], "allow");
        assert_eq!(v["suppressed"][0]["finding"]["rule_id"], "r/x");
        assert_eq!(v["suppressed"][0]["finding"]["domain"], "example.org");
        assert_eq!(v["suppressed"][0]["source"], "repo");
        assert_eq!(v["allowlist_warnings"][0], "unknown rule id \"q\" in x");
    }

    #[test]
    fn a_finding_without_domain_or_package_omits_both_keys() {
        let mut r = report_with_one_suppressed();
        r = Report::from_rules(vec![r.suppressed()[0].finding.clone()]);
        let v: serde_json::Value = serde_json::from_str(&to_json(&r).unwrap()).unwrap();
        assert!(v["findings"][0].get("package").is_none());
        assert_eq!(v["findings"][0]["domain"], "example.org");
    }

    #[test]
    fn the_human_footer_counts_suppressed_findings_and_shows_warnings() {
        let text = to_human(&report_with_one_suppressed());
        assert!(text.contains("1 finding suppressed by allowlists\n"));
        assert!(text.contains("allowlist: unknown rule id \"q\" in x\n"));
    }

    #[test]
    fn skipped_rules_are_listed_in_both_outputs() {
        let report = Report::from_rules(vec![]).with_skipped_rules(vec!["command/x".into()]);
        assert!(to_human(&report).contains("rules skipped on this platform: command/x\n"));
        let v: serde_json::Value = serde_json::from_str(&to_json(&report).unwrap()).unwrap();
        assert_eq!(v["skipped_rules"], serde_json::json!(["command/x"]));
    }
}
