use std::fmt::Write;

use serde::Serialize;

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
}

pub fn to_json(report: &Report) -> serde_json::Result<String> {
    let view = JsonReport {
        schema: JSON_SCHEMA,
        verdict: report.verdict(),
        layers: report.layers(),
        findings: report.findings(),
        skipped: report.skipped(),
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
        .map(|(layer, status)| format!("{layer} {status}"))
        .collect();
    let _ = writeln!(out, "layers: {}", layers.join(", "));
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
    }
}
