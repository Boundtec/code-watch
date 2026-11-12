use std::fmt::Write;

use serde::Serialize;

use crate::finding::{Finding, Layer, Severity};
use crate::report::{LayerStatus, Report, Verdict};

/// Version of the `--json` shape; bump it on any breaking change to the output.
pub const JSON_SCHEMA: u32 = 1;

#[derive(Serialize)]
struct JsonReport<'a> {
    schema: u32,
    verdict: Verdict,
    layers: &'a std::collections::BTreeMap<Layer, LayerStatus>,
    findings: &'a [Finding],
}

pub fn to_json(report: &Report) -> String {
    let view = JsonReport {
        schema: JSON_SCHEMA,
        verdict: report.verdict(),
        layers: report.layers(),
        findings: report.findings(),
    };
    serde_json::to_string_pretty(&view).expect("a report always serializes")
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
            "{} {}{place}: {}",
            label(f.severity),
            f.rule_id,
            f.title
        );
        let _ = writeln!(out, "      evidence: {}", f.evidence.excerpt);
        let _ = writeln!(out, "      fix: {}", f.remediation);
    }
    let layers: Vec<String> = report
        .layers()
        .iter()
        .map(|(layer, status)| format!("{} {}", layer_name(*layer), status_name(*status)))
        .collect();
    let _ = writeln!(out, "layers: {}", layers.join(", "));
    let _ = writeln!(out, "verdict: {}", verdict_name(report.verdict()));
    out
}

fn label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO ",
        Severity::Warn => "WARN ",
        Severity::Block => "BLOCK",
    }
}

fn layer_name(l: Layer) -> &'static str {
    match l {
        Layer::Rules => "rules",
        Layer::Osv => "osv",
        Layer::Llm => "llm",
    }
}

fn status_name(s: LayerStatus) -> &'static str {
    match s {
        LayerStatus::Ran => "ran",
        LayerStatus::Off => "off",
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Warn => "warn",
        Verdict::Block => "block",
    }
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
    fn json_carries_schema_verdict_and_layers() {
        let v: serde_json::Value =
            serde_json::from_str(&to_json(&Report::from_rules(vec![]))).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["verdict"], "allow");
        assert_eq!(v["layers"]["llm"], "off");
        assert_eq!(v["findings"], serde_json::json!([]));
    }
}
