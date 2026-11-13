use serde::{Deserialize, Serialize};
use unicode_general_category::{GeneralCategory, get_general_category};

use crate::names::display_as_wire_name;

const MAX_EXCERPT_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Rules,
    Osv,
    Llm,
    Download,
}

display_as_wire_name!(Severity, Layer);

/// Where a finding was seen. The excerpt comes from untrusted input, so it is truncated and
/// stripped of control characters (a hostile repo must not be able to drive the terminal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub file: Option<String>,
    pub line: Option<usize>,
    pub excerpt: String,
}

impl Evidence {
    pub fn new(file: Option<String>, line: Option<usize>, excerpt: &str) -> Self {
        let excerpt = clean_text(excerpt);
        Self {
            file,
            line,
            excerpt,
        }
    }
}

/// Trims, truncates and replaces invisible characters, for any text taken from untrusted input.
pub(crate) fn clean_text(text: &str) -> String {
    sanitize(text.trim())
        .chars()
        .take(MAX_EXCERPT_CHARS)
        .collect()
}

/// Replaces invisible characters without trimming or truncating, for text that is printed whole.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if is_invisible(c) { '?' } else { c })
        .collect()
}

/// Control characters and Unicode format characters (bidi overrides, zero-width joiners) can
/// reorder or hide text on a terminal.
fn is_invisible(c: char) -> bool {
    c.is_control() || get_general_category(c) == GeneralCategory::Format
}

/// One vulnerability a finding reports, with the other ids the databases know it by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub layer: Layer,
    pub title: String,
    pub evidence: Evidence,
    pub remediation: String,
    /// The host the finding is about, set by the rule that parsed it. Allowlist `domain` entries
    /// match only this field, never the excerpt, which is untrusted and truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The package the finding is about, set by the layer that knows it (the OSV layer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Every vulnerability a grouped OSV finding covers; the other layers leave it empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<Advisory>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_info_below_warn_below_block() {
        assert!(Severity::Info < Severity::Warn && Severity::Warn < Severity::Block);
    }

    #[test]
    fn evidence_strips_control_characters() {
        let e = Evidence::new(None, None, "a\u{1b}[31mred\u{7}");
        assert_eq!(e.excerpt, "a?[31mred?");
    }

    #[test]
    fn evidence_strips_format_characters_that_spoof_the_terminal() {
        let e = Evidence::new(None, None, "a\u{202e}txt.exe\u{200b}b");
        assert_eq!(e.excerpt, "a?txt.exe?b");
    }

    #[test]
    fn evidence_truncates_by_characters() {
        let e = Evidence::new(None, None, &"é".repeat(500));
        assert_eq!(e.excerpt.chars().count(), MAX_EXCERPT_CHARS);
    }
}
