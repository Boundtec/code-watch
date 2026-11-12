use serde::{Deserialize, Serialize};

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
}

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
        let excerpt: String = excerpt
            .trim()
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .take(MAX_EXCERPT_CHARS)
            .collect();
        Self {
            file,
            line,
            excerpt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub layer: Layer,
    pub title: String,
    pub evidence: Evidence,
    pub remediation: String,
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
    fn evidence_truncates_by_characters() {
        let e = Evidence::new(None, None, &"é".repeat(500));
        assert_eq!(e.excerpt.chars().count(), MAX_EXCERPT_CHARS);
    }
}
