use std::collections::HashSet;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;

use crate::finding::{Evidence, Finding, Layer, Severity};

/// Rule file schema this binary understands. A file with a newer schema is refused rather than
/// half-applied.
const SUPPORTED_SCHEMA: u32 = 1;

const EMBEDDED: &[(&str, &str)] = &[
    ("repo.toml", include_str!("../rules/repo.toml")),
    ("command.toml", include_str!("../rules/command.toml")),
];

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("rules file {file}: {source}")]
    Parse {
        file: String,
        source: toml::de::Error,
    },
    #[error("rules file {file} uses schema {found}, this build supports {SUPPORTED_SCHEMA}")]
    Schema { file: String, found: u32 },
    #[error("rule {id}: invalid pattern: {reason}")]
    Pattern { id: String, reason: String },
    #[error("rule id {0} is defined twice")]
    Duplicate(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Repo,
    Command,
}

#[derive(Deserialize)]
struct RawFile {
    schema: u32,
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    severity: Severity,
    title: String,
    remediation: String,
    #[serde(rename = "match")]
    matcher: RawMatcher,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawMatcher {
    JsonPointer {
        files: Vec<String>,
        pointers: Vec<String>,
    },
    FileRegex {
        files: Vec<String>,
        pattern: String,
    },
    AllRegex {
        files: Vec<String>,
        patterns: Vec<String>,
    },
    BinaryFile {
        files: Vec<String>,
        formats: Vec<BinaryFormat>,
    },
    ExecutableFile {
        files: Vec<String>,
    },
    CommandRegex {
        pattern: String,
    },
}

/// Executable formats recognised by their leading bytes. `cafebabe` is left out on purpose: Java
/// class files share it with fat Mach-O.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BinaryFormat {
    Elf,
    MachO,
    Pe,
}

impl BinaryFormat {
    fn matches(self, head: &[u8]) -> bool {
        match self {
            Self::Elf => head.starts_with(b"\x7fELF"),
            Self::MachO => [
                [0xfe, 0xed, 0xfa, 0xce],
                [0xfe, 0xed, 0xfa, 0xcf],
                [0xce, 0xfa, 0xed, 0xfe],
                [0xcf, 0xfa, 0xed, 0xfe],
            ]
            .iter()
            .any(|magic| head.starts_with(magic)),
            Self::Pe => head.starts_with(b"MZ"),
        }
    }
}

/// How many leading bytes the engine reads to recognise a binary.
pub const HEAD_BYTES: usize = 4;

enum Matcher {
    JsonPointer {
        files: GlobSet,
        pointers: Vec<String>,
    },
    FileRegex {
        files: GlobSet,
        regex: Regex,
    },
    AllRegex {
        files: GlobSet,
        regexes: Vec<Regex>,
    },
    BinaryFile {
        files: GlobSet,
        formats: Vec<BinaryFormat>,
    },
    ExecutableFile {
        files: GlobSet,
    },
    CommandRegex(Regex),
}

pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub remediation: String,
    matcher: Matcher,
}

impl Rule {
    pub fn target(&self) -> Target {
        match self.matcher {
            Matcher::CommandRegex(_) => Target::Command,
            _ => Target::Repo,
        }
    }

    /// Whether the rule judges a file by its leading bytes and mode instead of its text.
    pub fn is_binary_rule(&self) -> bool {
        matches!(
            self.matcher,
            Matcher::BinaryFile { .. } | Matcher::ExecutableFile { .. }
        )
    }

    /// Whether the rule wants to read the file at `rel` (a path relative to the scanned root).
    pub fn applies_to(&self, rel: &Path) -> bool {
        match &self.matcher {
            Matcher::JsonPointer { files, .. }
            | Matcher::FileRegex { files, .. }
            | Matcher::AllRegex { files, .. }
            | Matcher::BinaryFile { files, .. }
            | Matcher::ExecutableFile { files } => files.is_match(rel),
            Matcher::CommandRegex(_) => false,
        }
    }

    /// Judges a file by its first bytes and whether it is executable, without reading its text.
    pub fn check_head(&self, rel: &Path, head: &[u8], executable: bool) -> Vec<Finding> {
        let file = rel.to_string_lossy().into_owned();
        let hit = match &self.matcher {
            Matcher::BinaryFile { formats, .. } => formats.iter().any(|f| f.matches(head)),
            Matcher::ExecutableFile { .. } => executable,
            _ => false,
        };
        if hit {
            vec![self.finding(Evidence::new(Some(file), None, "executable file"))]
        } else {
            Vec::new()
        }
    }

    pub fn check_file(&self, rel: &Path, content: &str) -> Vec<Finding> {
        let file = rel.to_string_lossy().into_owned();
        match &self.matcher {
            Matcher::JsonPointer { pointers, .. } => {
                let Ok(doc) = serde_json::from_str::<serde_json::Value>(content) else {
                    return Vec::new();
                };
                pointers
                    .iter()
                    .filter_map(|p| doc.pointer(p).map(|v| (p, v)))
                    .map(|(p, v)| {
                        let key = p.rsplit('/').next().unwrap_or(p);
                        let line = content
                            .lines()
                            .position(|l| l.contains(&format!("\"{key}\"")))
                            .map(|i| i + 1);
                        self.finding(Evidence::new(
                            Some(file.clone()),
                            line,
                            &format!("\"{key}\": {v}"),
                        ))
                    })
                    .collect()
            }
            Matcher::FileRegex { regex, .. } => regex
                .find(content)
                .map(|m| {
                    let line = content[..m.start()].matches('\n').count() + 1;
                    let text = content.lines().nth(line - 1).unwrap_or_default();
                    self.finding(Evidence::new(Some(file), Some(line), text))
                })
                .into_iter()
                .collect(),
            Matcher::AllRegex { regexes, .. } => {
                let mut matches = regexes.iter().map(|r| r.find(content));
                let first = matches.next().flatten();
                match first {
                    Some(m) if matches.all(|x| x.is_some()) => {
                        let line = content[..m.start()].matches('\n').count() + 1;
                        let text = content.lines().nth(line - 1).unwrap_or_default();
                        vec![self.finding(Evidence::new(Some(file), Some(line), text))]
                    }
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }

    pub fn check_command(&self, command: &str) -> Vec<Finding> {
        match &self.matcher {
            Matcher::CommandRegex(regex) if regex.is_match(command) => {
                vec![self.finding(Evidence::new(None, None, command))]
            }
            _ => Vec::new(),
        }
    }

    fn finding(&self, evidence: Evidence) -> Finding {
        Finding {
            rule_id: self.id.clone(),
            severity: self.severity,
            layer: Layer::Rules,
            title: self.title.clone(),
            evidence,
            remediation: self.remediation.clone(),
        }
    }
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// The rules shipped inside the binary.
    pub fn embedded() -> Result<Self, RuleError> {
        Self::from_sources(EMBEDDED)
    }

    pub fn from_sources(sources: &[(&str, &str)]) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut seen = HashSet::new();
        for (file, text) in sources {
            let raw: RawFile = toml::from_str(text).map_err(|source| RuleError::Parse {
                file: (*file).into(),
                source,
            })?;
            if raw.schema != SUPPORTED_SCHEMA {
                return Err(RuleError::Schema {
                    file: (*file).into(),
                    found: raw.schema,
                });
            }
            for r in raw.rule {
                if !seen.insert(r.id.clone()) {
                    return Err(RuleError::Duplicate(r.id));
                }
                rules.push(compile(r)?);
            }
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

fn compile(raw: RawRule) -> Result<Rule, RuleError> {
    let bad = |reason: String| RuleError::Pattern {
        id: raw.id.clone(),
        reason,
    };
    let matcher = match &raw.matcher {
        RawMatcher::JsonPointer { files, pointers } => Matcher::JsonPointer {
            files: globs(files).map_err(&bad)?,
            pointers: pointers.clone(),
        },
        RawMatcher::FileRegex { files, pattern } => Matcher::FileRegex {
            files: globs(files).map_err(&bad)?,
            regex: Regex::new(pattern).map_err(|e| bad(e.to_string()))?,
        },
        RawMatcher::AllRegex { files, patterns } => Matcher::AllRegex {
            files: globs(files).map_err(&bad)?,
            regexes: patterns
                .iter()
                .map(|p| Regex::new(p).map_err(|e| bad(e.to_string())))
                .collect::<Result<_, _>>()?,
        },
        RawMatcher::BinaryFile { files, formats } => Matcher::BinaryFile {
            files: globs(files).map_err(&bad)?,
            formats: formats.clone(),
        },
        RawMatcher::ExecutableFile { files } => Matcher::ExecutableFile {
            files: globs(files).map_err(&bad)?,
        },
        RawMatcher::CommandRegex { pattern } => {
            Matcher::CommandRegex(Regex::new(pattern).map_err(|e| bad(e.to_string()))?)
        }
    };
    Ok(Rule {
        id: raw.id,
        severity: raw.severity,
        title: raw.title,
        remediation: raw.remediation,
        matcher,
    })
}

fn globs(patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p).map_err(|e| e.to_string())?);
    }
    builder.build().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema = 1
[[rule]]
id = "t/one"
severity = "warn"
title = "t"
remediation = "r"
match = { kind = "command_regex", pattern = "boom" }
"#;

    #[test]
    fn embedded_rules_load() {
        assert!(!RuleSet::embedded().unwrap().rules().is_empty());
    }

    #[test]
    fn newer_schema_is_refused() {
        let err = RuleSet::from_sources(&[("x.toml", "schema = 2")])
            .err()
            .unwrap();
        assert!(matches!(err, RuleError::Schema { found: 2, .. }));
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let err = RuleSet::from_sources(&[("a.toml", VALID), ("b.toml", VALID)])
            .err()
            .unwrap();
        assert!(matches!(err, RuleError::Duplicate(id) if id == "t/one"));
    }

    #[test]
    fn invalid_regex_names_the_rule() {
        let bad = VALID.replace("boom", "(");
        let err = RuleSet::from_sources(&[("a.toml", &bad)]).err().unwrap();
        assert!(matches!(err, RuleError::Pattern { id, .. } if id == "t/one"));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let bad = VALID.replace(
            "severity = \"warn\"",
            "severity = \"warn\"\nseverty = \"x\"",
        );
        assert!(RuleSet::from_sources(&[("a.toml", &bad)]).is_err());
    }
}
