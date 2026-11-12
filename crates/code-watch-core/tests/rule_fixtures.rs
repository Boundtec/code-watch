//! Every embedded rule must come with a positive and a negative fixture: a rule that cannot
//! fail is a finding. Repo rules use `tests/fixtures/<id>/{positive,negative}/` directories
//! (inert text only), command rules use `positive.txt` / `negative.txt` with one command per line.

use std::fs;
use std::path::PathBuf;

use code_watch_core::{Engine, RuleSet, Target, command};

fn fixture_dir(rule_id: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rule_id.replace('/', "__"))
}

fn lines(path: PathBuf) -> Vec<String> {
    fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing fixture {}", path.display()))
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// Runs one command line against one rule; the built-in rules are checked with the macOS-only
/// ones enabled, whatever platform the tests run on.
fn fires(engine: &Engine, id: &str, cmd: &str, builtin: bool) -> bool {
    if builtin {
        command::analyze(cmd, true).iter().any(|f| f.rule_id == id)
    } else {
        engine
            .check_command(cmd)
            .findings()
            .iter()
            .any(|f| f.rule_id == id)
    }
}

fn assert_command_fixtures(engine: &Engine, id: &str, builtin: bool) {
    let dir = fixture_dir(id);
    let positive = lines(dir.join("positive.txt"));
    let negative = lines(dir.join("negative.txt"));
    assert!(
        !positive.is_empty() && !negative.is_empty(),
        "{id} needs both fixtures"
    );
    for cmd in positive {
        assert!(fires(engine, id, &cmd, builtin), "{id} missed: {cmd}");
    }
    for cmd in negative {
        assert!(!fires(engine, id, &cmd, builtin), "{id} fired on: {cmd}");
    }
}

#[test]
fn every_rule_has_a_positive_and_a_negative_fixture() {
    let engine = Engine::embedded().unwrap();
    for rule in RuleSet::embedded().unwrap().rules() {
        match rule.target() {
            Target::Repo => {
                let dir = fixture_dir(&rule.id);
                let positive = engine.scan_dir(&dir.join("positive")).unwrap();
                assert!(
                    positive.findings().iter().any(|f| f.rule_id == rule.id),
                    "{} did not fire on its positive fixture",
                    rule.id
                );
                let negative = engine.scan_dir(&dir.join("negative")).unwrap();
                assert!(
                    negative.findings().iter().all(|f| f.rule_id != rule.id),
                    "{} fired on its negative fixture",
                    rule.id
                );
            }
            Target::Command => assert_command_fixtures(&engine, &rule.id, false),
        }
    }
    for rule in command::RULES {
        assert_command_fixtures(&engine, rule.id, true);
    }
}

#[test]
fn repo_findings_point_at_the_file_and_line() {
    let engine = Engine::embedded().unwrap();
    let report = engine
        .scan_dir(&fixture_dir("repo/vscode-folderopen-task").join("positive"))
        .unwrap();
    let finding = &report.findings()[0];
    assert_eq!(finding.evidence.file.as_deref(), Some(".vscode/tasks.json"));
    assert_eq!(finding.evidence.line, Some(6));
}
