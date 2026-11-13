//! Security properties of the CI and release workflows, checked on the YAML itself.

use std::fs;
use std::path::PathBuf;

use serde_norway::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name);
    serde_norway::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn workflows() -> [(&'static str, Value); 2] {
    [
        ("ci.yaml", load("ci.yaml")),
        ("release.yaml", load("release.yaml")),
    ]
}

fn jobs(wf: &Value) -> Vec<(&str, &Value)> {
    wf["jobs"]
        .as_mapping()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.as_str().unwrap(), v))
        .collect()
}

fn steps(job: &Value) -> &[Value] {
    job["steps"].as_sequence().unwrap()
}

#[test]
fn top_level_permissions_are_read_only() {
    for (name, wf) in workflows() {
        let perms = wf["permissions"]
            .as_mapping()
            .unwrap_or_else(|| panic!("{name}: no top-level permissions"));
        assert_eq!(perms.len(), 1, "{name}");
        assert_eq!(
            wf["permissions"]["contents"].as_str(),
            Some("read"),
            "{name}"
        );
    }
}

#[test]
fn only_the_publish_job_can_write() {
    for (name, wf) in workflows() {
        for (job_name, job) in jobs(&wf) {
            let has_perms = !job["permissions"].is_null();
            if job_name == "publish" && name == "release.yaml" {
                assert_eq!(job["permissions"]["contents"].as_str(), Some("write"));
                assert_eq!(job["permissions"]["id-token"].as_str(), Some("write"));
                assert_eq!(job["permissions"]["attestations"].as_str(), Some("write"));
            } else {
                assert!(
                    !has_perms,
                    "{name}: job {job_name} must not widen permissions"
                );
            }
        }
    }
}

#[test]
fn publish_runs_only_for_tags_and_needs_every_build() {
    let wf = load("release.yaml");
    let publish = &wf["jobs"]["publish"];
    assert_eq!(publish["if"].as_str(), Some("github.ref_type == 'tag'"));
    assert_eq!(publish["needs"].as_str(), Some("build"));
}

#[test]
fn every_checkout_drops_credentials() {
    let mut seen = 0;
    for (name, wf) in workflows() {
        for (job_name, job) in jobs(&wf) {
            for step in steps(job) {
                if step["uses"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("actions/checkout@"))
                {
                    seen += 1;
                    assert_eq!(
                        step["with"]["persist-credentials"].as_bool(),
                        Some(false),
                        "{name}: {job_name} checkout keeps credentials"
                    );
                }
            }
        }
    }
    assert!(
        seen >= 3,
        "expected checkouts in ci and release, saw {seen}"
    );
}

#[test]
fn every_action_is_pinned_to_a_full_commit_sha() {
    let mut seen = 0;
    for (name, wf) in workflows() {
        for (job_name, job) in jobs(&wf) {
            for step in steps(job) {
                let Some(uses) = step["uses"].as_str() else {
                    continue;
                };
                seen += 1;
                let (_, rev) = uses
                    .split_once('@')
                    .unwrap_or_else(|| panic!("{name}/{job_name}: {uses} has no pin"));
                assert!(
                    rev.len() == 40 && rev.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
                    "{name}/{job_name}: {uses} is not pinned by a 40-hex sha"
                );
            }
        }
    }
    assert!(seen >= 8, "saw only {seen} actions");
}

#[test]
fn the_release_build_uses_no_cache() {
    let wf = load("release.yaml");
    for (job_name, job) in jobs(&wf) {
        for step in steps(job) {
            let uses = step["uses"].as_str().unwrap_or("");
            assert!(
                !uses.contains("rust-cache") && !uses.contains("actions/cache"),
                "{job_name} uses a cache: {uses}"
            );
        }
    }
}
