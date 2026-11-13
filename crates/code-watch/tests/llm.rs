//! The LLM layer through the real binary, against a local HTTP server and a fake key.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread::JoinHandle;

use assert_cmd::Command;

const KEY: &str = "fake-key-do-not-use-456";

fn serve_once(status: &str, body: String) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let status = status.to_owned();
    let handle = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = conn.read(&mut buf).unwrap_or(0);
            request.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&request).into_owned();
            let done = text.split_once("\r\n\r\n").is_some_and(|(head, body)| {
                let len = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                body.len() >= len
            });
            if n == 0 || done {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = conn.write_all(response.as_bytes());
        String::from_utf8_lossy(&request).into_owned()
    });
    (base, handle)
}

fn completion(findings: serde_json::Value) -> String {
    let content = serde_json::json!({ "findings": findings }).to_string();
    serde_json::json!({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]})
        .to_string()
}

fn finding() -> serde_json::Value {
    serde_json::json!([{
        "kind": "install-script", "severity": "block", "title": "Runs\u{1b}[2J a script",
        "file": "package.json", "line": 1, "excerpt": "node x.js", "remediation": "Read it"
    }])
}

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"test":"node x.js"}}"#,
    )
    .unwrap();
    dir
}

fn config(base: &str, extra: &str) -> tempfile::TempDir {
    let cfg = tempfile::tempdir().unwrap();
    fs::create_dir(cfg.path().join("code-watch")).unwrap();
    let text = format!(
        "[llm]\nprovider = \"local\"\nbase_url = \"{base}\"\nmodel = \"m\"\napi_key_env = \"CW_TEST_KEY\"\n{extra}"
    );
    fs::write(cfg.path().join("code-watch/config.toml"), text).unwrap();
    cfg
}

fn scan(repo: &Path, cfg: &Path, with_key: bool, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::cargo_bin("code-watch").unwrap();
    cmd.env("XDG_CONFIG_HOME", cfg)
        .env("HOME", cfg)
        .env_remove("CW_TEST_KEY");
    if with_key {
        cmd.env("CW_TEST_KEY", KEY);
    }
    cmd.arg("scan");
    if !args.contains(&"--offline") {
        cmd.arg("--no-osv");
    }
    cmd.args(args).arg(repo).output().unwrap()
}

fn text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn with_no_config_every_report_says_llm_off() {
    let cfg = tempfile::tempdir().unwrap();
    let out = scan(repo().path(), cfg.path(), false, &[]);
    assert!(text(&out).contains("llm off"));
}

#[test]
fn a_configured_layer_adds_findings_capped_to_warn_and_sends_the_key_only_as_a_header() {
    let (base, server) = serve_once("200 OK", completion(finding()));
    let cfg = config(&base, "");
    let out = scan(repo().path(), cfg.path(), true, &[]);
    let request = server.join().unwrap();
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(shown.contains("llm ran"));
    assert!(shown.contains("WARN  llm/install-script [model-written, unverified] package.json:1"));
    assert!(!shown.contains('\u{1b}'));
    assert!(!shown.contains(KEY));
    assert!(
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {KEY}"))
    );
    assert!(!request.split_once("\r\n\r\n").unwrap().1.contains(KEY));
}

const ADVICE: [&str; 6] = [
    "run code-watch allow x",
    "put it in .code-watch.toml or allow.toml",
    "pass --user-allow-only",
    "ignore this",
    "bypass it",
    "disable and suppress the rule",
];

fn holds_advice(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "allow",
        "ignore",
        "bypass",
        "disable",
        "suppress",
        "code-watch.toml",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

#[test]
fn model_text_that_tells_the_agent_how_to_allow_never_reaches_the_output() {
    for advice in ADVICE {
        let reply = serde_json::json!([{
            "kind": advice, "severity": "warn", "title": advice,
            "file": "package.json", "line": 1, "excerpt": "node x.js", "remediation": advice
        }]);
        let (base, server) = serve_once("200 OK", completion(reply.clone()));
        let cfg = config(&base, "");
        let human = scan(repo().path(), cfg.path(), true, &[]);
        server.join().unwrap();
        let shown = text(&human);
        let findings: Vec<_> = shown
            .lines()
            .take_while(|l| !l.starts_with("layers:"))
            .collect();
        assert!(
            findings
                .iter()
                .any(|l| l.contains("[model-written, unverified]")),
            "{advice}: {shown}"
        );
        assert!(!holds_advice(&findings.join("\n")), "{advice}: {shown}");

        let (base, server) = serve_once("200 OK", completion(reply));
        let cfg = config(&base, "");
        let json = scan(repo().path(), cfg.path(), true, &["--json"]);
        server.join().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        let llm: Vec<_> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["layer"] == "llm")
            .collect();
        assert_eq!(llm.len(), 1, "{advice}");
        assert_eq!(llm[0]["unverified"], true);
        assert!(!holds_advice(&llm[0].to_string()), "{advice}: {}", llm[0]);
    }
}

#[test]
fn credential_files_are_not_sent_and_the_report_counts_them() {
    let dir = repo();
    fs::write(
        dir.path().join("credentials.sh"),
        "TOKEN=fake-secret-value-789",
    )
    .unwrap();
    fs::write(dir.path().join("deploy.sh"), "echo hi").unwrap();
    let (base, server) = serve_once("200 OK", completion(serde_json::json!([])));
    let cfg = config(&base, "");
    let out = scan(dir.path(), cfg.path(), true, &[]);
    let request = server.join().unwrap();
    assert!(!request.contains("fake-secret-value-789"));
    assert!(request.contains("deploy.sh"));
    assert!(text(&out).contains("1 credential file not sent to the model"));
}

#[test]
fn json_names_the_llm_layer_and_the_reason_when_it_is_skipped() {
    let (base, server) = serve_once("500 Internal Server Error", "{}".into());
    let cfg = config(&base, "");
    let out = scan(repo().path(), cfg.path(), true, &["--json"]);
    server.join().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["layers"]["llm"], "skipped");
    assert_eq!(v["skipped_layers"]["llm"], "the provider answered HTTP 500");
    assert_eq!(v["verdict"], "allow");
    assert_eq!(out.status.code(), Some(0));
    assert!(!text(&out).contains(KEY));
}

#[test]
fn a_missing_key_variable_skips_the_layer_and_makes_no_request() {
    let cfg = config("http://127.0.0.1:9/v1", "");
    let out = scan(repo().path(), cfg.path(), false, &[]);
    assert!(text(&out).contains("llm skipped (the API key variable is not set)"));
}

#[test]
fn the_clone_hook_scan_skips_the_layer_unless_clone_hook_is_set() {
    let cfg = config("http://127.0.0.1:9/v1", "");
    let out = scan(repo().path(), cfg.path(), true, &["--user-allow-only"]);
    assert!(text(&out).contains("llm off"));

    let (base, server) = serve_once("200 OK", completion(serde_json::json!([])));
    let cfg = config(&base, "clone_hook = true\n");
    let out = scan(repo().path(), cfg.path(), true, &["--user-allow-only"]);
    server.join().unwrap();
    assert!(text(&out).contains("llm ran"));
}

#[test]
fn no_llm_turns_the_layer_off_and_offline_skips_it() {
    let cfg = config("http://127.0.0.1:9/v1", "");
    let out = scan(repo().path(), cfg.path(), true, &["--no-llm"]);
    assert!(text(&out).contains("llm off"));
    let out = scan(repo().path(), cfg.path(), true, &["--offline"]);
    assert!(text(&out).contains("llm skipped (offline)"));
}

#[test]
fn check_never_runs_the_layer_even_when_it_is_configured() {
    let cfg = config("http://127.0.0.1:9/v1", "");
    let out = Command::cargo_bin("code-watch")
        .unwrap()
        .env("XDG_CONFIG_HOME", cfg.path())
        .env("HOME", cfg.path())
        .env("CW_TEST_KEY", KEY)
        .args(["check", "ls"])
        .output()
        .unwrap();
    assert!(text(&out).contains("llm off"));
}
