//! Test helpers and the tests that drive the real clients against a local HTTP server.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::provider::{LlmError, LlmProvider, LlmReply, LlmRequest};
use super::{Anthropic, OpenAiCompat};

pub(crate) const FAKE_KEY: &str = "fake-key-do-not-use-123";

/// Answers with a canned result and counts calls.
pub(crate) struct Fake {
    pub reply: Result<String, LlmError>,
    pub calls: Cell<usize>,
}

impl Fake {
    pub(crate) fn text(text: &str) -> Self {
        Self {
            reply: Ok(text.to_owned()),
            calls: Cell::new(0),
        }
    }

    pub(crate) fn failing(e: LlmError) -> Self {
        Self {
            reply: Err(e),
            calls: Cell::new(0),
        }
    }
}

impl LlmProvider for Fake {
    fn complete(&self, _: &LlmRequest) -> Result<LlmReply, LlmError> {
        self.calls.set(self.calls.get() + 1);
        self.reply.clone().map(|text| LlmReply { text })
    }
}

pub(crate) fn http_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Serves one canned raw response per connection on an ephemeral loopback port and records each
/// request. After writing it waits for the client to close, so a stalled body ends when the
/// client's own timeout fires, with no waiting loop here.
pub(crate) fn serve(responses: Vec<Vec<u8>>) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let handle = std::thread::spawn(move || {
        for response in responses {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
                if complete(&request) {
                    break;
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&request).into_owned());
            let _ = conn.write_all(&response);
            while matches!(conn.read(&mut buf), Ok(n) if n > 0) {}
        }
    });
    (base, seen, handle)
}

fn complete(request: &[u8]) -> bool {
    let text = String::from_utf8_lossy(request);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    body.len() >= length
}

fn key_fn() -> super::KeyFn {
    Box::new(|name| (name == "KEY_VAR").then(|| FAKE_KEY.to_owned()))
}

const SHORT: Duration = Duration::from_millis(250);

fn request() -> LlmRequest {
    LlmRequest {
        system: "sys".into(),
        user: "usr".into(),
    }
}

fn openai(base: &str, timeout: Duration) -> OpenAiCompat {
    OpenAiCompat::new(base, "m", Some("KEY_VAR".into()), key_fn(), timeout)
}

fn anthropic(base: &str, timeout: Duration) -> Anthropic {
    Anthropic::new(base, "m", "KEY_VAR", key_fn(), timeout)
}

fn openai_ok(content: &str) -> Vec<u8> {
    let body = serde_json::json!({"choices": [{"message": {"content": content, "refusal": null}, "finish_reason": "stop"}]});
    http_response("200 OK", &body.to_string())
}

fn anthropic_ok(text: &str) -> Vec<u8> {
    let body = serde_json::json!({"content": [{"type": "thinking"}, {"type": "text", "text": text}], "stop_reason": "end_turn"});
    http_response("200 OK", &body.to_string())
}

/// Both clients through the same failure rows, each with the real API's refusal shapes.
fn both(openai_response: Vec<u8>, anthropic_response: Vec<u8>) -> [Result<LlmReply, LlmError>; 2] {
    let (base, _, h1) = serve(vec![openai_response]);
    let a = openai(&base, SHORT).complete(&request());
    h1.join().unwrap();
    let (base, _, h2) = serve(vec![anthropic_response]);
    let b = anthropic(&base, SHORT).complete(&request());
    h2.join().unwrap();
    [a, b]
}

#[test]
fn a_good_reply_is_returned_and_the_key_goes_only_in_the_auth_header() {
    let (base, seen, h) = serve(vec![openai_ok("{\"findings\":[]}")]);
    let reply = openai(&base, SHORT).complete(&request()).unwrap();
    h.join().unwrap();
    assert_eq!(reply.text, "{\"findings\":[]}");
    let sent = &seen.lock().unwrap()[0];
    let lower = sent.to_ascii_lowercase();
    assert!(sent.starts_with("POST /chat/completions "));
    assert!(lower.contains(&format!("authorization: bearer {FAKE_KEY}")));
    let body = sent.split_once("\r\n\r\n").unwrap().1;
    assert!(!body.contains(FAKE_KEY));
    assert!(body.contains("\"max_completion_tokens\"") && body.contains("\"system\""));

    let (base, seen, h) = serve(vec![anthropic_ok("hello")]);
    let reply = anthropic(&base, SHORT).complete(&request()).unwrap();
    h.join().unwrap();
    assert_eq!(reply.text, "hello");
    let sent = &seen.lock().unwrap()[0];
    let lower = sent.to_ascii_lowercase();
    assert!(sent.starts_with("POST /v1/messages "));
    assert!(lower.contains(&format!("x-api-key: {FAKE_KEY}")));
    assert!(lower.contains("anthropic-version: 2023-06-01"));
    assert!(!sent.split_once("\r\n\r\n").unwrap().1.contains(FAKE_KEY));
}

#[test]
fn a_local_provider_without_a_key_sends_no_auth_header() {
    let (base, seen, h) = serve(vec![openai_ok("{}")]);
    let client = OpenAiCompat::new(&base, "m", None, key_fn(), SHORT);
    client.complete(&request()).unwrap();
    h.join().unwrap();
    assert!(
        !seen.lock().unwrap()[0]
            .to_ascii_lowercase()
            .contains("authorization")
    );
}

#[test]
fn http_errors_become_named_failures() {
    for (status, code) in [
        ("401 Unauthorized", 401),
        ("429 Too Many Requests", 429),
        ("500 Internal Server Error", 500),
    ] {
        let body = "{\"type\":\"error\",\"error\":{\"message\":\"echo of request text\"}}";
        let [a, b] = both(http_response(status, body), http_response(status, body));
        assert_eq!(a, Err(LlmError::Status(code)));
        assert_eq!(b, Err(LlmError::Status(code)));
    }
}

#[test]
fn a_redirect_is_not_followed_so_the_key_never_reaches_another_host() {
    for provider in ["openai", "anthropic"] {
        let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            elsewhere.local_addr().unwrap()
        );
        let (base, _, h) = serve(vec![redirect.into_bytes()]);
        let result = if provider == "openai" {
            openai(&base, SHORT).complete(&request())
        } else {
            anthropic(&base, SHORT).complete(&request())
        };
        h.join().unwrap();
        assert!(result.is_err(), "{provider}");
        elsewhere.set_nonblocking(true).unwrap();
        assert!(
            elsewhere.accept().is_err(),
            "{provider} followed the redirect"
        );
    }
}

#[test]
fn refusals_and_cut_short_answers_are_failures_not_findings() {
    let refusal = serde_json::json!({"choices": [{"message": {"content": null, "refusal": "I can't help"}, "finish_reason": "stop"}]});
    let [a, _] = both(
        http_response("200 OK", &refusal.to_string()),
        anthropic_ok("x"),
    );
    assert_eq!(a, Err(LlmError::Refused));
    let filtered = serde_json::json!({"choices": [{"message": {"content": "x"}, "finish_reason": "content_filter"}]});
    let [a, _] = both(
        http_response("200 OK", &filtered.to_string()),
        anthropic_ok("x"),
    );
    assert_eq!(a, Err(LlmError::Refused));
    let length = serde_json::json!({"choices": [{"message": {"content": "{\"find"}, "finish_reason": "length"}]});
    let [a, _] = both(
        http_response("200 OK", &length.to_string()),
        anthropic_ok("x"),
    );
    assert_eq!(a, Err(LlmError::Truncated));
    let refused = serde_json::json!({"content": [], "stop_reason": "refusal"});
    let [_, b] = both(
        openai_ok("x"),
        http_response("200 OK", &refused.to_string()),
    );
    assert_eq!(b, Err(LlmError::Refused));
    let max = serde_json::json!({"content": [{"type": "text", "text": "{\"fi"}], "stop_reason": "max_tokens"});
    let [_, b] = both(openai_ok("x"), http_response("200 OK", &max.to_string()));
    assert_eq!(b, Err(LlmError::Truncated));
}

#[test]
fn unreadable_replies_are_bad_responses() {
    for body in [
        "",
        "not json",
        "{}",
        "{\"choices\":[]}",
        "{\"content\":\"x\"}",
    ] {
        let [a, b] = both(http_response("200 OK", body), http_response("200 OK", body));
        assert_eq!(a, Err(LlmError::BadResponse), "{body}");
        assert_eq!(b, Err(LlmError::BadResponse), "{body}");
    }
    let empty =
        serde_json::json!({"choices": [{"message": {"content": "  "}, "finish_reason": "stop"}]});
    let [a, _] = both(
        http_response("200 OK", &empty.to_string()),
        anthropic_ok("x"),
    );
    assert_eq!(a, Err(LlmError::BadResponse));
    let no_text = serde_json::json!({"content": [{"type": "tool_use"}], "stop_reason": "tool_use"});
    let [_, b] = both(
        openai_ok("x"),
        http_response("200 OK", &no_text.to_string()),
    );
    assert_eq!(b, Err(LlmError::BadResponse));
}

#[test]
fn a_body_over_the_size_cap_is_too_large() {
    let huge = "x".repeat(300 * 1024);
    let [a, b] = both(
        http_response("200 OK", &huge),
        http_response("200 OK", &huge),
    );
    assert_eq!(a, Err(LlmError::TooLarge));
    assert_eq!(b, Err(LlmError::TooLarge));
}

#[test]
fn a_body_that_stalls_ends_at_the_injected_timeout() {
    let stalled =
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{\"choices\":["
            .to_vec();
    let (base, _, h) = serve(vec![stalled.clone()]);
    let a = openai(&base, Duration::from_millis(150)).complete(&request());
    h.join().unwrap();
    assert_eq!(a, Err(LlmError::Timeout));
    let (base, _, h) = serve(vec![stalled]);
    let b = anthropic(&base, Duration::from_millis(150)).complete(&request());
    h.join().unwrap();
    assert_eq!(b, Err(LlmError::Timeout));
}

#[test]
fn a_closed_port_is_a_network_failure() {
    let base = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    assert_eq!(
        openai(&base, SHORT).complete(&request()),
        Err(LlmError::Network)
    );
    assert_eq!(
        anthropic(&base, SHORT).complete(&request()),
        Err(LlmError::Network)
    );
}

#[test]
fn a_missing_key_fails_before_any_request() {
    let none: super::KeyFn = Box::new(|_| None);
    let client = OpenAiCompat::new(
        "http://127.0.0.1:9",
        "m",
        Some("KEY_VAR".into()),
        none,
        SHORT,
    );
    assert_eq!(client.complete(&request()), Err(LlmError::MissingKey));
    let none: super::KeyFn = Box::new(|_| None);
    let client = Anthropic::new("http://127.0.0.1:9", "m", "KEY_VAR", none, SHORT);
    assert_eq!(client.complete(&request()), Err(LlmError::MissingKey));
}

#[test]
fn no_error_or_debug_text_carries_the_key() {
    let errors = [
        LlmError::Timeout,
        LlmError::Network,
        LlmError::Status(401),
        LlmError::Refused,
        LlmError::Truncated,
        LlmError::BadResponse,
        LlmError::TooLarge,
        LlmError::MissingKey,
    ];
    for e in errors {
        assert!(!format!("{e} {e:?}").contains(FAKE_KEY));
    }
    let (base, _, h) = serve(vec![http_response(
        "401 Unauthorized",
        &format!("{{\"error\":\"bad key {FAKE_KEY}\"}}"),
    )]);
    let client = openai(&base, SHORT);
    let err = client.complete(&request()).unwrap_err();
    h.join().unwrap();
    assert!(!format!("{err} {err:?} {client:?}").contains(FAKE_KEY));
    let client = anthropic(&base, SHORT);
    assert!(!format!("{client:?}").contains(FAKE_KEY));
}
