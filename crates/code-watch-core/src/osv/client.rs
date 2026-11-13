use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use super::advisory::OsvRecord;
use super::package::Ecosystem;

const OSV_BASE: &str = "https://api.osv.dev";
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;
/// OSV rejects batches above this many queries.
pub const MAX_BATCH: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub page_token: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryAnswer {
    pub ids: Vec<String>,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvError {
    Timeout,
    Network,
    Status(u16),
    BadResponse,
    Partial,
    /// The time budget for the whole layer passed before every lookup was made.
    OutOfTime,
}

impl fmt::Display for OsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsvError::Timeout => f.write_str("OSV timed out"),
            OsvError::Network => f.write_str("OSV is unreachable"),
            OsvError::Status(code) => write!(f, "OSV answered HTTP {code}"),
            OsvError::BadResponse => f.write_str("OSV sent an answer that could not be read"),
            OsvError::Partial => f.write_str("OSV answered only part of a batch"),
            OsvError::OutOfTime => f.write_str("the time limit for OSV lookups passed"),
        }
    }
}

/// The two OSV calls the layer needs. `query_batch` returns one answer per query, in order;
/// a shorter list means the tail was not answered.
pub trait OsvClient {
    fn query_batch(&self, queries: &[Query]) -> Result<Vec<QueryAnswer>, OsvError>;
    fn record(&self, id: &str) -> Result<OsvRecord, OsvError>;
}

pub struct UreqOsv {
    agent: ureq::Agent,
    base: String,
}

impl Default for UreqOsv {
    fn default() -> Self {
        Self::with_base(OSV_BASE)
    }
}

impl UreqOsv {
    pub(crate) fn with_base(base: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .user_agent(concat!("code-watch/", env!("CARGO_PKG_VERSION")))
            .build()
            .new_agent();
        Self {
            agent,
            base: base.to_owned(),
        }
    }

    fn read(
        result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<String, OsvError> {
        let mut response = result.map_err(map_error)?;
        response
            .body_mut()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_string()
            .map_err(map_error)
    }
}

fn map_error(err: ureq::Error) -> OsvError {
    match err {
        ureq::Error::StatusCode(code) => OsvError::Status(code),
        ureq::Error::Timeout(_) => OsvError::Timeout,
        ureq::Error::BodyExceedsLimit(_) => OsvError::BadResponse,
        _ => OsvError::Network,
    }
}

impl OsvClient for UreqOsv {
    fn query_batch(&self, queries: &[Query]) -> Result<Vec<QueryAnswer>, OsvError> {
        let body = batch_body(queries);
        let text = Self::read(
            self.agent
                .post(format!("{}/v1/querybatch", self.base))
                .header("content-type", "application/json")
                .send(body),
        )?;
        parse_batch(&text)
    }

    fn record(&self, id: &str) -> Result<OsvRecord, OsvError> {
        if !is_safe_id(id) {
            return Err(OsvError::BadResponse);
        }
        let text = Self::read(
            self.agent
                .get(format!("{}/v1/vulns/{id}", self.base))
                .call(),
        )?;
        serde_json::from_str(&text).map_err(|_| OsvError::BadResponse)
    }
}

/// Advisory ids come from the server and end up in a URL path.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

pub(crate) fn batch_body(queries: &[Query]) -> String {
    let queries: Vec<_> = queries
        .iter()
        .map(|q| {
            let mut v = json!({
                "package": { "ecosystem": q.ecosystem.osv_name(), "name": q.name },
                "version": q.version,
            });
            if let Some(token) = &q.page_token {
                v["page_token"] = json!(token);
            }
            v
        })
        .collect();
    json!({ "queries": queries }).to_string()
}

#[derive(Deserialize)]
struct BatchReply {
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnId>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct VulnId {
    id: String,
}

pub(crate) fn parse_batch(text: &str) -> Result<Vec<QueryAnswer>, OsvError> {
    let reply: BatchReply = serde_json::from_str(text).map_err(|_| OsvError::BadResponse)?;
    Ok(reply
        .results
        .into_iter()
        .map(|r| QueryAnswer {
            ids: r.vulns.into_iter().map(|v| v.id).collect(),
            next_page_token: r.next_page_token,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, token: Option<&str>) -> Query {
        Query {
            ecosystem: Ecosystem::PyPI,
            name: name.into(),
            version: "1.0".into(),
            page_token: token.map(Into::into),
        }
    }

    #[test]
    fn the_batch_body_names_ecosystem_package_version_and_page_token() {
        let body: serde_json::Value =
            serde_json::from_str(&batch_body(&[query("a", None), query("b", Some("t"))])).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"queries": [
                {"package": {"ecosystem": "PyPI", "name": "a"}, "version": "1.0"},
                {"package": {"ecosystem": "PyPI", "name": "b"}, "version": "1.0", "page_token": "t"},
            ]})
        );
    }

    #[test]
    fn a_batch_reply_gives_one_answer_per_result_with_empty_results_allowed() {
        let reply = r#"{"results":[{"vulns":[{"id":"A","modified":"x"},{"id":"B"}],"next_page_token":"n"},{}]}"#;
        assert_eq!(
            parse_batch(reply).unwrap(),
            [
                QueryAnswer {
                    ids: vec!["A".into(), "B".into()],
                    next_page_token: Some("n".into())
                },
                QueryAnswer::default(),
            ]
        );
    }

    #[test]
    fn a_reply_that_is_not_a_batch_is_a_bad_response() {
        for bad in [
            "",
            "not json",
            "{}",
            r#"{"results":"x"}"#,
            r#"{"results":[{"vulns":[{"no_id":1}]}]}"#,
        ] {
            assert_eq!(parse_batch(bad), Err(OsvError::BadResponse), "{bad}");
        }
    }

    #[test]
    fn advisory_ids_from_the_server_are_checked_before_they_enter_a_url() {
        for ok in [
            "GHSA-aaaa-bbbb-cccc",
            "MAL-2024-1",
            "CVE-2020-1234",
            "PYSEC-2021-1",
            "OSV:1.2",
        ] {
            assert!(is_safe_id(ok), "{ok}");
        }
        for bad in [
            "",
            "a/b",
            "../x",
            "a?b=1",
            "a b",
            "a#b",
            "é",
            &"a".repeat(129),
        ] {
            assert!(!is_safe_id(bad), "{bad}");
        }
    }

    #[test]
    fn transport_errors_map_to_the_named_failures() {
        assert_eq!(
            map_error(ureq::Error::StatusCode(503)),
            OsvError::Status(503)
        );
        assert_eq!(
            map_error(ureq::Error::Timeout(ureq::Timeout::Global)),
            OsvError::Timeout
        );
        assert_eq!(map_error(ureq::Error::HostNotFound), OsvError::Network);
        assert_eq!(
            map_error(ureq::Error::BodyExceedsLimit(1)),
            OsvError::BadResponse
        );
    }

    /// Serves one canned raw HTTP response per connection from a thread the test owns, and
    /// returns the base URL.
    fn serve(responses: Vec<&'static str>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for response in responses {
                let (mut conn, _) = listener.accept().unwrap();
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = conn.write_all(response.as_bytes());
            }
        });
        (base, handle)
    }

    #[test]
    fn http_failures_become_named_errors_not_clean_answers() {
        let (base, server) = serve(vec![
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{\"results\":[",
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"results\":[",
        ]);
        let client = UreqOsv::with_base(&base);
        let q = [query("a", None)];
        assert_eq!(client.query_batch(&q), Err(OsvError::Status(429)));
        assert!(client.query_batch(&q).is_err(), "a body cut short");
        assert_eq!(client.query_batch(&q), Err(OsvError::BadResponse));
        server.join().unwrap();
    }
}
