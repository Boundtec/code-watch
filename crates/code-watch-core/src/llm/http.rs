use std::time::Duration;

use serde_json::Value;

use super::provider::LlmError;

/// Replies are small JSON documents; anything bigger is not a reply.
pub(crate) const MAX_BODY_BYTES: u64 = 256 * 1024;
/// Output cap sent with every request.
pub(crate) const MAX_OUTPUT_TOKENS: u32 = 2048;

/// Reads an API key from the environment at call time. A closure so tests never touch the
/// process environment.
pub type KeyFn = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub(crate) fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .user_agent(concat!("code-watch/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

pub(crate) fn map_error(err: ureq::Error) -> LlmError {
    match err {
        ureq::Error::StatusCode(code) => LlmError::Status(code),
        ureq::Error::Timeout(_) => LlmError::Timeout,
        ureq::Error::BodyExceedsLimit(_) => LlmError::TooLarge,
        _ => LlmError::Network,
    }
}

/// POSTs `body` as JSON and returns the parsed reply, with the size cap enforced while reading.
pub(crate) fn post_json(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, &str)],
    body: &Value,
) -> Result<Value, LlmError> {
    let mut request = agent.post(url).header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut response = request.send(body.to_string()).map_err(map_error)?;
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(map_error)?;
    serde_json::from_str(&text).map_err(|_| LlmError::BadResponse)
}

pub(crate) fn join(base: &str, path: &str) -> String {
    format!("{}/{path}", base.trim_end_matches('/'))
}
