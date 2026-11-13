use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use super::http::{self, KeyFn, MAX_OUTPUT_TOKENS};
use super::provider::{LlmError, LlmProvider, LlmReply, LlmRequest};

const VERSION: &str = "2023-06-01";

/// The Anthropic Messages API.
pub struct Anthropic {
    agent: ureq::Agent,
    base_url: String,
    model: String,
    key_env: String,
    key: KeyFn,
}

impl fmt::Debug for Anthropic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anthropic")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

impl Anthropic {
    pub fn new(base_url: &str, model: &str, key_env: &str, key: KeyFn, timeout: Duration) -> Self {
        Self {
            agent: http::agent(timeout),
            base_url: base_url.to_owned(),
            model: model.to_owned(),
            key_env: key_env.to_owned(),
            key,
        }
    }
}

#[derive(Deserialize)]
struct Message {
    content: Vec<Block>,
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct Block {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

impl LlmProvider for Anthropic {
    fn complete(&self, req: &LlmRequest) -> Result<LlmReply, LlmError> {
        let key = (self.key)(&self.key_env).ok_or(LlmError::MissingKey)?;
        let body = json!({
            "model": self.model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0,
            "system": req.system,
            "messages": [{"role": "user", "content": req.user}],
        });
        let value = http::post_json(
            &self.agent,
            &http::join(&self.base_url, "v1/messages"),
            &[("x-api-key", &key), ("anthropic-version", VERSION)],
            &body,
        )?;
        let reply: Message = serde_json::from_value(value).map_err(|_| LlmError::BadResponse)?;
        match reply.stop_reason.as_deref() {
            Some("refusal") => return Err(LlmError::Refused),
            Some("max_tokens") => return Err(LlmError::Truncated),
            _ => {}
        }
        let text: String = reply
            .content
            .into_iter()
            .filter(|b| b.kind == "text")
            .filter_map(|b| b.text)
            .collect();
        if text.trim().is_empty() {
            return Err(LlmError::BadResponse);
        }
        Ok(LlmReply { text })
    }
}
