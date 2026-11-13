use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use super::http::{self, KeyFn, MAX_OUTPUT_TOKENS};
use super::provider::{LlmError, LlmProvider, LlmReply, LlmRequest};

/// The chat-completions shape: OpenAI, OpenRouter, Ollama, LM Studio, vLLM. `local` is this
/// client pointed at a loopback address, with the key optional.
pub struct OpenAiCompat {
    agent: ureq::Agent,
    base_url: String,
    model: String,
    key_env: Option<String>,
    key: KeyFn,
}

impl fmt::Debug for OpenAiCompat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiCompat")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

impl OpenAiCompat {
    pub fn new(
        base_url: &str,
        model: &str,
        key_env: Option<String>,
        key: KeyFn,
        timeout: Duration,
    ) -> Self {
        Self {
            agent: http::agent(timeout),
            base_url: base_url.to_owned(),
            model: model.to_owned(),
            key_env,
            key,
        }
    }
}

#[derive(Deserialize)]
struct Completion {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct Message {
    content: Option<String>,
    refusal: Option<String>,
}

impl LlmProvider for OpenAiCompat {
    fn complete(&self, req: &LlmRequest) -> Result<LlmReply, LlmError> {
        let key = match &self.key_env {
            Some(name) => Some((self.key)(name).ok_or(LlmError::MissingKey)?),
            None => None,
        };
        let auth = key.map(|k| format!("Bearer {k}"));
        let headers: Vec<(&str, &str)> = auth
            .as_deref()
            .map(|a| ("authorization", a))
            .into_iter()
            .collect();
        let body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
            "max_completion_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        });
        let value = http::post_json(
            &self.agent,
            &http::join(&self.base_url, "chat/completions"),
            &headers,
            &body,
        )?;
        let reply: Completion = serde_json::from_value(value).map_err(|_| LlmError::BadResponse)?;
        let choice = reply
            .choices
            .into_iter()
            .next()
            .ok_or(LlmError::BadResponse)?;
        if choice.message.refusal.is_some_and(|r| !r.is_empty())
            || choice.finish_reason.as_deref() == Some("content_filter")
        {
            return Err(LlmError::Refused);
        }
        if choice.finish_reason.as_deref() == Some("length") {
            return Err(LlmError::Truncated);
        }
        match choice.message.content {
            Some(text) if !text.trim().is_empty() => Ok(LlmReply { text }),
            _ => Err(LlmError::BadResponse),
        }
    }
}
