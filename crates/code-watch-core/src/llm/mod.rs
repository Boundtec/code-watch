//! The optional LLM layer. It can only add findings: a model reply is parsed into a schema that
//! has nothing but findings, and the report only grows.

mod anthropic;
mod config;
mod findings;
mod http;
mod openai;
mod prompt;
mod provider;
mod run;
mod select;
#[cfg(test)]
mod testing;

pub use anthropic::Anthropic;
pub use config::{DEFAULT_TIMEOUT, MAX_TIMEOUT_SECS, Resolution, resolve};
pub use findings::{LlmFindings, MAX_FINDINGS};
pub use http::KeyFn;
pub use openai::OpenAiCompat;
pub use provider::{LlmError, LlmProvider, LlmReply, LlmRequest};
pub use run::{LlmMode, LlmOutcome, run};
pub use select::{MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, Sent, SentFile, select};
