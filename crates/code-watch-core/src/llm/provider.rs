use std::fmt;

/// What is sent to a model: a fixed system prompt and the user message built from the repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmRequest {
    pub system: String,
    pub user: String,
}

/// The text of the model's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmReply {
    pub text: String,
}

/// Why a call produced no usable answer. The texts end up in the report, so they never carry
/// the key, the request, or anything the provider or the model said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmError {
    Timeout,
    Network,
    Redirected,
    Status(u16),
    Refused,
    Truncated,
    BadResponse,
    TooLarge,
    MissingKey,
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::Timeout => f.write_str("the provider timed out"),
            LlmError::Network => f.write_str("the provider is unreachable"),
            LlmError::Redirected => {
                f.write_str("the provider redirected the request, check base_url")
            }
            LlmError::Status(code) => write!(f, "the provider answered HTTP {code}"),
            LlmError::Refused => f.write_str("the model refused the request"),
            LlmError::Truncated => f.write_str("the model's answer was cut short"),
            LlmError::BadResponse => {
                f.write_str("the provider sent an answer that could not be read")
            }
            LlmError::TooLarge => f.write_str("the provider's answer was too large"),
            LlmError::MissingKey => f.write_str("the API key variable is not set"),
        }
    }
}

/// One call to a model. The two real clients are `OpenAiCompat` and `Anthropic`.
pub trait LlmProvider {
    fn complete(&self, req: &LlmRequest) -> Result<LlmReply, LlmError>;
}
