//! Detection engine of code-watch. The CLI, the git hook, the agent adapters and the PATH
//! shims are thin callers of [`Engine`].

pub mod allow;
pub mod command;
pub mod download;
pub mod engine;
pub mod finding;
pub mod install;
pub mod llm;
mod names;
pub mod osv;
pub mod render;
pub mod report;
pub mod rules;

pub use allow::{AllowError, Allowlists, Source, Suppressed};
pub use engine::{Engine, OsvSetup, ScanError};
pub use finding::{Advisory, Evidence, Finding, Layer, Severity};
pub use llm::{LlmFindings, LlmMode, LlmOutcome};
pub use report::{LayerStatus, Report, SkipReason, Skipped, Verdict};
pub use rules::{Rule, RuleError, RuleSet, Target};
