//! Detection engine of code-watch. The CLI, the git hook, the agent adapters and the PATH
//! shims are thin callers of [`Engine`].

pub mod engine;
pub mod finding;
mod names;
pub mod render;
pub mod report;
pub mod rules;

pub use engine::{Engine, ScanError};
pub use finding::{Evidence, Finding, Layer, Severity};
pub use report::{LayerStatus, Report, SkipReason, Skipped, Verdict};
pub use rules::{Rule, RuleError, RuleSet, Target};
