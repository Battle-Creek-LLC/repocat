//! Host-agnostic reporting types shared by every provider.
//!
//! A `Finding` carries only what `output.rs` needs to render a result — rule
//! id, severity, NIST controls, pass/fail/skip status, and human-readable
//! messages. It deliberately holds **no executable action**: how a drift is
//! reconciled is host-specific and lives inside each provider module, which
//! executes its own changes and then maps its internal result down to this
//! type for reporting.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Skip => "skip",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub nist: &'static str,
    pub status: Status,
    pub messages: Vec<String>,
}

/// What a provider run hands back to `main` for cross-provider rendering and
/// exit accounting. Text output and (for GitHub) apply execution already
/// happened inside the run; `findings` exists for deferred JSON/SARIF.
pub struct Outcome {
    /// org (GitHub) or group (GitLab) — used to qualify findings in output.
    pub namespace: String,
    pub findings: Vec<(String, Vec<Finding>)>,
    pub any_error: bool,
    pub any_apply_error: bool,
}
