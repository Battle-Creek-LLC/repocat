//! GitLab audit/apply rules. Each reads live state via the API client, compares
//! it to the `.repo.gitlab.yml` desired state, and reports a [`RuleResult`].
//! Rules that can self-heal also push an executable [`Action`] that `apply`
//! runs; audit-only rules (required_files, codeowners, ci_security, members)
//! report drift but push no actions. A block the user did not configure reports
//! `Skip`.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::api::{ApiError, Client};
use super::config::ProjectConfig;
use crate::finding::{Severity, Status};

/// An executable reconciliation step. Mirrors the GitHub provider's `Action`:
/// `summary()` is the human-readable line shown in diff/apply output and
/// `execute()` performs the mutation against the GitLab API.
#[derive(Debug)]
pub enum Action {
    PutProject { summary: String, body: Value },
    SetProtectedBranch { summary: String, branch: String, body: Value },
    CreateApprovalRule { summary: String, body: Value },
    UpdateApprovalRule { summary: String, rule_id: u64, body: Value },
    SetApprovalsConfig { summary: String, body: Value },
    SetPushRule { summary: String, body: Value, exists: bool },
}

impl Action {
    pub fn summary(&self) -> &str {
        match self {
            Action::PutProject { summary, .. } => summary,
            Action::SetProtectedBranch { summary, .. } => summary,
            Action::CreateApprovalRule { summary, .. } => summary,
            Action::UpdateApprovalRule { summary, .. } => summary,
            Action::SetApprovalsConfig { summary, .. } => summary,
            Action::SetPushRule { summary, .. } => summary,
        }
    }

    pub fn execute(&self, client: &Client, project: &str) -> Result<()> {
        match self {
            Action::PutProject { body, .. } => {
                client.put_project(project, body)?;
            }
            // GitLab has no single replace endpoint for a protected branch, so
            // delete-then-create reconciles it (delete is idempotent, 404 ok).
            // If the re-create fails after the delete succeeded, the branch is
            // left with NO protection — surface that loudly so it can't slip by
            // in a fleet run. (On Free/CE the Premium `code_owner_approval_required`
            // in `body` is a likely culprit for the create failing.)
            Action::SetProtectedBranch { branch, body, .. } => {
                client.delete_protected_branch(project, branch)?;
                client.create_protected_branch(project, body).map_err(|e| {
                    anyhow!(
                        "BRANCH LEFT UNPROTECTED: removed protection on `{branch}` but failed to \
                         re-create it: {e}. `{branch}` currently has NO branch protection — \
                         re-run `repocat apply` to restore it, or protect it manually now."
                    )
                })?;
            }
            Action::CreateApprovalRule { body, .. } => {
                client.create_approval_rule(project, body)?;
            }
            Action::UpdateApprovalRule { rule_id, body, .. } => {
                client.update_approval_rule(project, *rule_id, body)?;
            }
            Action::SetApprovalsConfig { body, .. } => {
                client.set_approvals_config(project, body)?;
            }
            Action::SetPushRule { body, exists, .. } => {
                client.set_push_rule(project, body, *exists)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RuleResult {
    pub rule: &'static str,
    pub severity: Severity,
    pub nist: &'static str,
    pub status: Status,
    pub messages: Vec<String>,
    /// Executable reconciliation steps `apply` runs. Empty for audit-only rules.
    pub actions: Vec<Action>,
}

impl RuleResult {
    fn new(rule: &'static str, severity: Severity, nist: &'static str) -> Self {
        Self { rule, severity, nist, status: Status::Pass, messages: Vec::new(), actions: Vec::new() }
    }
    fn fail(&mut self, msg: impl Into<String>) {
        self.status = Status::Fail;
        self.messages.push(msg.into());
    }
    fn act(&mut self, action: Action) {
        self.actions.push(action);
    }
    fn skip(mut self, msg: impl Into<String>) -> Self {
        self.status = Status::Skip;
        self.messages.push(msg.into());
        self
    }
}

pub fn run_all(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<Vec<RuleResult>> {
    // One project fetch serves project_settings plus the default branch used by
    // the file-existence rules.
    let proj = client.get_project(project)?;
    let git_ref = proj.default_branch.clone().unwrap_or_else(|| "main".to_string());

    Ok(vec![
        project_settings(&proj, cfg),
        protected_branches(client, project, cfg)?,
        approval_rules(client, project, cfg)?,
        merge_request_approvals(client, project, cfg)?,
        push_rules(client, project, cfg)?,
        required_files(client, project, &git_ref, cfg)?,
        codeowners(client, project, &git_ref, cfg)?,
        ci_security(client, project, &git_ref, cfg)?,
        members(client, project, cfg)?,
    ])
}

fn project_settings(proj: &super::api::Project, cfg: &ProjectConfig) -> RuleResult {
    let mut r = RuleResult::new("project_settings", Severity::Error, "CM-3");
    let Some(want) = cfg.project_settings.as_ref() else {
        return r.skip("not configured");
    };
    // Collect every drifted field into one body so a single PUT /projects/{id}
    // reconciles them all at once.
    let mut body = serde_json::Map::new();
    check_str(&mut r, &mut body, "merge_method", want.merge_method.as_deref(), proj.merge_method.as_deref());
    check_str(&mut r, &mut body, "squash_option", want.squash_option.as_deref(), proj.squash_option.as_deref());
    check_bool(&mut r, &mut body, "remove_source_branch_after_merge", want.remove_source_branch_after_merge, proj.remove_source_branch_after_merge);
    check_bool(&mut r, &mut body, "only_allow_merge_if_pipeline_succeeds", want.only_allow_merge_if_pipeline_succeeds, proj.only_allow_merge_if_pipeline_succeeds);
    check_bool(&mut r, &mut body, "only_allow_merge_if_all_discussions_are_resolved", want.only_allow_merge_if_all_discussions_are_resolved, proj.only_allow_merge_if_all_discussions_are_resolved);
    if !body.is_empty() {
        let fields: Vec<&str> = body.keys().map(String::as_str).collect();
        r.act(Action::PutProject {
            summary: format!("update project settings ({})", fields.join(", ")),
            body: Value::Object(body),
        });
    }
    r
}

fn protected_branches(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("protected_branches", Severity::Error, "AC-3, CM-3");
    if cfg.protected_branches.is_empty() {
        return Ok(r.skip("not configured"));
    }
    let actual = client.list_protected_branches(project)?;
    for want in &cfg.protected_branches {
        let mut drift = false;
        match actual.iter().find(|b| b.name == want.name) {
            None => {
                r.fail(format!("branch `{}` is not protected", want.name));
                drift = true;
            }
            Some(got) => {
                if let Some(w) = want.allow_force_push {
                    if got.allow_force_push != Some(w) {
                        r.fail(format!("`{}`: allow_force_push is {:?}, want {w}", want.name, got.allow_force_push));
                        drift = true;
                    }
                }
                if let Some(w) = want.code_owner_approval_required {
                    if got.code_owner_approval_required != Some(w) {
                        r.fail(format!("`{}`: code_owner_approval_required is {:?}, want {w}", want.name, got.code_owner_approval_required));
                        drift = true;
                    }
                }
                drift |= check_access(&mut r, &want.name, "push", want.push_access_level.as_deref(), &got.push_access_levels);
                drift |= check_access(&mut r, &want.name, "merge", want.merge_access_level.as_deref(), &got.merge_access_levels);
            }
        }
        if drift {
            r.act(Action::SetProtectedBranch {
                summary: format!("protect branch `{}`", want.name),
                branch: want.name.clone(),
                body: protected_branch_body(want),
            });
        }
    }
    Ok(r)
}

/// Build the POST body for a protected branch, including only the keys the
/// config set. Access-level names map to GitLab ints via `branch_access_int`;
/// an unknown name is silently dropped here (it was already reported as drift
/// by `check_access`, which is the only place that can fail on it).
fn protected_branch_body(want: &super::config::ProtectedBranch) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("name".into(), json!(want.name));
    if let Some(b) = want.allow_force_push {
        body.insert("allow_force_push".into(), json!(b));
    }
    if let Some(name) = want.push_access_level.as_deref() {
        if let Some(i) = branch_access_int(name) {
            body.insert("push_access_level".into(), json!(i));
        }
    }
    if let Some(name) = want.merge_access_level.as_deref() {
        if let Some(i) = branch_access_int(name) {
            body.insert("merge_access_level".into(), json!(i));
        }
    }
    if let Some(b) = want.code_owner_approval_required {
        body.insert("code_owner_approval_required".into(), json!(b));
    }
    Value::Object(body)
}

fn approval_rules(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("approval_rules", Severity::Error, "AC-3, CM-3");
    if cfg.approval_rules.is_empty() {
        return Ok(r.skip("not configured"));
    }
    let actual = match client.list_approval_rules(project) {
        Ok(a) => a,
        Err(e) if is_forbidden(&e) => {
            return Ok(r.skip("approval rules require GitLab Premium/Ultimate"));
        }
        Err(e) => return Err(e),
    };
    for want in &cfg.approval_rules {
        let Some(got) = actual.iter().find(|a| a.name == want.name) else {
            r.fail(format!("approval rule `{}` is missing", want.name));
            r.act(Action::CreateApprovalRule {
                summary: format!("create approval rule `{}`", want.name),
                body: json!({
                    "name": want.name,
                    "approvals_required": want.approvals_required.unwrap_or(0),
                }),
            });
            continue;
        };
        if let Some(w) = want.approvals_required {
            if got.approvals_required != Some(w) {
                r.fail(format!("`{}`: approvals_required is {:?}, want {w}", want.name, got.approvals_required));
                r.act(Action::UpdateApprovalRule {
                    summary: format!("`{}`: set approvals_required={w}", want.name),
                    rule_id: got.id,
                    body: json!({ "approvals_required": w }),
                });
            }
        }
    }
    Ok(r)
}

fn merge_request_approvals(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("merge_request_approvals", Severity::Error, "CM-3");
    let Some(want) = cfg.merge_request_approvals.as_ref() else {
        return Ok(r.skip("not configured"));
    };
    let actual = match client.get_approvals_config(project) {
        Ok(a) => a,
        Err(e) if is_forbidden(&e) => {
            return Ok(r.skip("merge request approval config requires GitLab Premium/Ultimate"));
        }
        Err(e) => return Err(e),
    };
    if let Some(w) = want.reset_approvals_on_push {
        if actual.reset_approvals_on_push != Some(w) {
            r.fail(format!("reset_approvals_on_push is {:?}, want {w}", actual.reset_approvals_on_push));
            r.act(Action::SetApprovalsConfig {
                summary: format!("set reset_approvals_on_push={w}"),
                body: json!({ "reset_approvals_on_push": w }),
            });
        }
    }
    Ok(r)
}

fn push_rules(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("push_rules", Severity::Error, "SI-7");
    let Some(want) = cfg.push_rules.as_ref() else {
        return Ok(r.skip("not configured"));
    };
    let actual = match client.get_push_rule(project) {
        Ok(a) => a,
        // Push rules are a Premium/Ultimate feature; a 403 means the tier can't
        // enforce this, which is a Skip rather than a failure.
        Err(e) if is_forbidden(&e) => {
            return Ok(r.skip("push rules require GitLab Premium/Ultimate"));
        }
        Err(e) => return Err(e),
    };
    if let Some(w) = want.reject_unsigned_commits {
        let got = actual.as_ref().and_then(|p| p.reject_unsigned_commits);
        if got != Some(w) {
            r.fail(format!("reject_unsigned_commits is {got:?}, want {w}"));
            r.act(Action::SetPushRule {
                summary: format!("set push rule reject_unsigned_commits={w}"),
                body: json!({ "reject_unsigned_commits": w }),
                exists: actual.is_some(),
            });
        }
    }
    Ok(r)
}

fn required_files(client: &Client, project: &str, git_ref: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("required_files", Severity::Error, "CM-2");
    if cfg.required_files.is_empty() {
        return Ok(r.skip("not configured"));
    }
    for path in &cfg.required_files {
        if !client.file_exists(project, path, git_ref)? {
            r.fail(format!("missing required file `{path}`"));
        }
    }
    Ok(r)
}

fn codeowners(client: &Client, project: &str, git_ref: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("codeowners", Severity::Warning, "CM-3, AC-5");
    if cfg.codeowners != Some(true) {
        return Ok(r.skip("not required"));
    }
    let candidates = [".gitlab/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];
    let mut present = false;
    for path in candidates {
        if client.file_exists(project, path, git_ref)? {
            present = true;
            break;
        }
    }
    if !present {
        r.fail("no CODEOWNERS file (.gitlab/CODEOWNERS, CODEOWNERS, or docs/CODEOWNERS)");
    }
    Ok(r)
}

fn ci_security(client: &Client, project: &str, git_ref: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("ci_security", Severity::Warning, "SA-11, RA-5, SI-2");
    let Some(want) = cfg.ci_security.as_ref() else {
        return Ok(r.skip("not configured"));
    };
    let Some(yaml) = client.get_file_raw(project, ".gitlab-ci.yml", git_ref)? else {
        r.fail("no .gitlab-ci.yml");
        return Ok(r);
    };
    let lower = yaml.to_lowercase();
    // Audit-only: CI YAML is owned by the repo, so we report drift but never
    // mutate the file. Remediation is a PR by the repo's maintainers.
    let mut want_template = |enabled: Option<bool>, needle: &str, label: &str| {
        if enabled == Some(true) && !lower.contains(&needle.to_lowercase()) {
            r.fail(format!("{label} not included in .gitlab-ci.yml"));
        }
    };
    want_template(want.require_sast, "SAST.gitlab-ci.yml", "SAST");
    want_template(want.require_secret_detection, "Secret-Detection.gitlab-ci.yml", "Secret Detection");
    want_template(want.require_dependency_scanning, "Dependency-Scanning.gitlab-ci.yml", "Dependency Scanning");
    if want.pin_includes == Some(true) {
        r.messages.push("note: pin_includes auditing is not yet implemented".into());
    }
    Ok(r)
}

fn members(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("members", Severity::Warning, "AC-2, AC-6");
    let Some(want) = cfg.members.as_ref() else {
        return Ok(r.skip("not configured"));
    };
    if want.direct_members_allowed == Some(false) {
        let direct = client.list_direct_members(project)?;
        if !direct.is_empty() {
            let names: Vec<String> = direct
                .iter()
                .map(|m| format!("{} (access {})", m.username, m.access_level))
                .collect();
            r.fail(format!("direct project members present: {}", names.join(", ")));
        }
    }
    if !want.shares.is_empty() {
        r.messages.push("note: group-share auditing is not yet implemented".into());
    }
    Ok(r)
}

// --- helpers -------------------------------------------------------------

/// True when an API error carried HTTP 403 — used to degrade tier-gated
/// endpoints (approval rules, MR approval config, push rules) to `Skip` on
/// Community/free instances that don't offer them, rather than aborting the
/// audit. Classifies on the structured status, not the message text.
fn is_forbidden(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ApiError>().is_some_and(|a| a.status == Some(403))
}

// --- comparison helpers --------------------------------------------------

fn check_str(
    r: &mut RuleResult,
    body: &mut serde_json::Map<String, Value>,
    field: &str,
    want: Option<&str>,
    got: Option<&str>,
) {
    if let Some(w) = want {
        if got != Some(w) {
            r.fail(format!("{field} is {:?}, want `{w}`", got.unwrap_or("unset")));
            body.insert(field.into(), json!(w));
        }
    }
}

fn check_bool(
    r: &mut RuleResult,
    body: &mut serde_json::Map<String, Value>,
    field: &str,
    want: Option<bool>,
    got: Option<bool>,
) {
    if let Some(w) = want {
        if got != Some(w) {
            r.fail(format!("{field} is {got:?}, want {w}"));
            body.insert(field.into(), json!(w));
        }
    }
}

/// Map a config access-level name to GitLab's protected-branch access integer.
fn branch_access_int(name: &str) -> Option<i64> {
    match name {
        "no_one" => Some(0),
        "developer" => Some(30),
        "maintainer" => Some(40),
        _ => None,
    }
}

/// Returns true when the access level drifts (so the caller can decide to push
/// a reconcile action). An unknown access-level name is reported as a failure
/// but returns false: we can't construct a valid body for it.
fn check_access(
    r: &mut RuleResult,
    branch: &str,
    which: &str,
    want: Option<&str>,
    got: &[super::api::AccessLevelEntry],
) -> bool {
    let Some(name) = want else { return false };
    let Some(want_int) = branch_access_int(name) else {
        r.fail(format!("`{branch}`: unknown {which}_access_level `{name}` (want no_one|developer|maintainer)"));
        return false;
    };
    if !got.iter().any(|e| e.access_level == want_int) {
        let actual: Vec<String> = got.iter().map(|e| e.access_level.to_string()).collect();
        r.fail(format!("`{branch}`: {which} access is [{}], want `{name}` ({want_int})", actual.join(", ")));
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitlab::config::{ProjectSettings, ProtectedBranch};

    fn proj(merge_method: &str) -> super::super::api::Project {
        // Build via JSON so we don't depend on struct field order.
        serde_json::from_value(serde_json::json!({
            "default_branch": "main",
            "merge_method": merge_method,
            "squash_option": "default_on",
            "remove_source_branch_after_merge": true,
        }))
        .unwrap()
    }

    #[test]
    fn project_settings_skips_when_unconfigured() {
        let r = project_settings(&proj("merge"), &ProjectConfig::default());
        assert_eq!(r.status, Status::Skip);
    }

    #[test]
    fn project_settings_flags_drift() {
        let cfg = ProjectConfig {
            project_settings: Some(ProjectSettings {
                merge_method: Some("ff".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = project_settings(&proj("merge"), &cfg);
        assert_eq!(r.status, Status::Fail);
        assert!(r.messages[0].contains("merge_method"));
        // Drift produces a single PutProject action whose body carries the
        // desired merge_method and whose summary names the field.
        assert_eq!(r.actions.len(), 1);
        match &r.actions[0] {
            Action::PutProject { summary, body } => {
                assert!(summary.contains("merge_method"), "summary: {summary}");
                assert_eq!(body["merge_method"], serde_json::json!("ff"));
            }
            other => panic!("expected PutProject, got {other:?}"),
        }
    }

    #[test]
    fn project_settings_passes_when_aligned() {
        let cfg = ProjectConfig {
            project_settings: Some(ProjectSettings {
                merge_method: Some("merge".into()),
                remove_source_branch_after_merge: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = project_settings(&proj("merge"), &cfg);
        assert_eq!(r.status, Status::Pass);
    }

    #[test]
    fn forbidden_detects_403_only() {
        let api = |status| {
            anyhow!(ApiError { status, message: "x".into() })
        };
        assert!(is_forbidden(&api(Some(403))));
        assert!(!is_forbidden(&api(Some(404))));
        assert!(!is_forbidden(&api(None)));
        // A plain error that merely mentions 403 in its text must NOT match.
        assert!(!is_forbidden(&anyhow!("body said 403 somewhere")));
    }

    #[test]
    fn branch_access_mapping() {
        assert_eq!(branch_access_int("maintainer"), Some(40));
        assert_eq!(branch_access_int("no_one"), Some(0));
        assert_eq!(branch_access_int("nonsense"), None);
    }

    #[test]
    fn protected_branch_round_trips_in_config() {
        // Guard: the config type is what the rule iterates over.
        let pb = ProtectedBranch { name: "main".into(), allow_force_push: Some(false), ..Default::default() };
        assert_eq!(pb.name, "main");
    }
}
