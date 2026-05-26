//! GitLab audit rules. Each reads live state via the API client, compares it to
//! the `.repo.gitlab.yml` desired state, and reports a [`RuleResult`]. These are
//! audit-only for now: drift is described in `planned`, but `apply` execution is
//! not yet wired (Phase 3). A block the user did not configure reports `Skip`.

use anyhow::Result;

use super::api::Client;
use super::config::ProjectConfig;
use crate::finding::{Severity, Status};

#[derive(Debug)]
pub struct RuleResult {
    pub rule: &'static str,
    pub severity: Severity,
    pub nist: &'static str,
    pub status: Status,
    pub messages: Vec<String>,
    /// Human-readable description of what `apply` would change. Display-only.
    pub planned: Vec<String>,
}

impl RuleResult {
    fn new(rule: &'static str, severity: Severity, nist: &'static str) -> Self {
        Self { rule, severity, nist, status: Status::Pass, messages: Vec::new(), planned: Vec::new() }
    }
    fn fail(&mut self, msg: impl Into<String>) {
        self.status = Status::Fail;
        self.messages.push(msg.into());
    }
    fn plan(&mut self, msg: impl Into<String>) {
        self.planned.push(msg.into());
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
    check_str(&mut r, "merge_method", want.merge_method.as_deref(), proj.merge_method.as_deref());
    check_str(&mut r, "squash_option", want.squash_option.as_deref(), proj.squash_option.as_deref());
    check_bool(&mut r, "remove_source_branch_after_merge", want.remove_source_branch_after_merge, proj.remove_source_branch_after_merge);
    check_bool(&mut r, "only_allow_merge_if_pipeline_succeeds", want.only_allow_merge_if_pipeline_succeeds, proj.only_allow_merge_if_pipeline_succeeds);
    check_bool(&mut r, "only_allow_merge_if_all_discussions_are_resolved", want.only_allow_merge_if_all_discussions_are_resolved, proj.only_allow_merge_if_all_discussions_are_resolved);
    r
}

fn protected_branches(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("protected_branches", Severity::Error, "AC-3, CM-3");
    if cfg.protected_branches.is_empty() {
        return Ok(r.skip("not configured"));
    }
    let actual = client.list_protected_branches(project)?;
    for want in &cfg.protected_branches {
        let Some(got) = actual.iter().find(|b| b.name == want.name) else {
            r.fail(format!("branch `{}` is not protected", want.name));
            r.plan(format!("protect branch `{}`", want.name));
            continue;
        };
        if let Some(w) = want.allow_force_push {
            if got.allow_force_push != Some(w) {
                r.fail(format!("`{}`: allow_force_push is {:?}, want {w}", want.name, got.allow_force_push));
                r.plan(format!("`{}`: set allow_force_push={w}", want.name));
            }
        }
        if let Some(w) = want.code_owner_approval_required {
            if got.code_owner_approval_required != Some(w) {
                r.fail(format!("`{}`: code_owner_approval_required is {:?}, want {w}", want.name, got.code_owner_approval_required));
                r.plan(format!("`{}`: set code_owner_approval_required={w}", want.name));
            }
        }
        check_access(&mut r, &want.name, "push", want.push_access_level.as_deref(), &got.push_access_levels);
        check_access(&mut r, &want.name, "merge", want.merge_access_level.as_deref(), &got.merge_access_levels);
    }
    Ok(r)
}

fn approval_rules(client: &Client, project: &str, cfg: &ProjectConfig) -> Result<RuleResult> {
    let mut r = RuleResult::new("approval_rules", Severity::Error, "AC-3, CM-3");
    if cfg.approval_rules.is_empty() {
        return Ok(r.skip("not configured"));
    }
    let actual = client.list_approval_rules(project)?;
    for want in &cfg.approval_rules {
        let Some(got) = actual.iter().find(|a| a.name == want.name) else {
            r.fail(format!("approval rule `{}` is missing", want.name));
            r.plan(format!("create approval rule `{}`", want.name));
            continue;
        };
        if let Some(w) = want.approvals_required {
            if got.approvals_required != Some(w) {
                r.fail(format!("`{}`: approvals_required is {:?}, want {w}", want.name, got.approvals_required));
                r.plan(format!("`{}`: set approvals_required={w}", want.name));
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
    let actual = client.get_approvals_config(project)?;
    check_bool(&mut r, "reset_approvals_on_push", want.reset_approvals_on_push, actual.reset_approvals_on_push);
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
        Err(e) if e.to_string().contains(" 403") => {
            return Ok(r.skip("push rules require GitLab Premium/Ultimate"));
        }
        Err(e) => return Err(e),
    };
    if let Some(w) = want.reject_unsigned_commits {
        let got = actual.as_ref().and_then(|p| p.reject_unsigned_commits);
        if got != Some(w) {
            r.fail(format!("reject_unsigned_commits is {got:?}, want {w}"));
            r.plan(format!("set push rule reject_unsigned_commits={w}"));
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
    let mut want_template = |enabled: Option<bool>, needle: &str, label: &str| {
        if enabled == Some(true) && !lower.contains(&needle.to_lowercase()) {
            r.fail(format!("{label} not included in .gitlab-ci.yml"));
            r.plan(format!("include the {label} template"));
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

// --- comparison helpers --------------------------------------------------

fn check_str(r: &mut RuleResult, field: &str, want: Option<&str>, got: Option<&str>) {
    if let Some(w) = want {
        if got != Some(w) {
            r.fail(format!("{field} is {:?}, want `{w}`", got.unwrap_or("unset")));
            r.plan(format!("set {field}=`{w}`"));
        }
    }
}

fn check_bool(r: &mut RuleResult, field: &str, want: Option<bool>, got: Option<bool>) {
    if let Some(w) = want {
        if got != Some(w) {
            r.fail(format!("{field} is {got:?}, want {w}"));
            r.plan(format!("set {field}={w}"));
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

fn check_access(
    r: &mut RuleResult,
    branch: &str,
    which: &str,
    want: Option<&str>,
    got: &[super::api::AccessLevelEntry],
) {
    let Some(name) = want else { return };
    let Some(want_int) = branch_access_int(name) else {
        r.fail(format!("`{branch}`: unknown {which}_access_level `{name}` (want no_one|developer|maintainer)"));
        return;
    };
    if !got.iter().any(|e| e.access_level == want_int) {
        let actual: Vec<String> = got.iter().map(|e| e.access_level.to_string()).collect();
        r.fail(format!("`{branch}`: {which} access is [{}], want `{name}` ({want_int})", actual.join(", ")));
        r.plan(format!("`{branch}`: set {which}_access_level=`{name}`"));
    }
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
        assert!(r.planned.iter().any(|p| p.contains("set merge_method=`ff`")));
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
