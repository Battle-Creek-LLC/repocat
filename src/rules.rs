use crate::api::{BranchProtection as ActualBp, Client, Repo as ActualRepo, RepoTeam};
use crate::config::{BranchProtection as DesiredBp, RepoConfig};
use anyhow::Result;
use serde_json::{json, Value};
use std::fmt;

#[derive(Debug)]
pub enum Action {
    PatchRepo { summary: String, body: Value },
    PutBranchProtection { summary: String, branch: String, body: Value },
    SimplePut { summary: String, path: String },
    SimplePost { summary: String, path: String },
    PutJson { summary: String, path: String, body: Value },
}

impl Action {
    pub fn summary(&self) -> &str {
        match self {
            Action::PatchRepo { summary, .. } => summary,
            Action::PutBranchProtection { summary, .. } => summary,
            Action::SimplePut { summary, .. } => summary,
            Action::SimplePost { summary, .. } => summary,
            Action::PutJson { summary, .. } => summary,
        }
    }

    pub fn execute(&self, client: &Client, org: &str, repo: &str) -> Result<()> {
        match self {
            Action::PatchRepo { body, .. } => {
                client.patch_repo(org, repo, body)?;
            }
            Action::PutBranchProtection { branch, body, .. } => {
                client.put_branch_protection(org, repo, branch, body)?;
            }
            Action::SimplePut { path, .. } => {
                client.put_no_body(path)?;
            }
            Action::SimplePost { path, .. } => {
                client.post_no_body(path)?;
            }
            Action::PutJson { path, body, .. } => {
                client.put_json(path, body)?;
            }
        }
        Ok(())
    }
}

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

#[derive(Debug)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub nist: &'static str,
    pub status: Status,
    pub messages: Vec<String>,
    pub actions: Vec<Action>,
}

impl Finding {
    fn new(rule: &'static str, severity: Severity, nist: &'static str) -> Self {
        Self { rule, severity, nist, status: Status::Pass, messages: Vec::new(), actions: Vec::new() }
    }
    fn fail(&mut self, msg: impl Into<String>) {
        self.status = Status::Fail;
        self.messages.push(msg.into());
    }
    fn skip(mut self, msg: impl Into<String>) -> Self {
        self.status = Status::Skip;
        self.messages.push(msg.into());
        self
    }
}

pub fn run_all(client: &Client, org: &str, name: &str, cfg: &RepoConfig) -> Result<Vec<Finding>> {
    let actual_repo = client.get_repo(org, name)?;
    let mut findings = Vec::new();

    findings.push(branch_protection(client, org, name, cfg)?);
    findings.push(merge_settings(cfg, &actual_repo));
    findings.push(secret_scanning(cfg, &actual_repo));
    findings.push(required_files(client, org, name, cfg)?);
    findings.push(codeowners(client, org, name, cfg)?);
    findings.push(dependabot_security(client, org, name, cfg)?);
    findings.push(workflow_permissions(client, org, name, cfg)?);
    findings.push(workflow_yaml(client, org, name, cfg)?);
    findings.push(signed_commits(client, org, name, cfg)?);
    findings.push(teams_only_access(client, org, name, cfg)?);

    Ok(findings)
}

fn teams_only_access(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("teams_only_access", Severity::Warning, "AC-2, AC-6");
    if cfg.teams.is_empty() {
        return Ok(f.skip("no teams block configured"));
    }

    let direct: Vec<_> = client
        .list_direct_collaborators(org, repo)?
        .into_iter()
        .map(|c| c.login)
        .collect();
    if !direct.is_empty() {
        f.fail(format!(
            "direct collaborators (should be on a team): {}",
            direct.join(", ")
        ));
    }

    let attached = client.list_repo_teams(org, repo)?;
    for want in &cfg.teams {
        match find_team(&attached, &want.name) {
            None => f.fail(format!("team `{}` not attached to repo", want.name)),
            Some(actual) if actual.permission != want.permission => f.fail(format!(
                "team `{}` permission: want {}, got {}",
                want.name, want.permission, actual.permission
            )),
            Some(_) => {}
        }
    }

    if f.status == Status::Fail {
        f.messages.push("no automatic remediation — adjust access via org settings".into());
    }
    Ok(f)
}

fn find_team<'a>(attached: &'a [RepoTeam], name: &str) -> Option<&'a RepoTeam> {
    attached.iter().find(|t| t.name == name || t.slug == name)
}

fn signed_commits(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("signed_commits", Severity::Warning, "SI-7");
    let Some(want) = cfg.branch_protection.as_ref() else {
        return Ok(f.skip("no branch_protection block configured"));
    };
    if want.signed_commits != Some(true) {
        return Ok(f.skip("signed_commits not required"));
    }
    if !client.required_signatures_enabled(org, repo, &want.branch)? {
        f.fail(format!("signed commits not enforced on `{}`", want.branch));
        f.actions.push(Action::SimplePost {
            summary: format!("require signed commits on `{}`", want.branch),
            path: format!("/repos/{org}/{repo}/branches/{}/protection/required_signatures", want.branch),
        });
    }
    Ok(f)
}

fn workflow_yaml(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("workflow_yaml", Severity::Error, "AC-6, SR-3");
    let Some(want) = cfg.actions.as_ref() else {
        return Ok(f.skip("no actions block configured"));
    };
    let pin = want.pin_actions == Some(true);
    let perms = want.require_workflow_permissions == Some(true);
    if !pin && !perms {
        return Ok(f.skip("no workflow yaml checks configured"));
    }

    let entries = client.list_directory(org, repo, ".github/workflows")?;
    let workflow_files: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == "file" && (e.name.ends_with(".yml") || e.name.ends_with(".yaml")))
        .collect();
    if workflow_files.is_empty() {
        return Ok(f.skip("no .github/workflows/*.yml files"));
    }

    for entry in workflow_files {
        let Some(content) = client.get_file_content(org, repo, &entry.path)? else { continue };
        let parsed: serde_yml::Value = match serde_yml::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                f.fail(format!("{}: yaml parse error: {e}", entry.name));
                continue;
            }
        };
        if pin {
            check_action_pins(&parsed, &entry.name, &mut f);
        }
        if perms {
            check_workflow_permissions_block(&parsed, &entry.name, &mut f);
        }
    }

    if f.status == Status::Fail {
        f.messages.push("no automatic remediation — fix workflow files via PR".into());
    }
    Ok(f)
}

fn check_action_pins(yml: &serde_yml::Value, file: &str, f: &mut Finding) {
    let Some(jobs) = yml.get("jobs").and_then(|j| j.as_mapping()) else { return };
    for (job_name, job) in jobs {
        let job_label = job_name.as_str().unwrap_or("?");
        if let Some(uses) = job.get("uses").and_then(|u| u.as_str()) {
            check_one_use(uses, file, job_label, None, f);
        }
        let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) else { continue };
        for (i, step) in steps.iter().enumerate() {
            if let Some(uses) = step.get("uses").and_then(|u| u.as_str()) {
                check_one_use(uses, file, job_label, Some(i), f);
            }
        }
    }
}

fn check_one_use(uses: &str, file: &str, job: &str, step: Option<usize>, f: &mut Finding) {
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return;
    }
    let Some((_, reference)) = uses.rsplit_once('@') else {
        f.fail(format!("{file}:{job}: `{uses}` has no version reference"));
        return;
    };
    let is_sha = reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit());
    if !is_sha {
        let loc = match step {
            Some(i) => format!("{file}:{job}[{i}]"),
            None => format!("{file}:{job}"),
        };
        f.fail(format!("{loc}: unpinned `{uses}` (use SHA, not `{reference}`)"));
    }
}

fn check_workflow_permissions_block(yml: &serde_yml::Value, file: &str, f: &mut Finding) {
    if yml.get("permissions").is_some() {
        return;
    }
    let Some(jobs) = yml.get("jobs").and_then(|j| j.as_mapping()) else { return };
    for (job_name, job) in jobs {
        if job.get("permissions").is_none() {
            let label = job_name.as_str().unwrap_or("?");
            f.fail(format!("{file}:{label}: no permissions block (top-level or job-level)"));
        }
    }
}

fn workflow_permissions(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("workflow_permissions", Severity::Error, "AC-6, SR-3");
    let Some(want) = cfg.actions.as_ref() else {
        return Ok(f.skip("no actions block configured"));
    };
    if want.default_workflow_permissions.is_none() && want.can_approve_pull_request_reviews.is_none() {
        return Ok(f.skip("no actions fields configured"));
    }

    let actual = client.get_workflow_permissions(org, repo)?;
    let mut body = serde_json::Map::new();

    if let Some(want_perm) = want.default_workflow_permissions.as_deref() {
        if want_perm != actual.default_workflow_permissions {
            f.fail(format!(
                "default_workflow_permissions: want {want_perm}, got {}",
                actual.default_workflow_permissions
            ));
            body.insert("default_workflow_permissions".into(), json!(want_perm));
        }
    }
    if let Some(want_approve) = want.can_approve_pull_request_reviews {
        if want_approve != actual.can_approve_pull_request_reviews {
            f.fail(format!(
                "can_approve_pull_request_reviews: want {want_approve}, got {}",
                actual.can_approve_pull_request_reviews
            ));
            body.insert("can_approve_pull_request_reviews".into(), json!(want_approve));
        }
    }

    if !body.is_empty() {
        f.actions.push(Action::PutJson {
            summary: "update workflow permissions".into(),
            path: format!("/repos/{org}/{repo}/actions/permissions/workflow"),
            body: Value::Object(body),
        });
    }
    Ok(f)
}

fn dependabot_security(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("dependabot_security", Severity::Error, "SI-2, SR-3");
    let Some(want) = cfg.security.as_ref() else {
        return Ok(f.skip("no security block configured"));
    };
    if want.vulnerability_alerts.is_none()
        && want.dependabot_security_updates.is_none()
        && want.dependabot_config != Some(true)
    {
        return Ok(f.skip("no dependabot fields configured"));
    }

    if want.vulnerability_alerts == Some(true) {
        if !client.vulnerability_alerts_enabled(org, repo)? {
            f.fail("vulnerability_alerts not enabled");
            f.actions.push(Action::SimplePut {
                summary: "enable vulnerability alerts".into(),
                path: format!("/repos/{org}/{repo}/vulnerability-alerts"),
            });
        }
    }

    if want.dependabot_security_updates == Some(true) {
        if !client.automated_security_fixes_enabled(org, repo)? {
            f.fail("dependabot_security_updates not enabled");
            f.actions.push(Action::SimplePut {
                summary: "enable Dependabot security updates".into(),
                path: format!("/repos/{org}/{repo}/automated-security-fixes"),
            });
        }
    }

    if want.dependabot_config == Some(true)
        && !client.path_exists(org, repo, ".github/dependabot.yml")?
    {
        f.fail(".github/dependabot.yml is missing");
        f.messages.push("no automatic remediation — add config via PR".into());
    }

    Ok(f)
}

fn codeowners(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("codeowners", Severity::Error, "CM-3, AC-5");
    if cfg.codeowners != Some(true) {
        return Ok(f.skip("codeowners not required"));
    }
    let path = ".github/CODEOWNERS";
    let Some(content) = client.get_file_content(org, repo, path)? else {
        f.fail(format!("{path} is missing"));
        f.messages.push("no automatic remediation — add file via PR".into());
        return Ok(f);
    };
    let has_rule = content
        .lines()
        .map(str::trim)
        .any(|l| !l.is_empty() && !l.starts_with('#'));
    if !has_rule {
        f.fail(format!("{path} has no ownership rules (only blank/comment lines)"));
        f.messages.push("no automatic remediation — add owners via PR".into());
    }
    Ok(f)
}

fn required_files(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("required_files", Severity::Warning, "CM-2");
    let want = &cfg.required_files;
    if want.is_empty() {
        return Ok(f.skip("no required_files configured"));
    }
    let mut missing = Vec::new();
    for path in want {
        if !client.path_exists(org, repo, path)? {
            missing.push(path.clone());
        }
    }
    if !missing.is_empty() {
        f.fail(format!("missing: {}", missing.join(", ")));
        f.messages.push("no automatic remediation — add files via PR".into());
    }
    Ok(f)
}

fn branch_protection(client: &Client, org: &str, repo: &str, cfg: &RepoConfig) -> Result<Finding> {
    let mut f = Finding::new("branch_protection", Severity::Error, "AC-3, CM-3");
    let Some(want) = cfg.branch_protection.as_ref() else {
        return Ok(f.skip("no branch_protection block configured"));
    };
    let actual: Option<ActualBp> = client.get_branch_protection(org, repo, &want.branch)?;
    let Some(actual) = actual else {
        f.fail(format!("branch `{}` has no protection rule", want.branch));
        f.actions.push(Action::PutBranchProtection {
            summary: format!("create branch protection on `{}`", want.branch),
            branch: want.branch.clone(),
            body: branch_protection_body(want),
        });
        return Ok(f);
    };

    let actual_reviews = actual
        .required_pull_request_reviews
        .as_ref()
        .and_then(|r| r.required_approving_review_count)
        .unwrap_or(0);
    if actual_reviews != want.required_reviews {
        f.fail(format!(
            "required_reviews: want {}, got {actual_reviews}",
            want.required_reviews
        ));
    }

    if want.required_reviews > 0 {
        let actual_dismiss = actual
            .required_pull_request_reviews
            .as_ref()
            .and_then(|r| r.dismiss_stale_reviews)
            .unwrap_or(false);
        if want.dismiss_stale_reviews && !actual_dismiss {
            f.fail("dismiss_stale_reviews not enabled");
        }
        let actual_codeowners = actual
            .required_pull_request_reviews
            .as_ref()
            .and_then(|r| r.require_code_owner_reviews)
            .unwrap_or(false);
        if want.require_codeowners && !actual_codeowners {
            f.fail("require_codeowners not enabled");
        }
    }

    let actual_linear = actual.required_linear_history.as_ref().is_some_and(|e| e.enabled);
    if want.require_linear_history && !actual_linear {
        f.fail("require_linear_history not enabled");
    }

    let actual_convo = actual.required_conversation_resolution.as_ref().is_some_and(|e| e.enabled);
    if want.require_conversation_resolution && !actual_convo {
        f.fail("require_conversation_resolution not enabled");
    }

    let actual_force = actual.allow_force_pushes.as_ref().is_some_and(|e| e.enabled);
    if want.block_force_push && actual_force {
        f.fail("force pushes are allowed (want blocked)");
    }

    let actual_delete = actual.allow_deletions.as_ref().is_some_and(|e| e.enabled);
    if want.block_deletions && actual_delete {
        f.fail("branch deletions are allowed (want blocked)");
    }

    let actual_checks: Vec<String> = actual
        .required_status_checks
        .map(|c| c.contexts)
        .unwrap_or_default();
    let missing: Vec<&String> = want
        .required_status_checks
        .iter()
        .filter(|c| !actual_checks.contains(c))
        .collect();
    if !missing.is_empty() {
        f.fail(format!(
            "missing required status checks: {}",
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    if f.status == Status::Fail {
        f.actions.push(Action::PutBranchProtection {
            summary: format!("reconcile branch protection on `{}`", want.branch),
            branch: want.branch.clone(),
            body: branch_protection_body(want),
        });
    }

    Ok(f)
}

fn branch_protection_body(want: &DesiredBp) -> Value {
    let pr_reviews = if want.required_reviews > 0 {
        json!({
            "required_approving_review_count": want.required_reviews,
            "dismiss_stale_reviews": want.dismiss_stale_reviews,
            "require_code_owner_reviews": want.require_codeowners,
        })
    } else {
        Value::Null
    };
    let status_checks = if want.required_status_checks.is_empty() {
        Value::Null
    } else {
        json!({ "strict": false, "contexts": want.required_status_checks })
    };
    json!({
        "required_status_checks": status_checks,
        "enforce_admins": Value::Null,
        "required_pull_request_reviews": pr_reviews,
        "restrictions": Value::Null,
        "required_linear_history": want.require_linear_history,
        "allow_force_pushes": !want.block_force_push,
        "allow_deletions": !want.block_deletions,
        "required_conversation_resolution": want.require_conversation_resolution,
    })
}

fn merge_settings(cfg: &RepoConfig, actual: &ActualRepo) -> Finding {
    let mut f = Finding::new("merge_settings", Severity::Warning, "CM-3");
    let Some(want) = cfg.merge.as_ref() else {
        return f.skip("no merge block configured");
    };

    let mut body = serde_json::Map::new();
    check_and_patch(&mut f, &mut body, "allow_squash_merge", "allow_squash",
        want.allow_squash, actual.allow_squash_merge);
    check_and_patch(&mut f, &mut body, "allow_merge_commit", "allow_merge_commit",
        want.allow_merge_commit, actual.allow_merge_commit);
    check_and_patch(&mut f, &mut body, "allow_rebase_merge", "allow_rebase",
        want.allow_rebase, actual.allow_rebase_merge);
    check_and_patch(&mut f, &mut body, "delete_branch_on_merge", "delete_branch_on_merge",
        want.delete_branch_on_merge, actual.delete_branch_on_merge);

    if !body.is_empty() {
        f.actions.push(Action::PatchRepo {
            summary: "update merge settings".to_string(),
            body: Value::Object(body),
        });
    }
    f
}

fn secret_scanning(cfg: &RepoConfig, actual: &ActualRepo) -> Finding {
    let mut f = Finding::new("secret_scanning", Severity::Error, "SI-2, SI-4");
    let Some(want) = cfg.security.as_ref() else {
        return f.skip("no security block configured");
    };

    let saa = actual.security_and_analysis.as_ref();
    let scanning_on = saa.and_then(|s| s.secret_scanning.as_ref()).is_some_and(|t| t.is_enabled());
    let pushp_on = saa
        .and_then(|s| s.secret_scanning_push_protection.as_ref())
        .is_some_and(|t| t.is_enabled());

    let mut saa_body = serde_json::Map::new();
    if want.secret_scanning == Some(true) && !scanning_on {
        f.fail("secret_scanning not enabled");
        saa_body.insert("secret_scanning".into(), json!({ "status": "enabled" }));
    }
    if want.push_protection == Some(true) && !pushp_on {
        f.fail("push_protection not enabled");
        saa_body.insert("secret_scanning_push_protection".into(), json!({ "status": "enabled" }));
    }
    if !saa_body.is_empty() {
        f.actions.push(Action::PatchRepo {
            summary: "enable secret scanning".to_string(),
            body: json!({ "security_and_analysis": Value::Object(saa_body) }),
        });
    }
    f
}

fn check_and_patch(
    f: &mut Finding,
    body: &mut serde_json::Map<String, Value>,
    api_key: &str,
    display_key: &str,
    want: Option<bool>,
    actual: Option<bool>,
) {
    let Some(want) = want else { return };
    let actual = actual.unwrap_or(false);
    if want != actual {
        f.fail(format!("{display_key}: want {want}, got {actual}"));
        body.insert(api_key.into(), Value::Bool(want));
    }
}
