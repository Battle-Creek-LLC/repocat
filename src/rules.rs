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
    ScaffoldDependencyReviewWorkflow { summary: String },
}

impl Action {
    pub fn summary(&self) -> &str {
        match self {
            Action::PatchRepo { summary, .. } => summary,
            Action::PutBranchProtection { summary, .. } => summary,
            Action::SimplePut { summary, .. } => summary,
            Action::SimplePost { summary, .. } => summary,
            Action::PutJson { summary, .. } => summary,
            Action::ScaffoldDependencyReviewWorkflow { summary } => summary,
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
            Action::ScaffoldDependencyReviewWorkflow { .. } => {
                scaffold_dependency_review_workflow(client, org, repo)?;
            }
        }
        Ok(())
    }
}

fn scaffold_dependency_review_workflow(client: &Client, org: &str, repo: &str) -> Result<()> {
    let path = ".github/workflows/dependency-review.yml";
    if client.path_exists(org, repo, path)? {
        return Err(anyhow::anyhow!(
            "{path} already exists; refusing to overwrite — \
             remove or update it manually if it doesn't satisfy the rule"
        ));
    }
    let checkout_sha = client.latest_action_sha("actions", "checkout")?;
    let dep_review_sha = client.latest_action_sha("actions", "dependency-review-action")?;
    let content = format!(
        "name: Dependency Review\n\
         \n\
         on:\n\
         \x20\x20pull_request:\n\
         \n\
         permissions:\n\
         \x20\x20contents: read\n\
         \n\
         jobs:\n\
         \x20\x20dependency-review:\n\
         \x20\x20\x20\x20runs-on: ubuntu-latest\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- uses: actions/checkout@{checkout_sha}\n\
         \x20\x20\x20\x20\x20\x20- uses: actions/dependency-review-action@{dep_review_sha}\n"
    );
    client
        .create_file(
            org,
            repo,
            path,
            &content,
            "Add dependency-review workflow (scaffolded by repocat)",
        )
        .map_err(|e| {
            // GitHub returns 404 (not 403) when an OAuth token lacks the `workflow`
            // scope but tries to write under .github/workflows/. Translate so users
            // know what to do instead of chasing a misleading 404.
            if e.to_string().contains("404") {
                anyhow::anyhow!(
                    "writing to .github/workflows/ requires the `workflow` OAuth \
                     scope, which the gh CLI does not request by default. Run \
                     `gh auth refresh -s workflow` and retry. Underlying error: {e}"
                )
            } else {
                e
            }
        })
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
    findings.push(dependabot_security(client, org, name, cfg, &actual_repo)?);
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
    let pin = want.pin_actions_to_sha == Some(true);
    let perms = want.require_workflow_permissions == Some(true);
    let dep_review = want.require_dependency_review_action == Some(true);
    if !pin && !perms && !dep_review {
        return Ok(f.skip("no workflow yaml checks configured"));
    }

    let entries = client.list_directory(org, repo, ".github/workflows")?;
    let workflow_files: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == "file" && (e.name.ends_with(".yml") || e.name.ends_with(".yaml")))
        .collect();
    if workflow_files.is_empty() {
        if dep_review {
            f.fail("require_dependency_review_action set, but no workflows present");
            f.actions.push(Action::ScaffoldDependencyReviewWorkflow {
                summary: "scaffold .github/workflows/dependency-review.yml".into(),
            });
            return Ok(f);
        }
        return Ok(f.skip("no .github/workflows/*.yml files"));
    }

    let mut has_dep_review_action = false;
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
        if dep_review && !has_dep_review_action {
            has_dep_review_action = uses_dependency_review_action(&parsed);
        }
    }

    if dep_review && !has_dep_review_action {
        f.fail("no workflow uses actions/dependency-review-action");
        f.actions.push(Action::ScaffoldDependencyReviewWorkflow {
            summary: "scaffold .github/workflows/dependency-review.yml".into(),
        });
    }

    if f.status == Status::Fail && f.actions.is_empty() {
        f.messages.push("no automatic remediation — fix workflow files via PR".into());
    }
    Ok(f)
}

fn uses_dependency_review_action(yml: &serde_yml::Value) -> bool {
    let Some(jobs) = yml.get("jobs").and_then(|j| j.as_mapping()) else { return false };
    for (_, job) in jobs {
        let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) else { continue };
        for step in steps {
            let Some(uses) = step.get("uses").and_then(|u| u.as_str()) else { continue };
            let key = uses.split('@').next().unwrap_or(uses);
            if key == "actions/dependency-review-action"
                || key.starts_with("actions/dependency-review-action/")
            {
                return true;
            }
        }
    }
    false
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

fn dependabot_security(
    client: &Client,
    org: &str,
    repo: &str,
    cfg: &RepoConfig,
    actual_repo: &ActualRepo,
) -> Result<Finding> {
    let mut f = Finding::new("dependabot_security", Severity::Error, "SI-2, SR-3");
    let Some(want) = cfg.security.as_ref() else {
        return Ok(f.skip("no security block configured"));
    };
    if want.vulnerability_alerts.is_none()
        && want.dependabot_security_updates.is_none()
        && want.dependabot_config != Some(true)
        && want.dependency_graph != Some(true)
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

    if want.dependency_graph == Some(true) {
        let echoed = actual_repo
            .security_and_analysis
            .as_ref()
            .and_then(|s| s.dependency_graph.as_ref());
        // Public repos have the dependency graph implicitly enabled but the
        // API omits the field from the response; treat absence as enabled.
        let on = match echoed {
            Some(t) => t.is_enabled(),
            None => !actual_repo.private,
        };
        if !on {
            f.fail("dependency_graph not enabled (private repo without GitHub Advanced Security?)");
            f.actions.push(Action::PatchRepo {
                summary: "enable dependency graph".into(),
                body: json!({
                    "security_and_analysis": {
                        "dependency_graph": { "status": "enabled" }
                    }
                }),
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
    let actual_raw: Option<Value> = client.get_branch_protection(org, repo, &want.branch)?;
    let Some(actual_raw) = actual_raw else {
        f.fail(format!("branch `{}` has no protection rule", want.branch));
        f.actions.push(Action::PutBranchProtection {
            summary: format!("create branch protection on `{}`", want.branch),
            branch: want.branch.clone(),
            body: branch_protection_body(want, None),
        });
        return Ok(f);
    };
    let actual: ActualBp = serde_json::from_value(actual_raw.clone())?;

    let actual_reviews = actual
        .required_pull_request_reviews
        .as_ref()
        .and_then(|r| r.required_approving_review_count)
        .unwrap_or(0);
    if let Some(want_reviews) = want.required_reviews {
        if actual_reviews != want_reviews {
            f.fail(format!("required_reviews: want {want_reviews}, got {actual_reviews}"));
        }
    }

    // dismiss_stale_reviews and require_codeowners are sub-fields of the
    // required_pull_request_reviews object. If that object doesn't exist on
    // GitHub (because no reviews are required), there is nothing to enforce —
    // skip the sub-checks rather than failing with a misleading message.
    if actual.required_pull_request_reviews.is_some() {
        if let Some(true) = want.dismiss_stale_reviews {
            let actual_dismiss = actual
                .required_pull_request_reviews
                .as_ref()
                .and_then(|r| r.dismiss_stale_reviews)
                .unwrap_or(false);
            if !actual_dismiss {
                f.fail("dismiss_stale_reviews not enabled");
            }
        }
        if let Some(true) = want.require_codeowners {
            let actual_codeowners = actual
                .required_pull_request_reviews
                .as_ref()
                .and_then(|r| r.require_code_owner_reviews)
                .unwrap_or(false);
            if !actual_codeowners {
                f.fail("require_codeowners not enabled");
            }
        }
    }

    if let Some(true) = want.require_linear_history {
        let actual_linear = actual.required_linear_history.as_ref().is_some_and(|e| e.enabled);
        if !actual_linear {
            f.fail("require_linear_history not enabled");
        }
    }

    if let Some(true) = want.require_conversation_resolution {
        let actual_convo = actual.required_conversation_resolution.as_ref().is_some_and(|e| e.enabled);
        if !actual_convo {
            f.fail("require_conversation_resolution not enabled");
        }
    }

    if let Some(true) = want.block_force_push {
        let actual_force = actual.allow_force_pushes.as_ref().is_some_and(|e| e.enabled);
        if actual_force {
            f.fail("force pushes are allowed (want blocked)");
        }
    }

    if let Some(true) = want.block_deletions {
        let actual_delete = actual.allow_deletions.as_ref().is_some_and(|e| e.enabled);
        if actual_delete {
            f.fail("branch deletions are allowed (want blocked)");
        }
    }

    if let Some(want_admins) = want.enforce_admins {
        let actual_admins = actual_raw
            .get("enforce_admins")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if want_admins != actual_admins {
            f.fail(format!("enforce_admins: want {want_admins}, got {actual_admins}"));
        }
    }

    if !want.required_status_checks.is_empty() {
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
    }

    if f.status == Status::Fail {
        f.actions.push(Action::PutBranchProtection {
            summary: format!("reconcile branch protection on `{}`", want.branch),
            branch: want.branch.clone(),
            body: branch_protection_body(want, Some(&actual_raw)),
        });
    }

    Ok(f)
}

// GitHub's PUT /branches/{branch}/protection replaces the whole object — any
// field omitted (or null) is reset. To avoid clobbering settings the user did
// not declare in .repo.yml, start from the GET response and overlay only the
// fields the user explicitly set. When no protection rule exists yet, build a
// minimal body with conservative defaults.
fn branch_protection_body(want: &DesiredBp, actual: Option<&Value>) -> Value {
    let mut body = match actual {
        Some(a) => actual_to_put_body(a),
        None => json!({
            "required_status_checks": Value::Null,
            "enforce_admins": Value::Null,
            "required_pull_request_reviews": Value::Null,
            "restrictions": Value::Null,
            "required_linear_history": false,
            "allow_force_pushes": false,
            "allow_deletions": false,
            "required_conversation_resolution": false,
        }),
    };
    let map = body.as_object_mut().expect("body is an object");

    if let Some(v) = want.require_linear_history {
        map.insert("required_linear_history".into(), Value::Bool(v));
    }
    if let Some(v) = want.block_force_push {
        map.insert("allow_force_pushes".into(), Value::Bool(!v));
    }
    if let Some(v) = want.block_deletions {
        map.insert("allow_deletions".into(), Value::Bool(!v));
    }
    if let Some(v) = want.require_conversation_resolution {
        map.insert("required_conversation_resolution".into(), Value::Bool(v));
    }
    if let Some(v) = want.enforce_admins {
        map.insert("enforce_admins".into(), Value::Bool(v));
    }

    overlay_pr_reviews(map, want);
    overlay_status_checks(map, want);

    body
}

// The GET response for branch protection is shaped differently than the PUT
// body. Convert the relevant fields so we have a starting point we can overlay.
// Anything we do not explicitly handle is dropped — but only after we have
// preserved the fields GitHub's PUT cares about.
fn actual_to_put_body(actual: &Value) -> Value {
    let get_enabled = |key: &str| -> bool {
        actual.get(key)
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    let pr_reviews = actual.get("required_pull_request_reviews").cloned()
        .map(pr_reviews_to_put_body)
        .unwrap_or(Value::Null);
    let status_checks = actual.get("required_status_checks").cloned()
        .map(strip_status_checks_url)
        .unwrap_or(Value::Null);
    let restrictions = actual.get("restrictions").cloned()
        .map(strip_restrictions_for_put)
        .unwrap_or(Value::Null);

    json!({
        "required_status_checks": status_checks,
        "enforce_admins": get_enabled("enforce_admins"),
        "required_pull_request_reviews": pr_reviews,
        "restrictions": restrictions,
        "required_linear_history": get_enabled("required_linear_history"),
        "allow_force_pushes": get_enabled("allow_force_pushes"),
        "allow_deletions": get_enabled("allow_deletions"),
        "required_conversation_resolution": get_enabled("required_conversation_resolution"),
        // Preserve PUT-accepted toggles that the DSL does not model. Without
        // these, any apply on a repo that has them on would silently turn them
        // off. required_signatures is managed by a separate endpoint
        // (PUT/DELETE /protection/required_signatures) and is intentionally
        // omitted from this body.
        "lock_branch":         get_enabled("lock_branch"),
        "allow_fork_syncing":  get_enabled("allow_fork_syncing"),
        "block_creations":     get_enabled("block_creations"),
    })
}

// PUT body for required_pull_request_reviews drops the URL and shape-transforms
// dismissal_restrictions and bypass_pull_request_allowances — both are nested
// actor sets whose GET shape (objects with login/slug/id/url) is rejected by
// the PUT endpoint, which expects bare-string arrays.
fn pr_reviews_to_put_body(mut v: Value) -> Value {
    let Some(obj) = v.as_object_mut() else { return v };
    obj.remove("url");
    if let Some(dr) = obj.get("dismissal_restrictions").cloned() {
        obj.insert("dismissal_restrictions".into(), to_put_actor_set(&dr, &["users", "teams"]));
    }
    if let Some(bp) = obj.get("bypass_pull_request_allowances").cloned() {
        obj.insert(
            "bypass_pull_request_allowances".into(),
            to_put_actor_set(&bp, &["users", "teams", "apps"]),
        );
    }
    v
}

fn strip_status_checks_url(mut v: Value) -> Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("url");
        obj.remove("contexts_url");
    }
    v
}

// Convert a GET-shape actor set ({ users: [{login, ...}], teams: [{slug, ...}], ... })
// to the PUT-shape ({ users: ["login"], teams: ["slug"], ... }). `kinds` lets
// callers opt out of fields the endpoint doesn't accept (dismissal_restrictions
// has no `apps`, restrictions and bypass_pull_request_allowances do).
fn to_put_actor_set(v: &Value, kinds: &[&str]) -> Value {
    let Some(obj) = v.as_object() else { return Value::Null };
    let mut out = serde_json::Map::new();
    for kind in kinds {
        let name_field = if *kind == "users" { "login" } else { "slug" };
        let names: Vec<Value> = obj
            .get(*kind)
            .and_then(|v| v.as_array())
            .map(|a| a.iter()
                .filter_map(|e| e.get(name_field).and_then(|s| s.as_str()))
                .map(|s| Value::String(s.into()))
                .collect())
            .unwrap_or_default();
        out.insert((*kind).into(), Value::Array(names));
    }
    Value::Object(out)
}

fn strip_restrictions_for_put(v: Value) -> Value {
    if !v.is_object() {
        return Value::Null;
    }
    to_put_actor_set(&v, &["users", "teams", "apps"])
}

fn overlay_pr_reviews(map: &mut serde_json::Map<String, Value>, want: &DesiredBp) {
    let touches_pr = want.required_reviews.is_some()
        || want.dismiss_stale_reviews.is_some()
        || want.require_codeowners.is_some();
    if !touches_pr {
        return;
    }
    let mut pr = map.get("required_pull_request_reviews")
        .cloned()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    let pr_obj = pr.as_object_mut().expect("pr is an object");
    if let Some(n) = want.required_reviews {
        pr_obj.insert("required_approving_review_count".into(), json!(n));
    }
    if let Some(b) = want.dismiss_stale_reviews {
        pr_obj.insert("dismiss_stale_reviews".into(), Value::Bool(b));
    }
    if let Some(b) = want.require_codeowners {
        pr_obj.insert("require_code_owner_reviews".into(), Value::Bool(b));
    }
    // GitHub rejects a non-null required_pull_request_reviews block that lacks
    // required_approving_review_count. If the user declared sub-fields without
    // a count and the actual state had no block to inherit one from, drop the
    // overlay rather than emit a body the API will 422 on.
    if !pr_obj.contains_key("required_approving_review_count") {
        return;
    }
    map.insert("required_pull_request_reviews".into(), pr);
}

fn overlay_status_checks(map: &mut serde_json::Map<String, Value>, want: &DesiredBp) {
    if want.required_status_checks.is_empty() {
        return;
    }
    let mut sc = map.get("required_status_checks")
        .cloned()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({ "strict": false, "contexts": [] }));
    let sc_obj = sc.as_object_mut().expect("sc is an object");
    let existing: Vec<String> = sc_obj.get("contexts")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut merged = existing;
    for c in &want.required_status_checks {
        if !merged.contains(c) {
            merged.push(c.clone());
        }
    }
    sc_obj.insert("contexts".into(), json!(merged));
    map.insert("required_status_checks".into(), sc);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn want_minimal(branch: &str) -> DesiredBp {
        DesiredBp {
            branch: branch.into(),
            required_reviews: None,
            dismiss_stale_reviews: None,
            require_codeowners: None,
            require_conversation_resolution: None,
            require_linear_history: None,
            required_status_checks: vec![],
            block_force_push: None,
            block_deletions: None,
            enforce_admins: None,
            signed_commits: None,
        }
    }

    // Realistic GET response: every field GitHub returns for a heavily-protected
    // branch. The point of these tests is that any field we don't model must
    // still survive a PUT, and any field the user didn't declare must be
    // inherited from this actual state.
    fn realistic_actual() -> Value {
        json!({
            "url": "https://api.github.com/repos/o/r/branches/main/protection",
            "required_pull_request_reviews": {
                "url": "https://api.github.com/.../required_pull_request_reviews",
                "required_approving_review_count": 3,
                "dismiss_stale_reviews": true,
                "require_code_owner_reviews": true,
                "require_last_push_approval": true,
                "dismissal_restrictions": {
                    "url": "https://api.github.com/.../dismissal_restrictions",
                    "users_url": "https://api.github.com/.../users",
                    "teams_url": "https://api.github.com/.../teams",
                    "users": [{"login": "alice", "id": 1}],
                    "teams": [{"slug": "platform", "id": 2}]
                },
                "bypass_pull_request_allowances": {
                    "users": [{"login": "ops-bot", "id": 7}],
                    "teams": [{"slug": "release", "id": 8}],
                    "apps":  [{"slug": "deploy-bot", "id": 9}]
                }
            },
            "required_status_checks": {
                "url": "https://api.github.com/.../required_status_checks",
                "contexts_url": "https://api.github.com/.../contexts",
                "strict": true,
                "contexts": ["ci/build", "ci/test"]
            },
            "enforce_admins": { "enabled": true, "url": "..." },
            "restrictions": {
                "users": [{"login": "alice", "id": 1}],
                "teams": [{"slug": "platform", "id": 2}],
                "apps":  [{"slug": "deploy-bot", "id": 3}]
            },
            "required_linear_history": { "enabled": true },
            "allow_force_pushes":      { "enabled": false },
            "allow_deletions":         { "enabled": false },
            "required_conversation_resolution": { "enabled": true },
            "lock_branch":             { "enabled": true },
            "allow_fork_syncing":      { "enabled": true },
            "block_creations":         { "enabled": true }
        })
    }

    #[test]
    fn empty_want_with_actual_preserves_everything() {
        let want = want_minimal("main");
        let actual = realistic_actual();
        let body = branch_protection_body(&want, Some(&actual));

        assert_eq!(body["enforce_admins"], json!(true), "admin enforcement must survive");
        assert_eq!(body["required_linear_history"], json!(true));
        assert_eq!(body["required_conversation_resolution"], json!(true));
        assert_eq!(body["allow_force_pushes"], json!(false));
        assert_eq!(body["allow_deletions"], json!(false));

        let pr = &body["required_pull_request_reviews"];
        assert_eq!(pr["required_approving_review_count"], json!(3));
        assert_eq!(pr["dismiss_stale_reviews"], json!(true));
        assert_eq!(pr["require_code_owner_reviews"], json!(true));
        // unmodeled fields preserved
        assert_eq!(pr["require_last_push_approval"], json!(true));
        assert!(pr["bypass_pull_request_allowances"].is_object());

        let sc = &body["required_status_checks"];
        assert_eq!(sc["strict"], json!(true), "strict must not be flipped to false");
        assert_eq!(sc["contexts"], json!(["ci/build", "ci/test"]));

        let r = &body["restrictions"];
        assert_eq!(r["users"], json!(["alice"]));
        assert_eq!(r["teams"], json!(["platform"]));
        assert_eq!(r["apps"], json!(["deploy-bot"]));
    }

    #[test]
    fn declaring_one_field_does_not_clobber_others() {
        let mut want = want_minimal("main");
        want.required_reviews = Some(2);
        let actual = realistic_actual();
        let body = branch_protection_body(&want, Some(&actual));

        assert_eq!(body["required_pull_request_reviews"]["required_approving_review_count"], json!(2));
        // sibling PR fields the user did not touch are preserved
        assert_eq!(body["required_pull_request_reviews"]["require_code_owner_reviews"], json!(true));
        assert_eq!(body["required_pull_request_reviews"]["require_last_push_approval"], json!(true));
        // unrelated top-level fields preserved
        assert_eq!(body["enforce_admins"], json!(true));
        assert_eq!(body["required_status_checks"]["strict"], json!(true));
    }

    #[test]
    fn block_false_means_allow_true() {
        let mut want = want_minimal("main");
        want.block_force_push = Some(false);
        want.block_deletions = Some(true);
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        assert_eq!(body["allow_force_pushes"], json!(true));
        assert_eq!(body["allow_deletions"], json!(false));
    }

    #[test]
    fn enforce_admins_can_be_explicitly_disabled() {
        let mut want = want_minimal("main");
        want.enforce_admins = Some(false);
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        assert_eq!(body["enforce_admins"], json!(false));
    }

    #[test]
    fn status_checks_merge_additively() {
        let mut want = want_minimal("main");
        want.required_status_checks = vec!["ci/security".into(), "ci/build".into()];
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        let contexts = body["required_status_checks"]["contexts"].as_array().unwrap();
        let names: Vec<&str> = contexts.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"ci/build"));
        assert!(names.contains(&"ci/test"));
        assert!(names.contains(&"ci/security"));
        assert_eq!(body["required_status_checks"]["strict"], json!(true));
    }

    #[test]
    fn unmodeled_toggles_survive_put() {
        // lock_branch, allow_fork_syncing, block_creations are real PUT fields
        // the DSL doesn't expose. They must survive an apply unchanged.
        let want = want_minimal("main");
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        assert_eq!(body["lock_branch"], json!(true));
        assert_eq!(body["allow_fork_syncing"], json!(true));
        assert_eq!(body["block_creations"], json!(true));
    }

    #[test]
    fn dismissal_restrictions_become_put_shape() {
        let want = want_minimal("main");
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        let dr = &body["required_pull_request_reviews"]["dismissal_restrictions"];
        assert_eq!(dr["users"], json!(["alice"]), "users must be string array, not user objects");
        assert_eq!(dr["teams"], json!(["platform"]));
        assert!(dr.get("url").is_none(), "URL fields must be stripped");
        assert!(dr.get("users_url").is_none());
        assert!(dr.get("teams_url").is_none());
    }

    #[test]
    fn bypass_allowances_become_put_shape() {
        let want = want_minimal("main");
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        let bp = &body["required_pull_request_reviews"]["bypass_pull_request_allowances"];
        assert_eq!(bp["users"], json!(["ops-bot"]));
        assert_eq!(bp["teams"], json!(["release"]));
        assert_eq!(bp["apps"], json!(["deploy-bot"]));
    }

    #[test]
    fn pr_subfield_without_count_is_dropped() {
        // User declares dismiss_stale_reviews but never required_reviews, and
        // there's no actual PR-review block to inherit a count from. We must
        // not emit a malformed PR-review block — drop it entirely.
        let mut want = want_minimal("main");
        want.dismiss_stale_reviews = Some(true);
        let body = branch_protection_body(&want, None);
        assert_eq!(
            body["required_pull_request_reviews"], Value::Null,
            "should not emit PR block without required_approving_review_count"
        );
    }

    #[test]
    fn pr_subfield_with_inherited_count_is_kept() {
        // Same shape as above but actual already has a PR-review block with a
        // count — the count is inherited, so the overlay is well-formed.
        let mut want = want_minimal("main");
        want.dismiss_stale_reviews = Some(false);
        let body = branch_protection_body(&want, Some(&realistic_actual()));
        let pr = &body["required_pull_request_reviews"];
        assert_eq!(pr["dismiss_stale_reviews"], json!(false), "user override applied");
        assert_eq!(pr["required_approving_review_count"], json!(3), "count inherited from actual");
    }

    #[test]
    fn no_actual_uses_conservative_defaults() {
        let mut want = want_minimal("main");
        want.required_reviews = Some(1);
        want.enforce_admins = Some(true);
        let body = branch_protection_body(&want, None);
        assert_eq!(body["enforce_admins"], json!(true));
        assert_eq!(body["required_pull_request_reviews"]["required_approving_review_count"], json!(1));
        assert_eq!(body["allow_force_pushes"], json!(false));
        assert_eq!(body["allow_deletions"], json!(false));
        assert_eq!(body["restrictions"], Value::Null);
    }
}
