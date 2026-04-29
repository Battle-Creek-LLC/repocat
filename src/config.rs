use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub org: String,
    pub defaults: RepoConfig,
    #[serde(default)]
    pub repos: BTreeMap<String, RepoConfig>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    #[serde(default)]
    pub branch_protection: Option<BranchProtection>,
    #[serde(default)]
    pub merge: Option<MergeSettings>,
    #[serde(default)]
    pub security: Option<SecuritySettings>,
    #[serde(default)]
    pub required_files: Vec<String>,
    #[serde(default)]
    pub codeowners: Option<bool>,
    #[serde(default)]
    pub actions: Option<ActionsSettings>,
    #[serde(default)]
    pub teams: Vec<TeamSpec>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TeamSpec {
    pub name: String,
    pub permission: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ActionsSettings {
    #[serde(default)]
    pub default_workflow_permissions: Option<String>,
    #[serde(default)]
    pub can_approve_pull_request_reviews: Option<bool>,
    #[serde(default)]
    pub pin_actions_to_sha: Option<bool>,
    #[serde(default)]
    pub require_workflow_permissions: Option<bool>,
    #[serde(default)]
    pub require_dependency_review_action: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BranchProtection {
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub required_reviews: Option<u32>,
    #[serde(default)]
    pub dismiss_stale_reviews: Option<bool>,
    #[serde(default)]
    pub require_codeowners: Option<bool>,
    #[serde(default)]
    pub require_conversation_resolution: Option<bool>,
    #[serde(default)]
    pub require_linear_history: Option<bool>,
    #[serde(default)]
    pub required_status_checks: Vec<String>,
    #[serde(default)]
    pub block_force_push: Option<bool>,
    #[serde(default)]
    pub block_deletions: Option<bool>,
    #[serde(default)]
    pub enforce_admins: Option<bool>,
    #[serde(default)]
    pub signed_commits: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MergeSettings {
    #[serde(default)]
    pub allow_squash: Option<bool>,
    #[serde(default)]
    pub allow_merge_commit: Option<bool>,
    #[serde(default)]
    pub allow_rebase: Option<bool>,
    #[serde(default)]
    pub delete_branch_on_merge: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecuritySettings {
    #[serde(default)]
    pub secret_scanning: Option<bool>,
    #[serde(default)]
    pub push_protection: Option<bool>,
    #[serde(default)]
    pub dependabot_security_updates: Option<bool>,
    #[serde(default)]
    pub dependabot_config: Option<bool>,
    #[serde(default)]
    pub dependency_graph: Option<bool>,
    #[serde(default)]
    pub vulnerability_alerts: Option<bool>,
}

impl RepoConfig {
    /// True when no field has been set. Used to enforce that `defaults:` is
    /// present and non-empty in `.repo.yml`.
    pub fn is_empty(&self) -> bool {
        self.branch_protection.is_none()
            && self.merge.is_none()
            && self.security.is_none()
            && self.required_files.is_empty()
            && self.codeowners.is_none()
            && self.actions.is_none()
            && self.teams.is_empty()
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    if cfg.org.trim().is_empty() {
        return Err(anyhow!("`org:` is required at the top of {}", path.display()));
    }
    if cfg.defaults.is_empty() {
        return Err(anyhow!(
            "`defaults:` block is required and must not be empty in {}",
            path.display()
        ));
    }
    // `repos:` may be empty right after `init` — callers that need at least
    // one repo (audit/diff/apply) should check separately.
    Ok(cfg)
}
