use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub org: String,
    #[serde(default)]
    pub tier: Option<String>,
    pub repos: BTreeMap<String, RepoConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RepoConfig {
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub branch_protection: Option<BranchProtection>,
    #[serde(default)]
    pub merge: Option<MergeSettings>,
    #[serde(default)]
    pub security: Option<SecuritySettings>,
    #[serde(default)]
    pub required_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BranchProtection {
    pub branch: String,
    #[serde(default)]
    pub required_reviews: u32,
    #[serde(default)]
    pub dismiss_stale_reviews: bool,
    #[serde(default)]
    pub require_codeowners: bool,
    #[serde(default)]
    pub require_conversation_resolution: bool,
    #[serde(default)]
    pub require_linear_history: bool,
    #[serde(default)]
    pub required_status_checks: Vec<String>,
    #[serde(default)]
    pub block_force_push: bool,
    #[serde(default)]
    pub block_deletions: bool,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct SecuritySettings {
    #[serde(default)]
    pub secret_scanning: Option<bool>,
    #[serde(default)]
    pub push_protection: Option<bool>,
    #[serde(default)]
    pub dependabot_security_updates: Option<bool>,
    #[serde(default)]
    pub dependency_review: Option<bool>,
    #[serde(default)]
    pub vulnerability_alerts: Option<bool>,
    #[serde(default)]
    pub signed_commits_required: Option<bool>,
}

pub fn load(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config = serde_yml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    if cfg.org.trim().is_empty() {
        return Err(anyhow!("`org:` is required at the top of {}", path.display()));
    }
    if cfg.repos.is_empty() {
        return Err(anyhow!("`repos:` map is empty in {}", path.display()));
    }
    Ok(cfg)
}
