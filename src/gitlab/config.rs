//! `.repo.gitlab.yml` — GitLab's own native schema. Shares nothing with the
//! GitHub config: it is authored in GitLab's vocabulary (group/project,
//! protected branches, approval rules, push rules, project settings, CI
//! security templates) and parsed into GitLab-only types.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Namespace path: a top-level group or a nested `group/subgroup`.
    pub group: String,
    /// Self-managed instance host (e.g. `git.example.com`). Defaults to
    /// gitlab.com and also selects which `glab` `hosts.<host>` block to read.
    #[serde(default)]
    pub host: Option<String>,
    pub defaults: ProjectConfig,
    /// Keyed by project path within `group`.
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectConfig>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(default)]
    pub protected_branches: Vec<ProtectedBranch>,
    #[serde(default)]
    pub approval_rules: Vec<ApprovalRule>,
    #[serde(default)]
    pub merge_request_approvals: Option<MergeRequestApprovals>,
    #[serde(default)]
    pub project_settings: Option<ProjectSettings>,
    #[serde(default)]
    pub push_rules: Option<PushRules>,
    #[serde(default)]
    pub required_files: Vec<String>,
    #[serde(default)]
    pub codeowners: Option<bool>,
    #[serde(default)]
    pub ci_security: Option<CiSecurity>,
    #[serde(default)]
    pub members: Option<Members>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBranch {
    pub name: String,
    #[serde(default)]
    pub allow_force_push: Option<bool>,
    /// One of `no_one`, `developer`, `maintainer`.
    #[serde(default)]
    pub push_access_level: Option<String>,
    #[serde(default)]
    pub merge_access_level: Option<String>,
    #[serde(default)]
    pub code_owner_approval_required: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRule {
    pub name: String,
    #[serde(default)]
    pub approvals_required: Option<u32>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MergeRequestApprovals {
    #[serde(default)]
    pub reset_approvals_on_push: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProjectSettings {
    /// `merge`, `rebase_merge`, or `ff`.
    #[serde(default)]
    pub merge_method: Option<String>,
    /// `never`, `always`, `default_on`, or `default_off`.
    #[serde(default)]
    pub squash_option: Option<String>,
    #[serde(default)]
    pub remove_source_branch_after_merge: Option<bool>,
    #[serde(default)]
    pub only_allow_merge_if_pipeline_succeeds: Option<bool>,
    #[serde(default)]
    pub only_allow_merge_if_all_discussions_are_resolved: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PushRules {
    #[serde(default)]
    pub reject_unsigned_commits: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CiSecurity {
    #[serde(default)]
    pub require_sast: Option<bool>,
    #[serde(default)]
    pub require_secret_detection: Option<bool>,
    #[serde(default)]
    pub require_dependency_scanning: Option<bool>,
    #[serde(default)]
    pub pin_includes: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Members {
    /// When `false`, direct project members (not granted via a group share) are
    /// flagged as drift.
    #[serde(default)]
    pub direct_members_allowed: Option<bool>,
    #[serde(default)]
    pub shares: Vec<MemberShare>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemberShare {
    pub group: String,
    /// One of `guest`, `reporter`, `developer`, `maintainer`, `owner`.
    pub access_level: String,
}

impl ProjectConfig {
    /// True when no field is set. Used to require a non-empty `defaults:`.
    pub fn is_empty(&self) -> bool {
        self.protected_branches.is_empty()
            && self.approval_rules.is_empty()
            && self.merge_request_approvals.is_none()
            && self.project_settings.is_none()
            && self.push_rules.is_none()
            && self.required_files.is_empty()
            && self.codeowners.is_none()
            && self.ci_security.is_none()
            && self.members.is_none()
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    if cfg.group.trim().is_empty() {
        return Err(anyhow!("`group:` is required at the top of {}", path.display()));
    }
    if cfg.defaults.is_empty() {
        return Err(anyhow!(
            "`defaults:` block is required and must not be empty in {}",
            path.display()
        ));
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Config {
        serde_yaml_ng::from_str(yaml).expect("parse")
    }

    #[test]
    fn parses_native_schema() {
        let cfg = parse(
            "group: my-group/platform\n\
             host: git.example.com\n\
             defaults:\n\
             \x20\x20protected_branches:\n\
             \x20\x20\x20\x20- name: main\n\
             \x20\x20\x20\x20\x20\x20allow_force_push: false\n\
             \x20\x20approval_rules:\n\
             \x20\x20\x20\x20- name: default\n\
             \x20\x20\x20\x20\x20\x20approvals_required: 1\n\
             \x20\x20project_settings:\n\
             \x20\x20\x20\x20merge_method: ff\n\
             projects:\n\
             \x20\x20svc-a: {}\n",
        );
        assert_eq!(cfg.group, "my-group/platform");
        assert_eq!(cfg.host.as_deref(), Some("git.example.com"));
        assert_eq!(cfg.defaults.protected_branches[0].name, "main");
        assert_eq!(cfg.defaults.approval_rules[0].approvals_required, Some(1));
        assert_eq!(cfg.defaults.project_settings.unwrap().merge_method.as_deref(), Some("ff"));
        assert!(cfg.projects.contains_key("svc-a"));
    }

    #[test]
    fn rejects_unknown_field() {
        let err = serde_yaml_ng::from_str::<Config>(
            "group: g\ndefaults:\n  branch_protection:\n    required_reviews: 1\n",
        );
        // `branch_protection` is GitHub vocabulary; the GitLab schema must reject it.
        assert!(err.is_err());
    }

    #[test]
    fn host_defaults_to_none() {
        let cfg = parse("group: g\ndefaults:\n  codeowners: true\n");
        assert!(cfg.host.is_none());
        assert!(!cfg.defaults.is_empty());
    }
}
