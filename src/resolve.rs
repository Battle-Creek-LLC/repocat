use crate::config::{
    ActionsSettings, BranchProtection, MergeSettings, RepoConfig, SecuritySettings, TeamSpec,
};

/// Compute the effective per-repo configuration by overlaying `repo` on top of
/// `defaults`. Rules:
///   - scalar `Option<T>` fields: `repo`'s `Some(_)` wins; otherwise inherit
///     from `defaults`.
///   - `Vec<_>` fields: concatenate `defaults` then `repo`, deduping while
///     preserving first-seen order.
///   - nested `Option<struct>` fields: if both sides have `Some`, recurse using
///     the same rules; otherwise use whichever side has `Some`.
pub fn effective(defaults: &RepoConfig, repo: &RepoConfig) -> RepoConfig {
    RepoConfig {
        branch_protection: overlay_opt(
            &defaults.branch_protection,
            &repo.branch_protection,
            overlay_branch_protection,
        ),
        merge: overlay_opt(&defaults.merge, &repo.merge, overlay_merge),
        security: overlay_opt(&defaults.security, &repo.security, overlay_security),
        required_files: extend_dedup(&defaults.required_files, &repo.required_files),
        codeowners: repo.codeowners.or(defaults.codeowners),
        actions: overlay_opt(&defaults.actions, &repo.actions, overlay_actions),
        teams: extend_dedup_teams(&defaults.teams, &repo.teams),
    }
}

fn overlay_opt<T, F>(d: &Option<T>, r: &Option<T>, f: F) -> Option<T>
where
    T: Clone,
    F: FnOnce(&T, &T) -> T,
{
    match (d, r) {
        (Some(d), Some(r)) => Some(f(d, r)),
        (Some(d), None) => Some(d.clone()),
        (None, Some(r)) => Some(r.clone()),
        (None, None) => None,
    }
}

fn overlay_branch_protection(d: &BranchProtection, r: &BranchProtection) -> BranchProtection {
    BranchProtection {
        // `branch` is a plain String, not an Option. Treat empty as "not set".
        branch: if r.branch.is_empty() { d.branch.clone() } else { r.branch.clone() },
        required_reviews: r.required_reviews.or(d.required_reviews),
        dismiss_stale_reviews: r.dismiss_stale_reviews.or(d.dismiss_stale_reviews),
        require_codeowners: r.require_codeowners.or(d.require_codeowners),
        require_conversation_resolution: r
            .require_conversation_resolution
            .or(d.require_conversation_resolution),
        require_linear_history: r.require_linear_history.or(d.require_linear_history),
        required_status_checks: extend_dedup(
            &d.required_status_checks,
            &r.required_status_checks,
        ),
        block_force_push: r.block_force_push.or(d.block_force_push),
        block_deletions: r.block_deletions.or(d.block_deletions),
        enforce_admins: r.enforce_admins.or(d.enforce_admins),
        signed_commits: r.signed_commits.or(d.signed_commits),
    }
}

fn overlay_merge(d: &MergeSettings, r: &MergeSettings) -> MergeSettings {
    MergeSettings {
        allow_squash: r.allow_squash.or(d.allow_squash),
        allow_merge_commit: r.allow_merge_commit.or(d.allow_merge_commit),
        allow_rebase: r.allow_rebase.or(d.allow_rebase),
        delete_branch_on_merge: r.delete_branch_on_merge.or(d.delete_branch_on_merge),
    }
}

fn overlay_security(d: &SecuritySettings, r: &SecuritySettings) -> SecuritySettings {
    SecuritySettings {
        secret_scanning: r.secret_scanning.or(d.secret_scanning),
        push_protection: r.push_protection.or(d.push_protection),
        dependabot_security_updates: r
            .dependabot_security_updates
            .or(d.dependabot_security_updates),
        dependabot_config: r.dependabot_config.or(d.dependabot_config),
        dependency_graph: r.dependency_graph.or(d.dependency_graph),
        vulnerability_alerts: r.vulnerability_alerts.or(d.vulnerability_alerts),
    }
}

fn overlay_actions(d: &ActionsSettings, r: &ActionsSettings) -> ActionsSettings {
    ActionsSettings {
        default_workflow_permissions: r
            .default_workflow_permissions
            .clone()
            .or_else(|| d.default_workflow_permissions.clone()),
        can_approve_pull_request_reviews: r
            .can_approve_pull_request_reviews
            .or(d.can_approve_pull_request_reviews),
        pin_actions_to_sha: r.pin_actions_to_sha.or(d.pin_actions_to_sha),
        require_workflow_permissions: r
            .require_workflow_permissions
            .or(d.require_workflow_permissions),
        require_dependency_review_action: r
            .require_dependency_review_action
            .or(d.require_dependency_review_action),
    }
}

fn extend_dedup(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(a.len() + b.len());
    for s in a.iter().chain(b.iter()) {
        if !out.iter().any(|x| x == s) {
            out.push(s.clone());
        }
    }
    out
}

// Teams dedupe by `name`; the repo-level entry's `permission` wins on conflict.
fn extend_dedup_teams(d: &[TeamSpec], r: &[TeamSpec]) -> Vec<TeamSpec> {
    let mut out: Vec<TeamSpec> = Vec::with_capacity(d.len() + r.len());
    for t in d.iter().chain(r.iter()) {
        if let Some(existing) = out.iter_mut().find(|x| x.name == t.name) {
            existing.permission = t.permission.clone();
        } else {
            out.push(t.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bp_full() -> BranchProtection {
        BranchProtection {
            branch: "main".into(),
            required_reviews: Some(2),
            dismiss_stale_reviews: Some(true),
            require_codeowners: Some(true),
            require_conversation_resolution: Some(true),
            require_linear_history: Some(true),
            required_status_checks: vec!["ci/build".into(), "ci/test".into()],
            block_force_push: Some(true),
            block_deletions: Some(true),
            enforce_admins: Some(true),
            signed_commits: Some(true),
        }
    }

    #[test]
    fn scalar_repo_overrides_default() {
        let mut d = RepoConfig::default();
        d.merge = Some(MergeSettings { allow_squash: Some(true), ..MergeSettings::default() });
        let mut r = RepoConfig::default();
        r.merge = Some(MergeSettings { allow_squash: Some(false), ..MergeSettings::default() });
        let eff = effective(&d, &r);
        assert_eq!(eff.merge.unwrap().allow_squash, Some(false));
    }

    #[test]
    fn scalar_falls_through_when_repo_unset() {
        let mut d = RepoConfig::default();
        d.merge = Some(MergeSettings { allow_squash: Some(true), allow_rebase: Some(false), ..MergeSettings::default() });
        let mut r = RepoConfig::default();
        r.merge = Some(MergeSettings { allow_rebase: Some(true), ..MergeSettings::default() });
        let eff = effective(&d, &r);
        let m = eff.merge.unwrap();
        assert_eq!(m.allow_squash, Some(true), "inherited from defaults");
        assert_eq!(m.allow_rebase, Some(true), "repo override wins");
    }

    #[test]
    fn vec_extends_and_dedupes_preserving_order() {
        let d = RepoConfig {
            required_files: vec!["README.md".into(), "LICENSE".into()],
            ..RepoConfig::default()
        };
        let r = RepoConfig {
            required_files: vec!["LICENSE".into(), "SECURITY.md".into()],
            ..RepoConfig::default()
        };
        let eff = effective(&d, &r);
        assert_eq!(eff.required_files, vec!["README.md", "LICENSE", "SECURITY.md"]);
    }

    #[test]
    fn nested_struct_overlays_field_by_field() {
        let d = RepoConfig {
            branch_protection: Some(bp_full()),
            ..RepoConfig::default()
        };
        let r = RepoConfig {
            branch_protection: Some(BranchProtection {
                required_reviews: Some(0),
                required_status_checks: vec!["ci/security".into(), "ci/build".into()],
                ..BranchProtection::default()
            }),
            ..RepoConfig::default()
        };
        let eff = effective(&d, &r);
        let bp = eff.branch_protection.unwrap();
        assert_eq!(bp.branch, "main", "branch inherited");
        assert_eq!(bp.required_reviews, Some(0), "scalar override wins");
        assert_eq!(bp.dismiss_stale_reviews, Some(true), "default field preserved");
        assert_eq!(bp.signed_commits, Some(true), "default field preserved");
        assert_eq!(
            bp.required_status_checks,
            vec!["ci/build", "ci/test", "ci/security"],
            "vec extended + deduped"
        );
    }

    #[test]
    fn nested_struct_present_only_in_defaults_is_used() {
        let d = RepoConfig {
            branch_protection: Some(bp_full()),
            ..RepoConfig::default()
        };
        let r = RepoConfig::default();
        let eff = effective(&d, &r);
        let bp = eff.branch_protection.unwrap();
        assert_eq!(bp.required_reviews, Some(2));
        assert_eq!(bp.signed_commits, Some(true));
    }

    #[test]
    fn nested_struct_present_only_in_repo_is_used() {
        let d = RepoConfig::default();
        let r = RepoConfig {
            branch_protection: Some(BranchProtection {
                branch: "develop".into(),
                required_reviews: Some(1),
                ..BranchProtection::default()
            }),
            ..RepoConfig::default()
        };
        let eff = effective(&d, &r);
        let bp = eff.branch_protection.unwrap();
        assert_eq!(bp.branch, "develop");
        assert_eq!(bp.required_reviews, Some(1));
        assert_eq!(bp.signed_commits, None);
    }

    #[test]
    fn codeowners_repo_wins() {
        let d = RepoConfig { codeowners: Some(true), ..RepoConfig::default() };
        let r = RepoConfig { codeowners: Some(false), ..RepoConfig::default() };
        assert_eq!(effective(&d, &r).codeowners, Some(false));
    }

    #[test]
    fn teams_dedupe_by_name_repo_permission_wins() {
        let d = RepoConfig {
            teams: vec![
                TeamSpec { name: "platform".into(), permission: "push".into() },
                TeamSpec { name: "security".into(), permission: "pull".into() },
            ],
            ..RepoConfig::default()
        };
        let r = RepoConfig {
            teams: vec![TeamSpec { name: "platform".into(), permission: "admin".into() }],
            ..RepoConfig::default()
        };
        let eff = effective(&d, &r);
        assert_eq!(eff.teams.len(), 2);
        assert_eq!(eff.teams[0].name, "platform");
        assert_eq!(eff.teams[0].permission, "admin", "repo permission wins on conflict");
        assert_eq!(eff.teams[1].name, "security");
    }
}
