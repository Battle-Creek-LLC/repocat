//! Merge a project's overlay onto `defaults`. GitLab blocks are coarser than
//! GitHub's, so the rule here is **whole-field override**: a field a project
//! sets (a non-empty vec, or a `Some(_)` block) replaces the default for that
//! field; otherwise the project inherits the default. This is simpler and more
//! predictable than deep-merging lists keyed by name, and matches how the spec
//! example overrides a project's `approval_rules` wholesale.

use super::config::ProjectConfig;

pub fn effective(defaults: &ProjectConfig, project: &ProjectConfig) -> ProjectConfig {
    ProjectConfig {
        protected_branches: pick_vec(&defaults.protected_branches, &project.protected_branches),
        approval_rules: pick_vec(&defaults.approval_rules, &project.approval_rules),
        merge_request_approvals: project
            .merge_request_approvals
            .clone()
            .or_else(|| defaults.merge_request_approvals.clone()),
        project_settings: project
            .project_settings
            .clone()
            .or_else(|| defaults.project_settings.clone()),
        push_rules: project.push_rules.clone().or_else(|| defaults.push_rules.clone()),
        required_files: pick_vec(&defaults.required_files, &project.required_files),
        codeowners: project.codeowners.or(defaults.codeowners),
        ci_security: project.ci_security.clone().or_else(|| defaults.ci_security.clone()),
        members: project.members.clone().or_else(|| defaults.members.clone()),
    }
}

fn pick_vec<T: Clone>(default: &[T], project: &[T]) -> Vec<T> {
    if project.is_empty() {
        default.to_vec()
    } else {
        project.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::{ApprovalRule, ProjectConfig, ProjectSettings};
    use super::*;

    fn rule(name: &str, n: u32) -> ApprovalRule {
        ApprovalRule { name: name.into(), approvals_required: Some(n) }
    }

    #[test]
    fn project_inherits_defaults_when_unset() {
        let defaults = ProjectConfig {
            approval_rules: vec![rule("default", 1)],
            codeowners: Some(true),
            ..Default::default()
        };
        let eff = effective(&defaults, &ProjectConfig::default());
        assert_eq!(eff.approval_rules, vec![rule("default", 1)]);
        assert_eq!(eff.codeowners, Some(true));
    }

    #[test]
    fn project_overrides_whole_field() {
        let defaults = ProjectConfig {
            approval_rules: vec![rule("default", 1)],
            project_settings: Some(ProjectSettings {
                merge_method: Some("merge".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let project = ProjectConfig {
            approval_rules: vec![rule("default", 2)],
            ..Default::default()
        };
        let eff = effective(&defaults, &project);
        // project's approval_rules win wholesale...
        assert_eq!(eff.approval_rules, vec![rule("default", 2)]);
        // ...but project_settings it didn't set are inherited.
        assert_eq!(eff.project_settings.unwrap().merge_method.as_deref(), Some("merge"));
    }
}
