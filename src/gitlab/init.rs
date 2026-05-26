//! Scaffolding for `.repo.gitlab.yml`: detect the namespace/host/project from
//! the git remote and render a sensible baseline config. Mirrors the role of
//! `github::git` + the GitHub preset templates, but emits GitLab's native
//! vocabulary so the output parses under [`crate::gitlab::config::Config`].

use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::Command;

/// Validate a scaffolded `.repo.gitlab.yml` by running the same loader the
/// audit/diff path uses. Exposed here because `gitlab::config` is module-private;
/// `init` lives inside `gitlab`, so it can reach `super::config`.
pub fn validate(path: &Path) -> Result<()> {
    super::config::load(path)?;
    Ok(())
}

/// Detect `(host, namespace, project)` from `git remote get-url origin`.
///
/// The namespace is everything between the host and the final path segment, so
/// nested groups (`group/subgroup`) are preserved; the last segment is the
/// project. Works for gitlab.com and self-managed hosts alike.
pub fn detect() -> Result<(String, String, String)> {
    let out = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .map_err(|e| anyhow!("running `git remote get-url origin`: {e}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "git remote get-url origin failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (host, ns, project) = parse_remote(&url)
        .ok_or_else(|| anyhow!("could not parse host/namespace/project from git remote URL `{url}`"))?;
    // A github.com origin is definitively not a GitLab host; refuse it so a
    // `.repo.gitlab.yml` never gets `host: github.com`. The caller then falls
    // back to gitlab.com (with --org) or asks for --org.
    if host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("www.github.com") {
        return Err(anyhow!("origin remote is on github.com, not a GitLab host (`{url}`)"));
    }
    Ok((host, ns, project))
}

/// Parse a git remote URL into `(host, namespace, project)`.
///
/// The last path segment (sans `.git`) is the project; everything before it is
/// the namespace, which may contain `/` for nested groups. Supports:
/// - SSH:      `git@host:ns/sub/proj.git`
/// - ssh://:   `ssh://git@host/ns/sub/proj.git` (optional port)
/// - https://: `https://host/ns/sub/proj.git` (and http://)
pub fn parse_remote(url: &str) -> Option<(String, String, String)> {
    let (host, path) = split_host_and_path(url)?;
    split_namespace_project(&path).map(|(ns, proj)| (host, ns, proj))
}

/// Split a remote URL into its host and the repository path that follows it.
fn split_host_and_path(url: &str) -> Option<(String, String)> {
    // scp-like SSH: git@host:ns/sub/proj.git  (no scheme, host/path split on ':')
    if let Some(rest) = url.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        return non_empty(host).map(|h| (h, path.to_string()));
    }

    // URL forms with a scheme: ssh://, https://, http://. Strip any `user@`
    // userinfo, then the authority is up to the first '/'; a `:port` is dropped.
    for prefix in ["ssh://", "https://", "http://"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
            let (authority, path) = rest.split_once('/')?;
            let host = authority.split(':').next().unwrap_or(authority);
            return non_empty(host).map(|h| (h, path.to_string()));
        }
    }

    None
}

/// Split a repository path (`ns/sub/proj.git`) into `(namespace, project)`.
fn split_namespace_project(path: &str) -> Option<(String, String)> {
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (ns, proj) = path.rsplit_once('/')?;
    Some((non_empty(ns)?, non_empty(proj)?))
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Render a baseline `.repo.gitlab.yml` for the given namespace/host/project.
/// When `host` is `gitlab.com` the `host:` line is omitted (it is the default).
/// The output parses under [`crate::gitlab::config::Config`].
pub fn template(group: &str, host: &str, project: &str) -> String {
    let host_line = if host == "gitlab.com" {
        // gitlab.com is the default host; omit the line so the config is portable.
        String::new()
    } else {
        format!("host: {host}\n")
    };

    format!(
        "# repocat GitLab config — audited/applied with `repocat audit|diff`.\n\
         # Authored in GitLab's native vocabulary; see `repocat init --provider gitlab --stdout`.\n\
         group: {group}\n\
         {host_line}\
         defaults:\n\
         \x20\x20protected_branches:\n\
         \x20\x20\x20\x20- name: main\n\
         \x20\x20\x20\x20\x20\x20allow_force_push: false\n\
         \x20\x20\x20\x20\x20\x20push_access_level: maintainer\n\
         \x20\x20\x20\x20\x20\x20merge_access_level: developer\n\
         \x20\x20\x20\x20\x20\x20# code_owner_approval_required requires GitLab Premium/Ultimate.\n\
         \x20\x20approval_rules:\n\
         \x20\x20\x20\x20- name: default\n\
         \x20\x20\x20\x20\x20\x20approvals_required: 1\n\
         \x20\x20merge_request_approvals:\n\
         \x20\x20\x20\x20reset_approvals_on_push: true\n\
         \x20\x20project_settings:\n\
         \x20\x20\x20\x20merge_method: ff\n\
         \x20\x20\x20\x20squash_option: default_on\n\
         \x20\x20\x20\x20remove_source_branch_after_merge: true\n\
         \x20\x20\x20\x20only_allow_merge_if_pipeline_succeeds: true\n\
         \x20\x20\x20\x20only_allow_merge_if_all_discussions_are_resolved: true\n\
         \x20\x20# push_rules (e.g. reject_unsigned_commits) requires GitLab Premium/Ultimate.\n\
         \x20\x20required_files:\n\
         \x20\x20\x20\x20- README.md\n\
         \x20\x20codeowners: true\n\
         \x20\x20ci_security:\n\
         \x20\x20\x20\x20require_sast: true\n\
         \x20\x20\x20\x20require_secret_detection: true\n\
         \x20\x20\x20\x20require_dependency_scanning: true\n\
         projects:\n\
         \x20\x20{project}: {{}}\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_ssh_form() {
        assert_eq!(
            parse_remote("git@gitlab.com:acme/widget.git"),
            Some(("gitlab.com".into(), "acme".into(), "widget".into()))
        );
    }

    #[test]
    fn parse_remote_ssh_nested_groups() {
        assert_eq!(
            parse_remote("git@gitlab.com:acme/team/sub/widget.git"),
            Some(("gitlab.com".into(), "acme/team/sub".into(), "widget".into()))
        );
    }

    #[test]
    fn parse_remote_ssh_self_managed_no_dot_git() {
        assert_eq!(
            parse_remote("git@git.example.com:platform/svc-a"),
            Some(("git.example.com".into(), "platform".into(), "svc-a".into()))
        );
    }

    #[test]
    fn parse_remote_ssh_scheme_with_port_strips_userinfo() {
        // The `git@` userinfo is dropped, and the `:2222` port is stripped from
        // the host, leaving the bare self-managed hostname.
        assert_eq!(
            parse_remote("ssh://git@gitlab.example.com:2222/acme/team/widget.git"),
            Some(("gitlab.example.com".into(), "acme/team".into(), "widget".into()))
        );
    }

    #[test]
    fn parse_remote_https_form_nested() {
        assert_eq!(
            parse_remote("https://gitlab.com/acme/team/widget.git"),
            Some(("gitlab.com".into(), "acme/team".into(), "widget".into()))
        );
    }

    #[test]
    fn parse_remote_https_without_dot_git() {
        assert_eq!(
            parse_remote("https://gitlab.com/acme/widget"),
            Some(("gitlab.com".into(), "acme".into(), "widget".into()))
        );
    }

    #[test]
    fn parse_remote_rejects_pathless_url() {
        // No namespace segment before the project: cannot split.
        assert_eq!(parse_remote("https://gitlab.com/widget.git"), None);
        assert_eq!(parse_remote("git@gitlab.com:widget.git"), None);
        assert_eq!(parse_remote("not a url"), None);
    }

    #[test]
    fn template_parses_under_config_and_round_trips() {
        let rendered = template("acme/team", "git.example.com", "widget");
        let cfg: crate::gitlab::config::Config =
            serde_yaml_ng::from_str(&rendered).expect("template must parse under gitlab Config");
        assert_eq!(cfg.group, "acme/team");
        assert_eq!(cfg.host.as_deref(), Some("git.example.com"));
        assert!(cfg.projects.contains_key("widget"));
        assert!(!cfg.defaults.is_empty());
    }

    #[test]
    fn template_omits_host_line_for_gitlab_com() {
        let rendered = template("acme", "gitlab.com", "widget");
        assert!(!rendered.contains("host:"), "gitlab.com host line should be omitted");
        let cfg: crate::gitlab::config::Config =
            serde_yaml_ng::from_str(&rendered).expect("must still parse");
        assert!(cfg.host.is_none());
        assert_eq!(cfg.group, "acme");
        assert!(cfg.projects.contains_key("widget"));
    }
}
