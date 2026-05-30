//! Detect `org/repo` from the cwd git remote. Ported from repocat's
//! `github::git` and extended to return both the org and the repo.

use anyhow::{Result, anyhow};
use std::process::Command;

/// Detect the GitHub `(org, repo)` from `git remote get-url origin`. Supports
/// the SSH (`git@github.com:ORG/REPO[.git]`), `ssh://`, and HTTPS forms.
pub fn detect_repo() -> Result<(String, String)> {
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
    parse_repo_from_url(&url)
        .ok_or_else(|| anyhow!("could not parse org/repo from git remote URL `{url}`"))
}

fn parse_repo_from_url(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))
        .or_else(|| url.strip_prefix("https://github.com/"))
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let mut parts = rest.splitn(2, '/');
    let org = parts.next()?.to_string();
    let repo_part = parts.next()?;
    // First path segment, with an optional `.git` suffix removed.
    let repo = repo_part.split('/').next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo).to_string();
    if org.is_empty() || repo.is_empty() {
        return None;
    }
    Some((org, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(url: &str) -> Option<(String, String)> {
        parse_repo_from_url(url)
    }

    #[test]
    fn parses_ssh_form() {
        assert_eq!(
            p("git@github.com:Battle-Creek-LLC/repocat.git"),
            Some(("Battle-Creek-LLC".into(), "repocat".into()))
        );
    }

    #[test]
    fn parses_ssh_form_without_dot_git() {
        assert_eq!(
            p("git@github.com:acme/widget"),
            Some(("acme".into(), "widget".into()))
        );
    }

    #[test]
    fn parses_ssh_alt_form() {
        assert_eq!(
            p("ssh://git@github.com/acme/widget.git"),
            Some(("acme".into(), "widget".into()))
        );
    }

    #[test]
    fn parses_https_form() {
        assert_eq!(
            p("https://github.com/Battle-Creek-LLC/repocat.git"),
            Some(("Battle-Creek-LLC".into(), "repocat".into()))
        );
    }

    #[test]
    fn parses_https_without_dot_git() {
        assert_eq!(
            p("https://github.com/acme/widget"),
            Some(("acme".into(), "widget".into()))
        );
    }

    #[test]
    fn rejects_non_github_remote() {
        assert_eq!(p("git@gitlab.com:acme/widget.git"), None);
        assert_eq!(p("https://example.com/acme/widget"), None);
    }
}
