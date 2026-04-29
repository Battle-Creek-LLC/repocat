use anyhow::{anyhow, Result};
use std::process::Command;

/// Detect the GitHub org/owner from `git remote get-url origin`. Supports the
/// common SSH (`git@github.com:ORG/REPO.git`) and HTTPS
/// (`https://github.com/ORG/REPO[.git]`) URL forms.
pub fn detect_org() -> Result<String> {
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
    parse_org_from_url(&url)
        .ok_or_else(|| anyhow!("could not parse org from git remote URL `{url}`"))
}

fn parse_org_from_url(url: &str) -> Option<String> {
    // SSH: git@github.com:ORG/REPO(.git)?
    if let Some(rest) = url.strip_prefix("git@github.com:") {
        return rest.split('/').next().map(str::to_string).filter(|s| !s.is_empty());
    }
    // SSH alt: ssh://git@github.com/ORG/REPO(.git)?
    if let Some(rest) = url.strip_prefix("ssh://git@github.com/") {
        return rest.split('/').next().map(str::to_string).filter(|s| !s.is_empty());
    }
    // HTTPS: https://github.com/ORG/REPO(.git)?
    for prefix in ["https://github.com/", "http://github.com/"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            return rest.split('/').next().map(str::to_string).filter(|s| !s.is_empty());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_form() {
        assert_eq!(
            parse_org_from_url("git@github.com:Battle-Creek-LLC/repocat.git"),
            Some("Battle-Creek-LLC".into())
        );
    }

    #[test]
    fn parses_ssh_form_without_dot_git() {
        assert_eq!(
            parse_org_from_url("git@github.com:acme/widget"),
            Some("acme".into())
        );
    }

    #[test]
    fn parses_https_form() {
        assert_eq!(
            parse_org_from_url("https://github.com/Battle-Creek-LLC/repocat.git"),
            Some("Battle-Creek-LLC".into())
        );
    }

    #[test]
    fn parses_https_without_dot_git() {
        assert_eq!(
            parse_org_from_url("https://github.com/acme/widget"),
            Some("acme".into())
        );
    }

    #[test]
    fn parses_ssh_alt_form() {
        assert_eq!(
            parse_org_from_url("ssh://git@github.com/acme/widget.git"),
            Some("acme".into())
        );
    }

    #[test]
    fn rejects_non_github_remote() {
        assert_eq!(parse_org_from_url("git@gitlab.com:acme/widget.git"), None);
        assert_eq!(parse_org_from_url("https://example.com/acme/widget"), None);
    }
}
