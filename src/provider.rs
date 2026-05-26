//! Maps config files to repository hosts. The **filename** is the
//! discriminator — `.repo.github.yml` / `.repo.gitlab.yml` — so there is no
//! `provider:` key inside a config and no default host. `main` discovers which
//! files are present and dispatches each to its provider module.

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    GitHub,
    GitLab,
}

pub const GITHUB_CONFIG: &str = ".repo.github.yml";
pub const GITLAB_CONFIG: &str = ".repo.gitlab.yml";
const LEGACY_CONFIG: &str = ".repo.yml";

/// Infer the provider from a config file name by its `.repo.<host>.yml` suffix.
/// Returns `None` for an unrecognized name (an explicit `-f` may still target
/// it, defaulting to GitHub — see [`discover`]).
pub fn provider_for(path: &Path) -> Option<Provider> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".repo.github.yml") || name == GITHUB_CONFIG {
        Some(Provider::GitHub)
    } else if name.ends_with(".repo.gitlab.yml") || name == GITLAB_CONFIG {
        Some(Provider::GitLab)
    } else {
        None
    }
}

/// Resolve which config files to act on: an explicit `-f` path if given,
/// otherwise every recognized config present in the working directory.
pub fn discover(explicit: Option<&Path>) -> Result<Vec<(Provider, PathBuf)>> {
    if let Some(p) = explicit {
        // A custom name passed via -f defaults to GitHub when the suffix is
        // unrecognized, so existing workflows pointing at arbitrary paths work.
        let provider = provider_for(p).unwrap_or(Provider::GitHub);
        return Ok(vec![(provider, p.to_path_buf())]);
    }

    let mut found = Vec::new();
    if Path::new(GITHUB_CONFIG).exists() {
        found.push((Provider::GitHub, PathBuf::from(GITHUB_CONFIG)));
    }
    if Path::new(GITLAB_CONFIG).exists() {
        found.push((Provider::GitLab, PathBuf::from(GITLAB_CONFIG)));
    }
    if found.is_empty() {
        if Path::new(LEGACY_CONFIG).exists() {
            return Err(anyhow!(
                "found legacy {LEGACY_CONFIG} — rename it to {GITHUB_CONFIG} \
                 (repocat no longer has a default provider)"
            ));
        }
        return Err(anyhow!(
            "no config found — expected {GITHUB_CONFIG} or {GITLAB_CONFIG} \
             (create one with `repocat init`)"
        ));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_from_filename() {
        assert_eq!(provider_for(Path::new(".repo.github.yml")), Some(Provider::GitHub));
        assert_eq!(provider_for(Path::new(".repo.gitlab.yml")), Some(Provider::GitLab));
        assert_eq!(provider_for(Path::new("/some/dir/.repo.gitlab.yml")), Some(Provider::GitLab));
        assert_eq!(provider_for(Path::new(".repo.yml")), None);
        assert_eq!(provider_for(Path::new("whatever.yml")), None);
    }

    #[test]
    fn explicit_unknown_name_defaults_to_github() {
        let got = discover(Some(Path::new("/tmp/custom.yml"))).unwrap();
        assert_eq!(got, vec![(Provider::GitHub, PathBuf::from("/tmp/custom.yml"))]);
    }

    #[test]
    fn explicit_gitlab_name_routes_to_gitlab() {
        let got = discover(Some(Path::new("foo/.repo.gitlab.yml"))).unwrap();
        assert_eq!(got, vec![(Provider::GitLab, PathBuf::from("foo/.repo.gitlab.yml"))]);
    }
}
