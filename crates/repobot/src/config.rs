//! Credentials. repobot reads its GitHub App identity from exactly one place:
//! `~/.config/repobot/config.yml`. No env vars, no flags, no fallback paths.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub app_id: u64,
    /// Path to the App's RSA private key PEM, with `~`/`$HOME` already expanded.
    pub private_key: PathBuf,
}

/// Optional fields so a missing one yields a named error rather than serde's
/// generic message; `deny_unknown_fields` still rejects typos/extra keys.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    app_id: Option<u64>,
    private_key: Option<String>,
}

/// The single, fixed config path. `~/.config/repobot/config.yml`.
pub fn config_path() -> Result<PathBuf> {
    Ok(home_dir()?.join(".config/repobot/config.yml"))
}

/// Load and validate the config from its fixed location.
pub fn load() -> Result<Config> {
    let path = config_path()?;
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} (repobot reads App credentials only from this file)",
            path.display()
        )
    })?;
    parse(&text).with_context(|| format!("parsing {}", path.display()))
}

fn parse(text: &str) -> Result<Config> {
    let raw: Raw = serde_yaml_ng::from_str(text)?;
    let app_id = raw
        .app_id
        .ok_or_else(|| anyhow!("missing required field `app_id`"))?;
    let private_key = raw
        .private_key
        .ok_or_else(|| anyhow!("missing required field `private_key`"))?;
    if private_key.trim().is_empty() {
        return Err(anyhow!("`private_key` is empty"));
    }
    Ok(Config {
        app_id,
        private_key: expand_tilde(&private_key)?,
    })
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("$HOME is not set; cannot locate config or expand `~`"))
}

fn expand_tilde(path: &str) -> Result<PathBuf> {
    Ok(expand_tilde_with(path, &home_dir()?))
}

fn expand_tilde_with(path: &str, home: &Path) -> PathBuf {
    if path == "~" || path == "$HOME" {
        return home.to_path_buf();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return home.join(rest);
    }
    if let Some(rest) = path.strip_prefix("$HOME/") {
        return home.join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_fields() {
        let cfg = parse("app_id: 3858237\nprivate_key: /abs/key.pem\n").unwrap();
        assert_eq!(cfg.app_id, 3858237);
        assert_eq!(cfg.private_key, PathBuf::from("/abs/key.pem"));
    }

    #[test]
    fn missing_app_id_names_the_field() {
        let e = parse("private_key: /abs/key.pem\n").unwrap_err();
        assert!(e.to_string().contains("app_id"), "got: {e}");
    }

    #[test]
    fn missing_private_key_names_the_field() {
        let e = parse("app_id: 1\n").unwrap_err();
        assert!(e.to_string().contains("private_key"), "got: {e}");
    }

    #[test]
    fn rejects_unknown_field() {
        let e = parse("app_id: 1\nprivate_key: /k.pem\ninstall_id: 9\n").unwrap_err();
        assert!(
            e.to_string().contains("install_id") || e.to_string().contains("unknown"),
            "got: {e}"
        );
    }

    #[test]
    fn expands_tilde_prefix() {
        let home = Path::new("/home/jonah");
        assert_eq!(
            expand_tilde_with("~/.config/repobot/key.pem", home),
            PathBuf::from("/home/jonah/.config/repobot/key.pem")
        );
        assert_eq!(expand_tilde_with("~", home), PathBuf::from("/home/jonah"));
        assert_eq!(
            expand_tilde_with("$HOME/k.pem", home),
            PathBuf::from("/home/jonah/k.pem")
        );
    }

    #[test]
    fn leaves_absolute_path_untouched() {
        let home = Path::new("/home/jonah");
        assert_eq!(
            expand_tilde_with("/etc/key.pem", home),
            PathBuf::from("/etc/key.pem")
        );
    }
}
