//! Reuse the credentials `glab` already stores. Unlike `gh`, `glab` keeps the
//! token in **plaintext** in a single `config.yml` (no OS keyring, no separate
//! `hosts.yml`), so this is a straight read of `hosts.<host>.token`.
//!
//! Resolution order: `GITLAB_TOKEN` env var, then the `glab` config file. The
//! host is chosen from the `.repo.gitlab.yml` `host:` (passed in), then
//! `GITLAB_HOST`/`GL_HOST`, then `glab`'s top-level `host:`, then `gitlab.com`.

use anyhow::{anyhow, Result};
use std::{env, fs, path::PathBuf};

pub const USER_AGENT: &str = concat!("repocat/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct Creds {
    pub token: String,
    /// e.g. `https://gitlab.com/api/v4`.
    pub base_url: String,
    pub host: String,
    /// Honored from `glab`'s `skip_tls_verify` / `skip_ssl_verify` (see
    /// [`super::api`]); the token came from the same host block, so this is the
    /// user's own per-host decision, not a new trust choice.
    pub skip_tls_verify: bool,
}

pub fn load_credentials(config_host: Option<&str>) -> Result<Creds> {
    let text = read_glab_config();
    let cfg = text.as_deref();

    let host = config_host
        .map(str::to_string)
        .or_else(|| nonempty_env("GITLAB_HOST"))
        .or_else(|| nonempty_env("GL_HOST"))
        .or_else(|| cfg.and_then(glab_default_host))
        .unwrap_or_else(|| "gitlab.com".to_string());

    let api_host = cfg
        .and_then(|t| glab_host_field(t, &host, "api_host"))
        .unwrap_or_else(|| host.clone());
    let api_protocol = cfg
        .and_then(|t| glab_host_field(t, &host, "api_protocol"))
        .unwrap_or_else(|| "https".to_string());
    let subfolder = cfg.and_then(|t| glab_host_field(t, &host, "subfolder"));
    let skip_tls_verify = cfg.is_some_and(|t| {
        glab_host_field(t, &host, "skip_tls_verify").as_deref() == Some("true")
            || glab_skip_ssl(t)
    });

    let token = match nonempty_env("GITLAB_TOKEN") {
        Some(t) => t,
        None => cfg.and_then(|t| glab_host_field(t, &host, "token")).ok_or_else(|| {
            anyhow!(
                "no glab credentials found for {host} (checked GITLAB_TOKEN, {})",
                config_path().display()
            )
        })?,
    };

    Ok(Creds {
        token,
        base_url: build_base_url(&api_protocol, &api_host, subfolder.as_deref()),
        host,
        skip_tls_verify,
    })
}

fn nonempty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}

fn config_dir() -> Option<PathBuf> {
    if let Ok(d) = env::var("GLAB_CONFIG_DIR") {
        return Some(PathBuf::from(d));
    }
    if let Ok(x) = env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(x).join("glab-cli"));
    }
    env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config").join("glab-cli"))
}

fn config_path() -> PathBuf {
    config_dir().unwrap_or_else(|| PathBuf::from("~/.config/glab-cli")).join("config.yml")
}

fn read_glab_config() -> Option<String> {
    fs::read_to_string(config_path()).ok()
}

/// `{proto}://{api_host}[/{subfolder}]/api/v4`.
pub fn build_base_url(api_protocol: &str, api_host: &str, subfolder: Option<&str>) -> String {
    match subfolder.map(|s| s.trim_matches('/')).filter(|s| !s.is_empty()) {
        Some(sub) => format!("{api_protocol}://{api_host}/{sub}/api/v4"),
        None => format!("{api_protocol}://{api_host}/api/v4"),
    }
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// Read `hosts.<host>.<key>` from a `glab` config. Hosts nest under a
/// top-level `hosts:` map (host headers at 4 spaces, fields at 8). Returns
/// `None` when the key is absent **or present but empty** (e.g. a tokenless
/// default host), so the caller falls through / errors rather than using "".
fn glab_host_field(text: &str, host: &str, key: &str) -> Option<String> {
    let host_header = format!("{host}:");
    let key_prefix = format!("{key}:");
    let mut in_hosts = false;
    let mut in_target_host = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_spaces(line);
        if indent == 0 {
            in_hosts = trimmed.trim_end() == "hosts:";
            in_target_host = false;
        } else if in_hosts && indent == 4 {
            in_target_host = trimmed.trim_end() == host_header;
        } else if in_target_host && indent >= 8 {
            if let Some(rest) = trimmed.strip_prefix(&key_prefix) {
                let v = rest.trim().trim_matches('"');
                return if v.is_empty() { None } else { Some(v.to_string()) };
            }
        }
    }
    None
}

/// `glab`'s top-level default `host:` value.
fn glab_default_host(text: &str) -> Option<String> {
    top_level_scalar(text, "host")
}

/// Top-level `skip_ssl_verify: "true"`.
fn glab_skip_ssl(text: &str) -> bool {
    top_level_scalar(text, "skip_ssl_verify").as_deref() == Some("true")
}

fn top_level_scalar(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in text.lines() {
        if leading_spaces(line) != 0 {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let v = rest.trim().trim_matches('"');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors the real `glab` config: a top-level default host, a tokenless
    // gitlab.com block, and a self-managed host that actually carries the PAT.
    const SAMPLE: &str = "\
git_protocol: ssh
host: gitlab.com
hosts:
    gitlab.com:
        # What protocol to use to access the API endpoint.
        api_protocol: https
        api_host: gitlab.com
        token:
    git.example.com:
        token: PLACEHOLDER_TOKEN
        skip_tls_verify: \"true\"
        api_host: git.example.com
        api_protocol: https
        user: someuser
skip_ssl_verify: \"true\"
";

    #[test]
    fn reads_token_from_self_managed_host() {
        assert_eq!(
            glab_host_field(SAMPLE, "git.example.com", "token").as_deref(),
            Some("PLACEHOLDER_TOKEN")
        );
        assert_eq!(
            glab_host_field(SAMPLE, "git.example.com", "user").as_deref(),
            Some("someuser")
        );
    }

    #[test]
    fn tokenless_host_yields_none() {
        // gitlab.com's `token:` is empty — must not return "".
        assert_eq!(glab_host_field(SAMPLE, "gitlab.com", "token"), None);
        // ...but other fields on that host still read.
        assert_eq!(
            glab_host_field(SAMPLE, "gitlab.com", "api_protocol").as_deref(),
            Some("https")
        );
    }

    #[test]
    fn default_host_and_skip_flags() {
        assert_eq!(glab_default_host(SAMPLE).as_deref(), Some("gitlab.com"));
        assert!(glab_skip_ssl(SAMPLE));
        assert_eq!(
            glab_host_field(SAMPLE, "git.example.com", "skip_tls_verify").as_deref(),
            Some("true")
        );
    }

    #[test]
    fn base_url_construction() {
        assert_eq!(build_base_url("https", "gitlab.com", None), "https://gitlab.com/api/v4");
        assert_eq!(
            build_base_url("https", "git.example.com", Some("/gitlab/")),
            "https://git.example.com/gitlab/api/v4"
        );
        assert_eq!(build_base_url("http", "h", Some("")), "http://h/api/v4");
    }

    #[test]
    fn missing_host_field_is_none() {
        assert_eq!(glab_host_field(SAMPLE, "nope.com", "token"), None);
    }
}
