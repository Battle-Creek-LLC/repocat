use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use std::{env, fs, path::PathBuf};

const GH_KEYRING_SERVICE: &str = "gh:github.com";
const GH_HOST: &str = "github.com";
const USER_AGENT: &str = "repocat/0.1";

pub fn user_agent() -> &'static str {
    USER_AGENT
}

/// Returns (token, login). Tries env vars, then macOS keychain (for the active
/// gh user named in hosts.yml), then a plaintext token in hosts.yml. The same
/// resolution order gh itself uses on macOS and headless Linux.
pub fn load_credentials() -> Result<(String, String)> {
    if let Ok(t) = env::var("GH_TOKEN").or_else(|_| env::var("GITHUB_TOKEN")) {
        if !t.is_empty() {
            let login = whoami(&t).unwrap_or_else(|_| "<env-token>".into());
            return Ok((t, login));
        }
    }

    let active_login = read_active_login_from_hosts().ok();
    if let Some(login) = active_login.as_deref() {
        if let Ok(tok) = read_token_from_keyring(login) {
            return Ok((tok, login.to_string()));
        }
    }
    if let Some((tok, login)) = read_token_from_hosts()? {
        return Ok((tok, login));
    }

    Err(anyhow!(
        "no gh credentials found (checked GH_TOKEN/GITHUB_TOKEN, keyring, ~/.config/gh/hosts.yml)"
    ))
}

fn read_token_from_keyring(account: &str) -> Result<String> {
    let entry = keyring::Entry::new(GH_KEYRING_SERVICE, account)?;
    let raw = entry.get_password()?;
    Ok(decode_go_keyring(&raw))
}

fn decode_go_keyring(raw: &str) -> String {
    if let Some(b64) = raw.strip_prefix("go-keyring-base64:") {
        if let Ok(bytes) = B64.decode(b64.trim()) {
            if let Ok(s) = String::from_utf8(bytes) {
                return s;
            }
        }
    }
    raw.to_string()
}

fn hosts_yml_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("GH_CONFIG_DIR") {
        return Some(PathBuf::from(p).join("hosts.yml"));
    }
    let xdg = env::var("XDG_CONFIG_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))?;
    Some(xdg.join("gh").join("hosts.yml"))
}

fn read_active_login_from_hosts() -> Result<String> {
    let path = hosts_yml_path().ok_or_else(|| anyhow!("cannot resolve config dir"))?;
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    parse_active_login(&text).ok_or_else(|| anyhow!("no active user in hosts.yml"))
}

fn read_token_from_hosts() -> Result<Option<(String, String)>> {
    let Some(path) = hosts_yml_path() else { return Ok(None); };
    let Ok(text) = fs::read_to_string(&path) else { return Ok(None); };
    Ok(parse_token(&text))
}

fn parse_token(text: &str) -> Option<(String, String)> {
    let block = extract_host_block(text, GH_HOST)?;
    let user = scalar_at_depth(&block, "user", 1);
    let top_token = scalar_at_depth(&block, "oauth_token", 1);
    if let (Some(u), Some(t)) = (user.clone(), top_token) {
        return Some((t, u));
    }
    let user = user?;
    let nested = nested_user_token(&block, &user)?;
    Some((nested, user))
}

fn parse_active_login(text: &str) -> Option<String> {
    let block = extract_host_block(text, GH_HOST)?;
    scalar_at_depth(&block, "user", 1)
}

fn extract_host_block(text: &str, host: &str) -> Option<String> {
    let mut out = String::new();
    let mut in_block = false;
    let header = format!("{host}:");
    for line in text.lines() {
        if !in_block {
            if line.trim_start() == header && !line.starts_with(' ') && !line.starts_with('\t') {
                in_block = true;
            }
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_block { Some(out) } else { None }
}

fn line_indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count() / 4
        + line.chars().take_while(|c| *c == '\t').count()
}

fn scalar_at_depth(block: &str, key: &str, depth: usize) -> Option<String> {
    let prefix = format!("{key}:");
    for line in block.lines() {
        if line.trim().is_empty() || line_indent(line) != depth {
            continue;
        }
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let val = rest.trim();
            if !val.is_empty() {
                return Some(val.trim_matches('"').to_string());
            }
        }
    }
    None
}

fn nested_user_token(block: &str, user: &str) -> Option<String> {
    let mut found_users = false;
    let mut found_user = false;
    let user_header = format!("{user}:");
    for line in block.lines() {
        let depth = line_indent(line);
        let trimmed = line.trim_start();
        if !found_users {
            if depth == 1 && trimmed == "users:" {
                found_users = true;
            }
            continue;
        }
        if !found_user {
            if depth == 2 && trimmed == user_header {
                found_user = true;
            } else if depth <= 1 && !trimmed.is_empty() {
                return None;
            }
            continue;
        }
        if depth <= 2 && !trimmed.is_empty() {
            return None;
        }
        if depth == 3 {
            if let Some(rest) = trimmed.strip_prefix("oauth_token:") {
                return Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn whoami(token: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct U { login: String }
    let r = ureq::get("https://api.github.com/user")
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", USER_AGENT)
        .call()?;
    Ok(r.into_json::<U>()?.login)
}
