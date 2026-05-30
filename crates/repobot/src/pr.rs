//! PR read verbs: show, diff, files, comments. Every call authenticates as the
//! bot via the installation token already held by the `Client`.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::client::Client;

/// A changed file from `GET /pulls/{n}/files`. Shared with `review` so anchor
/// validation reads the same patches `pr files` reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedFile {
    pub filename: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub additions: u64,
    #[serde(default)]
    pub deletions: u64,
    /// Absent for binary files and files too large for GitHub to diff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    /// Every other field GitHub returns (`previous_filename`, `changes`, `sha`,
    /// the `*_url`s, …), kept so `pr files --json` round-trips the full object.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub fn show(client: &Client, org: &str, repo: &str, pr: u64, json: bool) -> Result<()> {
    let v: serde_json::Value = client.get_json(&format!("/repos/{org}/{repo}/pulls/{pr}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    let nested = |a: &str, b: &str| {
        v.get(a)
            .and_then(|x| x.get(b))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    println!("#{pr} {}", s("title"));
    println!("author:    {}", nested("user", "login"));
    println!("state:     {}", s("state"));
    println!(
        "mergeable: {}",
        v.get("mergeable")
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    println!("base:      {}", nested("base", "sha"));
    println!("head:      {}", nested("head", "sha"));
    let labels: Vec<&str> = v
        .get("labels")
        .and_then(|l| l.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("name").and_then(|n| n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    println!("labels:    {}", labels.join(", "));
    if let Some(body) = v.get("body").and_then(|x| x.as_str()) {
        if !body.is_empty() {
            println!("\n{body}");
        }
    }
    Ok(())
}

pub fn diff(client: &Client, org: &str, repo: &str, pr: u64) -> Result<()> {
    let text = client.get_text(
        &format!("/repos/{org}/{repo}/pulls/{pr}"),
        "application/vnd.github.v3.diff",
    )?;
    print!("{text}");
    Ok(())
}

/// GitHub caps the PR files endpoint at this many entries.
const FILES_ENDPOINT_CAP: usize = 3000;

/// Fetch all changed files (paginated). Reused by `review` for anchoring.
pub fn fetch_files(client: &Client, org: &str, repo: &str, pr: u64) -> Result<Vec<ChangedFile>> {
    let files: Vec<ChangedFile> =
        client.get_paginated_json(&format!("/repos/{org}/{repo}/pulls/{pr}/files"))?;
    // Beyond the cap GitHub silently truncates the list; warn so a rejected
    // inline comment on an omitted file isn't mistaken for a bad anchor.
    if files.len() >= FILES_ENDPOINT_CAP {
        eprintln!(
            "warning: GitHub caps the changed-files list at {FILES_ENDPOINT_CAP}; this PR \
             reached that limit, so some files may be omitted and inline comments on them \
             will be rejected as not in the diff"
        );
    }
    Ok(files)
}

pub fn files(client: &Client, org: &str, repo: &str, pr: u64, json: bool) -> Result<()> {
    let files = fetch_files(client, org, repo, pr)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&files)?);
        return Ok(());
    }
    if files.is_empty() {
        println!("(no changed files)");
    }
    for f in &files {
        println!(
            "{:<9} +{:<5} -{:<5} {}",
            f.status, f.additions, f.deletions, f.filename
        );
    }
    Ok(())
}

pub fn comments(client: &Client, org: &str, repo: &str, pr: u64, json: bool) -> Result<()> {
    let comments: Vec<serde_json::Value> =
        client.get_paginated_json(&format!("/repos/{org}/{repo}/pulls/{pr}/comments"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&comments)?);
        return Ok(());
    }
    if comments.is_empty() {
        println!("(no review comments)");
    }
    for c in &comments {
        let get = |k: &str| c.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let id = c.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
        let login = c
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let path = get("path");
        // Outdated comments (after a force-push) carry line=null with the anchor
        // in original_line; fall back to it so the location isn't lost.
        let line = c.get("line").and_then(|x| x.as_u64());
        let original = c.get("original_line").and_then(|x| x.as_u64());
        match line.or(original) {
            Some(l) => {
                let tag = if line.is_none() { " (outdated)" } else { "" };
                println!("[{id}] {login} {path}:{l}{tag}");
            }
            None => println!("[{id}] {login} {path}"),
        }
        let body = get("body");
        if !body.is_empty() {
            println!("    {}", body.replace('\n', "\n    "));
        }
    }
    Ok(())
}
