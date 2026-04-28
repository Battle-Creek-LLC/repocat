use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;

use crate::auth::user_agent;

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct Client {
    token: String,
}

impl Client {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    fn get(&self, path: &str) -> Result<ureq::Response> {
        let url = format!("https://api.github.com{path}");
        ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", user_agent())
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => {
                    let body = r.into_string().unwrap_or_default();
                    anyhow!("GET {url} → {code}: {body}")
                }
                other => anyhow!("transport error on GET {url}: {other}"),
            })
    }

    /// Returns Some(response) on 200, None on 404, Err on anything else.
    fn get_optional(&self, path: &str) -> Result<Option<ureq::Response>> {
        let url = format!("https://api.github.com{path}");
        match ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", user_agent())
            .call()
        {
            Ok(r) => Ok(Some(r)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                Err(anyhow!("GET {url} → {code}: {body}"))
            }
            Err(other) => Err(anyhow!("transport error on GET {url}: {other}")),
        }
    }

    fn send_json(&self, method: &str, path: &str, body: &serde_json::Value) -> Result<ureq::Response> {
        let url = format!("https://api.github.com{path}");
        ureq::request(method, &url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", user_agent())
            .send_json(body.clone())
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => {
                    let body = r.into_string().unwrap_or_default();
                    anyhow!("{method} {url} → {code}: {body}")
                }
                other => anyhow!("transport error on {method} {url}: {other}"),
            })
    }

    pub fn patch_repo(&self, org: &str, repo: &str, body: &serde_json::Value) -> Result<()> {
        self.send_json("PATCH", &format!("/repos/{org}/{repo}"), body)?;
        Ok(())
    }

    pub fn put_json(&self, path: &str, body: &serde_json::Value) -> Result<()> {
        self.send_json("PUT", path, body)?;
        Ok(())
    }

    /// Resolves the latest release tag of an action repo to its commit SHA.
    /// Used to SHA-pin scaffolded workflow `uses:` lines.
    pub fn latest_action_sha(&self, owner: &str, repo: &str) -> Result<String> {
        let release: ReleaseRef = self
            .get(&format!("/repos/{owner}/{repo}/releases/latest"))?
            .into_json()?;
        let commit: CommitRef = self
            .get(&format!("/repos/{owner}/{repo}/commits/{}", release.tag_name))?
            .into_json()?;
        Ok(commit.sha)
    }

    /// Creates a new file in the repo on the default branch via the contents API.
    /// Errors if the file already exists (the contents API requires `sha` for updates,
    /// and we deliberately don't supply one to avoid clobbering user content).
    pub fn create_file(
        &self,
        org: &str,
        repo: &str,
        path: &str,
        content: &str,
        commit_message: &str,
    ) -> Result<()> {
        let encoded_path = path.split('/').map(urlencode).collect::<Vec<_>>().join("/");
        let endpoint = format!("/repos/{org}/{repo}/contents/{encoded_path}");
        let body = serde_json::json!({
            "message": commit_message,
            "content": B64.encode(content.as_bytes()),
        });
        self.send_json("PUT", &endpoint, &body)?;
        Ok(())
    }

    pub fn get_workflow_permissions(&self, org: &str, repo: &str) -> Result<WorkflowPermissions> {
        let path = format!("/repos/{org}/{repo}/actions/permissions/workflow");
        Ok(self.get(&path)?.into_json()?)
    }

    pub fn required_signatures_enabled(&self, org: &str, repo: &str, branch: &str) -> Result<bool> {
        let path = format!("/repos/{org}/{repo}/branches/{branch}/protection/required_signatures");
        let Some(resp) = self.get_optional(&path)? else { return Ok(false); };
        let payload: RequiredSignatures = resp.into_json()?;
        Ok(payload.enabled)
    }

    pub fn post_no_body(&self, path: &str) -> Result<()> {
        let url = format!("https://api.github.com{path}");
        ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", user_agent())
            .set("Content-Length", "0")
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => {
                    let body = r.into_string().unwrap_or_default();
                    anyhow!("POST {url} → {code}: {body}")
                }
                other => anyhow!("transport error on POST {url}: {other}"),
            })?;
        Ok(())
    }

    pub fn put_no_body(&self, path: &str) -> Result<()> {
        let url = format!("https://api.github.com{path}");
        ureq::put(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", user_agent())
            .set("Content-Length", "0")
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => {
                    let body = r.into_string().unwrap_or_default();
                    anyhow!("PUT {url} → {code}: {body}")
                }
                other => anyhow!("transport error on PUT {url}: {other}"),
            })?;
        Ok(())
    }

    pub fn vulnerability_alerts_enabled(&self, org: &str, repo: &str) -> Result<bool> {
        let path = format!("/repos/{org}/{repo}/vulnerability-alerts");
        Ok(self.get_optional(&path)?.is_some())
    }

    pub fn automated_security_fixes_enabled(&self, org: &str, repo: &str) -> Result<bool> {
        let path = format!("/repos/{org}/{repo}/automated-security-fixes");
        let Some(resp) = self.get_optional(&path)? else { return Ok(false); };
        let payload: AutomatedSecurityFixes = resp.into_json()?;
        Ok(payload.enabled && !payload.paused)
    }

    pub fn put_branch_protection(
        &self,
        org: &str,
        repo: &str,
        branch: &str,
        body: &serde_json::Value,
    ) -> Result<()> {
        self.send_json(
            "PUT",
            &format!("/repos/{org}/{repo}/branches/{branch}/protection"),
            body,
        )?;
        Ok(())
    }

    pub fn get_repo(&self, org: &str, repo: &str) -> Result<Repo> {
        Ok(self.get(&format!("/repos/{org}/{repo}"))?.into_json()?)
    }

    /// Lists entries in a directory. Returns empty Vec if the path doesn't exist.
    pub fn list_direct_collaborators(&self, org: &str, repo: &str) -> Result<Vec<Collaborator>> {
        let path = format!("/repos/{org}/{repo}/collaborators?affiliation=direct&per_page=100");
        Ok(self.get(&path)?.into_json()?)
    }

    pub fn list_repo_teams(&self, org: &str, repo: &str) -> Result<Vec<RepoTeam>> {
        let path = format!("/repos/{org}/{repo}/teams?per_page=100");
        Ok(self.get(&path)?.into_json()?)
    }

    pub fn list_directory(&self, org: &str, repo: &str, path: &str) -> Result<Vec<DirEntry>> {
        let encoded = path.split('/').map(urlencode).collect::<Vec<_>>().join("/");
        let endpoint = format!("/repos/{org}/{repo}/contents/{encoded}");
        let Some(resp) = self.get_optional(&endpoint)? else { return Ok(Vec::new()); };
        Ok(resp.into_json()?)
    }

    pub fn path_exists(&self, org: &str, repo: &str, path: &str) -> Result<bool> {
        let encoded = path.split('/').map(urlencode).collect::<Vec<_>>().join("/");
        let endpoint = format!("/repos/{org}/{repo}/contents/{encoded}");
        Ok(self.get_optional(&endpoint)?.is_some())
    }

    /// Returns Some(decoded text) if the path is a file, None if 404.
    /// Errors if the path resolves to a directory or if base64 decode fails.
    pub fn get_file_content(&self, org: &str, repo: &str, path: &str) -> Result<Option<String>> {
        let encoded = path.split('/').map(urlencode).collect::<Vec<_>>().join("/");
        let endpoint = format!("/repos/{org}/{repo}/contents/{encoded}");
        let Some(resp) = self.get_optional(&endpoint)? else { return Ok(None); };
        let payload: ContentPayload = resp.into_json()?;
        let bytes = B64.decode(payload.content.replace('\n', ""))
            .map_err(|e| anyhow!("base64 decode of {path}: {e}"))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    pub fn get_branch_protection(
        &self,
        org: &str,
        repo: &str,
        branch: &str,
    ) -> Result<Option<BranchProtection>> {
        let path = format!("/repos/{org}/{repo}/branches/{branch}/protection");
        let Some(resp) = self.get_optional(&path)? else { return Ok(None); };
        Ok(Some(resp.into_json()?))
    }
}

#[derive(Debug, Deserialize)]
struct ContentPayload {
    content: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseRef {
    tag_name: String,
}

#[derive(Debug, Deserialize)]
struct CommitRef {
    sha: String,
}

#[derive(Debug, Deserialize)]
pub struct Collaborator {
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct RepoTeam {
    pub slug: String,
    pub name: String,
    pub permission: String,
}

#[derive(Debug, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
struct RequiredSignatures {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct WorkflowPermissions {
    pub default_workflow_permissions: String,
    pub can_approve_pull_request_reviews: bool,
}

#[derive(Debug, Deserialize)]
struct AutomatedSecurityFixes {
    enabled: bool,
    #[serde(default)]
    paused: bool,
}

#[derive(Debug, Deserialize)]
pub struct Repo {
    pub full_name: String,
    pub default_branch: String,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub allow_squash_merge: Option<bool>,
    #[serde(default)]
    pub allow_merge_commit: Option<bool>,
    #[serde(default)]
    pub allow_rebase_merge: Option<bool>,
    #[serde(default)]
    pub delete_branch_on_merge: Option<bool>,
    #[serde(default)]
    pub security_and_analysis: Option<SecurityAndAnalysis>,
}

#[derive(Debug, Deserialize)]
pub struct SecurityAndAnalysis {
    #[serde(default)]
    pub secret_scanning: Option<Toggle>,
    #[serde(default)]
    pub secret_scanning_push_protection: Option<Toggle>,
    #[serde(default)]
    pub dependency_graph: Option<Toggle>,
}

#[derive(Debug, Deserialize)]
pub struct Toggle {
    #[serde(default)]
    pub status: Option<String>,
}

impl Toggle {
    pub fn is_enabled(&self) -> bool {
        self.status.as_deref() == Some("enabled")
    }
}

#[derive(Debug, Deserialize)]
pub struct BranchProtection {
    #[serde(default)]
    pub required_pull_request_reviews: Option<RequiredReviews>,
    #[serde(default)]
    pub required_linear_history: Option<Enabled>,
    #[serde(default)]
    pub required_conversation_resolution: Option<Enabled>,
    #[serde(default)]
    pub allow_force_pushes: Option<Enabled>,
    #[serde(default)]
    pub allow_deletions: Option<Enabled>,
    #[serde(default)]
    pub required_status_checks: Option<RequiredStatusChecks>,
}

#[derive(Debug, Deserialize)]
pub struct RequiredReviews {
    #[serde(default)]
    pub required_approving_review_count: Option<u32>,
    #[serde(default)]
    pub dismiss_stale_reviews: Option<bool>,
    #[serde(default)]
    pub require_code_owner_reviews: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Enabled {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct RequiredStatusChecks {
    #[serde(default)]
    pub contexts: Vec<String>,
}
