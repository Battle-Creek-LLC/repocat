//! GitLab REST client (`/api/v4`). Auth via the `PRIVATE-TOKEN` header,
//! projects addressed by URL-encoded path, list endpoints paginated. The base
//! URL and TLS posture come from the resolved `glab` credentials.

use anyhow::{anyhow, Result};
use serde::{de::DeserializeOwned, Deserialize};
use std::sync::Arc;

use super::auth::{Creds, USER_AGENT};

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct Client {
    base_url: String,
    token: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(creds: &Creds) -> Self {
        let agent = if creds.skip_tls_verify {
            eprintln!(
                "warning: TLS verification disabled for {} (per glab config skip_tls_verify)",
                creds.host
            );
            insecure_agent()
        } else {
            ureq::agent()
        };
        Self { base_url: creds.base_url.clone(), token: creds.token.clone(), agent }
    }

    fn req(&self, method: &str, url: &str) -> ureq::Request {
        self.agent
            .request(method, url)
            .set("PRIVATE-TOKEN", &self.token)
            .set("User-Agent", USER_AGENT)
    }

    fn get(&self, path: &str) -> Result<ureq::Response> {
        let url = format!("{}{path}", self.base_url);
        self.req("GET", &url).call().map_err(|e| map_err("GET", &url, e))
    }

    /// `Some` on 200, `None` on 404, `Err` otherwise.
    fn get_optional(&self, path: &str) -> Result<Option<ureq::Response>> {
        let url = format!("{}{path}", self.base_url);
        match self.req("GET", &url).call() {
            Ok(r) => Ok(Some(r)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(map_err("GET", &url, e)),
        }
    }

    /// Collect every page of a list endpoint (`?per_page=100&page=N`, following
    /// the `X-Next-Page` header).
    fn get_all<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!("{}{path}?per_page=100&page={page}", self.base_url);
            let r = self.req("GET", &url).call().map_err(|e| map_err("GET", &url, e))?;
            let next = r.header("x-next-page").unwrap_or("").trim().to_string();
            let batch: Vec<T> = r.into_json()?;
            out.extend(batch);
            match next.parse::<u32>() {
                Ok(n) if n > 0 => page = n,
                _ => break,
            }
        }
        Ok(out)
    }

    pub fn whoami(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct U {
            username: String,
        }
        Ok(self.get("/user")?.into_json::<U>()?.username)
    }

    pub fn get_project(&self, project: &str) -> Result<Project> {
        Ok(self.get(&format!("/projects/{}", urlencode(project)))?.into_json()?)
    }

    pub fn list_protected_branches(&self, project: &str) -> Result<Vec<ProtectedBranch>> {
        self.get_all(&format!("/projects/{}/protected_branches", urlencode(project)))
    }

    pub fn list_approval_rules(&self, project: &str) -> Result<Vec<ApprovalRule>> {
        self.get_all(&format!("/projects/{}/approval_rules", urlencode(project)))
    }

    pub fn get_approvals_config(&self, project: &str) -> Result<ApprovalsConfig> {
        Ok(self.get(&format!("/projects/{}/approvals", urlencode(project)))?.into_json()?)
    }

    /// `Ok(None)` when no push rule is set (404). A 403 (feature gated on the
    /// instance tier) is surfaced as an error the caller maps to `Skip`.
    pub fn get_push_rule(&self, project: &str) -> Result<Option<PushRule>> {
        match self.get_optional(&format!("/projects/{}/push_rule", urlencode(project)))? {
            Some(r) => Ok(Some(r.into_json()?)),
            None => Ok(None),
        }
    }

    pub fn file_exists(&self, project: &str, file_path: &str, git_ref: &str) -> Result<bool> {
        let path = format!(
            "/projects/{}/repository/files/{}?ref={}",
            urlencode(project),
            urlencode(file_path),
            urlencode(git_ref),
        );
        Ok(self.get_optional(&path)?.is_some())
    }

    pub fn get_file_raw(&self, project: &str, file_path: &str, git_ref: &str) -> Result<Option<String>> {
        let path = format!(
            "/projects/{}/repository/files/{}/raw?ref={}",
            urlencode(project),
            urlencode(file_path),
            urlencode(git_ref),
        );
        match self.get_optional(&path)? {
            Some(r) => Ok(Some(r.into_string()?)),
            None => Ok(None),
        }
    }

    pub fn list_direct_members(&self, project: &str) -> Result<Vec<Member>> {
        self.get_all(&format!("/projects/{}/members", urlencode(project)))
    }
}

fn map_err(method: &str, url: &str, e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(code, r) => {
            let body = r.into_string().unwrap_or_default();
            anyhow!("{method} {url} → {code}: {body}")
        }
        other => anyhow!("transport error on {method} {url}: {other}"),
    }
}

// --- response types ------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Project {
    pub default_branch: Option<String>,
    pub merge_method: Option<String>,
    pub squash_option: Option<String>,
    pub remove_source_branch_after_merge: Option<bool>,
    pub only_allow_merge_if_pipeline_succeeds: Option<bool>,
    pub only_allow_merge_if_all_discussions_are_resolved: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ProtectedBranch {
    pub name: String,
    pub allow_force_push: Option<bool>,
    pub code_owner_approval_required: Option<bool>,
    #[serde(default)]
    pub push_access_levels: Vec<AccessLevelEntry>,
    #[serde(default)]
    pub merge_access_levels: Vec<AccessLevelEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AccessLevelEntry {
    pub access_level: i64,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalRule {
    pub name: String,
    pub approvals_required: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalsConfig {
    pub reset_approvals_on_push: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PushRule {
    pub reject_unsigned_commits: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Member {
    pub username: String,
    pub access_level: i64,
}

// --- TLS ------------------------------------------------------------------

/// A ureq agent that does not verify server certificates. Used only when the
/// resolved `glab` host has `skip_tls_verify`/`skip_ssl_verify` set — the same
/// per-host decision the user already made for `glab` (see [`super::auth`]).
fn insecure_agent() -> ureq::Agent {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    ureq::AgentBuilder::new().tls_config(Arc::new(config)).build()
}

#[derive(Debug)]
struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}
