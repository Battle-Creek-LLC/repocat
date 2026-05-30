//! Thin `ureq` wrapper that carries a Bearer token — either the App JWT (during
//! minting) or the installation token (for every PR verb). Mirrors repocat's
//! GitHub client error mapping.

use anyhow::{Result, anyhow};
use serde::de::DeserializeOwned;

const USER_AGENT: &str = concat!("repobot/", env!("CARGO_PKG_VERSION"));
const API_VERSION: &str = "2022-11-28";

pub struct Client {
    token: String,
}

impl Client {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    fn request(&self, method: &str, url: &str, accept: &str) -> ureq::Request {
        ureq::request(method, url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", accept)
            .set("X-GitHub-Api-Version", API_VERSION)
            .set("User-Agent", USER_AGENT)
    }

    fn url(path: &str) -> String {
        format!("https://api.github.com{path}")
    }

    /// GET a path and decode the JSON body into `T`.
    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = Self::url(path);
        let resp = self
            .request("GET", &url, "application/vnd.github+json")
            .call()
            .map_err(|e| map_err("GET", &url, e))?;
        resp.into_json()
            .map_err(|e| anyhow!("decoding GET {url} response: {e}"))
    }

    /// GET a path with a custom `Accept` (e.g. the diff media type) as raw text.
    pub fn get_text(&self, path: &str, accept: &str) -> Result<String> {
        let url = Self::url(path);
        let resp = self
            .request("GET", &url, accept)
            .call()
            .map_err(|e| map_err("GET", &url, e))?;
        resp.into_string()
            .map_err(|e| anyhow!("reading GET {url} response: {e}"))
    }

    /// GET every page of a list endpoint, following `Link: rel="next"`.
    /// Used by `pr files`/`pr comments` so a large PR is fully covered — anchor
    /// validation must not miss files that fall on a later page.
    pub fn get_paginated_json<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut next = Some(format!("{}{sep}per_page=100", Self::url(path)));
        let mut out = Vec::new();
        while let Some(url) = next {
            let resp = self
                .request("GET", &url, "application/vnd.github+json")
                .call()
                .map_err(|e| map_err("GET", &url, e))?;
            let link = resp.header("Link").map(str::to_string);
            let page: Vec<T> = resp
                .into_json()
                .map_err(|e| anyhow!("decoding GET {url} response: {e}"))?;
            out.extend(page);
            next = link.as_deref().and_then(parse_next_link);
        }
        Ok(out)
    }

    /// POST a JSON body and decode the JSON response into `T`.
    pub fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let url = Self::url(path);
        let resp = self
            .request("POST", &url, "application/vnd.github+json")
            .send_json(body.clone())
            .map_err(|e| map_err("POST", &url, e))?;
        resp.into_json()
            .map_err(|e| anyhow!("decoding POST {url} response: {e}"))
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

/// Extract the `rel="next"` URL from an RFC 5988 `Link` header, if present.
fn parse_next_link(link_header: &str) -> Option<String> {
    for part in link_header.split(',') {
        let mut segs = part.split(';');
        let url = segs
            .next()?
            .trim()
            .strip_prefix('<')?
            .strip_suffix('>')?
            .to_string();
        if segs.any(|attr| attr.trim() == "rel=\"next\"") {
            return Some(url);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_next_link() {
        let h = "<https://api.github.com/x?page=2>; rel=\"next\", \
                 <https://api.github.com/x?page=5>; rel=\"last\"";
        assert_eq!(
            parse_next_link(h).as_deref(),
            Some("https://api.github.com/x?page=2")
        );
    }

    #[test]
    fn no_next_link_on_last_page() {
        let h = "<https://api.github.com/x?page=1>; rel=\"prev\", \
                 <https://api.github.com/x?page=1>; rel=\"first\"";
        assert_eq!(parse_next_link(h), None);
    }
}
