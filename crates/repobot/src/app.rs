//! GitHub App auth: build an RS256 JWT from the App's private key, then exchange
//! it for a short-lived installation token. The token is minted in-process and
//! passed to the HTTP client directly — it never appears on a command line.

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::Client;
use crate::config::Config;

#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: u64,
}

/// `iat` backdated 60s for clock skew; `exp` at +540s (GitHub caps App JWTs at
/// 10 min — we stay comfortably under).
fn build_claims(app_id: u64, now: u64) -> Claims {
    Claims {
        iat: now - 60,
        exp: now + 540,
        iss: app_id,
    }
}

fn sign_jwt(claims: &Claims, pem: &[u8]) -> Result<String> {
    let key = EncodingKey::from_rsa_pem(pem)
        .context("parsing RSA private key PEM (expected an RS256 PKCS#1/PKCS#8 key)")?;
    encode(&Header::new(Algorithm::RS256), claims, &key).context("signing app JWT")
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs())
}

fn app_jwt(cfg: &Config) -> Result<String> {
    let pem = std::fs::read(&cfg.private_key)
        .with_context(|| format!("reading private key {}", cfg.private_key.display()))?;
    sign_jwt(&build_claims(cfg.app_id, now_secs()?), &pem)
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct AccessToken {
    token: String,
}

/// Full flow: JWT → installation id for `org/repo` → installation access token.
/// The returned token authenticates every PR read/write verb.
pub fn mint_installation_token(cfg: &Config, org: &str, repo: &str) -> Result<String> {
    let app = Client::new(app_jwt(cfg)?);
    let inst: Installation = app
        .get_json(&format!("/repos/{org}/{repo}/installation"))
        .with_context(|| {
            format!("looking up app installation for {org}/{repo} (is the app installed there?)")
        })?;
    let tok: AccessToken = app
        .post_json(
            &format!("/app/installations/{}/access_tokens", inst.id),
            &serde_json::json!({}),
        )
        .context("minting installation access token")?;
    Ok(tok.token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_carry_skew_and_cap() {
        let c = build_claims(3858237, 1_000_000);
        assert_eq!(c.iat, 1_000_000 - 60);
        assert_eq!(c.exp, 1_000_000 + 540);
        assert_eq!(c.iss, 3858237);
    }

    #[test]
    fn signs_rs256_jwt_verifiable_by_public_key() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};

        // Throwaway key generated in-test — never the real App key.
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate test key");
        let priv_pem = private.to_pkcs1_pem(LineEnding::LF).unwrap();
        let pub_pem = private
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .unwrap();

        let claims = build_claims(42, 2_000_000);
        let token = sign_jwt(&claims, priv_pem.as_bytes()).unwrap();

        // Header announces RS256.
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);

        // Signature + claims verify against the matching public key.
        use jsonwebtoken::{DecodingKey, Validation};
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_exp = false; // exp is a fixed test instant, not "now"
        v.required_spec_claims.clear();
        let key = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        let data = jsonwebtoken::decode::<std::collections::HashMap<String, u64>>(
            &token, &key, &v,
        )
        .unwrap();
        assert_eq!(data.claims["iss"], 42);
        assert_eq!(data.claims["iat"], 2_000_000 - 60);
        assert_eq!(data.claims["exp"], 2_000_000 + 540);
    }

    #[test]
    fn rejects_non_rsa_pem() {
        let e = sign_jwt(&build_claims(1, 1000), b"not a pem").unwrap_err();
        assert!(e.to_string().contains("RSA private key"), "got: {e}");
    }
}
