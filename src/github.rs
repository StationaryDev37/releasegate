use hmac::{Hmac, Mac};

use std::{collections::HashMap, sync::Arc, time::Duration};

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use tokio::sync::RwLock;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

const JWT_BACKDATE_SECONDS: i64 = 60;
const JWT_LIFETIME_SECONDS: i64 = 9 * 60;

pub fn verify_webhook_signature(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(provided) = hex::decode(hex_sig) else {
        return false;
    };
    if provided.len() != 32 {
        return false;
    }

    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided.as_slice()).into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GithubAppClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Clone)]
pub struct GithubAppJwtSigner {
    issuer: String,
    key: EncodingKey,
}

impl GithubAppJwtSigner {
    pub fn from_app_id(app_id: u64, private_key_pem: &[u8]) -> Result<Self, AppError> {
        if app_id == 0 {
            return Err(AppError::BadRequest("GitHub App ID must be positive".into()));
        }
        let key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|_| AppError::BadRequest("invalid GitHub App RSA private key".into()))?;
        Ok(Self {
            issuer: app_id.to_string(),
            key,
        })
    }

    pub fn mint(&self) -> Result<String, AppError> {
        self.mint_at(time::OffsetDateTime::now_utc().unix_timestamp())
    }

    fn mint_at(&self, now_unix: i64) -> Result<String, AppError> {
        let claims = GithubAppClaims {
            iat: now_unix - JWT_BACKDATE_SECONDS,
            exp: now_unix + JWT_LIFETIME_SECONDS,
            iss: self.issuer.clone(),
        };
        encode(&Header::new(Algorithm::RS256), &claims, &self.key)
            .map_err(|_| AppError::BadRequest("failed to sign GitHub App JWT".into()))
    }
}


const GITHUB_API_VERSION: &str = "2026-03-10";
const TOKEN_REUSE_SAFETY_SECONDS: i64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum GithubApiError {
    #[error("failed to build GitHub HTTP client")]
    ClientBuild,
    #[error("failed to mint GitHub App JWT")]
    Jwt,
    #[error("GitHub API request failed")]
    Transport,
    #[error("GitHub API returned HTTP {0}")]
    HttpStatus(u16),
    #[error("GitHub API returned an invalid installation token response")]
    InvalidTokenResponse,
}

#[derive(Clone)]
struct CachedInstallationToken {
    token: String,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct InstallationTokenRequest {
    repository_ids: [i64; 1],
    permissions: InstallationPermissions,
}

#[derive(Debug, Serialize)]
struct InstallationPermissions {
    attestations: &'static str,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

#[derive(Clone)]
pub struct GithubApi {
    client: reqwest::Client,
    signer: Arc<GithubAppJwtSigner>,
    token_cache: Arc<RwLock<HashMap<(i64, i64), CachedInstallationToken>>>,
}

impl GithubApi {
    pub fn new(signer: GithubAppJwtSigner) -> Result<Self, GithubApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        headers.insert(USER_AGENT, HeaderValue::from_static("releasegate/0.2"));
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| GithubApiError::ClientBuild)?;
        Ok(Self {
            client,
            signer: Arc::new(signer),
            token_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn installation_token(
        &self,
        installation_id: i64,
        repository_id: i64,
    ) -> Result<String, GithubApiError> {
        if installation_id <= 0 || repository_id <= 0 {
            return Err(GithubApiError::InvalidTokenResponse);
        }
        let key = (installation_id, repository_id);
        let now = OffsetDateTime::now_utc();
        if let Some(cached) = self.token_cache.read().await.get(&key) {
            if cached.expires_at > now + time::Duration::seconds(TOKEN_REUSE_SAFETY_SECONDS) {
                return Ok(cached.token.clone());
            }
        }

        let jwt = self.signer.mint().map_err(|_| GithubApiError::Jwt)?;
        let url = format!(
            "https://api.github.com/app/installations/{installation_id}/access_tokens"
        );
        let request = InstallationTokenRequest {
            repository_ids: [repository_id],
            permissions: InstallationPermissions {
                attestations: "read",
            },
        };
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .json(&request)
            .send()
            .await
            .map_err(|_| GithubApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(GithubApiError::HttpStatus(status.as_u16()));
        }
        let body: InstallationTokenResponse = response
            .json()
            .await
            .map_err(|_| GithubApiError::InvalidTokenResponse)?;
        let expires_at = OffsetDateTime::parse(&body.expires_at, &Rfc3339)
            .map_err(|_| GithubApiError::InvalidTokenResponse)?;
        if body.token.is_empty() || expires_at <= now {
            return Err(GithubApiError::InvalidTokenResponse);
        }

        self.token_cache.write().await.insert(
            key,
            CachedInstallationToken {
                token: body.token.clone(),
                expires_at,
            },
        );
        Ok(body.token)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    };

    use super::{GithubAppClaims, GithubAppJwtSigner, verify_webhook_signature};

    #[test]
    fn accepts_known_github_vector() {
        let secret = b"It's a Secret to Everybody";
        let payload = b"Hello, World!";
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(verify_webhook_signature(secret, payload, sig));
    }

    #[test]
    fn rejects_modified_payload() {
        let secret = b"It's a Secret to Everybody";
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(!verify_webhook_signature(secret, b"Hello, World?", sig));
    }

    #[test]
    fn mints_rs256_jwt_with_bounded_claims() {
        let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("deterministic RSA fixture");
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private key");
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key");

        let signer = GithubAppJwtSigner::from_app_id(123_456, private_pem.as_bytes())
            .expect("create signer");
        let now = 1_900_000_000_i64;
        let token = signer.mint_at(now).expect("mint JWT");

        let header = decode_header(&token).expect("decode JWT header");
        assert_eq!(header.alg, Algorithm::RS256);

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let decoded = decode::<GithubAppClaims>(
            &token,
            &DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("decode public key"),
            &validation,
        )
        .expect("verify JWT signature");

        assert_eq!(decoded.claims.iss, "123456");
        assert_eq!(decoded.claims.iat, now - 60);
        assert_eq!(decoded.claims.exp, now + (9 * 60));
        assert!(decoded.claims.exp - decoded.claims.iat <= 10 * 60);
    }
}
