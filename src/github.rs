use hmac::{Hmac, Mac};

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, LINK, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::RwLock;

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
    app_id: u64,
    issuer: String,
    key: EncodingKey,
}

impl GithubAppJwtSigner {
    pub fn from_app_id(app_id: u64, private_key_pem: &[u8]) -> Result<Self, AppError> {
        if app_id == 0 {
            return Err(AppError::BadRequest(
                "GitHub App ID must be positive".into(),
            ));
        }
        let key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|_| AppError::BadRequest("invalid GitHub App RSA private key".into()))?;
        Ok(Self {
            app_id,
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
    #[error("invalid GitHub repository or artifact digest")]
    InvalidAttestationRequest,
    #[error("GitHub attestation response is invalid")]
    InvalidAttestationResponse,
    #[error("attestation bundle URL is not allowed")]
    UnsafeBundleUrl,
    #[error("attestation bundle exceeds size limit")]
    BundleTooLarge,
    #[error("attestation list is paginated beyond the bounded retrieval window")]
    AttestationListIncomplete,
    #[error("attestation bundle transport encoding is invalid")]
    InvalidBundleEncoding,
    #[error("attestation bundle is not valid JSON")]
    InvalidBundleJson,
    #[error("invalid GitHub check request")]
    InvalidCheckRequest,
    #[error("GitHub check response is invalid")]
    InvalidCheckResponse,
}

impl GithubApiError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport | Self::HttpStatus(429) | Self::HttpStatus(500..=599)
        )
    }

    #[must_use]
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::ClientBuild => "github_client_build",
            Self::Jwt => "github_jwt",
            Self::Transport => "github_transport",
            Self::HttpStatus(401) => "github_http_401",
            Self::HttpStatus(403) => "github_http_403",
            Self::HttpStatus(404) => "github_http_404",
            Self::HttpStatus(422) => "github_http_422",
            Self::HttpStatus(429) => "github_http_429",
            Self::HttpStatus(500..=599) => "github_http_5xx",
            Self::HttpStatus(_) => "github_http_other",
            Self::InvalidTokenResponse => "github_token_response",
            Self::InvalidAttestationRequest => "github_attestation_request",
            Self::InvalidAttestationResponse => "github_attestation_response",
            Self::UnsafeBundleUrl => "github_bundle_url",
            Self::BundleTooLarge => "github_bundle_too_large",
            Self::AttestationListIncomplete => "github_attestation_pagination",
            Self::InvalidBundleEncoding => "github_bundle_encoding",
            Self::InvalidBundleJson => "github_bundle_json",
            Self::InvalidCheckRequest => "github_check_request",
            Self::InvalidCheckResponse => "github_check_response",
        }
    }
}

#[derive(Clone)]
struct CachedInstallationToken {
    token: String,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TokenScope {
    AttestationRead,
    CheckWrite,
}

#[derive(Debug, Serialize)]
struct InstallationTokenRequest {
    repository_ids: [i64; 1],
    permissions: InstallationPermissions,
}

#[derive(Debug, Serialize)]
struct InstallationPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    attestations: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<&'static str>,
}

impl TokenScope {
    fn permissions(self) -> InstallationPermissions {
        match self {
            Self::AttestationRead => InstallationPermissions {
                attestations: Some("read"),
                checks: None,
            },
            Self::CheckWrite => InstallationPermissions {
                attestations: None,
                checks: Some("write"),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct AttestationListResponse {
    attestations: Vec<AttestationReference>,
}

#[derive(Debug, Deserialize)]
struct AttestationReference {
    repository_id: i64,
    initiator: String,
    bundle_url: String,
}

#[derive(Debug, Serialize)]
struct CreateCheckRunRequest<'a> {
    name: &'a str,
    head_sha: &'a str,
    status: &'static str,
    conclusion: &'a str,
    external_id: &'a str,
    output: CheckOutput<'a>,
}

#[derive(Debug, Serialize)]
struct CheckOutput<'a> {
    title: &'a str,
    summary: &'a str,
}

#[derive(Debug, Deserialize)]
struct CheckRunApp {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct CheckRunResponse {
    id: i64,
    external_id: Option<String>,
    app: CheckRunApp,
}

#[derive(Debug, Deserialize)]
struct CheckRunsResponse {
    check_runs: Vec<CheckRunResponse>,
}

#[derive(Debug, Serialize)]
struct CheckRunListQuery<'a> {
    check_name: &'a str,
    filter: &'static str,
    per_page: u8,
    app_id: u64,
}

#[derive(Debug, Clone)]
pub struct RawAttestationBundle {
    pub repository_id: i64,
    pub initiator: String,
    pub source_url_sha256: String,
    pub transport_encoding: String,
    pub wire_sha256: String,
    pub wire_bytes: Vec<u8>,
    pub bundle_sha256: String,
    pub raw_json: Vec<u8>,
}

#[derive(Clone)]
pub struct GithubApi {
    app_id: u64,
    client: reqwest::Client,
    signer: Arc<GithubAppJwtSigner>,
    token_cache: Arc<RwLock<HashMap<(i64, i64, TokenScope), CachedInstallationToken>>>,
    bundle_host: Arc<str>,
}

impl GithubApi {
    pub fn new(signer: GithubAppJwtSigner, bundle_host: String) -> Result<Self, GithubApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("releasegate/", env!("CARGO_PKG_VERSION"))),
        );
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| GithubApiError::ClientBuild)?;
        if bundle_host.is_empty()
            || bundle_host.eq_ignore_ascii_case("localhost")
            || bundle_host.parse::<IpAddr>().is_ok()
        {
            return Err(GithubApiError::UnsafeBundleUrl);
        }
        Ok(Self {
            app_id: signer.app_id,
            client,
            signer: Arc::new(signer),
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            bundle_host: Arc::from(bundle_host),
        })
    }

    async fn installation_token(
        &self,
        installation_id: i64,
        repository_id: i64,
        scope: TokenScope,
    ) -> Result<String, GithubApiError> {
        if installation_id <= 0 || repository_id <= 0 {
            return Err(GithubApiError::InvalidTokenResponse);
        }
        let key = (installation_id, repository_id, scope);
        let now = OffsetDateTime::now_utc();
        if let Some(cached) = self.token_cache.read().await.get(&key) {
            if cached.expires_at > now + time::Duration::seconds(TOKEN_REUSE_SAFETY_SECONDS) {
                return Ok(cached.token.clone());
            }
        }

        let jwt = self.signer.mint().map_err(|_| GithubApiError::Jwt)?;
        let url =
            format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
        let request = InstallationTokenRequest {
            repository_ids: [repository_id],
            permissions: scope.permissions(),
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

    async fn attestation_token(
        &self,
        installation_id: i64,
        repository_id: i64,
    ) -> Result<String, GithubApiError> {
        self.installation_token(installation_id, repository_id, TokenScope::AttestationRead)
            .await
    }

    async fn check_token(
        &self,
        installation_id: i64,
        repository_id: i64,
    ) -> Result<String, GithubApiError> {
        self.installation_token(installation_id, repository_id, TokenScope::CheckWrite)
            .await
    }

    pub async fn fetch_attestation_bundles(
        &self,
        installation_id: i64,
        repository_id: i64,
        repository: &str,
        artifact_sha256: &str,
    ) -> Result<Vec<RawAttestationBundle>, GithubApiError> {
        let (owner, repo) = split_repository(repository)?;
        if artifact_sha256.len() != 64 || !artifact_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GithubApiError::InvalidAttestationRequest);
        }
        let token = self
            .attestation_token(installation_id, repository_id)
            .await?;
        let digest = format!("sha256:{}", artifact_sha256.to_ascii_lowercase());
        let url = format!("https://api.github.com/repos/{owner}/{repo}/attestations/{digest}");
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .query(&[("predicate_type", "provenance"), ("per_page", "100")])
            .send()
            .await
            .map_err(|_| GithubApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(GithubApiError::HttpStatus(status.as_u16()));
        }
        if response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("rel=\"next\""))
        {
            return Err(GithubApiError::AttestationListIncomplete);
        }
        let listing: AttestationListResponse = response
            .json()
            .await
            .map_err(|_| GithubApiError::InvalidAttestationResponse)?;
        if listing.attestations.len() > 100 {
            return Err(GithubApiError::InvalidAttestationResponse);
        }

        let mut bundles = Vec::with_capacity(listing.attestations.len());
        for item in listing.attestations {
            if item.repository_id != repository_id {
                return Err(GithubApiError::InvalidAttestationResponse);
            }
            bundles.push(self.fetch_bundle(&item).await?);
        }
        bundles.sort_by(|a, b| a.bundle_sha256.cmp(&b.bundle_sha256));
        bundles.dedup_by(|a, b| a.bundle_sha256 == b.bundle_sha256);
        Ok(bundles)
    }

    pub async fn publish_check_run(
        &self,
        installation_id: i64,
        repository_id: i64,
        repository: &str,
        head_sha: &str,
        check_name: &str,
        external_id: &str,
        conclusion: &str,
        title: &str,
        summary: &str,
    ) -> Result<i64, GithubApiError> {
        let (owner, repo) = split_repository(repository)?;
        if head_sha.len() != 40
            || !head_sha.bytes().all(|b| b.is_ascii_hexdigit())
            || check_name.is_empty()
            || check_name.len() > 128
            || external_id.is_empty()
            || external_id.len() > 256
            || title.is_empty()
            || title.len() > 256
            || summary.is_empty()
            || summary.len() > 8_192
            || !matches!(conclusion, "success" | "failure" | "action_required")
        {
            return Err(GithubApiError::InvalidCheckRequest);
        }
        let token = self.check_token(installation_id, repository_id).await?;
        let list_url =
            format!("https://api.github.com/repos/{owner}/{repo}/commits/{head_sha}/check-runs");
        let existing = self
            .client
            .get(&list_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .query(&CheckRunListQuery {
                check_name,
                filter: "all",
                per_page: 100,
                app_id: self.app_id,
            })
            .send()
            .await
            .map_err(|_| GithubApiError::Transport)?;
        let status = existing.status();
        if !status.is_success() {
            return Err(GithubApiError::HttpStatus(status.as_u16()));
        }
        if existing
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("rel=\"next\""))
        {
            return Err(GithubApiError::InvalidCheckResponse);
        }
        let listed: CheckRunsResponse = existing
            .json()
            .await
            .map_err(|_| GithubApiError::InvalidCheckResponse)?;
        if let Some(check_run_id) =
            matching_check_run_id(listed.check_runs, self.app_id, external_id)
        {
            return Ok(check_run_id);
        }

        let create_url = format!("https://api.github.com/repos/{owner}/{repo}/check-runs");
        let request = CreateCheckRunRequest {
            name: check_name,
            head_sha,
            status: "completed",
            conclusion,
            external_id,
            output: CheckOutput { title, summary },
        };
        let response = self
            .client
            .post(create_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&request)
            .send()
            .await
            .map_err(|_| GithubApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(GithubApiError::HttpStatus(status.as_u16()));
        }
        let created: CheckRunResponse = response
            .json()
            .await
            .map_err(|_| GithubApiError::InvalidCheckResponse)?;
        if created.id <= 0
            || created.app.id != self.app_id
            || created.external_id.as_deref() != Some(external_id)
        {
            return Err(GithubApiError::InvalidCheckResponse);
        }
        Ok(created.id)
    }

    async fn fetch_bundle(
        &self,
        item: &AttestationReference,
    ) -> Result<RawAttestationBundle, GithubApiError> {
        const MAX_WIRE_BYTES: u64 = 4 * 1024 * 1024;
        const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;
        let url =
            reqwest::Url::parse(&item.bundle_url).map_err(|_| GithubApiError::UnsafeBundleUrl)?;
        validate_bundle_url(&url, self.bundle_host.as_ref())?;
        let pinned_addr = resolve_public_bundle_addr(self.bundle_host.as_ref()).await?;
        let bundle_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .resolve(self.bundle_host.as_ref(), pinned_addr)
            .build()
            .map_err(|_| GithubApiError::ClientBuild)?;
        let source_url_sha256 = hex::encode(Sha256::digest(item.bundle_url.as_bytes()));
        let response = bundle_client
            .get(url)
            .send()
            .await
            .map_err(|_| GithubApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(GithubApiError::HttpStatus(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_WIRE_BYTES)
        {
            return Err(GithubApiError::BundleTooLarge);
        }
        let wire = response
            .bytes()
            .await
            .map_err(|_| GithubApiError::Transport)?;
        if wire.is_empty() || wire.len() as u64 > MAX_WIRE_BYTES {
            return Err(GithubApiError::BundleTooLarge);
        }
        let wire_sha256 = hex::encode(Sha256::digest(&wire));
        let (transport_encoding, raw_json) = decode_bundle_json(&wire, MAX_DECODED_BYTES)?;
        let bundle_sha256 = hex::encode(Sha256::digest(&raw_json));
        Ok(RawAttestationBundle {
            repository_id: item.repository_id,
            initiator: item.initiator.clone(),
            source_url_sha256,
            transport_encoding: transport_encoding.to_owned(),
            wire_sha256,
            wire_bytes: wire.to_vec(),
            bundle_sha256,
            raw_json,
        })
    }
}

fn matching_check_run_id(
    runs: Vec<CheckRunResponse>,
    app_id: u64,
    external_id: &str,
) -> Option<i64> {
    runs.into_iter()
        .find(|run| {
            run.app.id == app_id && run.id > 0 && run.external_id.as_deref() == Some(external_id)
        })
        .map(|run| run.id)
}

fn decode_bundle_json(
    wire: &[u8],
    max_decoded_bytes: usize,
) -> Result<(&'static str, Vec<u8>), GithubApiError> {
    if serde_json::from_slice::<serde_json::Value>(wire).is_ok() {
        if wire.len() > max_decoded_bytes {
            return Err(GithubApiError::BundleTooLarge);
        }
        return Ok(("identity-json", wire.to_vec()));
    }

    let decoded_len =
        snap::raw::decompress_len(wire).map_err(|_| GithubApiError::InvalidBundleEncoding)?;
    if decoded_len == 0 || decoded_len > max_decoded_bytes {
        return Err(GithubApiError::BundleTooLarge);
    }
    let decoded = snap::raw::Decoder::new()
        .decompress_vec(wire)
        .map_err(|_| GithubApiError::InvalidBundleEncoding)?;
    if decoded.len() != decoded_len || decoded.len() > max_decoded_bytes {
        return Err(GithubApiError::InvalidBundleEncoding);
    }
    serde_json::from_slice::<serde_json::Value>(&decoded)
        .map_err(|_| GithubApiError::InvalidBundleJson)?;
    Ok(("snappy-raw", decoded))
}

fn split_repository(repository: &str) -> Result<(&str, &str), GithubApiError> {
    let Some((owner, repo)) = repository.split_once('/') else {
        return Err(GithubApiError::InvalidAttestationRequest);
    };
    if owner.is_empty()
        || repo.is_empty()
        || repo.contains('/')
        || !owner.bytes().all(valid_repo_byte)
        || !repo.bytes().all(valid_repo_byte)
    {
        return Err(GithubApiError::InvalidAttestationRequest);
    }
    Ok((owner, repo))
}

fn valid_repo_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

fn validate_bundle_url(url: &reqwest::Url, expected_host: &str) -> Result<(), GithubApiError> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.host_str().is_none()
    {
        return Err(GithubApiError::UnsafeBundleUrl);
    }
    let Some(host) = url.host_str() else {
        return Err(GithubApiError::UnsafeBundleUrl);
    };
    if !host.eq_ignore_ascii_case(expected_host) || host.parse::<IpAddr>().is_ok() {
        return Err(GithubApiError::UnsafeBundleUrl);
    }
    Ok(())
}

async fn resolve_public_bundle_addr(host: &str) -> Result<SocketAddr, GithubApiError> {
    let mut addrs = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| GithubApiError::Transport)?;
    let mut selected = None;
    let mut count = 0_u16;
    for addr in &mut addrs {
        count = count.saturating_add(1);
        if count > 32 || !is_public_ip(addr.ip()) {
            return Err(GithubApiError::UnsafeBundleUrl);
        }
        if selected.is_none() {
            selected = Some(addr);
        }
    }
    selected.ok_or(GithubApiError::UnsafeBundleUrl)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
    {
        return false;
    }
    // Carrier-grade NAT, benchmarking, protocol-assignment/reserved and 0/8.
    if a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && c == 0)
        || a >= 240
    {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    // Never let an IPv4 address bypass the IPv4 policy by arriving in mapped IPv6 form.
    if ip.to_ipv4_mapped().is_some() {
        return false;
    }

    let segments = ip.segments();
    // ReleaseGate egress accepts only IPv6 global-unicast space (2000::/3).
    // Special-purpose ranges inside that space remain fail-closed below.
    if (segments[0] & 0xe000) != 0x2000 {
        return false;
    }

    // IETF protocol assignments 2001:0000::/23, documentation 2001:db8::/32,
    // deprecated 6to4 2002::/16, and documentation 3fff::/20.
    if (segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use rsa::{
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        RsaPrivateKey,
    };

    use super::{
        is_public_ip, matching_check_run_id, validate_bundle_url, verify_webhook_signature,
        CheckRunApp, CheckRunResponse, GithubAppClaims, GithubAppJwtSigner,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    #[test]
    fn check_replay_is_bound_to_releasegate_app_identity() {
        let runs = vec![
            CheckRunResponse {
                id: 11,
                external_id: Some("rge_target".to_owned()),
                app: CheckRunApp { id: 999 },
            },
            CheckRunResponse {
                id: 12,
                external_id: Some("rge_other".to_owned()),
                app: CheckRunApp { id: 424242 },
            },
            CheckRunResponse {
                id: 13,
                external_id: Some("rge_target".to_owned()),
                app: CheckRunApp { id: 424242 },
            },
        ];
        assert_eq!(matching_check_run_id(runs, 424242, "rge_target"), Some(13));
    }

    #[test]
    fn bundle_url_requires_exact_configured_host() {
        let good =
            reqwest::Url::parse("https://attest.example.test/object.json").expect("url fixture");
        assert!(validate_bundle_url(&good, "attest.example.test").is_ok());
        let wrong =
            reqwest::Url::parse("https://evil.example.test/object.json").expect("url fixture");
        assert!(validate_bundle_url(&wrong, "attest.example.test").is_err());
    }

    #[test]
    fn bundle_egress_rejects_non_public_addresses() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "fc00::1".parse().expect("ipv6 fixture"),
            "fe80::1".parse().expect("ipv6 fixture"),
            "2001:db8::1".parse().expect("ipv6 fixture"),
            "2001:2::1".parse().expect("ipv6 fixture"),
            "2002::1".parse().expect("ipv6 fixture"),
            "3fff::1".parse().expect("ipv6 fixture"),
            "::ffff:127.0.0.1"
                .parse()
                .expect("ipv6 mapped loopback fixture"),
            "::ffff:8.8.8.8"
                .parse()
                .expect("ipv6 mapped public fixture"),
        ] {
            assert!(!is_public_ip(ip));
        }
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_public_ip(
            "2606:4700:4700::1111".parse().expect("public ipv6 fixture")
        ));
    }
}
