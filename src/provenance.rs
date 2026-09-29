use sqlx::SqlitePool;

use crate::{
    error::AppError,
    github::{GithubApi, GithubApiError, RawAttestationBundle},
    store,
};

#[derive(Debug, thiserror::Error)]
pub enum ProvenanceGateError {
    #[error("GitHub attestation retrieval failed: {0}")]
    Github(#[from] GithubApiError),
    #[error("attestation persistence failed")]
    Store(#[from] AppError),
}

pub async fn retrieve_and_store(
    github: &GithubApi,
    db: &SqlitePool,
    installation_id: i64,
    repository_id: i64,
    repository: &str,
    artifact_sha256: &str,
) -> Result<Vec<RawAttestationBundle>, ProvenanceGateError> {
    let bundles = github
        .fetch_attestation_bundles(
            installation_id,
            repository_id,
            repository,
            artifact_sha256,
        )
        .await?;
    for bundle in &bundles {
        store::store_attestation_bundle(
            db,
            installation_id,
            repository_id,
            repository,
            artifact_sha256,
            &bundle.initiator,
            &bundle.source_url_sha256,
            &bundle.transport_encoding,
            &bundle.wire_sha256,
            &bundle.wire_bytes,
            &bundle.bundle_sha256,
            &bundle.raw_json,
        )
        .await?;
    }
    Ok(bundles)
}
