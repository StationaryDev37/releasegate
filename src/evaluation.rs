use std::{fs::File, io::Read, path::PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{error::AppError, policy::{ReleasePolicy, TrustedSourceContext}};

const EVALUATION_SCHEMA_VERSION: &str = "releasegate-evaluation-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct EvaluationContext {
    pub evaluation_id: String,
    pub installation_id: i64,
    pub repository_id: i64,
    pub repository: String,
    pub source_delivery_id: String,
    pub source_ref: String,
    pub source_commit_sha: String,
    pub policy_sha256: String,
    pub artifact_sha256: String,
    pub trust_snapshot_sha256: String,
    pub verifier_build_sha256: String,
    pub created_at: String,
}

impl EvaluationContext {
    pub fn freeze(
        source: &TrustedSourceContext,
        policy: &ReleasePolicy,
        artifact_sha256: &str,
        trust_snapshot_sha256: &str,
        verifier_build_sha256: &str,
        created_at: String,
    ) -> Result<Self, AppError> {
        if source.installation_id != policy.installation_id
            || source.repository_id != policy.repository_id
            || source.repository != policy.repository
        {
            return Err(AppError::Conflict(
                "source and policy identities do not describe the same repository".into(),
            ));
        }
        for (name, digest) in [
            ("artifact_sha256", artifact_sha256),
            ("policy_sha256", policy.policy_sha256.as_str()),
            ("trust_snapshot_sha256", trust_snapshot_sha256),
            ("verifier_build_sha256", verifier_build_sha256),
        ] {
            if !is_sha256(digest) {
                return Err(AppError::BadRequest(format!(
                    "{name} must be exactly 64 hexadecimal characters"
                )));
            }
        }
        let artifact_sha256 = artifact_sha256.to_ascii_lowercase();
        let trust_snapshot_sha256 = trust_snapshot_sha256.to_ascii_lowercase();
        let verifier_build_sha256 = verifier_build_sha256.to_ascii_lowercase();
        let commitment = digest_join(&[
            EVALUATION_SCHEMA_VERSION,
            &source.installation_id.to_string(),
            &source.repository_id.to_string(),
            &source.repository,
            &source.delivery_id,
            &source.source_ref,
            &source.source_commit_sha.to_ascii_lowercase(),
            &policy.policy_sha256,
            &artifact_sha256,
            &trust_snapshot_sha256,
            &verifier_build_sha256,
        ]);
        Ok(Self {
            evaluation_id: format!("rge_{commitment}"),
            installation_id: source.installation_id,
            repository_id: source.repository_id,
            repository: source.repository.clone(),
            source_delivery_id: source.delivery_id.clone(),
            source_ref: source.source_ref.clone(),
            source_commit_sha: source.source_commit_sha.to_ascii_lowercase(),
            policy_sha256: policy.policy_sha256.clone(),
            artifact_sha256,
            trust_snapshot_sha256,
            verifier_build_sha256,
            created_at,
        })
    }
}

pub fn current_binary_sha256() -> Result<String, AppError> {
    let path: PathBuf = std::env::current_exe()
        .map_err(|_| AppError::Internal("failed to resolve current executable"))?;
    let mut file = File::open(path)
        .map_err(|_| AppError::Internal("failed to open current executable"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AppError::Internal("failed to hash current executable"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest_join(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        let bytes = part.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::digest_join;

    #[test]
    fn canonical_join_is_boundary_safe() {
        assert_ne!(digest_join(&["ab", "c"]), digest_join(&["a", "bc"]));
        assert_eq!(digest_join(&["ab", "c"]), digest_join(&["ab", "c"]));
    }
}
