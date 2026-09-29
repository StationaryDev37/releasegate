use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provenance::ProvenanceExpectation;

const POLICY_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefRuleKind {
    Exact,
    Prefix,
}

impl RefRuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePolicySpec {
    pub installation_id: i64,
    pub repository_id: i64,
    pub repository: String,
    pub ref_rule: RefRuleKind,
    pub ref_value: String,
    pub signer_repository: String,
    pub signer_workflow_path: String,
    pub signer_revision_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleasePolicy {
    pub version: u8,
    pub policy_sha256: String,
    pub installation_id: i64,
    pub repository_id: i64,
    pub repository: String,
    pub ref_rule: RefRuleKind,
    pub ref_value: String,
    pub signer_repository: String,
    pub signer_workflow_path: String,
    pub signer_revision_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSourceContext {
    pub installation_id: i64,
    pub repository_id: i64,
    pub repository: String,
    pub source_ref: String,
    pub source_commit_sha: String,
    pub delivery_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyResolution {
    Eligible {
        policy_sha256: String,
        expectation: ProvenanceExpectation,
    },
    Rejected {
        policy_sha256: String,
        reason: &'static str,
    },
    Indeterminate {
        policy_sha256: Option<String>,
        reason: &'static str,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("installation_id must be positive")]
    InvalidInstallationId,
    #[error("repository_id must be positive")]
    InvalidRepositoryId,
    #[error("repository must be owner/name")]
    InvalidRepository,
    #[error("ref rule value is invalid")]
    InvalidRefRule,
    #[error("signer repository must be owner/name")]
    InvalidSignerRepository,
    #[error("workflow path must be a .github/workflows YAML file")]
    InvalidWorkflowPath,
    #[error("signer revision must be exactly 40 hexadecimal characters")]
    InvalidSignerRevision,
    #[error("trusted source ref is invalid")]
    InvalidSourceRef,
    #[error("trusted source commit must be exactly 40 hexadecimal characters")]
    InvalidSourceCommit,
    #[error("trusted source delivery id is empty")]
    InvalidDeliveryId,
}

impl ReleasePolicy {
    pub fn new(spec: ReleasePolicySpec) -> Result<Self, PolicyError> {
        validate_policy_spec(&spec)?;
        let policy_sha256 = policy_hash(&spec);
        Ok(Self {
            version: POLICY_VERSION,
            policy_sha256,
            installation_id: spec.installation_id,
            repository_id: spec.repository_id,
            repository: spec.repository,
            ref_rule: spec.ref_rule,
            ref_value: spec.ref_value,
            signer_repository: spec.signer_repository,
            signer_workflow_path: spec.signer_workflow_path,
            signer_revision_sha: spec.signer_revision_sha.to_ascii_lowercase(),
        })
    }

    pub fn resolve(&self, source: &TrustedSourceContext) -> PolicyResolution {
        if validate_trusted_source(source).is_err() {
            return PolicyResolution::Indeterminate {
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "trusted_source_context_invalid",
            };
        }

        if source.installation_id != self.installation_id {
            return PolicyResolution::Indeterminate {
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "installation_identity_mismatch",
            };
        }
        if source.repository_id != self.repository_id || source.repository != self.repository {
            return PolicyResolution::Indeterminate {
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "repository_identity_mismatch",
            };
        }
        if !self.ref_allows(&source.source_ref) {
            return PolicyResolution::Rejected {
                policy_sha256: self.policy_sha256.clone(),
                reason: "source_ref_not_allowed",
            };
        }

        PolicyResolution::Eligible {
            policy_sha256: self.policy_sha256.clone(),
            expectation: ProvenanceExpectation {
                source_repository: source.repository.clone(),
                source_repository_id: source.repository_id as u64,
                source_ref: source.source_ref.clone(),
                source_commit_sha: source.source_commit_sha.to_ascii_lowercase(),
                signer_repository: self.signer_repository.clone(),
                signer_workflow_path: self.signer_workflow_path.clone(),
                signer_revision_sha: self.signer_revision_sha.clone(),
            },
        }
    }

    fn ref_allows(&self, source_ref: &str) -> bool {
        match self.ref_rule {
            RefRuleKind::Exact => source_ref == self.ref_value,
            RefRuleKind::Prefix => source_ref.starts_with(&self.ref_value),
        }
    }
}

pub fn validate_trusted_source(source: &TrustedSourceContext) -> Result<(), PolicyError> {
    if source.installation_id <= 0 {
        return Err(PolicyError::InvalidInstallationId);
    }
    if source.repository_id <= 0 {
        return Err(PolicyError::InvalidRepositoryId);
    }
    validate_repository(&source.repository).map_err(|_| PolicyError::InvalidRepository)?;
    validate_ref(&source.source_ref).map_err(|_| PolicyError::InvalidSourceRef)?;
    if !is_sha1_hex(&source.source_commit_sha) {
        return Err(PolicyError::InvalidSourceCommit);
    }
    if source.delivery_id.is_empty() {
        return Err(PolicyError::InvalidDeliveryId);
    }
    Ok(())
}

fn validate_policy_spec(spec: &ReleasePolicySpec) -> Result<(), PolicyError> {
    if spec.installation_id <= 0 {
        return Err(PolicyError::InvalidInstallationId);
    }
    if spec.repository_id <= 0 {
        return Err(PolicyError::InvalidRepositoryId);
    }
    validate_repository(&spec.repository).map_err(|_| PolicyError::InvalidRepository)?;
    validate_repository(&spec.signer_repository)
        .map_err(|_| PolicyError::InvalidSignerRepository)?;

    match spec.ref_rule {
        RefRuleKind::Exact => validate_ref(&spec.ref_value)?,
        RefRuleKind::Prefix => validate_ref_prefix(&spec.ref_value)?,
    }

    if !valid_workflow_path(&spec.signer_workflow_path) {
        return Err(PolicyError::InvalidWorkflowPath);
    }
    if !is_sha1_hex(&spec.signer_revision_sha) {
        return Err(PolicyError::InvalidSignerRevision);
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<(), PolicyError> {
    let Some((owner, name)) = value.split_once('/') else {
        return Err(PolicyError::InvalidRepository);
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') || value.trim() != value {
        return Err(PolicyError::InvalidRepository);
    }
    Ok(())
}

fn validate_ref(value: &str) -> Result<(), PolicyError> {
    let valid = value.starts_with("refs/heads/") || value.starts_with("refs/tags/");
    if !valid || value.len() <= "refs/tags/".len() || value.chars().any(|ch| matches!(ch, '\r' | '\n' | '*')) {
        return Err(PolicyError::InvalidRefRule);
    }
    Ok(())
}

fn validate_ref_prefix(value: &str) -> Result<(), PolicyError> {
    let valid = value.starts_with("refs/heads/") || value.starts_with("refs/tags/");
    if !valid || value.len() <= "refs/tags/".len() || value.chars().any(|ch| matches!(ch, '\r' | '\n' | '*')) {
        return Err(PolicyError::InvalidRefRule);
    }
    Ok(())
}

fn valid_workflow_path(path: &str) -> bool {
    path.starts_with(".github/workflows/")
        && (path.ends_with(".yml") || path.ends_with(".yaml"))
        && !path.contains("..")
        && !path.chars().any(|ch| matches!(ch, '\r' | '\n'))
}

fn is_sha1_hex(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn policy_hash(spec: &ReleasePolicySpec) -> String {
    let mut hasher = Sha256::new();
    for part in [
        POLICY_VERSION.to_string(),
        spec.installation_id.to_string(),
        spec.repository_id.to_string(),
        spec.repository.clone(),
        spec.ref_rule.as_str().to_owned(),
        spec.ref_value.clone(),
        spec.signer_repository.clone(),
        spec.signer_workflow_path.clone(),
        spec.signer_revision_sha.to_ascii_lowercase(),
    ] {
        let bytes = part.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyResolution, RefRuleKind, ReleasePolicy, ReleasePolicySpec, TrustedSourceContext,
    };

    fn policy() -> ReleasePolicy {
        ReleasePolicy::new(ReleasePolicySpec {
            installation_id: 42,
            repository_id: 99,
            repository: "acme/widget".into(),
            ref_rule: RefRuleKind::Prefix,
            ref_value: "refs/tags/v".into(),
            signer_repository: "acme/release-workflows".into(),
            signer_workflow_path: ".github/workflows/release.yml".into(),
            signer_revision_sha: "a".repeat(40),
        })
        .expect("valid policy")
    }

    fn source(git_ref: &str) -> TrustedSourceContext {
        TrustedSourceContext {
            installation_id: 42,
            repository_id: 99,
            repository: "acme/widget".into(),
            source_ref: git_ref.into(),
            source_commit_sha: "b".repeat(40),
            delivery_id: "delivery-1".into(),
        }
    }

    #[test]
    fn canonical_policy_hash_matches_independent_vector() {
        assert_eq!(
            policy().policy_sha256,
            "6bc707d83af54b493743d2f7ba4eb287302d8ce5cdfab99550421fb0880cefc1"
        );
    }

    #[test]
    fn exact_ref_rule_does_not_accept_prefix_extensions() {
        let exact = ReleasePolicy::new(ReleasePolicySpec {
            installation_id: 42,
            repository_id: 99,
            repository: "acme/widget".into(),
            ref_rule: RefRuleKind::Exact,
            ref_value: "refs/tags/v1.2.3".into(),
            signer_repository: "acme/release-workflows".into(),
            signer_workflow_path: ".github/workflows/release.yml".into(),
            signer_revision_sha: "a".repeat(40),
        })
        .expect("valid policy");
        assert!(matches!(
            exact.resolve(&source("refs/tags/v1.2.30")),
            PolicyResolution::Rejected {
                reason: "source_ref_not_allowed",
                ..
            }
        ));
    }

    #[test]
    fn allowed_source_generates_exact_provenance_expectation() {
        let result = policy().resolve(&source("refs/tags/v1.2.3"));
        match result {
            PolicyResolution::Eligible { expectation, .. } => {
                assert_eq!(expectation.source_ref, "refs/tags/v1.2.3");
                assert_eq!(expectation.source_commit_sha, "b".repeat(40));
                assert_eq!(expectation.signer_repository, "acme/release-workflows");
            }
            other => panic!("unexpected policy resolution: {other:?}"),
        }
    }

    #[test]
    fn disallowed_ref_is_rejected_not_indeterminate() {
        let result = policy().resolve(&source("refs/heads/main"));
        assert!(matches!(
            result,
            PolicyResolution::Rejected {
                reason: "source_ref_not_allowed",
                ..
            }
        ));
    }

    #[test]
    fn identity_mismatch_is_indeterminate() {
        let mut source = source("refs/tags/v1.2.3");
        source.repository_id = 100;
        let result = policy().resolve(&source);
        assert!(matches!(
            result,
            PolicyResolution::Indeterminate {
                reason: "repository_identity_mismatch",
                ..
            }
        ));
    }
}
