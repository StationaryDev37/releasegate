use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{decision::PolicyAuthorization, provenance::ProvenanceExpectation};

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
pub struct PolicyResolution {
    pub authorization: PolicyAuthorization,
    pub policy_sha256: Option<String>,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expectation: Option<ProvenanceExpectation>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("installation_id must be positive")]
    InstallationId,
    #[error("repository_id must be positive")]
    RepositoryId,
    #[error("repository must be owner/name")]
    Repository,
    #[error("ref rule value is invalid")]
    RefRule,
    #[error("signer repository must be owner/name")]
    SignerRepository,
    #[error("workflow path must be a .github/workflows YAML file")]
    WorkflowPath,
    #[error("signer revision must be exactly 40 hexadecimal characters")]
    SignerRevision,
    #[error("trusted source ref is invalid")]
    SourceRef,
    #[error("trusted source commit must be exactly 40 hexadecimal characters")]
    SourceCommit,
    #[error("trusted source delivery id is empty")]
    DeliveryId,
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
            return PolicyResolution {
                authorization: PolicyAuthorization::Indeterminate,
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "trusted_source_context_invalid",
                expectation: None,
            };
        }

        if source.installation_id != self.installation_id {
            return PolicyResolution {
                authorization: PolicyAuthorization::Indeterminate,
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "installation_identity_mismatch",
                expectation: None,
            };
        }
        if source.repository_id != self.repository_id || source.repository != self.repository {
            return PolicyResolution {
                authorization: PolicyAuthorization::Indeterminate,
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "repository_identity_mismatch",
                expectation: None,
            };
        }
        if !self.ref_allows(&source.source_ref) {
            return PolicyResolution {
                authorization: PolicyAuthorization::Deny,
                policy_sha256: Some(self.policy_sha256.clone()),
                reason: "source_ref_not_allowed",
                expectation: None,
            };
        }

        PolicyResolution {
            authorization: PolicyAuthorization::Allow,
            policy_sha256: Some(self.policy_sha256.clone()),
            reason: "source_and_signer_policy_bound",
            expectation: Some(ProvenanceExpectation {
                source_repository: source.repository.clone(),
                source_repository_id: source.repository_id as u64,
                source_ref: source.source_ref.clone(),
                source_commit_sha: source.source_commit_sha.to_ascii_lowercase(),
                signer_repository: self.signer_repository.clone(),
                signer_workflow_path: self.signer_workflow_path.clone(),
                signer_revision_sha: self.signer_revision_sha.clone(),
            }),
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
        return Err(PolicyError::InstallationId);
    }
    if source.repository_id <= 0 {
        return Err(PolicyError::RepositoryId);
    }
    validate_repository(&source.repository).map_err(|_| PolicyError::Repository)?;
    validate_ref(&source.source_ref).map_err(|_| PolicyError::SourceRef)?;
    if !is_sha1_hex(&source.source_commit_sha) {
        return Err(PolicyError::SourceCommit);
    }
    if source.delivery_id.is_empty() {
        return Err(PolicyError::DeliveryId);
    }
    Ok(())
}

fn validate_policy_spec(spec: &ReleasePolicySpec) -> Result<(), PolicyError> {
    if spec.installation_id <= 0 {
        return Err(PolicyError::InstallationId);
    }
    if spec.repository_id <= 0 {
        return Err(PolicyError::RepositoryId);
    }
    validate_repository(&spec.repository).map_err(|_| PolicyError::Repository)?;
    validate_repository(&spec.signer_repository).map_err(|_| PolicyError::SignerRepository)?;

    match spec.ref_rule {
        RefRuleKind::Exact => validate_ref(&spec.ref_value)?,
        RefRuleKind::Prefix => validate_ref_prefix(&spec.ref_value)?,
    }

    if !valid_workflow_path(&spec.signer_workflow_path) {
        return Err(PolicyError::WorkflowPath);
    }
    if !is_sha1_hex(&spec.signer_revision_sha) {
        return Err(PolicyError::SignerRevision);
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<(), PolicyError> {
    let Some((owner, name)) = value.split_once('/') else {
        return Err(PolicyError::Repository);
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') || value.trim() != value {
        return Err(PolicyError::Repository);
    }
    Ok(())
}

fn validate_ref(value: &str) -> Result<(), PolicyError> {
    let valid = value.starts_with("refs/heads/") || value.starts_with("refs/tags/");
    if !valid
        || value.len() <= "refs/tags/".len()
        || value.chars().any(|ch| matches!(ch, '\r' | '\n' | '*'))
    {
        return Err(PolicyError::RefRule);
    }
    Ok(())
}

fn validate_ref_prefix(value: &str) -> Result<(), PolicyError> {
    let valid = value.starts_with("refs/heads/") || value.starts_with("refs/tags/");
    if !valid
        || value.len() <= "refs/tags/".len()
        || value.chars().any(|ch| matches!(ch, '\r' | '\n' | '*'))
    {
        return Err(PolicyError::RefRule);
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
    use crate::decision::PolicyAuthorization;

    use super::{RefRuleKind, ReleasePolicy, ReleasePolicySpec, TrustedSourceContext};

    fn policy() -> Result<ReleasePolicy, super::PolicyError> {
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
    fn canonical_policy_hash_matches_independent_vector() -> Result<(), super::PolicyError> {
        assert_eq!(
            policy()?.policy_sha256,
            "6bc707d83af54b493743d2f7ba4eb287302d8ce5cdfab99550421fb0880cefc1"
        );
        Ok(())
    }

    #[test]
    fn exact_ref_rule_does_not_accept_prefix_extensions() -> Result<(), super::PolicyError> {
        let exact = ReleasePolicy::new(ReleasePolicySpec {
            installation_id: 42,
            repository_id: 99,
            repository: "acme/widget".into(),
            ref_rule: RefRuleKind::Exact,
            ref_value: "refs/tags/v1.2.3".into(),
            signer_repository: "acme/release-workflows".into(),
            signer_workflow_path: ".github/workflows/release.yml".into(),
            signer_revision_sha: "a".repeat(40),
        })?;
        let result = exact.resolve(&source("refs/tags/v1.2.30"));
        assert_eq!(result.authorization, PolicyAuthorization::Deny);
        assert_eq!(result.reason, "source_ref_not_allowed");
        assert!(result.expectation.is_none());
        Ok(())
    }

    #[test]
    fn allowed_source_generates_exact_provenance_expectation() -> Result<(), super::PolicyError> {
        let result = policy()?.resolve(&source("refs/tags/v1.2.3"));
        assert_eq!(result.authorization, PolicyAuthorization::Allow);
        let expectation = result.expectation.ok_or(super::PolicyError::SourceRef)?;
        assert_eq!(expectation.source_ref, "refs/tags/v1.2.3");
        assert_eq!(expectation.source_commit_sha, "b".repeat(40));
        assert_eq!(expectation.signer_repository, "acme/release-workflows");
        Ok(())
    }

    #[test]
    fn identity_mismatch_is_indeterminate() -> Result<(), super::PolicyError> {
        let mut source = source("refs/tags/v1.2.3");
        source.repository_id = 100;
        let result = policy()?.resolve(&source);
        assert_eq!(result.authorization, PolicyAuthorization::Indeterminate);
        assert_eq!(result.reason, "repository_identity_mismatch");
        assert!(result.expectation.is_none());
        Ok(())
    }
}
