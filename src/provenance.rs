use attestation_verify::{
    Bundle, CheckpointOriginPolicy, CommitSha, ContentBindingError, Error as AttestationError,
    GithubPolicy, RefPolicy, RepositoryIdentity, SignerPolicy, SourcePolicy, Subject, TrustStore,
    Verifier, WorkflowPath, WorkflowRevisionPolicy,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::{
    decision::EvidenceTruth,
    error::AppError,
    github::{GithubApi, GithubApiError, RawAttestationBundle},
    store,
};

/// Public Rekor v1 checkpoint origin used by Sigstore's public-good deployment.
///
/// This is intentionally exact, not normalized or inferred. If Sigstore moves to
/// a different log/origin, verification fails closed as INDETERMINATE until the
/// trusted origin configuration is deliberately updated.
const PUBLIC_REKOR_V1_CHECKPOINT_ORIGIN: &str = "rekor.sigstore.dev - 1193050959916656506";
const PUBLIC_REKOR_V1_KEY_SHA256: &str =
    "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

#[derive(Debug, thiserror::Error)]
pub enum ProvenanceGateError {
    #[error("GitHub attestation retrieval failed: {0}")]
    Github(#[from] GithubApiError),
    #[error("attestation persistence failed")]
    Store(#[from] AppError),
}

/// Identity facts ReleaseGate requires before an attestation can become VERIFIED.
///
/// All fields are caller-supplied expectations, never copied from the untrusted
/// bundle and then accepted as policy. The repository id is pinned because the
/// Fulcio certificate authenticates the source repository numeric id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvenanceExpectation {
    pub source_repository: String,
    pub source_repository_id: u64,
    pub source_ref: String,
    pub source_commit_sha: String,
    pub signer_repository: String,
    pub signer_workflow_path: String,
    pub signer_revision_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleVerification {
    pub bundle_sha256: String,
    pub truth: EvidenceTruth,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvenanceVerification {
    pub truth: EvidenceTruth,
    pub reason: String,
    pub bundles: Vec<BundleVerification>,
}

pub fn embedded_trust_snapshot_sha256() -> Result<String, AttestationError> {
    Ok(TrustStore::embedded_public_good()?.fingerprint)
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
        .fetch_attestation_bundles(installation_id, repository_id, repository, artifact_sha256)
        .await?;
    for bundle in &bundles {
        store::store_attestation_bundle(
            db,
            store::AttestationEvidenceRecord {
                installation_id,
                repository_id,
                repository,
                artifact_sha256,
                initiator: &bundle.initiator,
                source_url_sha256: &bundle.source_url_sha256,
                transport_encoding: &bundle.transport_encoding,
                wire_sha256: &bundle.wire_sha256,
                wire_bytes: &bundle.wire_bytes,
                bundle_sha256: &bundle.bundle_sha256,
                raw_json: &bundle.raw_json,
            },
        )
        .await?;
    }
    Ok(bundles)
}

/// Verify already-retrieved GitHub artifact-attestation bundles.
///
/// Semantics are deliberately conservative:
/// - VERIFIED: at least one bundle completes the entire Sigstore + GitHub
///   identity verification chain under the caller's exact policy.
/// - INVALID: every retrieved bundle is conclusively false because its DSSE
///   signature is cryptographically invalid.
/// - INDETERMINATE: everything else (missing evidence, unsupported bundle/log,
///   parse error, certificate validity/trust failure, Rekor failure, policy
///   mismatch, or a mixture of rejected and indeterminate candidates).
///
/// A Fulcio leaf certificate being expired *now* is not itself a failure:
/// Sigstore certificates are intentionally short-lived. The verifier validates
/// certificate validity at the authenticated signing/log time. If that time
/// cannot be established or lies outside the certificate window, the result is
/// INDETERMINATE.
pub fn verify_provenance(
    artifact_sha256: &str,
    expectation: &ProvenanceExpectation,
    bundles: &[RawAttestationBundle],
) -> ProvenanceVerification {
    if bundles.is_empty() {
        return ProvenanceVerification {
            truth: EvidenceTruth::Indeterminate,
            reason: "no_attestation_bundles".to_owned(),
            bundles: Vec::new(),
        };
    }

    let subject = match Subject::from_digest_hex(artifact_sha256) {
        Ok(subject) => subject,
        Err(error) => {
            return all_indeterminate(
                bundles,
                format!("invalid_artifact_digest:{}", stable_error_class(&error)),
            );
        }
    };

    let verifier = match build_verifier(expectation) {
        Ok(verifier) => verifier,
        Err(VerifierBuildError::Attestation(error)) => {
            return all_indeterminate(
                bundles,
                format!(
                    "invalid_or_unsupported_policy:{}",
                    stable_error_class(&error)
                ),
            );
        }
        Err(VerifierBuildError::MissingRekorLog) => {
            return all_indeterminate(
                bundles,
                "invalid_or_unsupported_policy:missing_rekor_log".to_owned(),
            );
        }
    };

    let outcomes = bundles
        .iter()
        .map(|raw| verify_one_bundle(&verifier, &subject, raw))
        .collect::<Vec<_>>();

    aggregate(outcomes)
}

#[derive(Debug)]
enum VerifierBuildError {
    Attestation(AttestationError),
    MissingRekorLog,
}

impl From<AttestationError> for VerifierBuildError {
    fn from(error: AttestationError) -> Self {
        Self::Attestation(error)
    }
}

fn build_verifier(expectation: &ProvenanceExpectation) -> Result<Verifier, VerifierBuildError> {
    let source_repository = RepositoryIdentity::parse(&expectation.source_repository)?
        .with_repository_id(expectation.source_repository_id);
    let signer_repository = RepositoryIdentity::parse(&expectation.signer_repository)?;

    let source_commit = CommitSha::new(&expectation.source_commit_sha)?;
    let signer_revision = CommitSha::new(&expectation.signer_revision_sha)?;

    let github_policy = GithubPolicy::builder()
        .source(SourcePolicy {
            repository: source_repository,
            git_ref: RefPolicy::Exact(expectation.source_ref.clone()),
            commit: Some(source_commit),
        })
        .signer(SignerPolicy {
            repository: signer_repository,
            path: WorkflowPath::new(expectation.signer_workflow_path.clone())?,
            revision: WorkflowRevisionPolicy::Sha(signer_revision),
        })
        .build()?;

    let trust_store = TrustStore::embedded_public_good()?;
    let rekor_log = trust_store
        .tlogs
        .iter()
        .find(|log| {
            hex::encode(&log.log_id_key_id) == PUBLIC_REKOR_V1_KEY_SHA256
                && hex::encode(Sha256::digest(&log.public_key.raw_bytes))
                    == PUBLIC_REKOR_V1_KEY_SHA256
        })
        .ok_or(VerifierBuildError::MissingRekorLog)?;
    let checkpoint_origin_policy = CheckpointOriginPolicy::builder()
        .allow_origin(rekor_log, PUBLIC_REKOR_V1_CHECKPOINT_ORIGIN)?
        .build()?;

    Verifier::builder()
        .trust_store(trust_store)
        .github_policy(github_policy)
        .checkpoint_origin_policy(checkpoint_origin_policy)
        .build()
        .map_err(VerifierBuildError::from)
}

fn verify_one_bundle(
    verifier: &Verifier,
    subject: &Subject,
    raw: &RawAttestationBundle,
) -> BundleVerification {
    let bundle = match Bundle::from_json(&raw.raw_json) {
        Ok(bundle) => bundle,
        Err(error) => {
            return BundleVerification {
                bundle_sha256: raw.bundle_sha256.clone(),
                truth: EvidenceTruth::Indeterminate,
                reason: format!("bundle_parse:{}", stable_error_class(&error)),
            };
        }
    };

    match verifier.verify_digest(subject, &bundle) {
        Ok(_) => BundleVerification {
            bundle_sha256: raw.bundle_sha256.clone(),
            truth: EvidenceTruth::Verified,
            reason: "full_sigstore_chain_and_github_identity_verified".to_owned(),
        },
        Err(error) => {
            let truth = classify_verification_error(&error);
            BundleVerification {
                bundle_sha256: raw.bundle_sha256.clone(),
                truth,
                reason: stable_error_class(&error).to_owned(),
            }
        }
    }
}

fn classify_verification_error(error: &AttestationError) -> EvidenceTruth {
    // Deliberately narrow: only the attestation's own DSSE signature failing
    // cryptographic verification is conclusive enough for INVALID evidence.
    // Certificate-chain, Rekor, timestamp, trust, unsupported, parsing and
    // policy failures all remain INDETERMINATE.
    match error {
        AttestationError::ContentBinding(ContentBindingError::DsseSignatureInvalid) => {
            EvidenceTruth::Invalid
        }
        _ => EvidenceTruth::Indeterminate,
    }
}

fn aggregate(outcomes: Vec<BundleVerification>) -> ProvenanceVerification {
    if outcomes
        .iter()
        .any(|outcome| outcome.truth == EvidenceTruth::Verified)
    {
        return ProvenanceVerification {
            truth: EvidenceTruth::Verified,
            reason: "at_least_one_attestation_verified".to_owned(),
            bundles: outcomes,
        };
    }

    if !outcomes.is_empty()
        && outcomes
            .iter()
            .all(|outcome| outcome.truth == EvidenceTruth::Invalid)
    {
        return ProvenanceVerification {
            truth: EvidenceTruth::Invalid,
            reason: "all_attestations_have_invalid_dsse_signatures".to_owned(),
            bundles: outcomes,
        };
    }

    ProvenanceVerification {
        truth: EvidenceTruth::Indeterminate,
        reason: "no_verified_attestation_and_truth_not_conclusively_false".to_owned(),
        bundles: outcomes,
    }
}

fn all_indeterminate(bundles: &[RawAttestationBundle], reason: String) -> ProvenanceVerification {
    ProvenanceVerification {
        truth: EvidenceTruth::Indeterminate,
        reason: reason.clone(),
        bundles: bundles
            .iter()
            .map(|bundle| BundleVerification {
                bundle_sha256: bundle.bundle_sha256.clone(),
                truth: EvidenceTruth::Indeterminate,
                reason: reason.clone(),
            })
            .collect(),
    }
}

/// Stable machine category. Do not expose dependency Display strings as a
/// protocol contract; upstream wording can change without semantic change.
fn stable_error_class(error: &AttestationError) -> &'static str {
    match error {
        AttestationError::Parse(_) => "parse",
        AttestationError::Unsupported(_) => "unsupported",
        AttestationError::Trust(_) => "trust",
        AttestationError::Certificate(_) => "certificate",
        AttestationError::Transparency(_) => "transparency",
        AttestationError::Timestamp(_) => "timestamp",
        AttestationError::ContentBinding(ContentBindingError::DsseSignatureInvalid) => {
            "dsse_signature_invalid"
        }
        AttestationError::ContentBinding(_) => "content_binding",
        AttestationError::Policy(_) => "policy",
        AttestationError::ResourceLimit(_) => "resource_limit",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{aggregate, BundleVerification};
    use crate::decision::EvidenceTruth;

    fn outcome(truth: EvidenceTruth, id: &str) -> BundleVerification {
        BundleVerification {
            bundle_sha256: id.to_owned(),
            truth,
            reason: "test".to_owned(),
        }
    }

    #[test]
    fn verified_candidate_dominates_other_candidates() {
        let result = aggregate(vec![
            outcome(EvidenceTruth::Indeterminate, "a"),
            outcome(EvidenceTruth::Verified, "b"),
            outcome(EvidenceTruth::Invalid, "c"),
        ]);
        assert_eq!(result.truth, EvidenceTruth::Verified);
    }

    #[test]
    fn rejected_requires_every_candidate_to_be_conclusively_false() {
        let rejected = aggregate(vec![
            outcome(EvidenceTruth::Invalid, "a"),
            outcome(EvidenceTruth::Invalid, "b"),
        ]);
        assert_eq!(rejected.truth, EvidenceTruth::Invalid);

        let mixed = aggregate(vec![
            outcome(EvidenceTruth::Invalid, "a"),
            outcome(EvidenceTruth::Indeterminate, "b"),
        ]);
        assert_eq!(mixed.truth, EvidenceTruth::Indeterminate);
    }

    #[test]
    fn no_verified_candidate_is_indeterminate() {
        let result = aggregate(vec![outcome(EvidenceTruth::Indeterminate, "a")]);
        assert_eq!(result.truth, EvidenceTruth::Indeterminate);
    }
}
