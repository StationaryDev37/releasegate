use serde::{Deserialize, Serialize};

use crate::{
    decision::{EvidenceTruth, PolicyAuthorization, ReleaseDecision},
    evaluation::EvaluationContext,
};

#[derive(Debug, Clone, Serialize)]
pub struct WebhookAck {
    pub status: &'static str,
    pub delivery_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvaluationRequest {
    pub installation_id: i64,
    pub repository_id: i64,
    pub source_commit_sha: String,
    pub source_ref: String,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluationResultResponse {
    pub context: EvaluationContext,
    pub evidence_truth: EvidenceTruth,
    pub policy_authorization: PolicyAuthorization,
    pub release_decision: ReleaseDecision,
    pub policy_reason: String,
    pub provenance_reason: String,
    pub attestation_set_sha256: String,
    pub decision_commitment: String,
    pub receipt_id: String,
    pub receipt_key_id: String,
    pub receipt_key_sha256: String,
    pub receipt_jws: String,
    pub receipt_sha256: String,
    pub completed_at: String,
    pub github_check: CheckProjection,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckProjection {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_run_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptKeyResponse {
    pub algorithm: &'static str,
    pub key_id: String,
    pub public_key_sha256: String,
    pub public_key_pem: String,
}
