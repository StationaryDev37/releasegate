use serde::{Deserialize, Serialize};

use crate::{decision::{EvidenceTruth, ReleaseDecision}, evaluation::EvaluationContext, policy::PolicyResolution};

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
pub struct EvaluationFreezeResponse {
    pub context: EvaluationContext,
    pub policy: PolicyResolution,
    pub evidence_truth: EvidenceTruth,
    pub release_decision: ReleaseDecision,
    pub provenance_reason: String,
    pub attestation_bundle_sha256: Vec<String>,
}
