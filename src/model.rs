use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationRequest {
    pub request_id: String,
    pub installation_id: i64,
    pub repository: String,
    pub source_commit: String,
    pub artifact_sha256: String,
    pub manifest_sha256: String,
    pub policy_sha256: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Receipt {
    pub receipt_id: String,
    pub installation_id: i64,
    pub request_id: String,
    pub repository: String,
    pub source_commit: String,
    pub artifact_sha256: String,
    pub manifest_sha256: String,
    pub policy_sha256: String,
    pub evidence_commitment: String,
    pub outcome: String,
    pub reason_code: String,
    pub receipt_sha256: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookAck {
    pub status: &'static str,
    pub delivery_id: String,
}


#[derive(Debug, Clone, Deserialize)]
pub struct PolicyResolveRequest {
    pub installation_id: i64,
    pub repository_id: i64,
    pub source_commit_sha: String,
    pub source_ref: String,
}
