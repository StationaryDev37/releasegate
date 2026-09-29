use sha2::{Digest, Sha256};

use crate::model::{Receipt, VerificationRequest};

pub fn build(req: &VerificationRequest, now: &str) -> Receipt {
    let evidence_commitment = digest_join(&[
        &req.repository,
        &req.source_commit,
        &req.artifact_sha256,
        &req.manifest_sha256,
        &req.policy_sha256,
    ]);
    let receipt_identity = digest_join(&[&req.installation_id.to_string(), &req.request_id]);
    let receipt_id = format!("rg_{}", &receipt_identity[..24]);

    let mut receipt = Receipt {
        receipt_id,
        installation_id: req.installation_id,
        request_id: req.request_id.clone(),
        repository: req.repository.clone(),
        source_commit: req.source_commit.to_ascii_lowercase(),
        artifact_sha256: req.artifact_sha256.to_ascii_lowercase(),
        manifest_sha256: req.manifest_sha256.to_ascii_lowercase(),
        policy_sha256: req.policy_sha256.to_ascii_lowercase(),
        evidence_commitment,
        outcome: "INDETERMINATE".to_owned(),
        reason_code: "EVIDENCE_COMMITTED_NOT_INDEPENDENTLY_VERIFIED".to_owned(),
        receipt_sha256: String::new(),
        created_at: now.to_owned(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt);
    receipt
}

fn receipt_digest(r: &Receipt) -> String {
    // Fixed field order, explicit separators, and length-prefixing avoid JSON-map ordering ambiguity.
    digest_join(&[
        &r.receipt_id,
        &r.installation_id.to_string(),
        &r.request_id,
        &r.repository,
        &r.source_commit,
        &r.artifact_sha256,
        &r.manifest_sha256,
        &r.policy_sha256,
        &r.evidence_commitment,
        &r.outcome,
        &r.reason_code,
        &r.created_at,
    ])
}

fn digest_join(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        let bytes = p.as_bytes();
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use crate::model::VerificationRequest;
    use super::build;

    fn request() -> VerificationRequest {
        VerificationRequest {
            request_id: "job-123".into(),
            installation_id: 42,
            repository: "acme/widget".into(),
            source_commit: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
            policy_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn deterministic_for_same_input_and_time() {
        let a = build(&request(), "2026-09-29T20:00:00Z");
        let b = build(&request(), "2026-09-29T20:00:00Z");
        assert_eq!(a.receipt_id, b.receipt_id);
        assert_eq!(a.receipt_sha256, b.receipt_sha256);
        assert_eq!(a.evidence_commitment, b.evidence_commitment);
        assert_eq!(a.receipt_id, "rg_0adf57dc816e6f82a95057ca");
        assert_eq!(
            a.evidence_commitment,
            "da35d57fa5e32595f427895268b5d8565225ec4524e08392838287a6d4e74272"
        );
        assert_eq!(
            a.receipt_sha256,
            "605d67c26e1353b5573bcbdf7d7fd27198bcca5c261d758dbbeef5fd8db2bac3"
        );
    }
}
