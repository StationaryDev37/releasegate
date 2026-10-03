use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    decision::{EvidenceTruth, PolicyAuthorization, ReleaseDecision},
    error::AppError,
    evaluation::EvaluationContext,
    provenance::BundleVerification,
};

const RECEIPT_SCHEMA: &str = "releasegate-receipt-v1";
const DECISION_DOMAIN: &[u8] = b"ReleaseGate\x00DecisionCommitment\x00v1";
const ATTESTATION_DOMAIN: &[u8] = b"ReleaseGate\x00AttestationSet\x00v1";

pub struct ReceiptSigner {
    key_id: String,
    public_key_sha256: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptClaims {
    pub schema: String,
    pub receipt_id: String,
    pub evaluation_id: String,
    pub decision_commitment: String,
    pub receipt_key_sha256: String,
    pub repository: String,
    pub source_commit_sha: String,
    pub artifact_sha256: String,
    pub policy_sha256: String,
    pub trust_snapshot_sha256: String,
    pub verifier_build_sha256: String,
    pub evidence_truth: EvidenceTruth,
    pub policy_authorization: PolicyAuthorization,
    pub release_decision: ReleaseDecision,
    pub policy_reason: String,
    pub provenance_reason: String,
    pub attestation_set_sha256: String,
    pub frozen_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReceipt {
    pub receipt_id: String,
    pub decision_commitment: String,
    pub attestation_set_sha256: String,
    pub receipt_jws: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyProbe {
    schema: String,
    key_id: String,
    public_key_sha256: String,
}

impl ReceiptSigner {
    pub fn new(
        key_id: String,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> Result<Self, AppError> {
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        {
            return Err(AppError::BadRequest(
                "invalid receipt signing key id".into(),
            ));
        }
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|_| AppError::BadRequest("invalid receipt RSA private key".into()))?;
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem)
            .map_err(|_| AppError::BadRequest("invalid receipt RSA public key".into()))?;
        let public_key_sha256 = canonical_pem_identity(public_key_pem)?;
        let signer = Self {
            key_id,
            public_key_sha256,
            encoding_key,
            decoding_key,
        };
        signer.self_test()?;
        Ok(signer)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_sha256(&self) -> &str {
        &self.public_key_sha256
    }

    pub fn sign_decision(
        &self,
        context: &EvaluationContext,
        evidence_truth: EvidenceTruth,
        policy_authorization: PolicyAuthorization,
        release_decision: ReleaseDecision,
        policy_reason: &str,
        provenance_reason: &str,
        bundles: &[BundleVerification],
    ) -> Result<SignedReceipt, AppError> {
        let attestation_set_sha256 = attestation_set_commitment(bundles);
        let decision_commitment = decision_commitment(
            context,
            evidence_truth,
            policy_authorization,
            release_decision,
            policy_reason,
            provenance_reason,
            &attestation_set_sha256,
        );
        let receipt_id = format!("rgr_{decision_commitment}");
        let claims = ReceiptClaims {
            schema: RECEIPT_SCHEMA.to_owned(),
            receipt_id: receipt_id.clone(),
            evaluation_id: context.evaluation_id.clone(),
            decision_commitment: decision_commitment.clone(),
            receipt_key_sha256: self.public_key_sha256.clone(),
            repository: context.repository.clone(),
            source_commit_sha: context.source_commit_sha.clone(),
            artifact_sha256: context.artifact_sha256.clone(),
            policy_sha256: context.policy_sha256.clone(),
            trust_snapshot_sha256: context.trust_snapshot_sha256.clone(),
            verifier_build_sha256: context.verifier_build_sha256.clone(),
            evidence_truth,
            policy_authorization,
            release_decision,
            policy_reason: policy_reason.to_owned(),
            provenance_reason: provenance_reason.to_owned(),
            attestation_set_sha256: attestation_set_sha256.clone(),
            frozen_at: context.created_at.clone(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_owned());
        header.cty = Some("application/releasegate-receipt+json".to_owned());
        header.kid = Some(self.key_id.clone());
        let receipt_jws = encode(&header, &claims, &self.encoding_key)
            .map_err(|_| AppError::Internal("failed to sign release receipt"))?;
        let receipt_sha256 = hex::encode(Sha256::digest(receipt_jws.as_bytes()));
        Ok(SignedReceipt {
            receipt_id,
            decision_commitment,
            attestation_set_sha256,
            receipt_jws,
            receipt_sha256,
        })
    }

    fn self_test(&self) -> Result<(), AppError> {
        let probe = KeyProbe {
            schema: "releasegate-key-probe-v1".to_owned(),
            key_id: self.key_id.clone(),
            public_key_sha256: self.public_key_sha256.clone(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_owned());
        header.cty = Some("application/releasegate-key-probe+json".to_owned());
        header.kid = Some(self.key_id.clone());
        let token = encode(&header, &probe, &self.encoding_key)
            .map_err(|_| AppError::BadRequest("receipt private key cannot sign".into()))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.clear();
        let decoded = decode::<KeyProbe>(&token, &self.decoding_key, &validation)
            .map_err(|_| AppError::BadRequest("receipt RSA keypair does not match".into()))?;
        if decoded.claims != probe {
            return Err(AppError::BadRequest(
                "receipt RSA keypair self-test changed claims".into(),
            ));
        }
        Ok(())
    }
}

pub fn attestation_set_commitment(bundles: &[BundleVerification]) -> String {
    let mut ordered = bundles.to_vec();
    ordered.sort_by(|a, b| a.bundle_sha256.cmp(&b.bundle_sha256));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ATTESTATION_DOMAIN);
    bytes.extend_from_slice(&(ordered.len() as u32).to_be_bytes());
    for bundle in ordered {
        push_text(&mut bytes, &bundle.bundle_sha256);
        push_text(&mut bytes, truth_str(bundle.truth));
        push_text(&mut bytes, &bundle.reason);
    }
    hex::encode(Sha256::digest(bytes))
}

pub fn decision_commitment(
    context: &EvaluationContext,
    evidence_truth: EvidenceTruth,
    policy_authorization: PolicyAuthorization,
    release_decision: ReleaseDecision,
    policy_reason: &str,
    provenance_reason: &str,
    attestation_set_sha256: &str,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DECISION_DOMAIN);
    bytes.extend_from_slice(&context.installation_id.to_be_bytes());
    bytes.extend_from_slice(&context.repository_id.to_be_bytes());
    for value in [
        context.evaluation_id.as_str(),
        context.repository.as_str(),
        context.source_delivery_id.as_str(),
        context.source_ref.as_str(),
        context.source_commit_sha.as_str(),
        context.policy_sha256.as_str(),
        context.artifact_sha256.as_str(),
        context.trust_snapshot_sha256.as_str(),
        context.verifier_build_sha256.as_str(),
        context.receipt_key_sha256.as_str(),
        truth_str(evidence_truth),
        authorization_str(policy_authorization),
        release_str(release_decision),
        policy_reason,
        provenance_reason,
        attestation_set_sha256,
    ] {
        push_text(&mut bytes, value);
    }
    hex::encode(Sha256::digest(bytes))
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn canonical_pem_identity(pem: &[u8]) -> Result<String, AppError> {
    let text = std::str::from_utf8(pem)
        .map_err(|_| AppError::BadRequest("receipt RSA public key is not UTF-8 PEM".into()))?;
    let mut begin_label: Option<&str> = None;
    let mut body = String::new();
    let mut complete = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if complete {
            return Err(AppError::BadRequest(
                "receipt RSA public key must contain exactly one PEM block".into(),
            ));
        }
        if begin_label.is_none() {
            let label = line
                .strip_prefix("-----BEGIN ")
                .and_then(|value| value.strip_suffix("-----"))
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "receipt RSA public key must contain exactly one public-key PEM block"
                            .into(),
                    )
                })?;
            if label != "PUBLIC KEY" && label != "RSA PUBLIC KEY" {
                return Err(AppError::BadRequest(
                    "receipt RSA public key PEM label is unsupported".into(),
                ));
            }
            begin_label = Some(label);
            continue;
        }

        if let Some(end_label) = line
            .strip_prefix("-----END ")
            .and_then(|value| value.strip_suffix("-----"))
        {
            if Some(end_label) != begin_label || body.is_empty() {
                return Err(AppError::BadRequest(
                    "receipt RSA public key PEM block is malformed".into(),
                ));
            }
            complete = true;
            continue;
        }
        if line.starts_with("-----BEGIN ") {
            return Err(AppError::BadRequest(
                "receipt RSA public key must contain exactly one PEM block".into(),
            ));
        }
        if !line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err(AppError::BadRequest(
                "receipt RSA public key PEM body is malformed".into(),
            ));
        }
        body.push_str(line);
    }

    if begin_label.is_none() || !complete || body.is_empty() {
        return Err(AppError::BadRequest(
            "receipt RSA public key PEM block is incomplete".into(),
        ));
    }
    Ok(hex::encode(Sha256::digest(body.as_bytes())))
}

pub fn truth_str(value: EvidenceTruth) -> &'static str {
    match value {
        EvidenceTruth::Verified => "VERIFIED",
        EvidenceTruth::Invalid => "INVALID",
        EvidenceTruth::Indeterminate => "INDETERMINATE",
    }
}

pub fn authorization_str(value: PolicyAuthorization) -> &'static str {
    match value {
        PolicyAuthorization::Allow => "ALLOW",
        PolicyAuthorization::Deny => "DENY",
        PolicyAuthorization::Indeterminate => "INDETERMINATE",
    }
}

pub fn release_str(value: ReleaseDecision) -> &'static str {
    match value {
        ReleaseDecision::Release => "RELEASE",
        ReleaseDecision::Block => "BLOCK",
        ReleaseDecision::Hold => "HOLD",
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use rsa::{
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        RsaPrivateKey,
    };

    use super::{attestation_set_commitment, canonical_pem_identity, ReceiptSigner};
    use crate::{
        decision::{EvidenceTruth, PolicyAuthorization, ReleaseDecision},
        evaluation::EvaluationContext,
        provenance::BundleVerification,
    };

    #[test]
    fn attestation_set_is_order_independent() {
        let a = BundleVerification {
            bundle_sha256: "a".repeat(64),
            truth: EvidenceTruth::Verified,
            reason: "ok".into(),
        };
        let b = BundleVerification {
            bundle_sha256: "b".repeat(64),
            truth: EvidenceTruth::Indeterminate,
            reason: "unsupported".into(),
        };
        assert_eq!(
            attestation_set_commitment(&[a.clone(), b.clone()]),
            attestation_set_commitment(&[b, a])
        );
    }

    #[test]
    fn public_key_identity_ignores_line_wrapping() {
        let a = b"-----BEGIN PUBLIC KEY-----\nQUJDREVGRw==\n-----END PUBLIC KEY-----\n";
        let b = b"-----BEGIN PUBLIC KEY-----\r\nQUJD\r\nREVGRw==\r\n-----END PUBLIC KEY-----\r\n";
        assert_eq!(canonical_pem_identity(a), canonical_pem_identity(b));
    }

    #[test]
    fn public_key_identity_rejects_concatenated_pem_blocks() {
        let concatenated = b"-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n\n-----BEGIN PUBLIC KEY-----\nREVG\n-----END PUBLIC KEY-----\n";
        assert!(canonical_pem_identity(concatenated).is_err());
    }

    #[test]
    fn receipt_signer_self_tests_and_signs_frozen_decision() {
        let mut rng = ChaCha20Rng::from_seed([0x47; 32]);
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("deterministic RSA fixture");
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private key");
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key");
        let signer = ReceiptSigner::new(
            "fixture-key".into(),
            private_pem.as_bytes(),
            public_pem.as_bytes(),
        )
        .expect("receipt signer");
        let context = EvaluationContext {
            evaluation_id: format!("rge_{}", "1".repeat(64)),
            installation_id: 42,
            repository_id: 99,
            repository: "acme/widget".into(),
            source_delivery_id: "delivery-1".into(),
            source_ref: "refs/tags/v1.2.3".into(),
            source_commit_sha: "b".repeat(40),
            policy_sha256: "c".repeat(64),
            artifact_sha256: "d".repeat(64),
            trust_snapshot_sha256: "e".repeat(64),
            verifier_build_sha256: "f".repeat(64),
            receipt_key_sha256: signer.public_key_sha256().to_owned(),
            created_at: "2026-09-30T00:00:00Z".into(),
        };
        let receipt = signer
            .sign_decision(
                &context,
                EvidenceTruth::Verified,
                PolicyAuthorization::Allow,
                ReleaseDecision::Release,
                "source_and_signer_policy_bound",
                "at_least_one_attestation_verified",
                &[],
            )
            .expect("sign receipt");
        assert!(receipt.receipt_id.starts_with("rgr_"));
        assert_eq!(receipt.decision_commitment.len(), 64);
        assert_eq!(receipt.receipt_sha256.len(), 64);
    }
}
