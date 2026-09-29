use crate::{error::AppError, model::VerificationRequest};

pub fn validate(req: &VerificationRequest) -> Result<(), AppError> {
    if !valid_request_id(&req.request_id) {
        return Err(AppError::BadRequest(
            "request_id must be 8..128 ASCII characters from [A-Za-z0-9._:-]".into(),
        ));
    }
    if req.installation_id <= 0 {
        return Err(AppError::BadRequest("installation_id must be positive".into()));
    }
    if !valid_repo(&req.repository) {
        return Err(AppError::BadRequest("repository must be owner/name".into()));
    }
    if !is_lower_or_upper_hex(&req.source_commit, 40) {
        return Err(AppError::BadRequest("source_commit must be a 40-character git SHA-1 hex id".into()));
    }
    for (name, value) in [
        ("artifact_sha256", &req.artifact_sha256),
        ("manifest_sha256", &req.manifest_sha256),
        ("policy_sha256", &req.policy_sha256),
    ] {
        if !is_lower_or_upper_hex(value, 64) {
            return Err(AppError::BadRequest(format!("{name} must be a 64-character SHA-256 hex digest")));
        }
    }
    Ok(())
}

fn valid_request_id(v: &str) -> bool {
    (8..=128).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_lower_or_upper_hex(v: &str, len: usize) -> bool {
    v.len() == len && v.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_repo(v: &str) -> bool {
    let mut p = v.split('/');
    matches!((p.next(), p.next(), p.next()), (Some(a), Some(b), None) if !a.is_empty() && !b.is_empty() && v.len() <= 200)
}

#[cfg(test)]
mod tests {
    use crate::model::VerificationRequest;
    use super::validate;

    #[test]
    fn rejects_non_hex_artifact_digest() {
        let req = VerificationRequest {
            request_id: "job-0001".into(),
            installation_id: 1,
            repository: "a/b".into(),
            source_commit: "a".repeat(40),
            artifact_sha256: "z".repeat(64),
            manifest_sha256: "b".repeat(64),
            policy_sha256: "c".repeat(64),
        };
        assert!(validate(&req).is_err());
    }
}
