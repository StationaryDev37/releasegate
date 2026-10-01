use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

const MAX_DELIVERY_ATTEMPTS: i64 = 12;

pub async fn connect(database_url: &str) -> anyhow::Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub fn now_rfc3339() -> Result<String, AppError> {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| AppError::Internal("failed to format UTC timestamp"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryLease {
    Acquired { token: String, attempt: i64 },
    DuplicateApplied,
    DuplicateRejected,
    InFlight,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedDelivery<'a> {
    pub source: &'a str,
    pub delivery_id: &'a str,
    pub event_type: &'a str,
    pub payload_sha256: &'a str,
    pub payload_bytes: &'a [u8],
    pub signature_header: &'a str,
}

pub async fn lease_delivery(
    pool: &SqlitePool,
    delivery: AuthenticatedDelivery<'_>,
    lease_seconds: i64,
) -> Result<DeliveryLease, AppError> {
    let AuthenticatedDelivery {
        source,
        delivery_id,
        event_type,
        payload_sha256,
        payload_bytes,
        signature_header,
    } = delivery;
    if lease_seconds < 5 {
        return Err(AppError::Internal(
            "delivery lease duration is below safety floor",
        ));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let received_at = now_rfc3339()?;
    sqlx::query(
        r#"INSERT OR IGNORE INTO webhook_deliveries(
            source,delivery_id,event_type,payload_sha256,received_at,payload_bytes,
            signature_header,state,attempt_count
        ) VALUES(?,?,?,?,?,?,?,'received',0)"#,
    )
    .bind(source)
    .bind(delivery_id)
    .bind(event_type)
    .bind(payload_sha256)
    .bind(received_at)
    .bind(payload_bytes)
    .bind(signature_header)
    .execute(pool)
    .await?;

    let identity: (String, String) = sqlx::query_as(
        "SELECT event_type,payload_sha256 FROM webhook_deliveries WHERE source=? AND delivery_id=?",
    )
    .bind(source)
    .bind(delivery_id)
    .fetch_one(pool)
    .await?;
    if identity.0 != event_type || identity.1 != payload_sha256 {
        return Err(AppError::Conflict(
            "delivery id was replayed with different authenticated bytes or event type".into(),
        ));
    }

    // If an unfinished delivery is legitimately redelivered after webhook
    // secret rotation, retain the newest signature that already passed the
    // current ingress HMAC check. Terminal rows remain immutable.
    sqlx::query(
        r#"UPDATE webhook_deliveries SET signature_header=?
           WHERE source=? AND delivery_id=? AND state IN ('received','leased')"#,
    )
    .bind(signature_header)
    .bind(source)
    .bind(delivery_id)
    .execute(pool)
    .await?;

    terminalize_exhausted_delivery(pool, source, delivery_id, now).await?;

    let token = Uuid::new_v4().simple().to_string();
    let expires = now.saturating_add(lease_seconds);
    let update = sqlx::query(
        r#"UPDATE webhook_deliveries
           SET state='leased',lease_token=?,lease_expires_unix=?,attempt_count=attempt_count+1,
               next_attempt_unix=0,last_error_code=NULL,completed_at=NULL
           WHERE source=? AND delivery_id=? AND attempt_count < ?
             AND ((state='received' AND next_attempt_unix <= ?)
               OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?))"#,
    )
    .bind(&token)
    .bind(expires)
    .bind(source)
    .bind(delivery_id)
    .bind(MAX_DELIVERY_ATTEMPTS)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    if update.rows_affected() == 1 {
        let attempt: i64 = sqlx::query_scalar(
            "SELECT attempt_count FROM webhook_deliveries WHERE source=? AND delivery_id=?",
        )
        .bind(source)
        .bind(delivery_id)
        .fetch_one(pool)
        .await?;
        return Ok(DeliveryLease::Acquired { token, attempt });
    }

    let state: String = sqlx::query_scalar(
        "SELECT state FROM webhook_deliveries WHERE source=? AND delivery_id=?",
    )
    .bind(source)
    .bind(delivery_id)
    .fetch_one(pool)
    .await?;
    match state.as_str() {
        "applied" => Ok(DeliveryLease::DuplicateApplied),
        "rejected" => Ok(DeliveryLease::DuplicateRejected),
        "leased" | "received" => Ok(DeliveryLease::InFlight),
        _ => Err(AppError::Conflict("stored delivery has invalid state".into())),
    }
}

pub async fn complete_delivery(
    pool: &SqlitePool,
    source: &str,
    delivery_id: &str,
    lease_token: &str,
) -> Result<(), AppError> {
    transition_delivery(pool, source, delivery_id, lease_token, "applied", None).await
}

pub async fn reject_delivery(
    pool: &SqlitePool,
    source: &str,
    delivery_id: &str,
    lease_token: &str,
    error_code: &str,
) -> Result<(), AppError> {
    transition_delivery(
        pool,
        source,
        delivery_id,
        lease_token,
        "rejected",
        Some(error_code),
    )
    .await
}

pub async fn release_delivery(
    pool: &SqlitePool,
    source: &str,
    delivery_id: &str,
    lease_token: &str,
    error_code: &str,
) -> Result<(), AppError> {
    let attempt: i64 = sqlx::query_scalar(
        "SELECT attempt_count FROM webhook_deliveries WHERE source=? AND delivery_id=? AND state='leased' AND lease_token=?",
    )
    .bind(source)
    .bind(delivery_id)
    .bind(lease_token)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::Conflict("delivery lease ownership was lost".into()))?;
    let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 6)).unwrap_or(6);
    let delay = 5_i64
        .saturating_mul(2_i64.saturating_pow(exponent))
        .min(300);
    let next_attempt = OffsetDateTime::now_utc()
        .unix_timestamp()
        .saturating_add(delay);
    let result = sqlx::query(
        r#"UPDATE webhook_deliveries
           SET state='received',lease_token=NULL,lease_expires_unix=NULL,
               next_attempt_unix=?,last_error_code=?
           WHERE source=? AND delivery_id=? AND state='leased' AND lease_token=?"#,
    )
    .bind(next_attempt)
    .bind(error_code)
    .bind(source)
    .bind(delivery_id)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict("delivery lease ownership was lost".into()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RecoveredDelivery {
    pub source: String,
    pub delivery_id: String,
    pub event_type: String,
    pub payload_sha256: String,
    pub payload_bytes: Vec<u8>,
    pub signature_header: String,
    pub lease_token: String,
}

pub async fn lease_recoverable_deliveries(
    pool: &SqlitePool,
    lease_seconds: i64,
    limit: i64,
) -> Result<Vec<RecoveredDelivery>, AppError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    terminalize_exhausted_deliveries(pool, now).await?;
    let candidates: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT source,delivery_id FROM webhook_deliveries
           WHERE payload_bytes IS NOT NULL AND signature_header IS NOT NULL
             AND attempt_count < ?
             AND ((state='received' AND next_attempt_unix <= ?)
               OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?))
           ORDER BY received_at ASC LIMIT ?"#,
    )
    .bind(MAX_DELIVERY_ATTEMPTS)
    .bind(now)
    .bind(now)
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;

    let mut recovered = Vec::with_capacity(candidates.len());
    for (source, delivery_id) in candidates {
        let token = Uuid::new_v4().simple().to_string();
        let expires = now.saturating_add(lease_seconds);
        let changed = sqlx::query(
            r#"UPDATE webhook_deliveries
               SET state='leased',lease_token=?,lease_expires_unix=?,attempt_count=attempt_count+1,
                   next_attempt_unix=0,last_error_code=NULL
               WHERE source=? AND delivery_id=? AND attempt_count < ?
                 AND ((state='received' AND next_attempt_unix <= ?)
                   OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?))"#,
        )
        .bind(&token)
        .bind(expires)
        .bind(&source)
        .bind(&delivery_id)
        .bind(MAX_DELIVERY_ATTEMPTS)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
        if changed.rows_affected() != 1 {
            continue;
        }
        let row: (String, String, Vec<u8>, String, i64) = sqlx::query_as(
            r#"SELECT event_type,payload_sha256,payload_bytes,signature_header,attempt_count
               FROM webhook_deliveries
               WHERE source=? AND delivery_id=? AND lease_token=?"#,
        )
        .bind(&source)
        .bind(&delivery_id)
        .bind(&token)
        .fetch_one(pool)
        .await?;
        recovered.push(RecoveredDelivery {
            source,
            delivery_id,
            event_type: row.0,
            payload_sha256: row.1,
            payload_bytes: row.2,
            signature_header: row.3,
            lease_token: token,
            attempt: row.4,
        });
    }
    Ok(recovered)
}

async fn terminalize_exhausted_delivery(
    pool: &SqlitePool,
    source: &str,
    delivery_id: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE webhook_deliveries
           SET state='rejected',lease_token=NULL,lease_expires_unix=NULL,
               last_error_code='retry_budget_exhausted',completed_at=?
           WHERE source=? AND delivery_id=? AND attempt_count >= ?
             AND ((state='received' AND next_attempt_unix <= ?)
               OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?))"#,
    )
    .bind(now_rfc3339()?)
    .bind(source)
    .bind(delivery_id)
    .bind(MAX_DELIVERY_ATTEMPTS)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn terminalize_exhausted_deliveries(
    pool: &SqlitePool,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE webhook_deliveries
           SET state='rejected',lease_token=NULL,lease_expires_unix=NULL,
               last_error_code='retry_budget_exhausted',completed_at=?
           WHERE attempt_count >= ?
             AND ((state='received' AND next_attempt_unix <= ?)
               OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?))"#,
    )
    .bind(now_rfc3339()?)
    .bind(MAX_DELIVERY_ATTEMPTS)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn transition_delivery(
    pool: &SqlitePool,
    source: &str,
    delivery_id: &str,
    lease_token: &str,
    state: &str,
    error_code: Option<&str>,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"UPDATE webhook_deliveries
           SET state=?,lease_token=NULL,lease_expires_unix=NULL,last_error_code=?,completed_at=?
           WHERE source=? AND delivery_id=? AND state='leased' AND lease_token=?"#,
    )
    .bind(state)
    .bind(error_code)
    .bind(now_rfc3339()?)
    .bind(source)
    .bind(delivery_id)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict("delivery lease ownership was lost".into()));
    }
    Ok(())
}

pub async fn upsert_installation(pool: &SqlitePool, installation_id: i64, account_id: i64, login: &str, account_type: &str, active: bool) -> Result<(), AppError> {
    sqlx::query(r#"INSERT INTO installations(installation_id,github_account_id,account_login,account_type,active,updated_at)
        VALUES(?,?,?,?,?,?) ON CONFLICT(installation_id) DO UPDATE SET github_account_id=excluded.github_account_id,
        account_login=excluded.account_login, account_type=excluded.account_type, active=excluded.active, updated_at=excluded.updated_at"#)
        .bind(installation_id).bind(account_id).bind(login).bind(account_type).bind(if active { 1_i64 } else { 0_i64 }).bind(now_rfc3339()?)
        .execute(pool).await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SubscriptionProjection {
    pub account_id: i64,
    pub login: String,
    pub plan_id: Option<i64>,
    pub plan_name: Option<String>,
    pub billing_cycle: Option<String>,
    pub unit_count: Option<i64>,
    pub status: String,
    pub effective_at: Option<String>,
}

pub async fn upsert_subscription(
    pool: &SqlitePool,
    projection: &SubscriptionProjection,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO subscriptions(
            github_account_id,account_login,plan_id,plan_name,billing_cycle,unit_count,status,effective_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(github_account_id) DO UPDATE SET
            account_login=excluded.account_login,
            plan_id=excluded.plan_id,
            plan_name=excluded.plan_name,
            billing_cycle=excluded.billing_cycle,
            unit_count=excluded.unit_count,
            status=excluded.status,
            effective_at=excluded.effective_at,
            updated_at=excluded.updated_at"#,
    )
    .bind(projection.account_id)
    .bind(&projection.login)
    .bind(projection.plan_id)
    .bind(&projection.plan_name)
    .bind(&projection.billing_cycle)
    .bind(projection.unit_count)
    .bind(&projection.status)
    .bind(&projection.effective_at)
    .bind(now_rfc3339()?)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn entitlement_active(pool: &SqlitePool, installation_id: i64) -> Result<bool, AppError> {
    let active: Option<i64> = sqlx::query_scalar(r#"SELECT 1 FROM installations i
        JOIN subscriptions s ON s.github_account_id=i.github_account_id
        WHERE i.installation_id=? AND i.active=1 AND s.status='active' LIMIT 1"#)
        .bind(installation_id).fetch_optional(pool).await?;
    Ok(active.is_some())
}



pub async fn installation_active(pool: &SqlitePool, installation_id: i64) -> Result<bool, AppError> {
    let active: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM installations WHERE installation_id=? AND active=1 LIMIT 1",
    )
    .bind(installation_id)
    .fetch_optional(pool)
    .await?;
    Ok(active.is_some())
}

#[derive(Debug, Clone, Copy)]
pub struct AttestationEvidenceRecord<'a> {
    pub installation_id: i64,
    pub repository_id: i64,
    pub repository: &'a str,
    pub artifact_sha256: &'a str,
    pub initiator: &'a str,
    pub source_url_sha256: &'a str,
    pub transport_encoding: &'a str,
    pub wire_sha256: &'a str,
    pub wire_bytes: &'a [u8],
    pub bundle_sha256: &'a str,
    pub raw_json: &'a [u8],
}

pub async fn store_attestation_bundle(
    pool: &SqlitePool,
    record: AttestationEvidenceRecord<'_>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT OR IGNORE INTO attestation_bundles(
            bundle_sha256,installation_id,repository_id,repository,artifact_sha256,
            source_url_sha256,raw_json,fetched_at,initiator,transport_encoding,
            wire_sha256,wire_bytes
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"#,
    )
    .bind(record.bundle_sha256)
    .bind(record.installation_id)
    .bind(record.repository_id)
    .bind(record.repository)
    .bind(record.artifact_sha256.to_ascii_lowercase())
    .bind(record.source_url_sha256)
    .bind(record.raw_json)
    .bind(now_rfc3339()?)
    .bind(record.initiator)
    .bind(record.transport_encoding)
    .bind(record.wire_sha256)
    .bind(record.wire_bytes)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct ReleasePolicyRow {
    policy_sha256: String,
    installation_id: i64,
    repository_id: i64,
    repository: String,
    ref_rule: String,
    ref_value: String,
    signer_repository: String,
    signer_workflow_path: String,
    signer_revision_sha: String,
}

pub async fn store_release_policy(
    pool: &SqlitePool,
    policy: &crate::policy::ReleasePolicy,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT OR IGNORE INTO release_policy_versions(
            policy_sha256,installation_id,repository_id,repository,ref_rule,ref_value,
            signer_repository,signer_workflow_path,signer_revision_sha,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?)"#,
    )
    .bind(&policy.policy_sha256)
    .bind(policy.installation_id)
    .bind(policy.repository_id)
    .bind(&policy.repository)
    .bind(policy.ref_rule.as_str())
    .bind(&policy.ref_value)
    .bind(&policy.signer_repository)
    .bind(&policy.signer_workflow_path)
    .bind(&policy.signer_revision_sha)
    .bind(now_rfc3339()?)
    .execute(pool)
    .await?;

    let stored = sqlx::query_as::<_, ReleasePolicyRow>(
        r#"SELECT policy_sha256,installation_id,repository_id,repository,ref_rule,ref_value,
           signer_repository,signer_workflow_path,signer_revision_sha
           FROM release_policy_versions WHERE policy_sha256=?"#,
    )
    .bind(&policy.policy_sha256)
    .fetch_one(pool)
    .await?;
    let reconstructed = policy_from_row(stored)?;
    if &reconstructed != policy {
        return Err(AppError::Conflict(
            "policy hash already exists with different canonical content".into(),
        ));
    }
    Ok(())
}

pub async fn activate_release_policy(
    pool: &SqlitePool,
    policy: &crate::policy::ReleasePolicy,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    let exists: Option<i64> = sqlx::query_scalar(
        r#"SELECT 1 FROM release_policy_versions
           WHERE policy_sha256=? AND installation_id=? AND repository_id=? LIMIT 1"#,
    )
    .bind(&policy.policy_sha256)
    .bind(policy.installation_id)
    .bind(policy.repository_id)
    .fetch_optional(&mut *tx)
    .await?;
    if exists.is_none() {
        return Err(AppError::Conflict(
            "cannot activate a policy version that is not stored".into(),
        ));
    }

    sqlx::query(
        r#"INSERT INTO active_release_policies(installation_id,repository_id,policy_sha256,activated_at)
           VALUES(?,?,?,?)
           ON CONFLICT(installation_id,repository_id) DO UPDATE SET
             policy_sha256=excluded.policy_sha256,
             activated_at=excluded.activated_at"#,
    )
    .bind(policy.installation_id)
    .bind(policy.repository_id)
    .bind(&policy.policy_sha256)
    .bind(now_rfc3339()?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn active_release_policy(
    pool: &SqlitePool,
    installation_id: i64,
    repository_id: i64,
) -> Result<Option<crate::policy::ReleasePolicy>, AppError> {
    let row = sqlx::query_as::<_, ReleasePolicyRow>(
        r#"SELECT p.policy_sha256,p.installation_id,p.repository_id,p.repository,p.ref_rule,p.ref_value,
           p.signer_repository,p.signer_workflow_path,p.signer_revision_sha
           FROM active_release_policies a
           JOIN release_policy_versions p ON p.policy_sha256=a.policy_sha256
           WHERE a.installation_id=? AND a.repository_id=? LIMIT 1"#,
    )
    .bind(installation_id)
    .bind(repository_id)
    .fetch_optional(pool)
    .await?;
    row.map(policy_from_row).transpose()
}

pub async fn record_trusted_source_event(
    pool: &SqlitePool,
    source: &crate::policy::TrustedSourceContext,
) -> Result<(), AppError> {
    crate::policy::validate_trusted_source(source)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    sqlx::query(
        r#"INSERT OR IGNORE INTO trusted_source_events(
            delivery_id,installation_id,repository_id,repository,source_ref,source_commit_sha,observed_at
        ) VALUES(?,?,?,?,?,?,?)"#,
    )
    .bind(&source.delivery_id)
    .bind(source.installation_id)
    .bind(source.repository_id)
    .bind(&source.repository)
    .bind(&source.source_ref)
    .bind(source.source_commit_sha.to_ascii_lowercase())
    .bind(now_rfc3339()?)
    .execute(pool)
    .await?;

    let stored = trusted_source_by_delivery(pool, &source.delivery_id)
        .await?
        .ok_or_else(|| AppError::Conflict("trusted source event disappeared after insert".into()))?;
    if &stored != source {
        return Err(AppError::Conflict(
            "delivery_id was already bound to different trusted source facts".into(),
        ));
    }
    Ok(())
}

pub async fn trusted_source_for_commit_ref(
    pool: &SqlitePool,
    installation_id: i64,
    repository_id: i64,
    source_commit_sha: &str,
    source_ref: &str,
) -> Result<Option<crate::policy::TrustedSourceContext>, AppError> {
    let row: Option<(String, i64, i64, String, String, String)> = sqlx::query_as(
        r#"SELECT delivery_id,installation_id,repository_id,repository,source_ref,source_commit_sha
           FROM trusted_source_events
           WHERE installation_id=? AND repository_id=? AND source_commit_sha=? AND source_ref=?
           ORDER BY observed_at DESC LIMIT 1"#,
    )
    .bind(installation_id)
    .bind(repository_id)
    .bind(source_commit_sha.to_ascii_lowercase())
    .bind(source_ref)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(delivery_id, installation_id, repository_id, repository, source_ref, source_commit_sha)| {
        crate::policy::TrustedSourceContext {
            installation_id,
            repository_id,
            repository,
            source_ref,
            source_commit_sha,
            delivery_id,
        }
    }))
}

async fn trusted_source_by_delivery(
    pool: &SqlitePool,
    delivery_id: &str,
) -> Result<Option<crate::policy::TrustedSourceContext>, AppError> {
    let row: Option<(String, i64, i64, String, String, String)> = sqlx::query_as(
        r#"SELECT delivery_id,installation_id,repository_id,repository,source_ref,source_commit_sha
           FROM trusted_source_events WHERE delivery_id=? LIMIT 1"#,
    )
    .bind(delivery_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(delivery_id, installation_id, repository_id, repository, source_ref, source_commit_sha)| {
        crate::policy::TrustedSourceContext {
            installation_id,
            repository_id,
            repository,
            source_ref,
            source_commit_sha,
            delivery_id,
        }
    }))
}

fn policy_from_row(row: ReleasePolicyRow) -> Result<crate::policy::ReleasePolicy, AppError> {
    let ref_rule = match row.ref_rule.as_str() {
        "exact" => crate::policy::RefRuleKind::Exact,
        "prefix" => crate::policy::RefRuleKind::Prefix,
        _ => {
            return Err(AppError::Conflict(
                "stored release policy has invalid ref rule".into(),
            ));
        }
    };
    let policy = crate::policy::ReleasePolicy::new(crate::policy::ReleasePolicySpec {
        installation_id: row.installation_id,
        repository_id: row.repository_id,
        repository: row.repository,
        ref_rule,
        ref_value: row.ref_value,
        signer_repository: row.signer_repository,
        signer_workflow_path: row.signer_workflow_path,
        signer_revision_sha: row.signer_revision_sha,
    })
    .map_err(|error| AppError::Conflict(format!("stored release policy is invalid: {error}")))?;
    if policy.policy_sha256 != row.policy_sha256 {
        return Err(AppError::Conflict(
            "stored release policy hash does not match canonical content".into(),
        ));
    }
    Ok(policy)
}

pub async fn freeze_evaluation_context(
    pool: &SqlitePool,
    context: &crate::evaluation::EvaluationContext,
) -> Result<crate::evaluation::EvaluationContext, AppError> {
    sqlx::query(
        r#"INSERT OR IGNORE INTO evaluation_contexts(
            evaluation_id,installation_id,repository_id,repository,source_delivery_id,
            source_ref,source_commit_sha,policy_sha256,artifact_sha256,trust_snapshot_sha256,
            verifier_build_sha256,receipt_key_sha256,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
    )
    .bind(&context.evaluation_id)
    .bind(context.installation_id)
    .bind(context.repository_id)
    .bind(&context.repository)
    .bind(&context.source_delivery_id)
    .bind(&context.source_ref)
    .bind(&context.source_commit_sha)
    .bind(&context.policy_sha256)
    .bind(&context.artifact_sha256)
    .bind(&context.trust_snapshot_sha256)
    .bind(&context.verifier_build_sha256)
    .bind(&context.receipt_key_sha256)
    .bind(&context.created_at)
    .execute(pool)
    .await?;

    let stored = get_evaluation_context(pool, &context.evaluation_id)
        .await?
        .ok_or_else(|| AppError::Conflict("evaluation context disappeared after insert".into()))?;
    if &stored != context {
        return Err(AppError::Conflict(
            "evaluation identity was already bound to different frozen facts".into(),
        ));
    }
    Ok(stored)
}

pub async fn get_evaluation_context(
    pool: &SqlitePool,
    evaluation_id: &str,
) -> Result<Option<crate::evaluation::EvaluationContext>, AppError> {
    Ok(sqlx::query_as::<_, crate::evaluation::EvaluationContext>(
        r#"SELECT evaluation_id,installation_id,repository_id,repository,source_delivery_id,
           source_ref,source_commit_sha,policy_sha256,artifact_sha256,trust_snapshot_sha256,
           verifier_build_sha256,receipt_key_sha256,created_at
           FROM evaluation_contexts WHERE evaluation_id=? LIMIT 1"#,
    )
    .bind(evaluation_id)
    .fetch_optional(pool)
    .await?)
}

const MAX_CHECK_ATTEMPTS: i64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEvaluationRecord {
    pub evaluation_id: String,
    pub evidence_truth: crate::decision::EvidenceTruth,
    pub policy_authorization: crate::decision::PolicyAuthorization,
    pub release_decision: crate::decision::ReleaseDecision,
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
}

#[derive(Debug, sqlx::FromRow)]
struct ReleaseEvaluationRow {
    evaluation_id: String,
    evidence_truth: String,
    policy_authorization: String,
    release_decision: String,
    policy_reason: String,
    provenance_reason: String,
    attestation_set_sha256: String,
    decision_commitment: String,
    receipt_id: String,
    receipt_key_id: String,
    receipt_key_sha256: String,
    receipt_jws: String,
    receipt_sha256: String,
    completed_at: String,
}

pub struct ReleaseFinalization<'a> {
    pub context: &'a crate::evaluation::EvaluationContext,
    pub evidence_truth: crate::decision::EvidenceTruth,
    pub policy_authorization: crate::decision::PolicyAuthorization,
    pub release_decision: crate::decision::ReleaseDecision,
    pub policy_reason: &'a str,
    pub provenance_reason: &'a str,
    pub receipt_key_id: &'a str,
    pub receipt: &'a crate::receipt::SignedReceipt,
    pub bundle_outcomes: &'a [crate::provenance::BundleVerification],
    pub check_name: &'a str,
    pub check_conclusion: &'a str,
    pub check_title: &'a str,
    pub check_summary: &'a str,
}

pub async fn finalize_release_evaluation(
    pool: &SqlitePool,
    finalization: ReleaseFinalization<'_>,
) -> Result<ReleaseEvaluationRecord, AppError> {
    let completed_at = now_rfc3339()?;
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(
        r#"INSERT OR IGNORE INTO release_evaluations(
            evaluation_id,evidence_truth,policy_authorization,release_decision,
            policy_reason,provenance_reason,attestation_set_sha256,decision_commitment,
            receipt_id,receipt_key_id,receipt_key_sha256,receipt_jws,receipt_sha256,completed_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
    )
    .bind(&finalization.context.evaluation_id)
    .bind(crate::receipt::truth_str(finalization.evidence_truth))
    .bind(crate::receipt::authorization_str(finalization.policy_authorization))
    .bind(crate::receipt::release_str(finalization.release_decision))
    .bind(finalization.policy_reason)
    .bind(finalization.provenance_reason)
    .bind(&finalization.receipt.attestation_set_sha256)
    .bind(&finalization.receipt.decision_commitment)
    .bind(&finalization.receipt.receipt_id)
    .bind(finalization.receipt_key_id)
    .bind(&finalization.context.receipt_key_sha256)
    .bind(&finalization.receipt.receipt_jws)
    .bind(&finalization.receipt.receipt_sha256)
    .bind(&completed_at)
    .execute(&mut *tx)
    .await?;

    if inserted.rows_affected() == 1 {
        for outcome in finalization.bundle_outcomes {
            sqlx::query(
                r#"INSERT INTO evaluation_attestation_outcomes(
                    evaluation_id,bundle_sha256,evidence_truth,reason_code
                ) VALUES(?,?,?,?)"#,
            )
            .bind(&finalization.context.evaluation_id)
            .bind(&outcome.bundle_sha256)
            .bind(crate::receipt::truth_str(outcome.truth))
            .bind(&outcome.reason)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"INSERT OR IGNORE INTO usage_events(
                installation_id,metric,quantity,source_key,repository,occurred_at
            ) VALUES(?,'release_evaluation_v1',1,?,?,?)"#,
        )
        .bind(finalization.context.installation_id)
        .bind(&finalization.context.evaluation_id)
        .bind(&finalization.context.repository)
        .bind(&completed_at)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"INSERT INTO github_check_outbox(
                evaluation_id,installation_id,repository_id,repository,head_sha,check_name,
                external_id,conclusion,title,summary,state,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?)"#,
        )
        .bind(&finalization.context.evaluation_id)
        .bind(finalization.context.installation_id)
        .bind(finalization.context.repository_id)
        .bind(&finalization.context.repository)
        .bind(&finalization.context.source_commit_sha)
        .bind(finalization.check_name)
        .bind(&finalization.context.evaluation_id)
        .bind(finalization.check_conclusion)
        .bind(finalization.check_title)
        .bind(finalization.check_summary)
        .bind(&completed_at)
        .bind(&completed_at)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    let stored = get_release_evaluation(pool, &finalization.context.evaluation_id)
        .await?
        .ok_or(AppError::Internal("release evaluation disappeared after finalization"))?;
    if stored.decision_commitment != finalization.receipt.decision_commitment
        || stored.receipt_sha256 != finalization.receipt.receipt_sha256
        || stored.receipt_key_sha256 != finalization.context.receipt_key_sha256
    {
        return Err(AppError::Conflict(
            "evaluation id was already finalized with different decision evidence".into(),
        ));
    }
    Ok(stored)
}

pub async fn get_release_evaluation(
    pool: &SqlitePool,
    evaluation_id: &str,
) -> Result<Option<ReleaseEvaluationRecord>, AppError> {
    let row = sqlx::query_as::<_, ReleaseEvaluationRow>(
        r#"SELECT evaluation_id,evidence_truth,policy_authorization,release_decision,
           policy_reason,provenance_reason,attestation_set_sha256,decision_commitment,
           receipt_id,receipt_key_id,receipt_key_sha256,receipt_jws,receipt_sha256,completed_at
           FROM release_evaluations WHERE evaluation_id=? LIMIT 1"#,
    )
    .bind(evaluation_id)
    .fetch_optional(pool)
    .await?;
    row.map(release_evaluation_from_row).transpose()
}

fn release_evaluation_from_row(row: ReleaseEvaluationRow) -> Result<ReleaseEvaluationRecord, AppError> {
    Ok(ReleaseEvaluationRecord {
        evaluation_id: row.evaluation_id,
        evidence_truth: parse_truth(&row.evidence_truth)?,
        policy_authorization: parse_authorization(&row.policy_authorization)?,
        release_decision: parse_release(&row.release_decision)?,
        policy_reason: row.policy_reason,
        provenance_reason: row.provenance_reason,
        attestation_set_sha256: row.attestation_set_sha256,
        decision_commitment: row.decision_commitment,
        receipt_id: row.receipt_id,
        receipt_key_id: row.receipt_key_id,
        receipt_key_sha256: row.receipt_key_sha256,
        receipt_jws: row.receipt_jws,
        receipt_sha256: row.receipt_sha256,
        completed_at: row.completed_at,
    })
}

fn parse_truth(value: &str) -> Result<crate::decision::EvidenceTruth, AppError> {
    match value {
        "VERIFIED" => Ok(crate::decision::EvidenceTruth::Verified),
        "INVALID" => Ok(crate::decision::EvidenceTruth::Invalid),
        "INDETERMINATE" => Ok(crate::decision::EvidenceTruth::Indeterminate),
        _ => Err(AppError::Conflict("stored evidence truth is invalid".into())),
    }
}

fn parse_authorization(value: &str) -> Result<crate::decision::PolicyAuthorization, AppError> {
    match value {
        "ALLOW" => Ok(crate::decision::PolicyAuthorization::Allow),
        "DENY" => Ok(crate::decision::PolicyAuthorization::Deny),
        "INDETERMINATE" => Ok(crate::decision::PolicyAuthorization::Indeterminate),
        _ => Err(AppError::Conflict("stored policy authorization is invalid".into())),
    }
}

fn parse_release(value: &str) -> Result<crate::decision::ReleaseDecision, AppError> {
    match value {
        "RELEASE" => Ok(crate::decision::ReleaseDecision::Release),
        "BLOCK" => Ok(crate::decision::ReleaseDecision::Block),
        "HOLD" => Ok(crate::decision::ReleaseDecision::Hold),
        _ => Err(AppError::Conflict("stored release decision is invalid".into())),
    }
}

#[derive(Debug, Clone)]
pub struct CheckDispatchLease {
    pub evaluation_id: String,
    pub installation_id: i64,
    pub repository_id: i64,
    pub repository: String,
    pub head_sha: String,
    pub check_name: String,
    pub external_id: String,
    pub conclusion: String,
    pub title: String,
    pub summary: String,
    pub lease_token: String,
}

pub async fn lease_check_dispatches(
    pool: &SqlitePool,
    lease_seconds: i64,
    limit: i64,
) -> Result<Vec<CheckDispatchLease>, AppError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    terminalize_exhausted_checks(pool, now).await?;
    let candidates: Vec<String> = sqlx::query_scalar(
        r#"SELECT evaluation_id FROM github_check_outbox
           WHERE attempt_count < ? AND (
             (state='pending' AND next_attempt_unix <= ?)
             OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?)
           ) ORDER BY created_at ASC LIMIT ?"#,
    )
    .bind(MAX_CHECK_ATTEMPTS)
    .bind(now)
    .bind(now)
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;

    let mut leases = Vec::with_capacity(candidates.len());
    for evaluation_id in candidates {
        let token = Uuid::new_v4().simple().to_string();
        let expires = now.saturating_add(lease_seconds);
        let changed = sqlx::query(
            r#"UPDATE github_check_outbox
               SET state='leased',lease_token=?,lease_expires_unix=?,
                   attempt_count=attempt_count+1,next_attempt_unix=0,last_error_code=NULL,updated_at=?
               WHERE evaluation_id=? AND attempt_count < ? AND (
                 (state='pending' AND next_attempt_unix <= ?)
                 OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?)
               )"#,
        )
        .bind(&token)
        .bind(expires)
        .bind(now_rfc3339()?)
        .bind(&evaluation_id)
        .bind(MAX_CHECK_ATTEMPTS)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
        if changed.rows_affected() != 1 {
            continue;
        }
        let row: (i64, i64, String, String, String, String, String, String, String) =
            sqlx::query_as(
                r#"SELECT installation_id,repository_id,repository,head_sha,check_name,
                   external_id,conclusion,title,summary
                   FROM github_check_outbox WHERE evaluation_id=? AND lease_token=?"#,
            )
            .bind(&evaluation_id)
            .bind(&token)
            .fetch_one(pool)
            .await?;
        leases.push(CheckDispatchLease {
            evaluation_id,
            installation_id: row.0,
            repository_id: row.1,
            repository: row.2,
            head_sha: row.3,
            check_name: row.4,
            external_id: row.5,
            conclusion: row.6,
            title: row.7,
            summary: row.8,
            lease_token: token,
        });
    }
    Ok(leases)
}

pub async fn complete_check_dispatch(
    pool: &SqlitePool,
    evaluation_id: &str,
    lease_token: &str,
    check_run_id: i64,
) -> Result<(), AppError> {
    if check_run_id <= 0 {
        return Err(AppError::Conflict("GitHub check run id must be positive".into()));
    }
    let result = sqlx::query(
        r#"UPDATE github_check_outbox
           SET state='sent',lease_token=NULL,lease_expires_unix=NULL,
               check_run_id=?,last_error_code=NULL,updated_at=?
           WHERE evaluation_id=? AND state='leased' AND lease_token=?"#,
    )
    .bind(check_run_id)
    .bind(now_rfc3339()?)
    .bind(evaluation_id)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict("GitHub check lease ownership was lost".into()));
    }
    Ok(())
}

pub async fn release_check_dispatch(
    pool: &SqlitePool,
    evaluation_id: &str,
    lease_token: &str,
    error_code: &str,
) -> Result<(), AppError> {
    let attempt: i64 = sqlx::query_scalar(
        "SELECT attempt_count FROM github_check_outbox WHERE evaluation_id=? AND state='leased' AND lease_token=?",
    )
    .bind(evaluation_id)
    .bind(lease_token)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::Conflict("GitHub check lease ownership was lost".into()))?;
    let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 6)).unwrap_or(6);
    let delay = 5_i64.saturating_mul(2_i64.saturating_pow(exponent)).min(300);
    let next_attempt = OffsetDateTime::now_utc().unix_timestamp().saturating_add(delay);
    let result = sqlx::query(
        r#"UPDATE github_check_outbox
           SET state='pending',lease_token=NULL,lease_expires_unix=NULL,next_attempt_unix=?,
               last_error_code=?,updated_at=?
           WHERE evaluation_id=? AND state='leased' AND lease_token=?"#,
    )
    .bind(next_attempt)
    .bind(error_code)
    .bind(now_rfc3339()?)
    .bind(evaluation_id)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict("GitHub check lease ownership was lost".into()));
    }
    Ok(())
}

pub async fn dead_letter_check_dispatch(
    pool: &SqlitePool,
    evaluation_id: &str,
    lease_token: &str,
    error_code: &str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"UPDATE github_check_outbox
           SET state='dead',lease_token=NULL,lease_expires_unix=NULL,
               last_error_code=?,updated_at=?
           WHERE evaluation_id=? AND state='leased' AND lease_token=?"#,
    )
    .bind(error_code)
    .bind(now_rfc3339()?)
    .bind(evaluation_id)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict("GitHub check lease ownership was lost".into()));
    }
    Ok(())
}

async fn terminalize_exhausted_checks(pool: &SqlitePool, now: i64) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE github_check_outbox
           SET state='dead',lease_token=NULL,lease_expires_unix=NULL,
               last_error_code='retry_budget_exhausted',updated_at=?
           WHERE attempt_count >= ? AND (
             (state='pending' AND next_attempt_unix <= ?)
             OR (state='leased' AND COALESCE(lease_expires_unix,0) <= ?)
           )"#,
    )
    .bind(now_rfc3339()?)
    .bind(MAX_CHECK_ATTEMPTS)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn check_dispatch_state(
    pool: &SqlitePool,
    evaluation_id: &str,
) -> Result<Option<(String, Option<i64>, Option<String>)>, AppError> {
    Ok(sqlx::query_as(
        "SELECT state,check_run_id,last_error_code FROM github_check_outbox WHERE evaluation_id=? LIMIT 1",
    )
    .bind(evaluation_id)
    .fetch_optional(pool)
    .await?)
}
