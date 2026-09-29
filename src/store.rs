use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use time::OffsetDateTime;

use crate::{error::AppError, model::Receipt};

pub async fn connect(database_url: &str) -> anyhow::Result<SqlitePool> {
    let pool = SqlitePoolOptions::new().max_connections(8).connect(database_url).await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting is infallible for OffsetDateTime")
}

pub async fn claim_delivery(pool: &SqlitePool, source: &str, delivery_id: &str, event_type: &str, payload_sha256: &str) -> Result<bool, AppError> {
    let result = sqlx::query("INSERT OR IGNORE INTO webhook_deliveries(source,delivery_id,event_type,payload_sha256,received_at) VALUES(?,?,?,?,?)")
        .bind(source).bind(delivery_id).bind(event_type).bind(payload_sha256).bind(now_rfc3339())
        .execute(pool).await?;
    Ok(result.rows_affected() == 1)
}

pub async fn upsert_installation(pool: &SqlitePool, installation_id: i64, account_id: i64, login: &str, account_type: &str, active: bool) -> Result<(), AppError> {
    sqlx::query(r#"INSERT INTO installations(installation_id,github_account_id,account_login,account_type,active,updated_at)
        VALUES(?,?,?,?,?,?) ON CONFLICT(installation_id) DO UPDATE SET github_account_id=excluded.github_account_id,
        account_login=excluded.account_login, account_type=excluded.account_type, active=excluded.active, updated_at=excluded.updated_at"#)
        .bind(installation_id).bind(account_id).bind(login).bind(account_type).bind(if active { 1_i64 } else { 0_i64 }).bind(now_rfc3339())
        .execute(pool).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_subscription(pool: &SqlitePool, account_id: i64, login: &str, plan_id: Option<i64>, plan_name: Option<&str>, billing_cycle: Option<&str>, unit_count: Option<i64>, status: &str, effective_at: Option<&str>) -> Result<(), AppError> {
    sqlx::query(r#"INSERT INTO subscriptions(github_account_id,account_login,plan_id,plan_name,billing_cycle,unit_count,status,effective_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(github_account_id) DO UPDATE SET account_login=excluded.account_login,
        plan_id=excluded.plan_id, plan_name=excluded.plan_name, billing_cycle=excluded.billing_cycle,
        unit_count=excluded.unit_count, status=excluded.status, effective_at=excluded.effective_at, updated_at=excluded.updated_at"#)
        .bind(account_id).bind(login).bind(plan_id).bind(plan_name).bind(billing_cycle).bind(unit_count).bind(status).bind(effective_at).bind(now_rfc3339())
        .execute(pool).await?;
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

pub async fn store_receipt(pool: &SqlitePool, r: &Receipt) -> Result<Receipt, AppError> {
    sqlx::query(r#"INSERT OR IGNORE INTO verification_receipts(receipt_id,installation_id,request_id,repository,source_commit,
        artifact_sha256,manifest_sha256,policy_sha256,evidence_commitment,outcome,reason_code,receipt_sha256,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"#)
        .bind(&r.receipt_id).bind(r.installation_id).bind(&r.request_id).bind(&r.repository).bind(&r.source_commit)
        .bind(&r.artifact_sha256).bind(&r.manifest_sha256).bind(&r.policy_sha256).bind(&r.evidence_commitment)
        .bind(&r.outcome).bind(&r.reason_code).bind(&r.receipt_sha256).bind(&r.created_at)
        .execute(pool).await?;

    let stored = sqlx::query_as::<_, Receipt>(
        "SELECT * FROM verification_receipts WHERE installation_id=? AND request_id=?",
    )
    .bind(r.installation_id)
    .bind(&r.request_id)
    .fetch_one(pool)
    .await?;

    if stored.evidence_commitment != r.evidence_commitment {
        return Err(AppError::Conflict(
            "request_id was already used with different evidence".into(),
        ));
    }
    Ok(stored)
}

pub async fn get_receipt(pool: &SqlitePool, receipt_id: &str) -> Result<Option<Receipt>, AppError> {
    Ok(sqlx::query_as::<_, Receipt>("SELECT * FROM verification_receipts WHERE receipt_id=?")
        .bind(receipt_id).fetch_optional(pool).await?)
}

pub async fn record_usage(pool: &SqlitePool, installation_id: i64, metric: &str, source_key: &str, repository: Option<&str>) -> Result<(), AppError> {
    sqlx::query("INSERT OR IGNORE INTO usage_events(installation_id,metric,quantity,source_key,repository,occurred_at) VALUES(?,?,?,?,?,?)")
        .bind(installation_id).bind(metric).bind(1_i64).bind(source_key).bind(repository).bind(now_rfc3339())
        .execute(pool).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn store_attestation_bundle(
    pool: &SqlitePool,
    installation_id: i64,
    repository_id: i64,
    repository: &str,
    artifact_sha256: &str,
    initiator: &str,
    source_url_sha256: &str,
    transport_encoding: &str,
    wire_sha256: &str,
    wire_bytes: &[u8],
    bundle_sha256: &str,
    raw_json: &[u8],
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT OR IGNORE INTO attestation_bundles(
            bundle_sha256,installation_id,repository_id,repository,artifact_sha256,
            source_url_sha256,raw_json,fetched_at,initiator,transport_encoding,
            wire_sha256,wire_bytes
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"#,
    )
    .bind(bundle_sha256)
    .bind(installation_id)
    .bind(repository_id)
    .bind(repository)
    .bind(artifact_sha256.to_ascii_lowercase())
    .bind(source_url_sha256)
    .bind(raw_json)
    .bind(now_rfc3339())
    .bind(initiator)
    .bind(transport_encoding)
    .bind(wire_sha256)
    .bind(wire_bytes)
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
    .bind(now_rfc3339())
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
    .bind(now_rfc3339())
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
    .bind(now_rfc3339())
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
