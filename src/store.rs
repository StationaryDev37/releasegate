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
    source_url_sha256: &str,
    bundle_sha256: &str,
    raw_json: &[u8],
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT OR IGNORE INTO attestation_bundles(
            bundle_sha256,installation_id,repository_id,repository,artifact_sha256,
            source_url_sha256,raw_json,fetched_at
        ) VALUES(?,?,?,?,?,?,?,?)"#,
    )
    .bind(bundle_sha256)
    .bind(installation_id)
    .bind(repository_id)
    .bind(repository)
    .bind(artifact_sha256.to_ascii_lowercase())
    .bind(source_url_sha256)
    .bind(raw_json)
    .bind(now_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}
