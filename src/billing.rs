use serde_json::Value;
use sqlx::SqlitePool;

use crate::{error::AppError, store};

pub async fn apply_marketplace_event(pool: &SqlitePool, payload: &Value) -> Result<(), AppError> {
    let action = payload.get("action").and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("marketplace_purchase.action missing".into()))?;
    let purchase = payload.get("marketplace_purchase")
        .ok_or_else(|| AppError::BadRequest("marketplace_purchase object missing".into()))?;
    let account = purchase.get("account").ok_or_else(|| AppError::BadRequest("account missing".into()))?;
    let account_id = account.get("id").and_then(Value::as_i64).ok_or_else(|| AppError::BadRequest("account.id missing".into()))?;
    let login = account.get("login").and_then(Value::as_str).unwrap_or("unknown");
    let plan = purchase.get("plan");
    let plan_id = plan.and_then(|v| v.get("id")).and_then(Value::as_i64);
    let plan_name = plan.and_then(|v| v.get("name")).and_then(Value::as_str);
    let billing_cycle = purchase.get("billing_cycle").and_then(Value::as_str);
    let unit_count = purchase.get("unit_count").and_then(Value::as_i64);
    let effective_at = purchase.get("effective_date").and_then(Value::as_str)
        .or_else(|| payload.get("effective_date").and_then(Value::as_str));

    let status = match action {
        "purchased" | "changed" => "active",
        "cancelled" => "cancelled",
        _ => "unknown",
    };
    store::upsert_subscription(pool, account_id, login, plan_id, plan_name, billing_cycle, unit_count, status, effective_at).await
}
