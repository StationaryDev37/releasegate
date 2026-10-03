use serde_json::Value;
use sqlx::SqlitePool;

use crate::{error::AppError, store};

pub async fn apply_marketplace_event(pool: &SqlitePool, payload: &Value) -> Result<(), AppError> {
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("marketplace_purchase.action missing".into()))?;
    let purchase = payload
        .get("marketplace_purchase")
        .ok_or_else(|| AppError::BadRequest("marketplace_purchase object missing".into()))?;
    let account = purchase
        .get("account")
        .ok_or_else(|| AppError::BadRequest("account missing".into()))?;
    let account_id = account
        .get("id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::BadRequest("account.id missing".into()))?;
    let login = account
        .get("login")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("account.login missing".into()))?;

    let status = match action {
        "purchased" | "changed" | "pending_change_cancelled" => "active",
        "pending_change" => "pending",
        "cancelled" => "cancelled",
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported marketplace_purchase action {action}"
            )))
        }
    };

    let plan = purchase.get("plan");
    let plan_id = plan
        .and_then(|value| value.get("id"))
        .and_then(Value::as_i64);
    let plan_name = plan
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str);
    if status == "active" && (plan_id.is_none() || plan_name.is_none()) {
        return Err(AppError::BadRequest(
            "active marketplace purchase is missing plan identity".into(),
        ));
    }
    let billing_cycle = purchase.get("billing_cycle").and_then(Value::as_str);
    let unit_count = purchase.get("unit_count").and_then(Value::as_i64);
    if unit_count.is_some_and(|count| count < 0) {
        return Err(AppError::BadRequest("unit_count cannot be negative".into()));
    }
    let effective_at = purchase
        .get("effective_date")
        .and_then(Value::as_str)
        .or_else(|| payload.get("effective_date").and_then(Value::as_str));

    let projection = store::SubscriptionProjection {
        account_id,
        login: login.to_owned(),
        plan_id,
        plan_name: plan_name.map(str::to_owned),
        billing_cycle: billing_cycle.map(str::to_owned),
        unit_count,
        status: status.to_owned(),
        effective_at: effective_at.map(str::to_owned),
    };
    store::upsert_subscription(pool, &projection).await
}
