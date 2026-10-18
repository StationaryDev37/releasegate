//! One-time Stripe purchase ingress. All signed events are authenticated before JSON parsing.
//! An unconfigured Stripe integration remains absent; no checkout is offered.
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::{error::AppError, model::EvaluationRequest, AppState};

type HmacSha256 = Hmac<Sha256>;
const MAX_SKEW_SECONDS: i64 = 300;
const PRICE_USD_CENTS: i64 = 2_900;

#[derive(Debug, Deserialize)]
pub struct PaidEvaluationRequest {
    pub session_id: String,
    #[serde(flatten)]
    pub request: EvaluationRequest,
}

#[derive(Debug, Deserialize)]
pub struct PaidPolicyRequest {
    pub session_id: String,
    #[serde(flatten)]
    pub spec: crate::policy::ReleasePolicySpec,
}

#[derive(Debug, Deserialize)]
pub struct OrderLookupRequest {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct CheckoutLink {
    pub purchase_url: String,
    pub installation_id: i64,
    pub price_usd_cents: i64,
}

fn hmac_hex(key: &[u8], bytes: &[u8]) -> Result<String, AppError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AppError::Internal("invalid HMAC key"))?;
    mac.update(bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn signed_ref(installation_id: i64, secret: &[u8]) -> Result<String, AppError> {
    if installation_id <= 0 {
        return Err(AppError::BadRequest("installation ID must be positive".into()));
    }
    let data = format!("rgp1_{installation_id}");
    let mac = hmac_hex(secret, data.as_bytes())?;
    Ok(format!("{data}_{mac}"))
}

fn verify_ref(reference: &str, secret: &[u8]) -> Result<i64, AppError> {
    let (prefix, claimed_mac) = reference.rsplit_once('_').ok_or(AppError::Unauthorized)?;
    let id = prefix.strip_prefix("rgp1_").ok_or(AppError::Unauthorized)?;
    if id.starts_with('0') || !id.bytes().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Unauthorized);
    }
    let id: i64 = id.parse().map_err(|_| AppError::Unauthorized)?;
    if id <= 0 || claimed_mac.len() != 64 {
        return Err(AppError::Unauthorized);
    }
    let mac = hex::decode(claimed_mac).map_err(|_| AppError::Unauthorized)?;
    let expected = hex::decode(hmac_hex(secret, prefix.as_bytes())?)
        .map_err(|_| AppError::Internal("invalid computed HMAC"))?;
    if !bool::from(mac.as_slice().ct_eq(expected.as_slice())) {
        return Err(AppError::Unauthorized);
    }
    Ok(id)
}

pub async fn checkout_link(
    State(state): State<AppState>,
    Path(installation_id): Path<i64>,
) -> Result<Json<CheckoutLink>, AppError> {
    let config = state.config.stripe_commercial.as_ref().ok_or(AppError::NotFound)?;
    if !crate::store::installation_active(&state.db, installation_id).await? {
        return Err(AppError::NotFound);
    }
    let reference = signed_ref(installation_id, config.claim_key.as_bytes())?;
    // Config is validated as a plain HTTPS Stripe URL with no existing query/fragment.
    Ok(Json(CheckoutLink {
        purchase_url: format!("{}?client_reference_id={reference}", config.payment_link_url),
        installation_id,
        price_usd_cents: PRICE_USD_CENTS,
    }))
}

fn verify_signature(secret: &[u8], header: &str, body: &[u8], now: i64) -> bool {
    let mut timestamp: Option<i64> = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else { return false; };
        match name {
            "t" if timestamp.is_none() => {
                if value.starts_with('-') || value.starts_with('+') || value.starts_with('0') {
                    return false;
                }
                timestamp = value.parse().ok();
            }
            "t" => return false,
            "v1" => {
                if value.len() != 64 { return false; }
                let Ok(bytes) = hex::decode(value) else { return false; };
                signatures.push(bytes);
            }
            _ => {},
        }
    }
    let Some(t) = timestamp else { return false; };
    if signatures.is_empty() || (i128::from(now) - i128::from(t)).abs() > i128::from(MAX_SKEW_SECONDS) {
        return false;
    }
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    signatures.iter().any(|sig| bool::from(sig.as_slice().ct_eq(digest.as_ref())))
}

pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let config = state.config.stripe_commercial.as_ref().ok_or(AppError::NotFound)?;
    let signature = headers.get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if !verify_signature(config.webhook_secret.as_bytes(), signature, &body, now) {
        return Err(AppError::Unauthorized);
    }
    let event: Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("invalid Stripe JSON".into()))?;
    let kind = event.get("type").and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("Stripe event type missing".into()))?;
    if event.get("livemode") != Some(&Value::Bool(true)) {
        return Err(AppError::BadRequest("live Stripe events only".into()));
    }
    let object = event.pointer("/data/object").ok_or_else(||
        AppError::BadRequest("Stripe event data.object missing".into()))?;
    match kind {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            // Session may be complete but awaiting delayed payment. Never credit before paid.
            if object.get("payment_status").and_then(Value::as_str) != Some("paid") {
                return Ok(StatusCode::OK);
            }
            let session_id = required_str(object, "id")?;
            let intent = required_str(object, "payment_intent")?;
            if object.get("object").and_then(Value::as_str) != Some("checkout.session")
                || object.get("mode").and_then(Value::as_str) != Some("payment")
                || object.get("status").and_then(Value::as_str) != Some("complete")
                || object.get("livemode") != Some(&Value::Bool(true))
                || object.get("payment_link").and_then(Value::as_str) != Some(config.payment_link_id.as_str())
                || object.get("amount_total").and_then(Value::as_i64) != Some(PRICE_USD_CENTS)
                || object.get("currency").and_then(Value::as_str) != Some("usd")
            {
                return Err(AppError::Unauthorized);
            }
            let reference = required_str(object, "client_reference_id")?;
            let installation_id = verify_ref(reference, config.claim_key.as_bytes())?;
            if !crate::store::installation_active(&state.db, installation_id).await? {
                // A paid but uninstalled checkout must not grant an orphan entitlement.
                return Err(AppError::Unauthorized);
            }
            let event_id = required_str(&event, "id")?;
            record_paid(&state.db, event_id, session_id, intent, installation_id).await?;
        }
        "charge.refunded" => {
            // Revocation applies to unspent credits, never rewrites signed prior results.
            if let Some(intent) = object.get("payment_intent").and_then(Value::as_str) {
                sqlx::query("UPDATE stripe_one_time_credits SET state='revoked' WHERE payment_intent=? AND consumed_evaluation_id IS NULL")
                    .bind(intent).execute(&state.db).await?;
            }
        }
        _ => {},
    }
    Ok(StatusCode::OK)
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, AppError> {
    value.get(key).and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| AppError::BadRequest(format!("Stripe field {key} invalid")))
}

async fn record_paid(
    db: &SqlitePool,
    event_id: &str,
    session_id: &str,
    intent: &str,
    installation_id: i64,
) -> Result<(), AppError> {
    if !event_id.starts_with("evt_") || !session_id.starts_with("cs_live_")
        || !intent.starts_with("pi_") {
        return Err(AppError::Unauthorized);
    }
    let mut tx = db.begin().await?;
    sqlx::query("INSERT OR IGNORE INTO stripe_one_time_credits(session_id,payment_intent,event_id,installation_id,state,created_at) VALUES(?,?,?,?,'paid',?)")
        .bind(session_id).bind(intent).bind(event_id).bind(installation_id)
        .bind(crate::store::now_rfc3339()?).execute(&mut *tx).await?;
    let stored: (String, String, i64) = sqlx::query_as(
        "SELECT payment_intent,event_id,installation_id FROM stripe_one_time_credits WHERE session_id=?")
        .bind(session_id).fetch_one(&mut *tx).await?;
    if stored.0 != intent || stored.2 != installation_id {
        return Err(AppError::Conflict("Stripe session replay identity conflict".into()));
    }
    // A different Stripe event ID for the same verified Checkout session may be legitimate
    // (completed then async success); neither event grants another credit.
    let _original_event_id = stored.1;
    tx.commit().await?;
    Ok(())
}

pub async fn paid_session_authorized(
    db: &SqlitePool,
    session_id: &str,
    installation_id: i64,
) -> Result<bool, AppError> {
    if !session_id.starts_with("cs_live_") || session_id.len() > 256 { return Ok(false); }
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM stripe_one_time_credits WHERE session_id=? AND installation_id=? AND state='paid' LIMIT 1")
        .bind(session_id).bind(installation_id).fetch_optional(db).await?;
    Ok(row.is_some())
}

pub async fn paid_session_open_or_matches(
    db: &SqlitePool,
    session_id: &str,
    evaluation_id: &str,
) -> Result<bool, AppError> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT consumed_evaluation_id FROM stripe_one_time_credits WHERE session_id=? AND state='paid'")
        .bind(session_id).fetch_optional(db).await?;
    Ok(match row {
        Some((None,)) => true,
        Some((Some(value),)) => value == evaluation_id,
        None => false,
    })
}

pub async fn activate_paid_policy(
    State(state): State<AppState>,
    Json(paid): Json<PaidPolicyRequest>,
) -> Result<Json<crate::policy::ReleasePolicy>, AppError> {
    if state.config.stripe_commercial.is_none()
        || !paid_session_authorized(&state.db, &paid.session_id, paid.spec.installation_id).await? {
        return Err(AppError::Unauthorized);
    }
    let available: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM stripe_one_time_credits WHERE session_id=? AND state='paid' AND consumed_evaluation_id IS NULL")
        .bind(&paid.session_id).fetch_optional(&state.db).await?;
    if available.is_none() { return Err(AppError::Unauthorized); }
    // Policy may only be configured for a repository observed through authenticated GitHub push.
    let observed: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM trusted_source_events WHERE installation_id=? AND repository_id=? AND repository=? LIMIT 1")
        .bind(paid.spec.installation_id)
        .bind(paid.spec.repository_id)
        .bind(&paid.spec.repository)
        .fetch_optional(&state.db).await?;
    if observed.is_none() { return Err(AppError::NotFound); }
    let policy = crate::policy::ReleasePolicy::new(paid.spec)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    crate::store::store_release_policy(&state.db, &policy).await?;
    crate::store::activate_release_policy(&state.db, &policy).await?;
    Ok(Json(policy))
}

pub async fn order_status(
    State(state): State<AppState>,
    Json(lookup): Json<OrderLookupRequest>,
) -> Result<Json<Value>, AppError> {
    if state.config.stripe_commercial.is_none() || !lookup.session_id.starts_with("cs_live_")
        || lookup.session_id.len() > 256 {
        return Err(AppError::NotFound);
    }
    // Session ID is a bearer capability, passed in the POST body rather than logged as a URL.
    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state,consumed_evaluation_id,installation_id FROM stripe_one_time_credits WHERE session_id=?")
        .bind(&lookup.session_id).fetch_optional(&state.db).await?;
    let (status, evaluation_id, installation_id) = row.ok_or(AppError::NotFound)?;
    if let Some(evaluation_id) = evaluation_id {
        let context = crate::store::get_evaluation_context(&state.db, &evaluation_id)
            .await?.ok_or(AppError::NotFound)?;
        let result = crate::store::get_release_evaluation(&state.db, &evaluation_id)
            .await?.ok_or(AppError::NotFound)?;
        let receipt = crate::build_evaluation_response(&state, context, result).await?;
        return Ok(Json(json!({"payment_state":status,"installation_id":installation_id,"result":receipt})));
    }
    Ok(Json(json!({"payment_state":status,"installation_id":installation_id,"evaluation_id":Value::Null})))
}

#[cfg(test)]
mod tests {
    use super::{hmac_hex, signed_ref, verify_ref, verify_signature};

    #[test]
    fn stripe_signature_with_timestamp_verifies() {
        let payload = br#"{"id":"evt_test","type":"checkout.session.completed"}"#;
        let t = 1_800_000_000_i64;
        let mut message = t.to_string().into_bytes();
        message.extend_from_slice(b".");
        message.extend_from_slice(payload);
        let mac = hmac_hex(b"whsec_fixture_not_live", &message).unwrap();
        let header = format!("t={t},v1={mac}");
        assert!(verify_signature(b"whsec_fixture_not_live", &header, payload, t));
        assert!(!verify_signature(b"wrong", &header, payload, t));
        assert!(!verify_signature(b"whsec_fixture_not_live", &header, b"mutated", t));
        assert!(!verify_signature(b"whsec_fixture_not_live", &header, payload, t + 301));
        assert!(!verify_signature(b"whsec_fixture_not_live", &header, payload, t - 301));
        assert!(verify_signature(b"whsec_fixture_not_live", &header, payload, t + 300));
    }

    #[test]
    fn signature_parser_rejects_ambiguous_and_malformed_headers() {
        let message = b"test";
        for header in ["", "t=0,v1=00", "t=-1,v1=00", "t=1,t=1,v1=abcd",
            "t=1,v1=abcd", "v1=00", "t=1", "t=1,v1=gggg"] {
            assert!(!verify_signature(b"whsec_fixture_not_live", header, message, 1));
        }
    }

    #[test]
    fn signed_payment_reference_binds_installation() {
        let key = b"distinct_claim_key_for_tests_only";
        let reference = signed_ref(123, key).unwrap();
        assert_eq!(verify_ref(&reference, key).unwrap(), 123);
        assert!(verify_ref(&reference, b"wrong").is_err());
        assert!(verify_ref(&reference.replace("_123_", "_124_"), key).is_err());
        assert!(signed_ref(0, key).is_err());
    }
}
