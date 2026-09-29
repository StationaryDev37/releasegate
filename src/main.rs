mod billing;
mod config;
mod error;
mod github;
mod model;
mod policy;
mod provenance;
mod receipt;
mod store;
mod verify;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use config::Config;
use error::AppError;
use model::{PolicyResolveRequest, Receipt, VerificationRequest, WebhookAck};
use serde_json::Value;
use policy::{PolicyResolution, ReleasePolicy, ReleasePolicySpec, TrustedSourceContext};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    db: SqlitePool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(Config::from_env()?);
    let db = store::connect(&config.database_url).await?;
    let state = AppState {
        config: config.clone(),
        db,
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(bind = %config.bind, "releasegate listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(ready))
        .route("/webhooks/github/app", post(github_app_webhook))
        .route(
            "/webhooks/github/marketplace",
            post(github_marketplace_webhook),
        )
        .route("/v1/verify", post(verify_evidence))
        .route("/v1/policies/active", post(put_active_policy))
        .route("/v1/policies/resolve", post(resolve_policy))
        .route("/v1/receipts/:id", get(get_receipt))
        .layer(RequestBodyLimitLayer::new(1_048_576))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn ready(State(state): State<AppState>) -> Result<StatusCode, AppError> {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn github_app_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let secret = state.config.github_app_webhook_secret.clone();
    handle_github_webhook(state, headers, body, "github_app", &secret).await
}

async fn github_marketplace_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let secret = state.config.github_marketplace_webhook_secret.clone();
    handle_github_webhook(state, headers, body, "github_marketplace", &secret).await
}

async fn handle_github_webhook(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    source: &str,
    secret: &str,
) -> Result<impl IntoResponse, AppError> {
    let signature = header(&headers, "x-hub-signature-256")?;
    if !github::verify_webhook_signature(secret.as_bytes(), &body, signature) {
        return Err(AppError::Unauthorized);
    }
    let delivery = header(&headers, "x-github-delivery")?.to_owned();
    let event = header(&headers, "x-github-event")?.to_owned();
    let payload_hash = hex::encode(Sha256::digest(&body));

    if !store::claim_delivery(&state.db, source, &delivery, &event, &payload_hash).await? {
        return Ok((
            StatusCode::ACCEPTED,
            Json(WebhookAck {
                status: "duplicate",
                delivery_id: delivery,
            }),
        ));
    }

    let payload: Value = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;

    match (source, event.as_str()) {
        ("github_app", "ping") | ("github_marketplace", "ping") => {}
("github_app", "installation") => handle_installation(&state.db, &payload).await?,
        ("github_app", "push") => handle_push_source(&state.db, &payload, &delivery).await?,
        ("github_marketplace", "marketplace_purchase") => {
            billing::apply_marketplace_event(&state.db, &payload).await?;
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "event {event} is not accepted on {source} ingress"
            )));
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(WebhookAck {
            status: "accepted",
            delivery_id: delivery,
        }),
    ))
}

async fn handle_installation(db: &SqlitePool, payload: &Value) -> Result<(), AppError> {
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let installation = payload
        .get("installation")
        .ok_or_else(|| AppError::BadRequest("installation missing".into()))?;
    let installation_id = installation
        .get("id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::BadRequest("installation.id missing".into()))?;
    let account = installation
        .get("account")
        .ok_or_else(|| AppError::BadRequest("installation.account missing".into()))?;
    let account_id = account
        .get("id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::BadRequest("installation.account.id missing".into()))?;
    let login = account
        .get("login")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let account_type = account
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let active = !matches!(action, "deleted" | "suspend");
    store::upsert_installation(
        db,
        installation_id,
        account_id,
        login,
        account_type,
        active,
    )
    .await
}


async fn handle_push_source(
    db: &SqlitePool,
    payload: &Value,
    delivery_id: &str,
) -> Result<(), AppError> {
    if payload.get("deleted").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    let installation_id = payload
        .pointer("/installation/id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::BadRequest("installation.id missing".into()))?;
    if !store::installation_active(db, installation_id).await? {
        return Err(AppError::Unauthorized);
    }
    let repository_id = payload
        .pointer("/repository/id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::BadRequest("repository.id missing".into()))?;
    let repository = payload
        .pointer("/repository/full_name")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("repository.full_name missing".into()))?;
    let source_ref = payload
        .get("ref")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("ref missing".into()))?;
    let source_commit_sha = payload
        .get("after")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("after missing".into()))?;

    let source = TrustedSourceContext {
        installation_id,
        repository_id,
        repository: repository.to_owned(),
        source_ref: source_ref.to_owned(),
        source_commit_sha: source_commit_sha.to_owned(),
        delivery_id: delivery_id.to_owned(),
    };
    store::record_trusted_source_event(db, &source).await
}

async fn put_active_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(spec): Json<ReleasePolicySpec>,
) -> Result<Json<ReleasePolicy>, AppError> {
    authorize_ingest(&state.config.ingest_token, &headers)?;
    let policy = ReleasePolicy::new(spec)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    store::store_release_policy(&state.db, &policy).await?;
    store::activate_release_policy(&state.db, &policy).await?;
    Ok(Json(policy))
}

async fn resolve_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PolicyResolveRequest>,
) -> Result<Json<PolicyResolution>, AppError> {
    authorize_ingest(&state.config.ingest_token, &headers)?;
    let policy = store::active_release_policy(&state.db, req.installation_id, req.repository_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let source = store::trusted_source_for_commit(
        &state.db,
        req.installation_id,
        req.repository_id,
        &req.source_commit_sha,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(policy.resolve(&source)))
}

async fn verify_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerificationRequest>,
) -> Result<Json<Receipt>, AppError> {
    authorize_ingest(&state.config.ingest_token, &headers)?;
    verify::validate(&req)?;
    if !store::entitlement_active(&state.db, req.installation_id).await? {
        return Err(AppError::Unauthorized);
    }

    let candidate = receipt::build(&req, &store::now_rfc3339());
    let stored = store::store_receipt(&state.db, &candidate).await?;
    store::record_usage(
        &state.db,
        req.installation_id,
        "verification_attempt",
        &stored.receipt_id,
        Some(&req.repository),
    )
    .await?;
    Ok(Json(stored))
}

async fn get_receipt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Receipt>, AppError> {
    authorize_ingest(&state.config.ingest_token, &headers)?;
    store::get_receipt(&state.db, &id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

fn authorize_ingest(expected: &str, headers: &HeaderMap) -> Result<(), AppError> {
    let provided = header(headers, "x-releasegate-token")?;
    let expected_hash = Sha256::digest(expected.as_bytes());
    let provided_hash = Sha256::digest(provided.as_bytes());
    if bool::from(
        expected_hash
            .as_slice()
            .ct_eq(provided_hash.as_slice()),
    ) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AppError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest(format!("missing or invalid {name} header")))
}

fn init_tracing() {
    let filter = std::env::var("RELEASEGATE_LOG")
        .unwrap_or_else(|_| "releasegate=info,tower_http=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}

async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("ctrl-c handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}
