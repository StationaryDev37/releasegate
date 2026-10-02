mod billing;
mod config;
mod decision;
mod error;
mod evaluation;
mod github;
mod model;
mod policy;
mod provenance;
mod receipt;
mod secret;
mod silicon;
mod store;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use config::Config;
use secret::Secret;
use error::AppError;
use decision::{compose, EvidenceTruth};
use model::{CheckProjection, EvaluationRequest, EvaluationResultResponse, ReceiptKeyResponse, WebhookAck};
use serde_json::Value;
use policy::{ReleasePolicy, ReleasePolicySpec, TrustedSourceContext};
use receipt::ReceiptSigner;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    db: SqlitePool,
    trust_snapshot_sha256: Arc<str>,
    verifier_build_sha256: Arc<str>,
    github: github::GithubApi,
    receipt_signer: Arc<ReceiptSigner>,
    receipt_public_key_pem: Arc<str>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(Config::from_env()?);
    let silicon = silicon::attest_runtime()?;
    let db = store::connect(&config.database_url).await?;
    let trust_snapshot_sha256 = provenance::embedded_trust_snapshot_sha256()
        .map_err(|_| anyhow::anyhow!("embedded trust snapshot failed to parse"))?;
    let verifier_build_sha256 = evaluation::current_binary_sha256()
        .map_err(|_| anyhow::anyhow!("failed to hash running ReleaseGate binary"))?;
    let signer = github::GithubAppJwtSigner::from_app_id(
        config.github_app_id,
        config.github_app_private_key_pem.as_bytes(),
    )?;
    let github = github::GithubApi::new(signer, config.bundle_host.clone())?;
    let receipt_signer = Arc::new(ReceiptSigner::new(
        config.receipt_signing_key_id.clone(),
        config.receipt_signing_private_key_pem.as_bytes(),
        config.receipt_signing_public_key_pem.as_bytes(),
    )?);
    let state = AppState {
        config: config.clone(),
        db,
        trust_snapshot_sha256: Arc::from(trust_snapshot_sha256),
        verifier_build_sha256: Arc::from(verifier_build_sha256),
        github,
        receipt_signer,
        receipt_public_key_pem: Arc::from(config.receipt_signing_public_key_pem.clone()),
    };

    let critical_worker_failed = Arc::new(AtomicBool::new(false));
    let recovery_state = state.clone();
    let recovery_task = tokio::spawn(async move { recovery_loop(recovery_state).await });
    let check_state = state.clone();
    let check_task = tokio::spawn(async move { check_dispatch_loop(check_state).await });

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(
        bind = %config.bind,
        silicon_fingerprint = %silicon.host_fingerprint,
        silicon_lock_sha256 = %silicon.lock_sha256,
        runtime_cpus = ?silicon.runtime_cpus,
        tokio_worker_threads = silicon.tokio_worker_threads,
        "releasegate listening"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown(
            recovery_task,
            check_task,
            critical_worker_failed.clone(),
        ))
        .await?;
    if critical_worker_failed.load(Ordering::SeqCst) {
        anyhow::bail!("invariant-critical worker exited unexpectedly");
    }
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
        .route("/v1/policies/active", post(put_active_policy))
        .route("/v1/evaluations", post(freeze_evaluation))
        .route("/v1/evaluations/:id", get(get_evaluation))
        .route("/v1/receipt-key", get(get_receipt_key))
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
    handle_github_webhook(
        &state,
        headers,
        body,
        "github_app",
        &state.config.github_app_webhook_secret,
    )
    .await
}

async fn github_marketplace_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    handle_github_webhook(
        &state,
        headers,
        body,
        "github_marketplace",
        &state.config.github_marketplace_webhook_secret,
    )
    .await
}

async fn handle_github_webhook(
    state: &AppState,
    headers: HeaderMap,
    body: Bytes,
    source: &str,
    secret: &Secret,
) -> Result<impl IntoResponse, AppError> {
    let signature = header(&headers, "x-hub-signature-256")?;
    if !github::verify_webhook_signature(secret.as_bytes(), &body, signature) {
        return Err(AppError::Unauthorized);
    }
    let delivery = header(&headers, "x-github-delivery")?.to_owned();
    let event = header(&headers, "x-github-event")?.to_owned();
    let payload_hash = hex::encode(Sha256::digest(&body));

    let lease = store::lease_delivery(
        &state.db,
        store::AuthenticatedDelivery {
            source,
            delivery_id: &delivery,
            event_type: &event,
            payload_sha256: &payload_hash,
            payload_bytes: &body,
            signature_header: signature,
        },
        state.config.delivery_lease_seconds,
    )
    .await?;
    let lease_token = match lease {
        store::DeliveryLease::Acquired { token, attempt } => {
            tracing::debug!(source, delivery_id = %delivery, attempt, "webhook delivery leased");
            token
        }
        store::DeliveryLease::DuplicateApplied => {
            return Ok((
                StatusCode::ACCEPTED,
                Json(WebhookAck { status: "duplicate_applied", delivery_id: delivery }),
            ));
        }
        store::DeliveryLease::DuplicateRejected => {
            return Ok((
                StatusCode::ACCEPTED,
                Json(WebhookAck { status: "duplicate_rejected", delivery_id: delivery }),
            ));
        }
        store::DeliveryLease::InFlight => {
            return Ok((
                StatusCode::ACCEPTED,
                Json(WebhookAck { status: "in_flight", delivery_id: delivery }),
            ));
        }
    };

    let processing = process_webhook(&state.db, source, &event, &delivery, &body).await;
    match processing {
        Ok(()) => {
            store::complete_delivery(&state.db, source, &delivery, &lease_token).await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(WebhookAck { status: "applied", delivery_id: delivery }),
            ))
        }
        Err(error) => {
            let code = error.stable_code();
            if error.is_retryable() {
                store::release_delivery(&state.db, source, &delivery, &lease_token, code).await?;
            } else {
                store::reject_delivery(&state.db, source, &delivery, &lease_token, code).await?;
            }
            Err(error)
        }
    }
}

async fn process_webhook(
    db: &SqlitePool,
    source: &str,
    event: &str,
    delivery: &str,
    body: &[u8],
) -> Result<(), AppError> {
    let payload: Value = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;

    match (source, event) {
        ("github_app", "ping") | ("github_marketplace", "ping") => Ok(()),
        ("github_app", "installation") => handle_installation(db, &payload).await,
        ("github_app", "push") => handle_push_source(db, &payload, delivery).await,
        ("github_marketplace", "marketplace_purchase") => {
            billing::apply_marketplace_event(db, &payload).await
        }
        _ => Err(AppError::BadRequest(format!(
            "event {event} is not accepted on {source} ingress"
        ))),
    }
}

async fn recovery_loop(state: AppState) {
    loop {
        match store::lease_recoverable_deliveries(
            &state.db,
            state.config.delivery_lease_seconds,
            32,
        )
        .await
        {
            Ok(deliveries) => {
                for delivery in deliveries {
                    if let Err(error) = process_recovered_delivery(&state, delivery).await {
                        tracing::error!(error = %error, "webhook recovery transition failed");
                    }
                }
            }
            Err(error) => tracing::error!(error = %error, "webhook recovery scan failed"),
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

async fn process_recovered_delivery(
    state: &AppState,
    delivery: store::RecoveredDelivery,
) -> Result<(), AppError> {
    tracing::warn!(
        source = %delivery.source,
        delivery_id = %delivery.delivery_id,
        attempt = delivery.attempt,
        "replaying authenticated webhook from durable inbox"
    );
    let secret = match delivery.source.as_str() {
        "github_app" => &state.config.github_app_webhook_secret,
        "github_marketplace" => &state.config.github_marketplace_webhook_secret,
        _ => {
            store::reject_delivery(
                &state.db,
                &delivery.source,
                &delivery.delivery_id,
                &delivery.lease_token,
                "unknown_durable_source",
            )
            .await?;
            return Ok(());
        }
    };
    let payload_hash = hex::encode(Sha256::digest(&delivery.payload_bytes));
    if payload_hash != delivery.payload_sha256
        || !github::verify_webhook_signature(
            secret.as_bytes(),
            &delivery.payload_bytes,
            &delivery.signature_header,
        )
    {
        store::reject_delivery(
            &state.db,
            &delivery.source,
            &delivery.delivery_id,
            &delivery.lease_token,
            "durable_authentication_failed",
        )
        .await?;
        return Ok(());
    }
    let result = process_webhook(
        &state.db,
        &delivery.source,
        &delivery.event_type,
        &delivery.delivery_id,
        &delivery.payload_bytes,
    )
    .await;
    match result {
        Ok(()) => store::complete_delivery(
            &state.db,
            &delivery.source,
            &delivery.delivery_id,
            &delivery.lease_token,
        )
        .await,
        Err(error) => {
            let code = error.stable_code();
            if error.is_retryable() {
                store::release_delivery(
                    &state.db,
                    &delivery.source,
                    &delivery.delivery_id,
                    &delivery.lease_token,
                    code,
                )
                .await?;
            } else {
                store::reject_delivery(
                    &state.db,
                    &delivery.source,
                    &delivery.delivery_id,
                    &delivery.lease_token,
                    code,
                )
                .await?;
            }
            Ok(())
        }
    }
}

async fn handle_installation(db: &SqlitePool, payload: &Value) -> Result<(), AppError> {
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("installation.action missing".into()))?;
    let active = match action {
        "created" | "unsuspend" | "new_permissions_accepted" => true,
        "deleted" | "suspend" => false,
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported installation action {action}"
            )))
        }
    };
    let installation = payload
        .get("installation")
        .ok_or_else(|| AppError::BadRequest("installation missing".into()))?;
    let installation_id = installation
        .get("id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or_else(|| AppError::BadRequest("installation.id missing or invalid".into()))?;
    let account = installation
        .get("account")
        .ok_or_else(|| AppError::BadRequest("installation.account missing".into()))?;
    let account_id = account
        .get("id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or_else(|| AppError::BadRequest("installation.account.id missing or invalid".into()))?;
    let login = account
        .get("login")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("installation.account.login missing".into()))?;
    let account_type = account
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "User" | "Organization"))
        .ok_or_else(|| AppError::BadRequest("installation.account.type unsupported".into()))?;

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
        source_commit_sha: source_commit_sha.to_ascii_lowercase(),
        delivery_id: delivery_id.to_owned(),
    };
    store::record_trusted_source_event(db, &source).await
}

async fn put_active_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(spec): Json<ReleasePolicySpec>,
) -> Result<Json<ReleasePolicy>, AppError> {
    authorize(&state.config.control_token, &headers)?;
    let policy = ReleasePolicy::new(spec)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    if !store::installation_active(&state.db, policy.installation_id).await? {
        return Err(AppError::Unauthorized);
    }
    store::store_release_policy(&state.db, &policy).await?;
    store::activate_release_policy(&state.db, &policy).await?;
    Ok(Json(policy))
}

async fn freeze_evaluation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EvaluationRequest>,
) -> Result<Json<EvaluationResultResponse>, AppError> {
    authorize(&state.config.evaluator_token, &headers)?;
    if !store::entitlement_active(&state.db, req.installation_id).await? {
        return Err(AppError::Unauthorized);
    }
    if req.artifact_sha256.len() != 64
        || !req.artifact_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AppError::BadRequest(
            "artifact_sha256 must be exactly 64 hexadecimal characters".into(),
        ));
    }
    let policy = store::active_release_policy(&state.db, req.installation_id, req.repository_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let source = store::trusted_source_for_commit_ref(
        &state.db,
        req.installation_id,
        req.repository_id,
        &req.source_commit_sha,
        &req.source_ref,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    let policy_resolution = policy.resolve(&source);
    let authorization = policy_resolution.authorization;
    let context = evaluation::EvaluationContext::freeze(
        &source,
        &policy,
        &req.artifact_sha256,
        &state.trust_snapshot_sha256,
        &state.verifier_build_sha256,
        state.receipt_signer.public_key_sha256(),
        store::now_rfc3339()?,
    )?;
    let context = store::freeze_evaluation_context(&state.db, &context).await?;

    if let Some(existing) = store::get_release_evaluation(&state.db, &context.evaluation_id).await? {
        return Ok(Json(build_evaluation_response(&state, context, existing).await?));
    }

    let (evidence_truth, provenance_reason, bundle_outcomes) =
        if authorization == decision::PolicyAuthorization::Allow {
            let expectation = policy_resolution
                .expectation
                .as_ref()
                .ok_or(AppError::Internal("allowed policy resolution omitted verifier expectation"))?;
            match provenance::retrieve_and_store(
                &state.github,
                &state.db,
                context.installation_id,
                context.repository_id,
                &context.repository,
                &context.artifact_sha256,
            )
            .await
            {
                Ok(bundles) => {
                    let verification = provenance::verify_provenance(
                        &context.artifact_sha256,
                        expectation,
                        &bundles,
                    );
                    (verification.truth, verification.reason, verification.bundles)
                }
                Err(provenance::ProvenanceGateError::Github(_)) => (
                    EvidenceTruth::Indeterminate,
                    "attestation_retrieval_unavailable".to_owned(),
                    Vec::new(),
                ),
                Err(provenance::ProvenanceGateError::Store(error)) => return Err(error),
            }
        } else {
            (
                EvidenceTruth::Indeterminate,
                "provenance_not_evaluated_without_policy_allow".to_owned(),
                Vec::new(),
            )
        };
    let release_decision = compose(evidence_truth, authorization);
    let receipt = state.receipt_signer.sign_decision(
        &context,
        evidence_truth,
        authorization,
        release_decision,
        policy_resolution.reason,
        &provenance_reason,
        &bundle_outcomes,
    )?;
    let (check_name, check_conclusion, check_title, check_summary) = check_projection_text(
        &context,
        release_decision,
        evidence_truth,
        authorization,
        policy_resolution.reason,
        &provenance_reason,
        &receipt.receipt_id,
    );
    let stored = store::finalize_release_evaluation(
        &state.db,
        store::ReleaseFinalization {
            context: &context,
            evidence_truth,
            policy_authorization: authorization,
            release_decision,
            policy_reason: policy_resolution.reason,
            provenance_reason: &provenance_reason,
            receipt_key_id: state.receipt_signer.key_id(),
            receipt: &receipt,
            bundle_outcomes: &bundle_outcomes,
            check_name: &check_name,
            check_conclusion,
            check_title: &check_title,
            check_summary: &check_summary,
        },
    )
    .await?;

    tracing::info!(
        evaluation_id = %context.evaluation_id,
        installation_id = context.installation_id,
        repository_id = context.repository_id,
        ?evidence_truth,
        ?authorization,
        ?release_decision,
        decision_commitment = %stored.decision_commitment,
        receipt_id = %stored.receipt_id,
        "release evaluation durably finalized"
    );
    Ok(Json(build_evaluation_response(&state, context, stored).await?))
}

async fn get_evaluation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<EvaluationResultResponse>, AppError> {
    authorize(&state.config.auditor_token, &headers)?;
    let context = store::get_evaluation_context(&state.db, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result = store::get_release_evaluation(&state.db, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(build_evaluation_response(&state, context, result).await?))
}

async fn get_receipt_key(State(state): State<AppState>) -> Json<ReceiptKeyResponse> {
    Json(ReceiptKeyResponse {
        algorithm: "RS256",
        key_id: state.receipt_signer.key_id().to_owned(),
        public_key_sha256: state.receipt_signer.public_key_sha256().to_owned(),
        public_key_pem: state.receipt_public_key_pem.to_string(),
    })
}

async fn build_evaluation_response(
    state: &AppState,
    context: evaluation::EvaluationContext,
    result: store::ReleaseEvaluationRecord,
) -> Result<EvaluationResultResponse, AppError> {
    if result.evaluation_id != context.evaluation_id {
        return Err(AppError::Conflict(
            "release result is bound to a different frozen evaluation context".into(),
        ));
    }
    let (check_state, check_run_id, last_error_code) = store::check_dispatch_state(
        &state.db,
        &context.evaluation_id,
    )
    .await?
    .unwrap_or_else(|| ("missing".to_owned(), None, Some("check_outbox_missing".to_owned())));
    Ok(EvaluationResultResponse {
        context,
        evidence_truth: result.evidence_truth,
        policy_authorization: result.policy_authorization,
        release_decision: result.release_decision,
        policy_reason: result.policy_reason,
        provenance_reason: result.provenance_reason,
        attestation_set_sha256: result.attestation_set_sha256,
        decision_commitment: result.decision_commitment,
        receipt_id: result.receipt_id,
        receipt_key_id: result.receipt_key_id,
        receipt_key_sha256: result.receipt_key_sha256,
        receipt_jws: result.receipt_jws,
        receipt_sha256: result.receipt_sha256,
        completed_at: result.completed_at,
        github_check: CheckProjection {
            state: check_state,
            check_run_id,
            last_error_code,
        },
    })
}

fn check_projection_text(
    context: &evaluation::EvaluationContext,
    release_decision: decision::ReleaseDecision,
    evidence_truth: decision::EvidenceTruth,
    authorization: decision::PolicyAuthorization,
    policy_reason: &str,
    provenance_reason: &str,
    receipt_id: &str,
) -> (String, &'static str, String, String) {
    let suffix = context
        .evaluation_id
        .strip_prefix("rge_")
        .unwrap_or(&context.evaluation_id);
    let name = format!("ReleaseGate {suffix}");
    let (conclusion, title) = match release_decision {
        decision::ReleaseDecision::Release => ("success", "Release authorized".to_owned()),
        decision::ReleaseDecision::Block => ("failure", "Release blocked".to_owned()),
        decision::ReleaseDecision::Hold => ("action_required", "Release held".to_owned()),
    };
    let summary = format!(
        "decision={:?}; evidence={:?}; policy={:?}; policy_reason={}; provenance_reason={}; receipt={}",
        release_decision,
        evidence_truth,
        authorization,
        policy_reason,
        provenance_reason,
        receipt_id,
    );
    (name, conclusion, title, summary)
}

async fn check_dispatch_loop(state: AppState) {
    loop {
        match store::lease_check_dispatches(&state.db, state.config.check_lease_seconds, 32).await {
            Ok(leases) => {
                for lease in leases {
                    let result = state
                        .github
                        .publish_check_run(
                            lease.installation_id,
                            lease.repository_id,
                            &lease.repository,
                            &lease.head_sha,
                            &lease.check_name,
                            &lease.external_id,
                            &lease.conclusion,
                            &lease.title,
                            &lease.summary,
                        )
                        .await;
                    match result {
                        Ok(check_run_id) => {
                            if let Err(error) = store::complete_check_dispatch(
                                &state.db,
                                &lease.evaluation_id,
                                &lease.lease_token,
                                check_run_id,
                            )
                            .await
                            {
                                tracing::error!(%error, evaluation_id=%lease.evaluation_id, "failed to commit GitHub check delivery");
                            }
                        }
                        Err(error) if error.is_retryable() => {
                            if let Err(store_error) = store::release_check_dispatch(
                                &state.db,
                                &lease.evaluation_id,
                                &lease.lease_token,
                                error.stable_code(),
                            )
                            .await
                            {
                                tracing::error!(%store_error, evaluation_id=%lease.evaluation_id, "failed to reschedule GitHub check delivery");
                            }
                        }
                        Err(error) => {
                            if let Err(store_error) = store::dead_letter_check_dispatch(
                                &state.db,
                                &lease.evaluation_id,
                                &lease.lease_token,
                                error.stable_code(),
                            )
                            .await
                            {
                                tracing::error!(%store_error, evaluation_id=%lease.evaluation_id, "failed to dead-letter GitHub check delivery");
                            }
                        }
                    }
                }
            }
            Err(error) => tracing::error!(%error, "GitHub check outbox scan failed"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn authorize(expected: &Secret, headers: &HeaderMap) -> Result<(), AppError> {
    let provided = header(headers, "x-releasegate-token")?;
    if expected.matches(provided) {
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

async fn shutdown(
    mut recovery_task: tokio::task::JoinHandle<()>,
    mut check_task: tokio::task::JoinHandle<()>,
    critical_worker_failed: Arc<AtomicBool>,
) {
    tokio::select! {
        () = shutdown_signal() => {
            tracing::info!("shutdown signal received");
        },
        result = &mut recovery_task => {
            critical_worker_failed.store(true, Ordering::SeqCst);
            match result {
                Ok(()) => tracing::error!("webhook recovery worker exited unexpectedly"),
                Err(error) => tracing::error!(%error, "webhook recovery worker failed"),
            }
        },
        result = &mut check_task => {
            critical_worker_failed.store(true, Ordering::SeqCst);
            match result {
                Ok(()) => tracing::error!("GitHub check worker exited unexpectedly"),
                Err(error) => tracing::error!(%error, "GitHub check worker failed"),
            }
        },
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install ctrl-c handler");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
