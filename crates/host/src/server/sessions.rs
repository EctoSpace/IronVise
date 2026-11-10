//! Session lifecycle: create, list, fetch, and verifiable credentials.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

#[derive(Deserialize)]
pub(crate) struct CreateSessionRequest {
    goal: String,
    /// Record what a client reports (the SDK recorders) instead of running
    /// IronVise's own audit loop: no LLM is needed, and the session stays
    /// open for appends until it is sealed.
    #[serde(default)]
    record: bool,
}

/// `llm_backend` of a recorder session.
const RECORDER_BACKEND_LABEL: &str = "sdk-recorder";

/// A session for a client to append to: signed first event, key held for
/// certificates, no loop to seal it early.
async fn create_recorder_session(
    state: &AppState,
    goal: &str,
) -> Result<axum::Json<SessionRow>, (StatusCode, String)> {
    let internal = |what: &str, e: &dyn std::fmt::Display| {
        tracing::error!("create_session (record): {what}: {e}");
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{what}: {e}"))
    };
    let (session, key) = state
        .pool
        .create_session(goal, RECORDER_BACKEND_LABEL, "n/a", None)
        .await
        .map_err(|e| internal("Failed to create session", &e))?;
    let key = std::sync::Arc::new(key);
    state
        .pool
        .append_event(
            EventPayload::PromptInput {
                content: goal.to_string(),
            },
            Some(session.id),
            Some(goal),
            Some(key.as_ref()),
        )
        .await
        .map_err(|e| internal("Failed to append prompt event", &e))?;
    super::session_keys::remember(session.id, key).await;
    state.metrics.inc_sessions_created();
    Ok(axum::Json(SessionRow {
        enclave_attestation_json: None,
        ..session
    }))
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct ListSessionsQuery {
    status: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

pub(crate) async fn list_sessions(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<ListSessionsQuery>,
) -> Result<axum::Json<Vec<SessionRow>>, StatusCode> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let sessions = state
        .pool
        .list_sessions_filtered(q.status.as_deref(), limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("list_sessions DB query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(axum::Json(sessions))
}

pub(crate) async fn get_session_by_id(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<axum::Json<SessionRow>, StatusCode> {
    state
        .pool
        .get_session(session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(axum::Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub(crate) async fn get_session_vc(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    use crate::verifiable_credential::decode_vc_payload;
    use ectoledger_core::merkle;
    let events = state
        .pool
        .get_events_by_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "get_events_by_session failed for session {}: {}",
                session_id,
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    for ev in events.iter().rev() {
        if let EventPayload::VerifiableCredential { vc_jwt } = &ev.payload {
            let decoded = decode_vc_payload(vc_jwt);

            let event_count = events.len();

            let hashes: Vec<&str> = events.iter().map(|e| e.content_hash.as_str()).collect();
            let merkle_root = merkle::build_merkle_tree(&hashes)
                .ok()
                .and_then(|tree| merkle::root(&tree).ok());

            let policy_hash = decoded
                .as_ref()
                .and_then(|p| p.get("vc"))
                .and_then(|vc| vc.get("credentialSubject"))
                .and_then(|cs| cs.get("policyHash"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // The JWT has a real signature when it doesn't end with a trailing dot
            let has_signature = !vc_jwt.ends_with('.');

            return Ok(axum::Json(serde_json::json!({
                "vc_jwt": vc_jwt,
                "vc_payload": decoded,
                "merkle_root": merkle_root,
                "event_count": event_count,
                "policy_hash": policy_hash,
                "proof": has_signature,
            })));
        }
    }
    Err(StatusCode::NOT_FOUND)
}

/// `GET /api/sessions/{id}/vc/verify` - Verify the W3C VC-JWT for a completed session.
///
/// Resolves the VC stored for the session and checks:
/// - JWT structure (header.payload.signature)
/// - `exp` claim (credential lifetime)
/// - Ed25519 signature (when the session signing key is present in the store)
///
/// Returns JSON with `"valid": true/false` and a `"reason"` field on failure.
#[derive(serde::Deserialize)]
pub(crate) struct VcVerifyQuery {
    /// The verifier's own identifier, checked against the VC's `aud`.
    audience: Option<String>,
}

pub(crate) async fn verify_session_vc(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
    axum::extract::Query(q): axum::extract::Query<VcVerifyQuery>,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    use crate::verifiable_credential::{VcVerifyError, verify_vc_jwt};
    let events = state
        .pool
        .get_events_by_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "get_events_by_session failed for session {}: {}",
                session_id,
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let Some(vc_jwt) = events.iter().rev().find_map(|ev| match &ev.payload {
        EventPayload::VerifiableCredential { vc_jwt } => Some(vc_jwt.clone()),
        _ => None,
    }) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let session_key = state
        .pool
        .load_session_verifying_key(session_id)
        .await
        .map(|k| crate::signing::public_key_hex(&k));
    let refused = |reason: String| {
        Ok(axum::Json(serde_json::json!({
            "valid": false,
            "signature_verified": false,
            "reason": reason,
        })))
    };
    let key = match vc_signing_key(&vc_jwt, session_key, events.iter().map(|e| &e.payload)) {
        Ok(key) => key,
        Err(reason) => return refused(reason),
    };
    match verify_vc_jwt(&vc_jwt, Some(&key), q.audience.as_deref()) {
        Ok(payload) => Ok(axum::Json(serde_json::json!({
            "valid": true,
            "signature_verified": true,
            "vc_jwt": vc_jwt,
            "vc_payload": payload,
        }))),
        Err(VcVerifyError::Expired) => refused("credential has expired".into()),
        Err(e) => refused(e.to_string()),
    }
}

/// The key a session's VC must verify under: the one its `iss` names, if the
/// session authorised it (its first key, or one it rotated to and did not
/// revoke). Before this, a VC signed after a rotation failed against the
/// session's first key, and an unsigned VC was reported valid.
fn vc_signing_key<'a>(
    vc_jwt: &str,
    session_key_hex: Option<String>,
    events: impl IntoIterator<Item = &'a EventPayload>,
) -> Result<ed25519_dalek::VerifyingKey, String> {
    use crate::verifiable_credential::{unverified_issuer, verifying_key_from_did};
    let (iss, alg) = unverified_issuer(vc_jwt).ok_or("the credential is malformed")?;
    if alg == "none" {
        return Err("the credential is unsigned (alg=none): nothing proves who issued it".into());
    }
    let key = verifying_key_from_did(&iss)
        .ok_or_else(|| format!("the issuer {iss} is not an Ed25519 did:key"))?;
    let mut keys = crate::ledger::KeyLifecycle::new(session_key_hex);
    for payload in events {
        keys.after(payload);
    }
    if !keys.permits(&crate::signing::public_key_hex(&key)) {
        return Err(format!(
            "the issuer {iss} is not a key this session authorised"
        ));
    }
    Ok(key)
}

type ApiError = (StatusCode, String);

pub(crate) async fn create_session(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<CreateSessionRequest>,
) -> Result<axum::Json<SessionRow>, ApiError> {
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot create sessions".into(),
        ));
    }
    let goal = body.goal.trim();
    if goal.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Goal must not be empty".into()));
    }
    if body.record {
        return create_recorder_session(&state, goal).await;
    }

    ensure_pool_capacity(&state).await?;
    let llm_backend = ready_llm_backend(&state).await?;
    let policy = policy_for_new_run(&state)?;

    let (session, session_signing_key) = state
        .pool
        .create_session(
            goal,
            llm_backend.backend_name(),
            llm_backend.model_name(),
            policy.as_ref().map(|p| p.hash.as_str()),
        )
        .await
        .map_err(|e| {
            tracing::error!("create_session failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create session: {e}"),
            )
        })?;
    state.metrics.inc_sessions_created();
    let session_signing_key = Arc::new(session_signing_key);

    state
        .pool
        .append_event(
            EventPayload::PromptInput {
                content: goal.to_string(),
            },
            Some(session.id),
            Some(goal),
            Some(session_signing_key.as_ref()),
        )
        .await
        .map_err(|e| {
            tracing::error!("append_event failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to append prompt event: {e}"),
            )
        })?;

    let run = SessionRun {
        session_id: session.id,
        goal: goal.to_string(),
        llm_backend,
        policy,
        guard: spawn_guard_if_required()?,
        session_signing_key,
    };
    spawn_session_run(&state, run);

    Ok(axum::Json(SessionRow {
        enclave_attestation_json: None,
        ..session
    }))
}

/// Refuse a new cognitive loop when the Postgres pool has no free connection,
/// so an authenticated caller cannot exhaust it by creating sessions quickly.
async fn ensure_pool_capacity(state: &AppState) -> Result<(), ApiError> {
    let Some(pg_pool) = state.pool.as_pg() else {
        return Ok(());
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), pg_pool.acquire()).await {
        Ok(Ok(_connection)) => Ok(()),
        Ok(Err(e)) => {
            tracing::error!("create_session: pool acquire failed: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database pool error: {e}"),
            ))
        }
        Err(_) => {
            tracing::warn!(
                "create_session: pool acquire timed out - pool saturated, rejecting session"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Database pool saturated - try again later".into(),
            ))
        }
    }
}

/// The configured LLM backend, checked to be reachable. Demo mode provisions a
/// small local model, so this is always the real pipeline.
async fn ready_llm_backend(state: &AppState) -> Result<Box<dyn llm::LlmBackend>, ApiError> {
    if let Some(factory) = &state.llm_factory {
        return Ok(factory());
    }
    let client = &state.http_client;
    let backend = llm::backend_from_env(client).map_err(|e| {
        tracing::error!("LLM setup failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("LLM setup failed: {e}"),
        )
    })?;
    backend.ensure_ready(client).await.map_err(|e| {
        tracing::error!("LLM not ready: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("LLM not ready: {e}. Is your LLM backend running?"),
        )
    })?;
    Ok(backend)
}

/// The policy this run is checked against, and the one its session records:
/// `ECTO_POLICY_PATH` when the operator set one, else the one chosen in
/// Settings (read now, so an edit applies to this run), else none. A run
/// checked against no policy records no policy hash, so its certificate never
/// names a governance baseline that was not evaluated.
fn policy_for_new_run(
    state: &AppState,
) -> Result<Option<Arc<crate::policy::LoadedPolicy>>, ApiError> {
    if let Some(policy) = &state.policy {
        return Ok(Some(policy.clone()));
    }
    let Some(name) = config::active_policy() else {
        return Ok(None);
    };
    let loaded = super::policies::load_named(&name).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("The policy chosen for new runs cannot be used: {e}"),
        )
    })?;
    Ok(Some(Arc::new(loaded)))
}

fn spawn_guard_if_required() -> Result<Option<Box<dyn GuardExecutor>>, ApiError> {
    if !config::guard_required() {
        return Ok(None);
    }
    config::ensure_guard_config().map_err(|e| {
        tracing::error!("Guard config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Guard configuration error: {e}. Set GUARD_REQUIRED=false to disable."),
        )
    })?;
    let worker = GuardProcess::spawn().map_err(|e| {
        tracing::error!("Guard spawn failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Guard process failed to start: {e}. Set GUARD_REQUIRED=false to disable."),
        )
    })?;
    Ok(Some(Box::new(worker)))
}

/// Everything a background cognitive loop needs that was prepared per request.
struct SessionRun {
    session_id: Uuid,
    goal: String,
    llm_backend: Box<dyn llm::LlmBackend>,
    policy: Option<Arc<crate::policy::LoadedPolicy>>,
    guard: Option<Box<dyn GuardExecutor>>,
    session_signing_key: Arc<ed25519_dalek::SigningKey>,
}

/// Run the cognitive loop on the server's task tracker. A panic marks the
/// session failed instead of leaving it `running` forever, and the session's
/// approval gates are withdrawn when it ends.
fn spawn_session_run(state: &AppState, run: SessionRun) {
    let pool = state.pool.clone();
    let client = state.http_client.clone();
    let metrics = state.metrics.clone();
    let approval_state = state.approval_state.clone();
    // The single egress worker started with the server, shared by every session.
    let egress_tx = state.egress_tx.clone();
    let cancel = state.cancel.clone();
    let session_id = run.session_id;

    state.task_tracker.spawn(async move {
        let loop_pool = pool.clone();
        let loop_approval_state = approval_state.clone();
        let cognitive_loop = std::panic::AssertUnwindSafe(async move {
            let tripwire = Arc::new(tripwire::Tripwire::from_operator_config());
            let agent_config = agent::AgentLoopConfig {
                llm: run.llm_backend,
                tripwire: &tripwire,
                max_steps: config::max_steps_configured(),
                session_id: Some(session_id),
                session_goal: run.goal,
                guard: run.guard,
                policy: run.policy.as_deref().map(|p| &p.engine),
                session_signing_key: Some(run.session_signing_key),
                metrics: Some(metrics),
                egress_tx: Some(egress_tx),
                cloud_creds: crate::cloud_creds::load_cloud_creds().map(Arc::new),
                interactive: false,
                approval_state: Some(loop_approval_state),
                firecracker_config: crate::sandbox::FirecrackerConfig::from_env_opt(),
                docker_config: crate::sandbox::DockerConfig::from_env_opt(),
                key_rotation_interval_steps: config::key_rotation_interval_steps(),
                compensation: Some(crate::compensation::CompensationPlanner::load()),
                enclave: None,
                enclave_attestation: None,
                cancel: Some(cancel),
            };
            let result = agent::run_cognitive_loop(&loop_pool, &client, agent_config).await;
            record_session_outcome(&loop_pool, session_id, result).await;
        });
        if let Err(panic) = futures_util::FutureExt::catch_unwind(cognitive_loop).await {
            tracing::error!(session_id = %session_id, "cognitive loop panicked: {:?}", panic);
            if let Err(db_err) = pool.finish_session_if_running(session_id, "failed").await {
                tracing::error!(
                    session_id = %session_id,
                    "CRITICAL: zombie session - failed to mark panicked session as failed: {}. \
                     Manual intervention required: UPDATE agent_sessions SET status='failed' WHERE id='{}'",
                    db_err,
                    session_id,
                );
            }
        }
        if let Err(e) = approval_state.forget(session_id).await {
            tracing::warn!("approval store: forgetting session {session_id}: {e}");
        }
    });
}

/// Seal a background session with the status its loop's result calls for.
async fn record_session_outcome(
    pool: &crate::pool::DatabasePool,
    session_id: Uuid,
    result: Result<(), agent::AgentError>,
) {
    use agent::AgentError;
    use ledger::AppendError;
    let status = match &result {
        Ok(()) => {
            tracing::info!("Session {} completed", session_id);
            "completed"
        }
        Err(AgentError::Append(AppendError::GoalMismatch)) => {
            record_security_thought(
                pool,
                session_id,
                "Security: session goal mismatch; aborting.".to_string(),
            )
            .await;
            tracing::warn!("Session {} aborted: goal mismatch", session_id);
            "aborted"
        }
        Err(AgentError::Append(AppendError::UnverifiedEvidence(msg))) => {
            record_security_thought(
                pool,
                session_id,
                format!("Findings verification failed: {msg}; commit rejected."),
            )
            .await;
            tracing::warn!("Session {} failed: {}", session_id, msg);
            "failed"
        }
        // The agent loop already recorded why; only the status is left.
        Err(AgentError::TripwireAbort(reason)) => {
            tracing::warn!("Session {} aborted (tripwire): {}", session_id, reason);
            "aborted"
        }
        Err(AgentError::GuardAbort) => {
            tracing::warn!("Session {} aborted (guard)", session_id);
            "aborted"
        }
        Err(AgentError::CircuitBreaker) => {
            tracing::warn!("Session {} aborted (circuit breaker)", session_id);
            "aborted"
        }
        Err(AgentError::Cancelled) => {
            tracing::info!("Session {} aborted (cancellation token)", session_id);
            "aborted"
        }
        Err(e) => {
            tracing::error!("Session {} failed: {}", session_id, e);
            "failed"
        }
    };
    if let Err(e) = pool.finish_session_if_running(session_id, status).await {
        tracing::error!("Failed to mark session {} as {}: {}", session_id, status, e);
    }
}

async fn record_security_thought(
    pool: &crate::pool::DatabasePool,
    session_id: Uuid,
    content: String,
) {
    if let Err(e) = pool
        .append_event(
            EventPayload::Thought { content },
            Some(session_id),
            None,
            None,
        )
        .await
    {
        tracing::error!(
            "CRITICAL: failed to log security event for session {}: {}",
            session_id,
            e
        );
    }
}

#[cfg(test)]
mod vc_key_tests {
    use super::*;
    use crate::signing::{generate_keypair, public_key_hex};
    use crate::verifiable_credential::build_vc_jwt;

    fn vc(key: &ed25519_dalek::SigningKey) -> String {
        build_vc_jwt(uuid::Uuid::new_v4(), "g", None, Some(key), None)
    }

    fn rotation(to: &ed25519_dalek::VerifyingKey) -> EventPayload {
        EventPayload::KeyRotation {
            new_public_key: public_key_hex(to),
            rotation_index: 1,
        }
    }

    #[test]
    fn a_vc_by_the_sessions_key_or_a_rotated_one_is_verified_with_that_key() {
        let (first, first_vk) = generate_keypair();
        let (second, second_vk) = generate_keypair();
        let session = Some(public_key_hex(&first_vk));
        assert_eq!(
            vc_signing_key(&vc(&first), session.clone(), []),
            Ok(first_vk)
        );
        let rotated = [rotation(&second_vk)];
        assert_eq!(
            vc_signing_key(&vc(&second), session, &rotated),
            Ok(second_vk)
        );
    }

    #[test]
    fn a_vc_by_any_other_key_or_none_is_refused() {
        let (first, first_vk) = generate_keypair();
        let (stranger, _) = generate_keypair();
        let session = Some(public_key_hex(&first_vk));
        assert!(vc_signing_key(&vc(&stranger), session.clone(), []).is_err());
        let unsigned = build_vc_jwt(uuid::Uuid::new_v4(), "g", None, None, None);
        let err = vc_signing_key(&unsigned, session.clone(), []).unwrap_err();
        assert!(err.contains("unsigned"), "{err}");
        let revoked = [EventPayload::KeyRevocation {
            revoked_public_key: public_key_hex(&first_vk),
            reason: "test".into(),
        }];
        assert!(vc_signing_key(&vc(&first), session, &revoked).is_err());
        assert!(vc_signing_key("not.a.jwt", None, []).is_err());
    }
}
