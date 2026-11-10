//! REST endpoints used by the Python and TypeScript SDKs.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

/// `POST /api/sessions/{id}/seal` - Seal (finish) a session.
pub(crate) async fn seal_session_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot seal sessions".into(),
        ));
    }
    state
        .pool
        .finish_session(session_id, "completed")
        .await
        .map_err(|e| {
            tracing::error!("seal_session failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to seal session: {e}"),
            )
        })?;
    Ok(axum::Json(serde_json::json!({"ok": true})))
}

/// Event kinds a client may assert about itself.
///
/// Everything else in [`EventPayload`] describes something the *server* did -
/// a genesis it wrote, an action it executed, a refusal it issued, an anchor it
/// obtained, a key it rotated. Those carry provenance an HTTP caller cannot
/// honestly claim, and two of them (`guard_denial` and `tripwire_rejection`)
/// carry an `enforced` flag whose whole purpose is to say *the system stopped
/// this*. A client that could post one would be able to manufacture evidence of
/// an enforcement that never ran, indistinguishable in the chain from a real
/// one.
///
/// The four kinds here are reports: this is what I observed, thought, was
/// prompted with, or said. They are true statements about the caller by
/// construction, because the caller is their subject.
// Shared with verification, which accepts exactly these (and the server's own
// unsigned kinds) without a signature.
use crate::ledger::CLIENT_ASSERTABLE_KINDS;

/// `POST /api/sessions/{id}/events` - Append a single event to a session.
///
/// Accepts an arbitrary JSON body. A body that is not a tagged `EventPayload`
/// is wrapped in `Observation { content }`, which is what every documented SDK
/// call does. A body that *is* a tagged payload must name one of
/// [`CLIENT_ASSERTABLE_KINDS`]; anything else is refused with 400 rather than
/// stored as though the server had produced it.
///
/// Note that events appended here are **unsigned**: the session's Ed25519 key
/// is returned once at creation and never stored, so the server has nothing to
/// sign a client's event with. They are hash-chained, and an Ed25519 signature
/// over them would in any case attest to the server having received a claim,
/// not to the claim being true.
pub(crate) async fn append_event_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Extension(caller): axum::Extension<Caller>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
    axum::Json(mut body): axum::Json<serde_json::Value>,
) -> Result<(StatusCode, axum::Json<serde_json::Value>), (StatusCode, String)> {
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot append events".into(),
        ));
    }
    let db_err = |e: sqlx::Error| {
        tracing::error!("append_event: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("database error: {e}"),
        )
    };
    match state
        .pool
        .session_goal_and_status(session_id)
        .await
        .map_err(db_err)?
    {
        None => return Err((StatusCode::NOT_FOUND, format!("no session {session_id}"))),
        // Sealing records the session's length; an event after it makes the
        // session fail verification as tampered.
        Some((_, status)) if status != "running" => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "session {session_id} is {status}: it is sealed, and an event appended now \
                     would make it fail verification. To record a run, create the session \
                     with \"record\": true; it stays open until you seal it."
                ),
            ));
        }
        Some(_) => {}
    }
    // An `Idempotency-Key` makes a retried or replayed append a refusal instead
    // of a second, indistinguishable event.
    if let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok())
        && !state
            .pool
            .consume_request(&format!("append:{session_id}"), key, &caller.0)
            .await
            .map_err(db_err)?
    {
        return Err((
            StatusCode::CONFLICT,
            format!("Idempotency-Key {key} was already used for this session: not appended again"),
        ));
    }
    // A provider's encrypted reasoning must not become permanent, exported
    // ledger content (arXiv 2608.09867); its hash stays as the record.
    crate::encrypted_reasoning::strip(&mut body);

    if let Some(kind) = body.get("type").and_then(|v| v.as_str())
        && !CLIENT_ASSERTABLE_KINDS.contains(&kind)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "`{kind}` records something the server did, so it cannot be submitted by a \
                 client - an appended `{kind}` would be indistinguishable in the chain from \
                 one the server produced. Clients may append: {}. Omit `type` to record an \
                 observation.",
                CLIENT_ASSERTABLE_KINDS.join(", ")
            ),
        ));
    }

    let payload: EventPayload =
        serde_json::from_value(body.clone()).unwrap_or_else(|_| EventPayload::Observation {
            content: body.to_string(),
        });
    let result = state
        .pool
        .append_event(payload, Some(session_id), None, None)
        .await
        .map_err(|e| {
            tracing::error!("append_event failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to append event: {e}"),
            )
        })?;
    state.metrics.inc_events_appended();
    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "id": result.id,
            "payload_hash": result.content_hash,
            "sequence": result.sequence,
        })),
    ))
}

/// `POST /api/sessions/{id}/verify-intent` - ask whether an action would be
/// permitted, **without executing or committing anything**.
///
/// This is the primitive that turns the SDKs from loggers into a governance
/// path. A caller submits an action it is about to take; the server runs the
/// policy → tripwire pipeline and answers allow or deny *before* the caller
/// acts.
///
/// ## What it applies, and what it does not
///
/// Sharing [`crate::verify::evaluate_intent`] with the cognitive loop and the
/// Claude Code hook is not the same as sharing their configuration, and an
/// earlier cut of this handler blurred the two: this handler passed `policy: None` and no guard, then
/// answered `"allow"` with nothing to say which layers had spoken.
///
/// Now it evaluates the server-wide policy (`ECTO_POLICY_PATH`) when one is
/// configured, always evaluates the tripwire, and **never** consults the
/// semantic guard - the guard-worker is spawned per cognitive-loop session and
/// a one-shot request has no equivalent lifecycle. When `GUARD_REQUIRED` is
/// set, that absence is a denial rather than an allow, and every response
/// carries a `coverage` object naming the layers that ran, the ones that did
/// not, and the hash of the policy that decided.
///
/// ## Commits nothing, executes nothing
///
/// No ledger event is written, deliberately: this endpoint is readable by the
/// auditor role, and an endpoint an auditor may call must not write. A caller
/// that wants the decision recorded should append it, or use the hook surface,
/// which does record. `docs/guides/integrations.md` states this for each surface.
pub(crate) async fn verify_intent_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(intent): axum::Json<ectoledger_core::intent::ProposedIntent>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    // Read-only by design: an auditor may ask, because asking writes nothing.
    let _ = role;

    // The session is loaded rather than echoed. The first cut returned the submitted
    // UUID unexamined, so a verdict could name a session that had never
    // existed - and the goal, which is what a guard would judge against, was
    // never available to fetch.
    let (goal, status) = state
        .pool
        .session_goal_and_status(session_id)
        .await
        .map_err(|e| {
            tracing::error!("verify_intent: loading session {session_id}: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load session: {e}"),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("No session {session_id}. Create one before asking about its actions."),
            )
        })?;

    if status != "running" {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Session {session_id} is {status}, not running. A verdict scoped to a \
                 finished session would be recorded against nothing."
            ),
        ));
    }

    let tripwire = crate::server::hook::build_tripwire();
    let guard_required = config::guard_required();
    let ctx = crate::verify::EvaluationContext {
        policy: state.policy.as_ref().map(|p| &p.engine),
        tripwire: &tripwire,
        // The session's own goal, which the guard judges the action against.
        goal: &goal,
        step: 0,
        guard_required,
    };

    let mut guard = state.guard.acquire(guard_required).await;
    let verdict = crate::verify::evaluate_intent(&ctx, guard.executor(), &intent).await;
    let coverage = crate::verify::Coverage::new(
        state.policy.as_ref().map(|p| p.hash.clone()),
        guard.running(),
    );
    if matches!(
        &verdict,
        crate::verify::Verdict::Deny {
            stage: crate::verify::DenyStage::GuardUnavailable,
            ..
        }
    ) {
        guard.discard();
    }
    drop(guard);

    Ok(axum::Json(match verdict {
        crate::verify::Verdict::Allow => serde_json::json!({
            "decision": "allow",
            "session_id": session_id,
            "coverage": coverage,
            "recorded": false,
        }),
        crate::verify::Verdict::Deny { reason, stage } => serde_json::json!({
            "decision": "deny",
            "reason": reason,
            "stage": stage.as_str(),
            "session_id": session_id,
            "coverage": coverage,
            "recorded": false,
        }),
    }))
}

/// `GET /api/sessions/{id}/verify` - Verify a session.
///
/// `ok` is the hash chain alone, as it always was, so existing SDK callers see
/// no change. `signatures` is `verify-session`'s verdict: whether the events
/// are bound to the session's key, and how many are unsigned by design. The
/// desktop app shows both; a chain can link perfectly and still have had its
/// signatures stripped.
pub(crate) async fn verify_chain_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let internal = |what: &'static str| {
        move |e: sqlx::Error| {
            tracing::error!("{what} failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{what} failed: {e}"),
            )
        }
    };
    let ok = state
        .pool
        .verify_chain_for_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("verify_chain failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Chain verification failed: {e}"),
            )
        })?;
    let verdict = state
        .pool
        .verify_session_detailed(session_id)
        .await
        .map_err(internal("Signature verification"))?;
    let (signed, unsigned) = match verdict {
        crate::ledger::SessionVerdict::Verified {
            signatures,
            unsigned,
        } => (signatures, unsigned),
        _ => (0, 0),
    };
    Ok(axum::Json(serde_json::json!({
        "ok": ok,
        "signatures": {
            "verified": verdict.is_verified(),
            "verdict": verdict.kind(),
            "message": verdict.to_string(),
            "signed": signed,
            "unsigned": unsigned,
        }
    })))
}

/// `GET /api/sessions/{id}/compliance` - Generate a compliance proof bundle.
pub(crate) async fn prove_compliance_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let value = state
        .pool
        .prove_compliance_for_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("prove_compliance failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Compliance proof failed: {e}"),
            )
        })?;
    Ok(axum::Json(value))
}

/// `GET /api/metrics` - JSON metrics summary (total_sessions, total_events).
pub(crate) async fn metrics_json_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(_role): axum::Extension<Role>,
) -> axum::Json<serde_json::Value> {
    let m = &state.metrics;
    axum::Json(serde_json::json!({
        "total_sessions": m.sessions_created.load(std::sync::atomic::Ordering::Relaxed),
        "total_events": m.events_appended.load(std::sync::atomic::Ordering::Relaxed),
    }))
}
