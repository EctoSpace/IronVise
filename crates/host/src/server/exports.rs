//! Evidence exports: certificates, reports, and the events JSON API.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct CertificateQuery {
    /// Submit the ledger tip to an OpenTimestamps calendar and embed the stamp.
    /// Off by default: it is a network call on a GET, and a fresh stamp is a
    /// calendar's promise rather than a Bitcoin attestation.
    #[serde(default)]
    ots: bool,
}

/// `GET /api/certificates/{id}` - export an audit certificate.
///
/// Signed when this process still holds the session's key, which is the case
/// for a Claude Code hook session that has not outlived a restart. Unsigned
/// otherwise, because the key is returned once at session creation and never
/// stored: there is nothing to sign with, and inventing an issuer identity to
/// fill the field would be worse than the empty one.
///
/// `verify-cert --strict` refuses an unsigned certificate; `--expected-key`
/// checks it against a key obtained out of band.
pub(crate) async fn get_certificate(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
    Query(q): Query<CertificateQuery>,
) -> Result<axum::Json<crate::certificate::EctoLedgerCertificate>, StatusCode> {
    let key = crate::server::session_keys::signing_key_for(session_id).await;
    let key = key.as_deref();
    let cert = match &state.pool {
        crate::pool::DatabasePool::Postgres(pg) => {
            crate::certificate::build_certificate(pg, session_id, key, q.ots, None).await
        }
        crate::pool::DatabasePool::Sqlite(sq) => {
            crate::certificate::build_certificate_sqlite(sq, session_id, key, q.ots, None).await
        }
    }
    .map_err(|e| {
        tracing::warn!("Certificate build failed for {}: {}", session_id, e);
        StatusCode::NOT_FOUND
    })?;
    Ok(axum::Json(cert))
}

pub(crate) async fn get_report(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<axum::Json<crate::report::AuditReport>, StatusCode> {
    let report = match &state.pool {
        crate::pool::DatabasePool::Postgres(pg) => {
            crate::report::build_report(pg, session_id).await
        }
        crate::pool::DatabasePool::Sqlite(sq) => {
            crate::report::build_report_sqlite(sq, session_id).await
        }
    }
    .map_err(|e| {
        tracing::warn!("Report build failed for {}: {}", session_id, e);
        StatusCode::NOT_FOUND
    })?;
    Ok(axum::Json(report))
}

// Events JSON API for the GUI; `/api/stream` carries the live SSE stream instead.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct EventsQuery {
    session_id: Option<Uuid>,
}

/// Admin and auditor tokens get payloads as recorded: they review and verify
/// evidence. Agent tokens are handed to automation, which writes events and
/// has no need to read what other sessions captured, so they get payloads
/// redacted as the live stream shows them.
pub(crate) async fn get_events_json(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    Query(q): Query<EventsQuery>,
) -> Result<axum::Json<Vec<serde_json::Value>>, StatusCode> {
    let session_id = q.session_id.ok_or(StatusCode::BAD_REQUEST)?;
    let events = state
        .pool
        .get_events_by_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("get_events_json: session_id={session_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let out: Vec<serde_json::Value> = events
        .into_iter()
        .map(|e| {
            let payload = serde_json::to_value(&e.payload).unwrap_or_default();
            serde_json::json!({
                "id": e.id,
                "sequence": e.sequence,
                "previous_hash": e.previous_hash,
                "content_hash": e.content_hash,
                "payload": if role == Role::Agent { redact_for_stream(&payload) } else { payload },
                "created_at": e.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(axum::Json(out))
}
