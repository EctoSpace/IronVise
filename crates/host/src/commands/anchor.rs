//! `ironvise anchor-session` - timestamp a session's ledger tip with OpenTimestamps.

use crate::schema::{EventPayload, LedgerEventRow};
use uuid::Uuid;

/// Submit a session's ledger tip hash to the OpenTimestamps calendars and
/// record the pending stamp as an Anchor event.
pub async fn run(
    pool: &sqlx::PgPool,
    session: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let events = crate::ledger::get_events_by_session(pool, session)
        .await
        .map_err(|e| format!("Failed to load session events: {e}"))?;
    let tip = tip_hash(&events, session)?;
    let payload = stamp_ots(&tip, session).await?;
    match crate::ledger::append_event(pool, payload, Some(session), None, None).await {
        Ok(e) => tracing::info!("Anchor event appended at sequence {}.", e.sequence),
        Err(e) => tracing::warn!("Failed to append Anchor event: {}", e),
    }
    Ok(())
}

/// SQLite variant of `run`.
pub async fn run_sqlite(
    pool: &sqlx::SqlitePool,
    session: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let events = crate::ledger::sqlite::get_events_by_session_sqlite(pool, session)
        .await
        .map_err(|e| format!("Failed to load session events: {e}"))?;
    let tip = tip_hash(&events, session)?;
    let payload = stamp_ots(&tip, session).await?;
    match crate::ledger::sqlite::append_event_sqlite(pool, &payload, Some(session), None, None)
        .await
    {
        Ok(e) => tracing::info!("Anchor event appended at sequence {}.", e.sequence),
        Err(e) => tracing::warn!("Failed to append Anchor event: {}", e),
    }
    Ok(())
}

fn tip_hash(
    events: &[LedgerEventRow],
    session: Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if events.is_empty() {
        return Err(format!("Session {session} has no events.").into());
    }
    Ok(events
        .last()
        .ok_or("Events list unexpectedly empty")?
        .content_hash
        .clone())
}

async fn stamp_ots(
    tip: &str,
    session: Uuid,
) -> Result<EventPayload, Box<dyn std::error::Error + Send + Sync>> {
    use crate::ots;
    println!("Anchoring session {session} to OpenTimestamps...");
    println!("Ledger tip hash: {tip}");

    match ots::submit_ots_stamp(tip).await {
        Ok(stamp_bytes) => {
            let proof_hex = hex::encode(&stamp_bytes);
            println!(
                "OTS stamp received ({} bytes). Status: pending Bitcoin confirmation.",
                stamp_bytes.len()
            );
            println!("OTS proof (hex): {}", &proof_hex[..proof_hex.len().min(64)]);
            println!("Run `ots upgrade` with the stamp file to confirm the Bitcoin block height.");
            Ok(EventPayload::Anchor {
                ledger_tip_hash: tip.to_string(),
                ots_proof_hex: proof_hex,
                bitcoin_block_height: None,
            })
        }
        Err(e) => Err(format!("OTS submission failed: {e}").into()),
    }
}
