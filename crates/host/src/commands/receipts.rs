//! `ironvise data-receipts <session> [--file PATH]...`: list what the
//! session's tools returned, by hash, and check files against it.
//!
//! The session is verified first: a receipt in a ledger that does not verify
//! proves nothing. A file matches when its SHA-256 is one of the texts a tool
//! returned, which is a whole file for a whole-file read; a partial read
//! (an offset, a line limit) receipts only the part that was returned.

use std::path::PathBuf;

use uuid::Uuid;

use crate::pool::DatabasePool;
use crate::receipts::sha256_hex;
use crate::schema::EventPayload;

/// One receipt, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub sequence: i64,
    pub tool: String,
    pub source: Option<String>,
    pub text_sha256: Vec<String>,
    pub text_bytes: u64,
}

/// A file and the receipts whose texts it matches (empty: none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMatch {
    pub file: PathBuf,
    pub sha256: String,
    pub sequences: Vec<i64>,
}

/// The session's receipts, once its chain and signatures verify.
pub async fn receipts(pool: &DatabasePool, session: Uuid) -> Result<Vec<Receipt>, String> {
    let chain = pool
        .verify_chain_for_session(session)
        .await
        .map_err(|e| format!("verifying the chain: {e}"))?;
    let verdict = pool
        .verify_session_detailed(session)
        .await
        .map_err(|e| format!("verifying signatures: {e}"))?;
    if !chain || !verdict.is_verified() {
        return Err(format!(
            "session {session} does not verify ({verdict}), so its receipts prove nothing"
        ));
    }
    let events = pool
        .get_events_by_session(session)
        .await
        .map_err(|e| format!("reading the session: {e}"))?;
    Ok(events
        .into_iter()
        .filter_map(|e| match e.payload {
            EventPayload::DataReceipt {
                tool,
                source,
                text_sha256,
                text_bytes,
                ..
            } => Some(Receipt {
                sequence: e.sequence,
                tool,
                source,
                text_sha256,
                text_bytes,
            }),
            _ => None,
        })
        .collect())
}

/// Which receipts each file's bytes match.
pub fn match_files(receipts: &[Receipt], files: &[PathBuf]) -> Result<Vec<FileMatch>, String> {
    files
        .iter()
        .map(|file| {
            let bytes =
                std::fs::read(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
            let sha256 = sha256_hex(&bytes);
            let sequences = receipts
                .iter()
                .filter(|r| r.text_sha256.contains(&sha256))
                .map(|r| r.sequence)
                .collect();
            Ok(FileMatch {
                file: file.clone(),
                sha256,
                sequences,
            })
        })
        .collect()
}

fn short(hash: &str) -> &str {
    hash.get(..16).unwrap_or(hash)
}

pub async fn run(
    pool: DatabasePool,
    session: Uuid,
    files: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let receipts = receipts(&pool, session).await?;
    let matches = match_files(&receipts, files)?;
    let (text, unmatched) = render(session, &receipts, &matches);
    print!("{text}");
    if unmatched > 0 {
        return Err(format!("{unmatched} file(s) match no receipt in session {session}").into());
    }
    Ok(())
}

/// What `data-receipts` prints, and how many files matched no receipt.
fn render(session: Uuid, receipts: &[Receipt], matches: &[FileMatch]) -> (String, usize) {
    let mut out = format!(
        "Session {session} verifies. {} data receipt(s):\n",
        receipts.len()
    );
    for r in receipts {
        let hashes: Vec<&str> = r.text_sha256.iter().map(|h| short(h)).collect();
        out.push_str(&format!(
            "  #{:<5} {:<28} {}  {} text(s), {} bytes  [{}]\n",
            r.sequence,
            r.tool,
            r.source.as_deref().unwrap_or("-"),
            r.text_sha256.len(),
            r.text_bytes,
            hashes.join(", ")
        ));
    }
    let mut unmatched = 0;
    for m in matches {
        let name = m.file.display();
        if m.sequences.is_empty() {
            unmatched += 1;
            out.push_str(&format!(
                "  ✗ {name} ({}…): no tool in this session returned these bytes\n",
                short(&m.sha256)
            ));
        } else {
            let at: Vec<String> = m.sequences.iter().map(|s| format!("#{s}")).collect();
            out.push_str(&format!(
                "  ✓ {name}: exactly what the tool returned at {}\n",
                at.join(", ")
            ));
        }
    }
    (out, unmatched)
}

#[cfg(test)]
mod tests;
