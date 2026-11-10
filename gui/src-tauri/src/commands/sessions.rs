//! Sessions: listing, events, starting a run, verification, certificates,
//! reports, verifiable credentials, approvals and metrics.

#[allow(unused_imports)]
use super::*;

#[tauri::command]
pub async fn get_events(session_id: Option<String>) -> Result<serde_json::Value, String> {
    let sid = session_id.ok_or("session_id required")?;
    let url = format!(
        "{}/api/events?session_id={}",
        base_url(),
        urlencoding::encode(&sid)
    );
    let client = http_client();
    let mut req = client.get(url);
    req = req.headers(auth_headers().clone());
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(match status.as_u16() {
            429 => "Rate limited - retrying automatically.".to_string(),
            404 => format!("Session {sid} not found."),
            _ => format!(
                "Failed to load events ({status}): {}",
                sanitize_error_body(&body)
            ),
        });
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Invalid events response: {e}"))
}

#[derive(Deserialize)]
// A misnamed field must fail, not vanish (see ipc_contract_tests).
#[serde(deny_unknown_fields)]
pub struct RunPromptArgs {
    pub goal: String,
}

#[tauri::command]
pub async fn run_prompt(args: RunPromptArgs) -> Result<serde_json::Value, String> {
    let client = http_client();
    let req = client
        .post(format!("{}/api/sessions", base_url()))
        .headers(auth_headers().clone())
        // The server runs the provider and model from Settings; it never read
        // a per-request backend or model (the "ollama"/"llama3" sent here
        // looked like it chose them).
        .json(&serde_json::json!({ "goal": args.goal }));
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach backend: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        // Prefer the server-provided body text (now includes real error
        // messages), but still strip HTML: a wrong or dead backend can answer
        // with a proxy/404 page here just as easily as on any GET route.
        // Fall back to the status reason phrase if the body is empty (legacy
        // server or network-level error).
        let detail = sanitize_error_body(&body);
        let detail = if detail.is_empty() {
            format!("Server returned {status}")
        } else {
            detail
        };
        return Err(detail);
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_metrics() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/metrics/security", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        let reason = status.canonical_reason().unwrap_or("").trim();
        return Err(match status.as_u16() {
            429 => "Server rate limit reached. Metrics will retry automatically.".to_string(),
            401 | 403 => format!("Authentication failed ({status}). Restart the application."),
            500..=599 => format!(
                "Server error ({status} {reason}): {}",
                sanitize_error_body(&body)
            ),
            _ => format!(
                "Metrics request failed: {status} {reason} {}",
                sanitize_error_body(&body)
            ),
        });
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Invalid metrics response: {e}"))
}

#[tauri::command]
pub async fn get_prometheus_metrics() -> Result<String, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/metrics", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Metrics request failed: {}", res.status()));
    }
    res.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_certificate(session_id: String) -> Result<Vec<u8>, String> {
    let client = http_client();
    let mut req = client.get(format!(
        "{}/api/certificates/{}",
        base_url(),
        urlencoding::encode(&session_id)
    ));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Certificate export failed: {}", res.status()));
    }
    let bytes = res.bytes().await.map_err(|e| e.to_string())?;
    Ok(bytes.to_vec())
}

#[tauri::command]
pub async fn download_report(session_id: String) -> Result<Vec<u8>, String> {
    let client = http_client();
    let mut req = client.get(format!(
        "{}/api/reports/{}",
        base_url(),
        urlencoding::encode(&session_id)
    ));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Report download failed: {}", res.status()));
    }
    res.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_sessions(
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut url = format!("{}/api/sessions", base_url());
    if status.is_some() || limit.is_some() || offset.is_some() {
        url.push('?');
        if let Some(s) = status {
            url.push_str(&format!("status={}&", urlencoding::encode(&s)));
        }
        if let Some(l) = limit {
            url.push_str(&format!("limit={l}&"));
        }
        if let Some(o) = offset {
            url.push_str(&format!("offset={o}&"));
        }
        while url.ends_with('&') || url.ends_with('?') {
            url.pop();
        }
    }
    let res = client
        .get(url)
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to list sessions: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_session(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to fetch session: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Call `GET /api/sessions/{id}/verify`: the ledger's own chain verifier.
///
/// Verification has exactly one implementation, in Rust, and the GUI asks it
/// rather than keeping a second copy in the webview: a JS reimplementation
/// has to track the ledger's content_hash input layout exactly, and a copy
/// that falls behind (e.g. still speaking the pre-0.8 v1 layout once write
/// paths moved to v2) would flag every untouched event as a tamper alarm.
/// Returns `{ "ok": bool }`.
#[tauri::command]
pub async fn verify_session_chain(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}/verify",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Chain verification could not run: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_session_vc(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}/vc",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status().as_u16() == 404 {
        return Err("No VC found for this session. Only completed Agent-mode sessions generate a Verifiable Credential. Run an audit via Agent mode first.".to_string());
    }
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!("Failed to fetch VC: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Call `GET /api/sessions/{id}/vc/verify` - returns the decoded VC payload plus a `valid` flag.
#[tauri::command]
pub async fn verify_session_vc(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}/vc/verify",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status().as_u16() == 404 {
        return Err("No VC found for this session. Only completed Agent-mode sessions generate a Verifiable Credential.".to_string());
    }
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_default();
        let msg = msg.trim();
        return Err(if msg.is_empty() {
            format!("VC verification failed (HTTP {})", status.as_u16())
        } else {
            format!("VC verify failed: {}", sanitize_error_body(msg))
        });
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Poll `GET /api/approvals/{session_id}/pending` to check for a pending
/// human-approval gate.  Returns `null` when no gate is pending.
#[tauri::command]
pub async fn get_pending_approval(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/approvals/{}/pending",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(format!(
            "Pending approval check failed ({status}): {}",
            sanitize_error_body(&body)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Post `POST /api/approvals/{session_id}` with an approval decision.
/// `approved` = true → approve, false → deny.
#[tauri::command]
pub async fn post_approval_decision(
    session_id: String,
    gate_id: String,
    approved: bool,
    reason: Option<String>,
) -> Result<(), String> {
    let client = http_client();
    let body = serde_json::json!({
        "gate_id": gate_id,
        "approved": approved,
        "reason": reason,
    });
    let res = client
        .post(format!(
            "{}/api/approvals/{}",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Approval decision failed: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}
