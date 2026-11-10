//! Policy and tripwire: the rules files and the tripwire configuration.

#[allow(unused_imports)]
use super::*;

#[tauri::command]
pub async fn get_policy_content(name: String) -> Result<String, String> {
    let client = http_client();
    let mut req = client.get(format!(
        "{}/api/policies/{}",
        base_url(),
        urlencoding::encode(&name)
    ));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if res.status().as_u16() == 404 {
        return Err(format!("Policy not found: {name}"));
    }
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to load policy {name} ({status}): {}",
            sanitize_error_body(&msg)
        ));
    }
    res.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_tripwire_config() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/tripwire", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Failed to load tripwire config: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
// A misnamed field must fail, not vanish (see ipc_contract_tests).
#[serde(deny_unknown_fields)]
pub struct TripwireConfigPayload {
    pub allowed_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub banned_command_patterns: Vec<String>,
    pub min_justification_length: Option<u32>,
    pub require_https: Option<bool>,
}

#[tauri::command]
pub async fn save_tripwire_config(
    payload: TripwireConfigPayload,
) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .put(format!("{}/api/tripwire", base_url()))
        .headers(auth_headers().clone())
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!("Save failed: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Ask the tripwire whether `intent` (a `{ action, params, justification? }`
/// object) would be allowed, without opening a session or recording
/// anything - what the GUI's "try a command" panel calls.
#[tauri::command]
pub async fn check_tripwire(intent: serde_json::Value) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .post(format!("{}/api/tripwire/check", base_url()))
        .headers(auth_headers().clone())
        .json(&intent)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Tripwire check failed: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_policies() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/policies", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Failed to load policies: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_policy(name: String, content: String) -> Result<String, String> {
    let client = http_client();
    let res = client
        .put(format!(
            "{}/api/policies/{}",
            base_url(),
            urlencoding::encode(&name)
        ))
        .headers(auth_headers().clone())
        .body(content)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        // The server says why (not a policy, built-in, ...); pass that on.
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        let detail = sanitize_error_body(&body);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!("Save failed: {status}")
        } else {
            format!("Save failed: {detail}")
        });
    }
    Ok(res.status().to_string())
}

#[tauri::command]
pub async fn delete_policy(name: String) -> Result<(), String> {
    let client = http_client();
    let res = client
        .delete(format!(
            "{}/api/policies/{}",
            base_url(),
            urlencoding::encode(&name)
        ))
        .headers(auth_headers().clone())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(if status.as_u16() == 403 {
            "Built-in policies cannot be deleted.".to_string()
        } else {
            format!("Delete failed: {}", sanitize_error_body(&msg))
        });
    }
    Ok(())
}
