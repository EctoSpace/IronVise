//! Access: API tokens and webhooks.

#[allow(unused_imports)]
use super::*;

#[tauri::command]
pub async fn get_tokens() -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!("{}/api/tokens", base_url()))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to list tokens: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Roles the webview may mint. It never holds the admin token, so it must not
/// be able to create one either: anything injected into it would then have
/// admin rights.
fn check_token_role(role: &str) -> Result<(), String> {
    const ALLOWED_ROLES: &[&str] = &["auditor", "agent"];
    if ALLOWED_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(format!(
            "Role '{role}' cannot be created from the app. Allowed: {ALLOWED_ROLES:?}. \
             Admin tokens are made with OBSERVER_TOKEN or POST /api/tokens."
        ))
    }
}

#[tauri::command]
pub async fn create_token(
    label: String,
    role: String,
    expiry_days: Option<u32>,
) -> Result<serde_json::Value, String> {
    check_token_role(&role)?;
    let client = http_client();
    let body = serde_json::json!({ "label": label, "role": role, "expires_in_days": expiry_days });
    let res = client
        .post(format!("{}/api/tokens", base_url()))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create token: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_token(token_hash: String) -> Result<(), String> {
    let client = http_client();
    let res = client
        .delete(format!(
            "{}/api/tokens/{}",
            base_url(),
            urlencoding::encode(&token_hash)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to revoke token: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn get_webhooks() -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!("{}/api/webhooks", base_url()))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to list webhooks: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_webhook(
    label: String,
    url: String,
    bearer_token: Option<String>,
    siem_format: String,
    filter_kinds: Vec<String>,
    enabled: bool,
) -> Result<serde_json::Value, String> {
    let client = http_client();
    let body = serde_json::json!({
        "label": label,
        "url": url,
        "bearer_token": bearer_token,
        "siem_format": siem_format,
        "filter_kinds": filter_kinds,
        "enabled": enabled,
    });
    let res = client
        .post(format!("{}/api/webhooks", base_url()))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create webhook: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_webhook(webhook_id: String) -> Result<(), String> {
    let client = http_client();
    let res = client
        .delete(format!(
            "{}/api/webhooks/{}",
            base_url(),
            urlencoding::encode(&webhook_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to delete webhook: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn toggle_webhook(webhook_id: String, enabled: bool) -> Result<(), String> {
    let client = http_client();
    let body = serde_json::json!({ "enabled": enabled });
    let res = client
        .put(format!(
            "{}/api/webhooks/{}",
            base_url(),
            urlencoding::encode(&webhook_id)
        ))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to toggle webhook: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod token_role_tests {
    use super::check_token_role;

    #[test]
    fn the_app_cannot_mint_an_admin_token() {
        assert!(check_token_role("admin").is_err());
        assert!(check_token_role("ADMIN").is_err());
        assert!(check_token_role("").is_err());
        assert!(check_token_role("agent").is_ok());
        assert!(check_token_role("auditor").is_ok());
    }
}
