//! Dynamic webhook / SIEM egress configuration.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

#[derive(Serialize)]
pub(crate) struct WebhookListRow {
    id: Uuid,
    label: String,
    url: String,
    siem_format: String,
    filter_kinds: Vec<String>,
    enabled: bool,
    created_at: String,
}

pub(crate) fn default_siem_format() -> String {
    "json".to_string()
}
pub(crate) fn default_filter_kinds() -> Vec<String> {
    vec![
        "observation".to_string(),
        "guard_denial".to_string(),
        "tripwire_rejection".to_string(),
    ]
}
pub(crate) fn default_enabled() -> bool {
    true
}

#[derive(Deserialize)]
pub(crate) struct UpsertWebhookRequest {
    label: String,
    url: String,
    bearer_token: Option<String>,
    #[serde(default = "default_siem_format")]
    siem_format: String,
    #[serde(default = "default_filter_kinds")]
    filter_kinds: Vec<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

pub(crate) async fn list_webhooks(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<Vec<WebhookListRow>>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let rows = state
        .pool
        .list_webhooks()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut webhook_rows = Vec::new();
    for w in rows {
        let id: Uuid = w.id.parse().map_err(|e| {
            tracing::error!("Webhook has invalid UUID '{}': {e}", w.id);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        webhook_rows.push(WebhookListRow {
            id,
            label: w.label,
            url: w.url,
            siem_format: w.siem_format,
            filter_kinds: w
                .filter_kinds
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            enabled: w.enabled,
            created_at: w.created_at,
        });
    }
    Ok(axum::Json(webhook_rows))
}

pub(crate) async fn create_webhook(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<UpsertWebhookRequest>,
) -> Result<(StatusCode, axum::Json<WebhookListRow>), (StatusCode, String)> {
    // Each refusal says why: the app showed "Failed to create webhook:" and
    // nothing else, because these answered with a bare status.
    let bad = |msg: &str| (StatusCode::BAD_REQUEST, msg.to_string());
    if role != Role::Admin {
        return Err((StatusCode::FORBIDDEN, "Admin role required".into()));
    }
    if body.url.is_empty() {
        return Err(bad("The endpoint URL is empty."));
    }
    if !matches!(body.siem_format.as_str(), "json" | "cef" | "leef") {
        return Err(bad("The format must be json, cef or leef."));
    }
    // Validate webhook URL scheme to prevent SSRF via file://, ftp://, etc.
    let parsed_url = body
        .url
        .parse::<url::Url>()
        .map_err(|_| bad("The endpoint URL is not a valid URL."))?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return Err(bad("The endpoint URL must start with https:// or http://."));
    }
    // Block requests to internal/link-local addresses via async DNS resolution
    if let Some(host) = parsed_url.host_str() {
        let port = parsed_url
            .port()
            .unwrap_or(if parsed_url.scheme() == "https" {
                443
            } else {
                80
            });
        if let Ok(addrs) = tokio::net::lookup_host(format!("{host}:{port}")).await {
            for addr in addrs {
                let ip = addr.ip();
                let is_private = match ip {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_loopback()
                            || v4.is_private()
                            || v4.is_link_local()
                            || v4.is_unspecified()
                    }
                    std::net::IpAddr::V6(v6) => {
                        v6.is_loopback()
                            || v6.is_unspecified()
                            || (v6.segments()[0] & 0xffc0) == 0xfe80
                            || (v6.segments()[0] & 0xfe00) == 0xfc00
                            || v6.to_ipv4_mapped().is_some_and(|v4| {
                                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                            })
                    }
                };
                if is_private {
                    return Err(bad(
                        "The endpoint resolves to a private or local address; webhooks go to public endpoints only.",
                    ));
                }
            }
        }
        if is_internal_host(host) {
            // Catch localhost/metadata strings
            return Err(bad(
                "The endpoint is a local or internal host; webhooks go to public endpoints only.",
            ));
        }
    }
    let id_str = state
        .pool
        .insert_webhook(
            &body.label,
            &body.url,
            body.bearer_token.as_deref(),
            &body.siem_format,
            &body.filter_kinds,
            body.enabled,
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not store the webhook.".to_string(),
            )
        })?;
    let id: Uuid = id_str.parse().map_err(|e| {
        tracing::error!("insert_webhook returned invalid UUID '{id_str}': {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not store the webhook.".to_string(),
        )
    })?;
    Ok((
        StatusCode::CREATED,
        axum::Json(WebhookListRow {
            id,
            label: body.label,
            url: body.url,
            siem_format: body.siem_format,
            filter_kinds: body.filter_kinds,
            enabled: body.enabled,
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

pub(crate) async fn delete_webhook(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    state
        .pool
        .delete_webhook(&id.to_string())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Body accepted by `PUT /api/webhooks/{id}`.
#[derive(Deserialize)]
pub(crate) struct ToggleWebhookBody {
    /// Desired state: `true` to enable the webhook, `false` to disable it.
    enabled: bool,
}

/// Set a webhook's `enabled` flag to an explicit value (Admin only).
///
/// Uses SET semantics (`enabled = $2`) rather than a flip so that concurrent
/// requests from the GUI always converge to the caller's intent, regardless of
/// the current DB state.
pub(crate) async fn toggle_webhook(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    axum::Json(body): axum::Json<ToggleWebhookBody>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    state
        .pool
        .toggle_webhook(&id.to_string(), body.enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}
