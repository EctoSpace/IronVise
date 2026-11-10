//! RBAC API token management.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;
use chrono::Datelike;

#[derive(Deserialize)]
pub(crate) struct CreateTokenRequest {
    label: Option<String>,
    /// "admin", "auditor", or "agent"
    role: String,
    expires_in_days: Option<u32>,
}

#[derive(Serialize)]
pub(crate) struct CreateTokenResponse {
    /// Raw token - shown exactly once; the server stores only its SHA-256 hex digest.
    token: String,
    token_hash: String,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct TokenListRow {
    token_hash: String,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

pub(crate) async fn create_token(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<CreateTokenRequest>,
) -> Result<axum::Json<CreateTokenResponse>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let role_str = match body.role.as_str() {
        r @ ("admin" | "auditor" | "agent") => r.to_string(),
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let raw: [u8; 32] = rand::random();
    let token = hex::encode(raw);
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
    let expires_at = body
        .expires_in_days
        .map(|days| {
            chrono::Utc::now()
                .checked_add_days(chrono::Days::new(u64::from(days)))
                // SQLite date functions cannot interpret years above 9999;
                // reject them rather than issuing a token that never works.
                .filter(|expiry| expiry.year() <= 9999)
                .ok_or(StatusCode::BAD_REQUEST)
        })
        .transpose()?;
    state
        .pool
        .insert_token(&token_hash, &role_str, body.label.as_deref(), expires_at)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(CreateTokenResponse {
        token,
        token_hash,
        role: role_str,
        label: body.label,
    }))
}

pub(crate) async fn list_tokens(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<Vec<TokenListRow>>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let rows = state
        .pool
        .list_tokens()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(
        rows.into_iter()
            .map(|t| TokenListRow {
                token_hash: t.token_hash,
                role: t.role,
                label: t.label,
                created_at: t.created_at,
                expires_at: t.expires_at,
            })
            .collect(),
    ))
}

pub(crate) async fn delete_token(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    state
        .pool
        .delete_token(&hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
