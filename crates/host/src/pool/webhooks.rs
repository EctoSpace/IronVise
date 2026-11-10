//! Webhook (SIEM egress) destinations.

use super::DatabasePool;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct WebhookRow {
    pub id: String,
    pub label: String,
    pub url: String,
    pub bearer_token: Option<String>,
    pub siem_format: String,
    pub filter_kinds: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl DatabasePool {
    pub async fn list_webhooks(&self) -> Result<Vec<WebhookRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                // PG stores filter_kinds as TEXT[] - cast to TEXT for uniform WebhookRow.
                let rows = sqlx::query_as::<_, WebhookRow>(
                    "SELECT id::text, label, url, bearer_token, siem_format, \
                     array_to_string(filter_kinds, ',') AS filter_kinds, \
                     enabled, created_at::text, updated_at::text \
                     FROM webhooks ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, WebhookRow>(
                    "SELECT id, label, url, bearer_token, siem_format, filter_kinds, enabled, created_at, updated_at FROM webhooks ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
        }
    }

    pub async fn insert_webhook(
        &self,
        label: &str,
        url: &str,
        bearer_token: Option<&str>,
        siem_format: &str,
        filter_kinds: &[String],
        enabled: bool,
    ) -> Result<String, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO webhooks (label, url, bearer_token, siem_format, filter_kinds, enabled) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                )
                .bind(label)
                .bind(url)
                .bind(bearer_token)
                .bind(siem_format)
                .bind(filter_kinds)
                .bind(enabled)
                .fetch_one(p)
                .await?;
                Ok(id.to_string())
            }
            Self::Sqlite(p) => {
                let id = Uuid::new_v4().to_string();
                let fk_csv = filter_kinds.join(",");
                sqlx::query(
                    "INSERT INTO webhooks (id, label, url, bearer_token, siem_format, filter_kinds, enabled) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .bind(&id)
                .bind(label)
                .bind(url)
                .bind(bearer_token)
                .bind(siem_format)
                .bind(&fk_csv)
                .bind(enabled)
                .execute(p)
                .await?;
                Ok(id)
            }
        }
    }

    pub async fn delete_webhook(&self, id: &str) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let uid: Uuid = id
                    .parse()
                    .map_err(|_| sqlx::Error::Protocol("invalid UUID".into()))?;
                let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
                    .bind(uid)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
            Self::Sqlite(p) => {
                let result = sqlx::query("DELETE FROM webhooks WHERE id = ?1")
                    .bind(id)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    pub async fn toggle_webhook(&self, id: &str, enabled: bool) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let uid: Uuid = id
                    .parse()
                    .map_err(|_| sqlx::Error::Protocol("invalid UUID".into()))?;
                let result = sqlx::query(
                    "UPDATE webhooks SET enabled = $1, updated_at = now() WHERE id = $2",
                )
                .bind(enabled)
                .bind(uid)
                .execute(p)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            Self::Sqlite(p) => {
                let result = sqlx::query(
                    "UPDATE webhooks SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
                )
                .bind(enabled)
                .bind(id)
                .execute(p)
                .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    // SSE event streaming.
}
