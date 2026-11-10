//! API tokens, and the replay guard's consumed request ids.

use super::{DatabasePool, REPLAY_RETENTION_DAYS};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct TokenRow {
    pub token_hash: String,
    pub role: String,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

impl DatabasePool {
    /// Mark `request_id` as acted on within `scope`. `Ok(false)` means it
    /// already was: the request is a replay.
    pub async fn consume_request(
        &self,
        scope: &str,
        request_id: &str,
        caller: &str,
    ) -> Result<bool, sqlx::Error> {
        let done = match self {
            Self::Postgres(p) => {
                sqlx::query(
                    "INSERT INTO consumed_requests (scope, request_id, caller) VALUES ($1, $2, $3) \
                     ON CONFLICT (scope, request_id) DO NOTHING",
                )
                .bind(scope)
                .bind(request_id)
                .bind(caller)
                .execute(p)
                .await?
            }
            .rows_affected(),
            Self::Sqlite(p) => {
                sqlx::query(
                    "INSERT INTO consumed_requests (scope, request_id, caller) VALUES (?1, ?2, ?3) \
                     ON CONFLICT (scope, request_id) DO NOTHING",
                )
                .bind(scope)
                .bind(request_id)
                .bind(caller)
                .execute(p)
                .await?
            }
            .rows_affected(),
        };
        Ok(done == 1)
    }

    /// Forget request ids older than [`REPLAY_RETENTION_DAYS`].
    pub async fn purge_consumed_requests(&self) -> Result<u64, sqlx::Error> {
        let days = REPLAY_RETENTION_DAYS;
        Ok(match self {
            Self::Postgres(p) => sqlx::query(
                "DELETE FROM consumed_requests WHERE consumed_at < now() - make_interval(days => $1)",
            )
            .bind(days as i32)
            .execute(p)
            .await?
            .rows_affected(),
            Self::Sqlite(p) => sqlx::query(
                "DELETE FROM consumed_requests \
                 WHERE consumed_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            )
            .bind(format!("-{days} days"))
            .execute(p)
            .await?
            .rows_affected(),
        })
    }

    /// Make `token_hash` the only token labelled `label`: for tokens a process
    /// mints for itself at start-up, which otherwise pile up, each still valid.
    pub async fn replace_labelled_token(
        &self,
        label: &str,
        token_hash: &str,
        role: &str,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                sqlx::query("DELETE FROM api_tokens WHERE label = $1 AND token_hash <> $2")
                    .bind(label)
                    .bind(token_hash)
                    .execute(p)
                    .await?;
            }
            Self::Sqlite(p) => {
                sqlx::query("DELETE FROM api_tokens WHERE label = ?1 AND token_hash <> ?2")
                    .bind(label)
                    .bind(token_hash)
                    .execute(p)
                    .await?;
            }
        }
        self.insert_token(token_hash, role, Some(label), None).await
    }

    pub async fn find_token_role(&self, token_hash: &str) -> Result<Option<String>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT role FROM api_tokens WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())",
                )
                .bind(token_hash)
                .fetch_optional(p)
                .await?;
                Ok(row.map(|r| r.0))
            }
            Self::Sqlite(p) => {
                let row: Option<(String,)> = sqlx::query_as(
                    // julianday, not text: an RFC 3339 `…T…` compared with
                    // datetime('now')'s `… …` as strings stayed valid until
                    // the end of its expiry day.
                    "SELECT role FROM api_tokens WHERE token_hash = ?1 AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))",
                )
                .bind(token_hash)
                .fetch_optional(p)
                .await?;
                Ok(row.map(|r| r.0))
            }
        }
    }

    pub async fn insert_token(
        &self,
        token_hash: &str,
        role: &str,
        label: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                sqlx::query(
                    "INSERT INTO api_tokens (token_hash, role, label, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (token_hash) DO NOTHING",
                )
                .bind(token_hash)
                .bind(role)
                .bind(label)
                .bind(expires_at)
                .execute(p)
                .await?;
                Ok(())
            }
            Self::Sqlite(p) => {
                let exp_str = expires_at.map(|t| t.to_rfc3339());
                sqlx::query(
                    "INSERT OR IGNORE INTO api_tokens (token_hash, role, label, expires_at) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(token_hash)
                .bind(role)
                .bind(label)
                .bind(exp_str)
                .execute(p)
                .await?;
                Ok(())
            }
        }
    }

    pub async fn list_tokens(&self) -> Result<Vec<TokenRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let rows = sqlx::query_as::<_, TokenRow>(
                    "SELECT token_hash, role, label, created_at, expires_at FROM api_tokens ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, TokenRow>(
                    "SELECT token_hash, role, label, created_at, expires_at FROM api_tokens ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
        }
    }

    pub async fn delete_token(&self, token_hash: &str) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let result = sqlx::query("DELETE FROM api_tokens WHERE token_hash = $1")
                    .bind(token_hash)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
            Self::Sqlite(p) => {
                let result = sqlx::query("DELETE FROM api_tokens WHERE token_hash = ?1")
                    .bind(token_hash)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    // Webhook queries.
}
