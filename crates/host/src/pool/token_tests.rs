use super::*;

async fn pool() -> DatabasePool {
    create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap()
}

/// Expiry to the second. Compared as text, a token expired a minute ago
/// stayed valid until midnight UTC.
#[tokio::test]
async fn a_token_is_refused_the_moment_it_expires() {
    let pool = pool().await;
    let now = chrono::Utc::now();
    pool.insert_token(
        "expired",
        "agent",
        None,
        Some(now - chrono::Duration::minutes(1)),
    )
    .await
    .unwrap();
    pool.insert_token(
        "live",
        "agent",
        None,
        Some(now + chrono::Duration::minutes(1)),
    )
    .await
    .unwrap();
    assert_eq!(pool.find_token_role("expired").await.unwrap(), None);
    assert_eq!(
        pool.find_token_role("live").await.unwrap().as_deref(),
        Some("agent")
    );
}

#[tokio::test]
async fn a_start_up_token_retires_the_previous_one() {
    let pool = pool().await;
    pool.replace_labelled_token("gui-bootstrap", "first", "admin")
        .await
        .unwrap();
    pool.replace_labelled_token("gui-bootstrap", "second", "admin")
        .await
        .unwrap();
    pool.insert_token("user-made", "admin", Some("ci"), None)
        .await
        .unwrap();
    assert_eq!(pool.find_token_role("first").await.unwrap(), None);
    assert_eq!(
        pool.find_token_role("second").await.unwrap().as_deref(),
        Some("admin")
    );
    assert_eq!(
        pool.find_token_role("user-made").await.unwrap().as_deref(),
        Some("admin")
    );
    pool.replace_labelled_token("gui-bootstrap", "second", "admin")
        .await
        .unwrap();
    assert_eq!(
        pool.find_token_role("second").await.unwrap().as_deref(),
        Some("admin"),
        "re-registering the same token keeps it"
    );
}
