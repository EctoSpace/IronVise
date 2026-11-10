#![cfg(feature = "integration")]

use ectoledger::{pool::DatabasePool, schema::EventPayload};

#[tokio::test]
async fn a_failed_postgres_reset_rolls_back_rows_and_trigger_state() {
    use sqlx::Executor;
    let url = std::env::var("DATABASE_URL").expect("integration DATABASE_URL");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    // Dynamic identifiers below come only from this generated UUID and a
    // constant table list, never from a caller's SQL or configuration.
    let schema = format!("reset_atomic_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = format!("SET search_path TO {schema}");
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _| {
            let statement = search_path.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(statement))
                    .execute(conn)
                    .await
                    .map(|_| ())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pg).await.unwrap();
    let pool = DatabasePool::Postgres(pg.clone());
    let (session, key) = pool
        .create_session("reset test", "test", "test", None)
        .await
        .unwrap();
    pool.append_event(
        EventPayload::Thought {
            content: "keep me".into(),
        },
        Some(session.id),
        Some("reset test"),
        Some(&key),
    )
    .await
    .unwrap();
    let fetched = pool.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(fetched.goal, session.goal);
    assert!(
        pool.get_session(uuid::Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
    pg.execute("CREATE FUNCTION refuse_reset() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected reset refusal'; END $$;
        CREATE TRIGGER reject_reset BEFORE DELETE ON agent_sessions FOR EACH ROW EXECUTE FUNCTION refuse_reset();")
        .await.unwrap();
    let tables = [
        "agent_events",
        "agent_event_signatures",
        "agent_action_log",
        "agent_sessions",
    ];
    let mut before = Vec::new();
    for table in tables {
        before.push(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM {table}"
            )))
            .fetch_one(&pg)
            .await
            .unwrap(),
        );
    }
    assert!(pool.reset_demo_data().await.is_err());
    for (table, expected) in tables.into_iter().zip(before) {
        let count: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&pg)
                .await
                .unwrap();
        assert_eq!(count, expected, "{table} must survive rollback");
    }
    let enabled: String = sqlx::query_scalar("SELECT tgenabled::text FROM pg_trigger WHERE tgrelid = 'agent_events'::regclass AND tgname = 'agent_events_immutable'")
        .fetch_one(&pg).await.unwrap();
    assert_eq!(enabled, "O");
    assert!(
        sqlx::query("UPDATE agent_events SET content_hash = 'corrupt'")
            .execute(&pg)
            .await
            .is_err()
    );
    pg.execute("DROP TRIGGER reject_reset ON agent_sessions")
        .await
        .unwrap();
    pool.reset_demo_data().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_events")
        .fetch_one(&pg)
        .await
        .unwrap();
    assert_eq!(count, 0);
    pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
