mod common;

use common::{MockLlmBackend, assert_chain_valid, reset_ledger, spawn_test_pool};
use ectoledger::agent::{self, AgentLoopConfig};
use ectoledger::intent::ProposedIntent;
use ectoledger::ledger;
use ectoledger::schema::EventPayload;
use ectoledger::tripwire::{self, Tripwire};
use std::path::PathBuf;

#[tokio::test]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn mock_llm_read_file_then_complete() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("genesis");
    ledger::append_event(
        &pool,
        EventPayload::Thought {
            content: "Audit goal: read test".to_string(),
        },
        None,
        None,
        None,
    )
    .await
    .expect("append");

    let mock = MockLlmBackend::new(vec![
        ProposedIntent {
            action: "read_file".to_string(),
            params: serde_json::json!({"path": "Cargo.toml"}),
            justification: "Read Cargo.toml to inspect project dependencies.".to_string(),
            reasoning: "First step of audit: enumerate project structure.".to_string(),
        },
        ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::json!({"findings": []}),
            justification: "Audit complete; all planned checks finished.".to_string(),
            reasoning: "No findings from dependency review.".to_string(),
        },
    ]);
    let workspace = PathBuf::from(".")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("."));
    let tripwire = Tripwire::new(
        vec![workspace],
        vec![],
        tripwire::default_banned_command_patterns(),
        5,
        true,
    );
    let config = AgentLoopConfig {
        llm: Box::new(mock),
        tripwire: &tripwire,
        max_steps: Some(10),
        session_id: None,
        session_goal: "read test".to_string(),
        guard: None,
        metrics: None,
        policy: None,
        session_signing_key: None,
        egress_tx: None,
        cloud_creds: None,
        interactive: false,
        approval_state: None,
        firecracker_config: None,
        docker_config: None,
        key_rotation_interval_steps: None,
        compensation: None,
        enclave: None,
        enclave_attestation: None,
        cancel: None,
    };
    let client = reqwest::Client::new();
    let db = ectoledger::pool::DatabasePool::Postgres(pool.clone());
    agent::run_cognitive_loop(&db, &client, config)
        .await
        .expect("loop");

    let latest = ledger::get_latest(&pool).await.expect("get_latest");
    let (seq, _) = latest.expect("has events");
    assert!(
        seq >= 2,
        "expected at least 2 events (action + observation + complete)"
    );
    assert_chain_valid(&pool, 0, seq).await;
}

/// A flagged observation reaches the webhook as the ledger keeps it: after
/// the scanner and the policy's redact rules, never the raw tool output.
#[tokio::test]
async fn a_flagged_observations_webhook_preview_is_redacted() {
    // `read_file` re-checks at open time against the configured allowed
    // paths, which default to the working directory.
    let dir = tempfile::tempdir_in(".").expect("tempdir");
    let file = dir
        .path()
        .canonicalize()
        .expect("canonical")
        .join("notes.txt");
    std::fs::write(&file, "password=s3cret SUSPICIOUS").expect("write");
    let db = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .expect("pool");
    let (session, key) = db
        .create_session("preview test", "mock", "mock", None)
        .await
        .expect("session");
    let policy: ectoledger::policy::AuditPolicy = toml::from_str(
        r#"
        [[observation_rules]]
        pattern = "password=\\S+"
        action = "redact"
        label = "credential"

        [[observation_rules]]
        pattern = "SUSPICIOUS"
        action = "flag"
        label = "sus"
        "#,
    )
    .expect("policy");
    let policy = ectoledger::policy::PolicyEngine::new(policy).expect("engine");
    let tripwire = Tripwire::new(
        vec![dir.path().canonicalize().expect("canonical")],
        vec![],
        tripwire::default_banned_command_patterns(),
        5,
        true,
    );
    let mock = MockLlmBackend::new(vec![
        ProposedIntent {
            action: "read_file".to_string(),
            params: serde_json::json!({ "path": file }),
            justification: "Read the notes file.".to_string(),
            reasoning: "Inspect it.".to_string(),
        },
        ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::json!({ "findings": [] }),
            justification: "Done with the notes.".to_string(),
            reasoning: "Nothing else to check.".to_string(),
        },
    ]);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let config = AgentLoopConfig {
        llm: Box::new(mock),
        tripwire: &tripwire,
        max_steps: Some(10),
        session_id: Some(session.id),
        session_goal: "preview test".to_string(),
        guard: None,
        metrics: None,
        policy: Some(&policy),
        session_signing_key: Some(std::sync::Arc::new(key)),
        egress_tx: Some(tx),
        cloud_creds: None,
        interactive: false,
        approval_state: None,
        firecracker_config: None,
        docker_config: None,
        key_rotation_interval_steps: None,
        compensation: None,
        enclave: None,
        enclave_attestation: None,
        cancel: None,
    };
    agent::run_cognitive_loop(&db, &reqwest::Client::new(), config)
        .await
        .expect("loop");

    let flag = rx.try_recv().expect("a flag event");
    assert_eq!(flag.severity, "flag");
    assert_eq!(flag.rule_label, "sus");
    assert!(
        flag.observation_preview.contains("[REDACTED:credential]"),
        "{}",
        flag.observation_preview
    );
    assert!(!flag.observation_preview.contains("s3cret"));
    let events = db.get_events_by_session(session.id).await.expect("events");
    let kept = serde_json::to_string(&events.iter().map(|e| &e.payload).collect::<Vec<_>>())
        .expect("json");
    assert!(kept.contains("[REDACTED:credential]"), "{kept}");
    assert!(!kept.contains("s3cret"), "{kept}");
}

/// Records the prompts it is given, then answers like `MockLlmBackend`.
struct RecordingLlm {
    inner: MockLlmBackend,
    prompts: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl ectoledger::llm::LlmBackend for RecordingLlm {
    async fn propose(
        &self,
        system: &str,
        user: &str,
    ) -> Result<ProposedIntent, ectoledger::llm::LlmError> {
        self.prompts.lock().unwrap().push(user.to_string());
        self.inner.propose(system, user).await
    }
    async fn raw_call(&self, s: &str, u: &str) -> Result<String, ectoledger::llm::LlmError> {
        self.inner.raw_call(s, u).await
    }
    fn backend_name(&self) -> &str {
        "mock"
    }
    fn model_name(&self) -> &str {
        "mock"
    }
}

/// A session sees its own events only: other sessions' goals and observations
/// stay out of its prompt, and loop detection counts only its own actions, so
/// repeating an earlier session's task does not stop at step one.
#[tokio::test]
async fn a_session_does_not_see_or_count_another_sessions_events() {
    let db = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .expect("pool");
    // An earlier session that ran `ls` three times.
    let (earlier, earlier_key) = db
        .create_session("SECRET-GOAL-OF-ANOTHER-SESSION", "mock", "mock", None)
        .await
        .expect("session");
    for _ in 0..3 {
        db.append_event(
            EventPayload::Action {
                name: "run_command".into(),
                params: serde_json::json!({ "command": "ls" }),
            },
            Some(earlier.id),
            Some("SECRET-GOAL-OF-ANOTHER-SESSION"),
            Some(&earlier_key),
        )
        .await
        .expect("append");
    }

    let (session, key) = db
        .create_session("list files", "mock", "mock", None)
        .await
        .expect("session");
    let prompts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let llm = RecordingLlm {
        inner: MockLlmBackend::new(vec![ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::json!({ "findings": [] }),
            justification: "Nothing to list in this test.".to_string(),
            reasoning: "Done.".to_string(),
        }]),
        prompts: prompts.clone(),
    };
    let tripwire = Tripwire::new(
        vec![],
        vec![],
        tripwire::default_banned_command_patterns(),
        5,
        true,
    );
    let config = AgentLoopConfig {
        llm: Box::new(llm),
        tripwire: &tripwire,
        max_steps: Some(5),
        session_id: Some(session.id),
        session_goal: "list files".to_string(),
        guard: None,
        metrics: None,
        policy: None,
        session_signing_key: Some(std::sync::Arc::new(key)),
        egress_tx: None,
        cloud_creds: None,
        interactive: false,
        approval_state: None,
        firecracker_config: None,
        docker_config: None,
        key_rotation_interval_steps: None,
        compensation: None,
        enclave: None,
        enclave_attestation: None,
        cancel: None,
    };
    agent::run_cognitive_loop(&db, &reqwest::Client::new(), config)
        .await
        .expect("loop");

    let prompts = prompts.lock().unwrap().clone();
    assert_eq!(
        prompts.len(),
        1,
        "the model was asked once, not skipped by loop detection"
    );
    assert!(
        !prompts[0].contains("SECRET-GOAL-OF-ANOTHER-SESSION"),
        "another session's goal reached the prompt:\n{}",
        prompts[0]
    );
    let events = db.get_events_by_session(session.id).await.expect("events");
    let text =
        serde_json::to_string(&events.iter().map(|e| &e.payload).collect::<Vec<_>>()).unwrap();
    assert!(!text.contains("Loop detected"), "{text}");
}
