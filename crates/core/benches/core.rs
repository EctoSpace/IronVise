use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ectoledger_core::{
    hash::*,
    intent::ProposedIntent,
    merkle,
    policy::{AuditPolicy, PolicyEngine},
    schema::ChainEvent,
};
use std::hint::black_box;

const TS: &str = "2026-01-01T00:00:00.123456+00:00";

fn chain(size: usize) -> Vec<(ChainEvent, String)> {
    let mut previous = GENESIS_PREVIOUS_HASH.to_owned();
    (0..size)
        .map(|i| {
            let event = ChainEvent {
                sequence: i as i64,
                previous_hash: previous.clone(),
                payload_json: format!(
                    r#"{{"action":"read_file","index":{i},"path":"/safe/report.txt"}}"#
                ),
                session_id: Some("12345678-1234-1234-1234-123456789abc".into()),
                created_at: TS.into(),
            };
            previous = compute_content_hash_v2(
                &event.previous_hash,
                event.sequence,
                &event.payload_json,
                event.session_id.as_deref(),
                &event.created_at,
            );
            (event, previous.clone())
        })
        .collect()
}

fn verify_chain(events: &[(ChainEvent, String)]) -> bool {
    let mut previous = GENESIS_PREVIOUS_HASH;
    for (e, stored) in events {
        if e.previous_hash != previous
            || verify_content_hash_any_scheme(
                &e.previous_hash,
                e.sequence,
                &e.payload_json,
                e.session_id.as_deref(),
                Some(&e.created_at),
                stored,
            ) != Some(HashScheme::V2)
        {
            return false;
        }
        previous = stored;
    }
    true
}

fn benchmarks(c: &mut Criterion) {
    let one = chain(1);
    let e = &one[0].0;
    c.bench_function("hash_one_event", |b| {
        b.iter(|| {
            compute_content_hash_v2(
                black_box(&e.previous_hash),
                black_box(e.sequence),
                black_box(&e.payload_json),
                black_box(e.session_id.as_deref()),
                black_box(&e.created_at),
            )
        })
    });
    for size in [1_000, 10_000] {
        let events = chain(size);
        assert!(verify_chain(&events));
        c.bench_with_input(
            BenchmarkId::new("chain_verify", size),
            &events,
            |b, events| b.iter(|| black_box(verify_chain(black_box(events)))),
        );
        let leaves: Vec<&str> = events.iter().map(|(_, hash)| hash.as_str()).collect();
        c.bench_with_input(
            BenchmarkId::new("merkle_build_and_proof", size),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let tree = merkle::build_merkle_tree(black_box(leaves)).unwrap();
                    black_box(merkle::proof(&tree, leaves.len() / 2).unwrap());
                    black_box(tree)
                })
            },
        );
    }
    // The shipped SOC 2 pack: command rules with regexes, path patterns and
    // approval gates, so this measures a realistic evaluation.
    let soc2: AuditPolicy = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../host/policies/soc2-audit.toml"
    )))
    .unwrap();
    let engine = PolicyEngine::new(soc2).unwrap();
    let intent = ProposedIntent {
        action: "run_command".into(),
        params: serde_json::json!({"command": "grep -rn ssl_protocols /etc/nginx"}),
        justification: "check the TLS protocol versions the server accepts".into(),
        reasoning: String::new(),
    };
    c.bench_function("policy_evaluate_soc2_run_command", |b| {
        b.iter(|| {
            let _ = black_box(engine.validate_intent(black_box(&intent), black_box(0)));
            black_box(engine.check_approval_gates(black_box(&intent)))
        })
    });
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
