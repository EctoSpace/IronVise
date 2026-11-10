use criterion::{Criterion, criterion_group, criterion_main};
use ectoledger_elc::{
    parse_certificate,
    verify::{Requirements, verify},
};
use std::hint::black_box;

const SESSION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/verified-session/session.elc"
));

fn benchmarks(c: &mut Criterion) {
    let certificate = parse_certificate(SESSION.as_bytes()).unwrap();
    let requirements = Requirements::default();
    assert!(verify(&certificate, &requirements).is_valid());
    c.bench_function("verify_session_certificate", |b| {
        b.iter(|| black_box(verify(black_box(&certificate), black_box(&requirements))))
    });
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
