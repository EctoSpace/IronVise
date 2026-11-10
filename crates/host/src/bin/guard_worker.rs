// The guard-worker binary. The worker itself is `ectoledger::guard_worker`;
// the desktop app runs the same code as `<app> --guard-worker`, so it needs no
// second executable beside it.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ectoledger::guard_worker::run().await
}
