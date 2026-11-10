//! Exit codes other than 0 and 1.

/// The `verify-ledger` survey could not run at all - exit 2.
///
/// Distinct from exit 1, which under `--strict` means the survey ran and found
/// a session that does not verify. Collapsing the two would leave a CI job
/// unable to tell "this ledger has been tampered with" from "DATABASE_URL
/// points at nothing", and the only remaining way to tell would be to parse
/// the output. The contract is documented in `docs/guides/cli.md` and pinned by
/// `tests/qa_contracts.rs::verify_ledger_exit_codes`.
pub fn cannot_survey(e: &dyn std::fmt::Display) -> Box<dyn std::error::Error + Send + Sync> {
    eprintln!("Error: {e}");
    Box::new(ExitWith(2))
}

/// Leave `run` with this exit code, its message already printed. Returned
/// rather than calling `std::process::exit`, which skips destructors: an
/// embedded PostgreSQL that `verify-ledger` had started was left running.
#[derive(Debug)]
pub struct ExitWith(pub u8);

impl std::fmt::Display for ExitWith {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit {}", self.0)
    }
}

impl std::error::Error for ExitWith {}
