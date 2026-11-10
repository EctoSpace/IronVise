//! Running a command against the open ledger.

use super::BoxError;
use super::exit::{ExitWith, cannot_survey};
use crate::Commands;
use ectoledger::commands;
use ectoledger::pool::DatabasePool;
use tokio_util::sync::CancellationToken;

pub async fn run(
    command: Commands,
    backend: DatabasePool,
    cancel: CancellationToken,
) -> Result<(), BoxError> {
    let metrics = std::sync::Arc::new(ectoledger::metrics::Metrics::default());
    match command {
        Commands::Proxy {
            bind,
            upstream,
            allow_remote,
        } => {
            commands::proxy::run(backend, bind.as_str(), upstream.as_str(), allow_remote).await?;
        }
        Commands::DataReceipts { session, files } => {
            commands::receipts::run(backend, session, &files).await?;
        }
        Commands::ImportOpenshell { files, out } => {
            commands::openshell::run(backend, &files, &out).await?;
        }
        Commands::Serve { .. } => match backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::serve::run(pg, metrics, cancel).await?;
            }
            other => {
                commands::serve::run_with_pool(other, metrics, cancel).await?;
            }
        },
        Commands::Audit {
            prompt,
            policy,
            no_guard,
            no_guard_confirmed,
            interactive,
            key_password_fd,
            ..
        } => {
            commands::audit::run(
                backend,
                metrics,
                commands::audit::AuditArgs {
                    prompt,
                    policy,
                    no_guard,
                    no_guard_confirmed,
                    interactive,
                    key_password_fd,
                },
            )
            .await?;
        }
        Commands::Replay {
            session,
            to_step,
            inject_observation,
        } => match &backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::report::run_replay(pg, session, to_step, inject_observation).await?;
            }
            ectoledger::pool::DatabasePool::Sqlite(sq) => {
                commands::report::run_replay_sqlite(sq, session, to_step, inject_observation)
                    .await?;
            }
        },
        Commands::VerifySession {
            session,
            against,
            expected_key,
        } => {
            match &backend {
                ectoledger::pool::DatabasePool::Postgres(pg) => {
                    commands::report::run_verify_session(pg, session).await?;
                }
                ectoledger::pool::DatabasePool::Sqlite(sq) => {
                    commands::report::run_verify_session_sqlite(sq, session).await?;
                }
            }
            if let Some(cert) = against {
                commands::report::run_verify_against_certificate(
                    &backend,
                    session,
                    &cert,
                    expected_key.as_deref(),
                )
                .await?;
            }
        }
        Commands::Orchestrate {
            goal,
            policy,
            max_steps,
        } => {
            // SQLite is guarded above; safe to unwrap the Postgres pool.
            let pg = backend
                .as_pg()
                .expect("Orchestrate requires PostgreSQL")
                .clone();
            commands::orchestrate::run_orchestrate(
                &ectoledger::pool::DatabasePool::Postgres(pg),
                goal,
                policy,
                max_steps,
            )
            .await?;
        }
        Commands::DiffAudit {
            baseline,
            current,
            output,
        } => {
            let pg = backend
                .as_pg()
                .expect("DiffAudit requires PostgreSQL")
                .clone();
            commands::orchestrate::run_diff_audit(&pg, baseline, current, output).await?;
        }
        Commands::RedTeam {
            target_session,
            attack_budget,
            output,
        } => {
            let pg = backend
                .as_pg()
                .expect("RedTeam requires PostgreSQL")
                .clone();
            commands::orchestrate::run_red_team(&pg, target_session, attack_budget, output).await?;
        }
        Commands::AnchorSession { session, .. } => match &backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::anchor::run(pg, session).await?;
            }
            ectoledger::pool::DatabasePool::Sqlite(sq) => {
                commands::anchor::run_sqlite(sq, session).await?;
            }
        },
        Commands::VerifyLedger { all, strict } => {
            // Three outcomes, three exit codes, because a script has to tell
            // them apart: 0 surveyed, 1 surveyed and something failed under
            // --strict, 2 could not survey at all. Bubbling the error up to
            // `main` instead would collapse 2 into 1 and leave "your ledger is
            // tampered" and "you pointed me at an empty database" identical to
            // anything reading `$?`.
            let survey = match &backend {
                ectoledger::pool::DatabasePool::Postgres(pg) => {
                    commands::report::run_verify_ledger(pg, all).await
                }
                ectoledger::pool::DatabasePool::Sqlite(sq) => {
                    commands::report::run_verify_ledger_sqlite(sq, all).await
                }
            };
            let survey = match survey {
                Ok(s) => s,
                Err(e) => return Err(cannot_survey(&e)),
            };
            // The summary is already printed; --strict only decides whether a
            // finding is also a failure. Exiting here rather than returning an
            // error keeps the survey's own output as the explanation instead of
            // appending a redundant "Error:" line to it.
            if strict && !survey.all_verified() {
                return Err(Box::new(ExitWith(1)));
            }
        }
        Commands::Report {
            session,
            format,
            output,
            no_ots,
            key_password_fd,
        } => {
            let key = if format.eq_ignore_ascii_case("certificate") {
                commands::report::certificate_signing_key(session, key_password_fd)?
            } else {
                None
            };
            match &backend {
                ectoledger::pool::DatabasePool::Postgres(pg) => {
                    commands::report::run_report(pg, session, format, output, no_ots, key.as_ref())
                        .await?;
                }
                ectoledger::pool::DatabasePool::Sqlite(sq) => {
                    commands::report::run_report_sqlite(
                        sq,
                        session,
                        format,
                        output,
                        no_ots,
                        key.as_ref(),
                    )
                    .await?;
                }
            }
        }
        // VerifyCertificate and VerifyVc are handled above (early return, no DB).
        Commands::VerifyCertificate { .. }
        | Commands::IssuerKey { .. }
        | Commands::VerifyVc { .. }
        | Commands::WebhookKey { .. }
        | Commands::McpProxy { .. }
        | Commands::Hook { .. }
        | Commands::Health
        | Commands::ProveAudit { .. } => {
            unreachable!()
        }
    }
    Ok(())
}
