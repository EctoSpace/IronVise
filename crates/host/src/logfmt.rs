//! Process logging.
//!
//! The tracing target stays the crate and module path, so `RUST_LOG` filters
//! such as `ectoledger=debug` keep working. The line printed to the console
//! shows `ironvise` in that same position.

use std::fmt;
use std::io::IsTerminal;

use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::registry::LookupSpan;

/// Build the filter from `RUST_LOG`, after `.env` has been read.
pub fn init_from_env() {
    install(EnvFilter::from_default_env());
}

/// Use `RUST_LOG` when it is set, otherwise `default_directive`.
pub fn init_or_default(default_directive: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    install(filter);
}

fn install(filter: EnvFilter) {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .event_format(Branded)
        .init();
}

/// Console target. The real metadata target is not modified.
pub fn display_target(target: &str) -> String {
    match target.strip_prefix("ectoledger") {
        Some(rest) => format!("ironvise{rest}"),
        None => target.to_string(),
    }
}

struct Branded;

impl<S, N> FormatEvent<S, N> for Branded
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        SystemTime.format_time(&mut writer)?;
        write!(writer, " {} ", event.metadata().level())?;
        write!(writer, "{}: ", display_target(event.metadata().target()))?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::display_target;

    #[test]
    fn console_target_uses_the_product_name() {
        assert_eq!(
            display_target("ectoledger::config::server"),
            "ironvise::config::server"
        );
        assert_eq!(display_target("ectoledger_gui"), "ironvise_gui");
        assert_eq!(display_target("tower_http::trace"), "tower_http::trace");
    }
}
