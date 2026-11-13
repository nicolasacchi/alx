use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fmt;
use std::str::FromStr;

#[derive(Parser)]
#[command(
    name = "alx",
    version,
    about = "Algolia cost & abuse forensics CLI (read-only)",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output as JSON (this is already the default; kept as an explicit no-op flag)
    #[arg(long, global = true)]
    pub json: bool,

    /// Opt into colored human-readable rendering (JSON is the default)
    #[arg(long, global = true)]
    pub human: bool,

    /// Pipe the JSON payload through the system `jq` binary with this expression
    #[arg(long, global = true, value_name = "EXPR")]
    pub jq: Option<String>,

    /// Show progress/diagnostic output on stderr
    #[arg(long, short, global = true)]
    pub verbose: bool,

    /// HTTP timeout in seconds
    #[arg(long, global = true, default_value = "15")]
    pub timeout: u64,

    /// Force agent mode (machine-friendly JSON output)
    #[arg(long, global = true)]
    pub agent: bool,

    /// Acknowledge and proceed despite an over-privileged key (bypasses the safety refusal)
    #[arg(long, global = true)]
    pub i_know: bool,

    /// Algolia Application ID (overrides ALGOLIA_APPLICATION_ID)
    #[arg(long, global = true, value_name = "ID")]
    pub app_id: Option<String>,

    /// Algolia API key (highest priority; overrides every ALGOLIA_*_API_KEY env var)
    #[arg(long, global = true, value_name = "KEY")]
    pub key: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Probe which Algolia capabilities (logs/usage/analytics/keys) are reachable
    Doctor,

    /// Logs API forensics — sampling against the 7-day / 1,000-entry retention window
    #[command(subcommand)]
    Logs(LogsCommands),

    /// Key ACL / restriction audit (read-only)
    #[command(subcommand)]
    Keys(KeysCommands),

    /// Usage API — request/operation billing meters
    #[command(subcommand)]
    Usage(UsageCommands),

    /// Search Analytics — top searches, no-results, scrape heuristics
    #[command(subcommand)]
    Analytics(AnalyticsCommands),

    /// Insights API — Events -> Health (/1/metrics) and Events -> Debugger (/1/events)
    #[command(subcommand)]
    Events(EventsCommands),

    /// Generate shell completions
    Completions(CompletionsArgs),

    /// Generate man page
    #[command(hide = true)]
    Manpage,
}

#[derive(Subcommand)]
pub enum LogsCommands {
    /// Sample the live log ring buffer across all three per-server hosts
    Sample(LogsSampleArgs),
    /// Group non-own-egress, non-KEEP-list traffic by (ip, referer)
    Offsite(LogsOffsiteArgs),
    /// Filter to entries with answer_code != 200
    Errors(LogsErrorsArgs),
}

#[derive(Args)]
pub struct LogsSampleArgs {
    /// Sampling window applied client-side after fetch (Nm|Nh|Nd)
    #[arg(long, default_value = "1h")]
    pub since: SinceArg,

    /// Persist the aggregated sample to this directory (never overwrites; suffixes -2, -3, ...)
    #[arg(long, value_name = "DIR")]
    pub persist: Option<String>,
}

#[derive(Args)]
pub struct LogsOffsiteArgs {
    /// Sampling window applied client-side after fetch (Nm|Nh|Nd)
    #[arg(long, default_value = "1h")]
    pub since: SinceArg,
}

#[derive(Args)]
pub struct LogsErrorsArgs {
    /// Sampling window applied client-side after fetch (Nm|Nh|Nd)
    #[arg(long, default_value = "1h")]
    pub since: SinceArg,
}

#[derive(Subcommand)]
pub enum KeysCommands {
    /// Audit ACLs, referers, and index restrictions for the configured key(s)
    Audit(KeysAuditArgs),
}

#[derive(Args)]
pub struct KeysAuditArgs {
    /// Masked-prefix or description of a key known to also be used server-side
    /// (repeatable; also read from ALX_SERVER_SIDE_KEYS, comma-separated)
    #[arg(long = "server-side-key", value_name = "PREFIX")]
    pub server_side_key: Vec<String>,
}

#[derive(Subcommand)]
pub enum UsageCommands {
    /// Both meters side by side, plus the derived billed-requests approximation
    Summary(UsageSummaryArgs),
    /// Raw time series for one statistic
    Series(UsageSeriesArgs),
    /// Dedicated requests-vs-operations side-by-side view
    Meters(UsageMetersArgs),
}

#[derive(Args)]
pub struct UsageSummaryArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,
}

#[derive(Args)]
pub struct UsageSeriesArgs {
    /// Statistic name, e.g. total_search_requests
    #[arg(long, value_name = "NAME")]
    pub statistic: String,

    /// Granularity: hourly (<=7d) or daily (<=365d)
    #[arg(long, value_enum)]
    pub granularity: Granularity,

    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,
}

#[derive(Args)]
pub struct UsageMetersArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Granularity {
    Hourly,
    Daily,
}

#[derive(Subcommand)]
pub enum AnalyticsCommands {
    /// Top searches for the window
    TopSearches(AnalyticsTopSearchesArgs),
    /// Searches that returned zero results
    NoResults(AnalyticsNoResultsArgs),
    /// Heuristic scrape/enumeration signals over top-searches + no-results
    ScrapeSignals(AnalyticsScrapeSignalsArgs),
    /// Click-through rate, average click position, and click position histogram
    Clicks(AnalyticsClicksArgs),
    /// Conversion rate, add-to-cart rate, and purchase rate side by side
    Conversions(AnalyticsConversionsArgs),
    /// Revenue by currency
    Revenue(AnalyticsRevenueArgs),
}

#[derive(Args)]
pub struct AnalyticsTopSearchesArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Max rows to return
    #[arg(long)]
    pub limit: Option<u32>,

    /// Analytics region (default: de — our app is EU)
    #[arg(long, value_enum, default_value = "de")]
    pub region: Region,
}

#[derive(Args)]
pub struct AnalyticsNoResultsArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Max rows to return
    #[arg(long)]
    pub limit: Option<u32>,

    /// Analytics region (default: de — our app is EU)
    #[arg(long, value_enum, default_value = "de")]
    pub region: Region,
}

#[derive(Args)]
pub struct AnalyticsScrapeSignalsArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Analytics region (default: de — our app is EU)
    #[arg(long, value_enum, default_value = "de")]
    pub region: Region,
}

#[derive(Args)]
pub struct AnalyticsClicksArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Analytics region (default: de — our app is EU)
    #[arg(long, value_enum, default_value = "de")]
    pub region: Region,
}

#[derive(Args)]
pub struct AnalyticsConversionsArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Analytics region (default: de — our app is EU)
    #[arg(long, value_enum, default_value = "de")]
    pub region: Region,
}

#[derive(Args)]
pub struct AnalyticsRevenueArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Analytics region (default: de — our app is EU)
    #[arg(long, value_enum, default_value = "de")]
    pub region: Region,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Region {
    De,
    Us,
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Region::De => write!(f, "de"),
            Region::Us => write!(f, "us"),
        }
    }
}

#[derive(Subcommand)]
pub enum EventsCommands {
    /// Events -> Health: /1/metrics totals + per-bucket series (eventCount, errorCount/errorRate, ...)
    Metrics(EventsMetricsArgs),
    /// Events -> Debugger: aggregated sample of the live ~3,000-event rolling buffer (NOT time-windowed, no pagination)
    Sample(EventsSampleArgs),
    /// Same fetch as `sample`, filtered + grouped to ingest failures (status != 200 or errors[] non-empty)
    Errors(EventsErrorsArgs),
}

#[derive(Args)]
pub struct EventsMetricsArgs {
    /// Lookback window (Nm|Nh|Nd)
    #[arg(long, default_value = "30d")]
    pub since: SinceArg,

    /// Bucket granularity. 'week' is not offered here — the live API
    /// returns HTTP 422 for it (verified 2026-08-04); only hour|day exist.
    #[arg(long, value_enum, default_value = "hour")]
    pub granularity: EventsGranularity,

    /// Include near-real-time (not-yet-finalized) event counts. Difference
    /// vs false is negligible (~8 events across a measured 3-day window),
    /// but exposed rather than hidden, per this repo's quota/evidentiary
    /// honesty conventions.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub approximate: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EventsGranularity {
    Hour,
    Day,
}

#[derive(Args)]
pub struct EventsSampleArgs {
    /// Sampling window applied client-side (Nm|Nh|Nd). Largely cosmetic:
    /// the live /1/events buffer holds ~3,000 most-recent events regardless
    /// of window width (default 10m).
    #[arg(long, default_value = "10m")]
    pub since: SinceArg,

    /// Cap the number of events fetched. Truncates only — the API has no
    /// pagination (offset/page/length all return 0 events, verified
    /// 2026-08-04).
    #[arg(long)]
    pub limit: Option<u32>,

    /// Persist the raw events (jsonl) + meta.json to this directory. Never
    /// overwrites; collisions get -2, -3, ... suffixes (same contract as
    /// `logs sample --persist`).
    #[arg(long, value_name = "DIR")]
    pub persist: Option<String>,
}

#[derive(Args)]
pub struct EventsErrorsArgs {
    /// Sampling window applied client-side (Nm|Nh|Nd) — see `events
    /// sample`'s buffer-cap caveat; same rolling-buffer constraint applies.
    #[arg(long, default_value = "10m")]
    pub since: SinceArg,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: ShellType,
}

#[derive(Clone, ValueEnum)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell")]
    PowerShell,
}

/// `--since` value: `Nm` (minutes), `Nh` (hours), or `Nd` (days).
#[derive(Debug, Clone, Copy)]
pub struct SinceArg {
    pub minutes: i64,
}

impl SinceArg {
    pub fn as_chrono_duration(&self) -> chrono::Duration {
        chrono::Duration::minutes(self.minutes)
    }

    pub fn days(&self) -> i64 {
        self.minutes / (24 * 60)
    }
}

impl FromStr for SinceArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() < 2 {
            return Err(format!(
                "invalid --since value '{s}': expected Nm|Nh|Nd, e.g. 30m, 1h, 7d"
            ));
        }
        let (num_part, unit) = s.split_at(s.len() - 1);
        let n: i64 = num_part
            .parse()
            .map_err(|_| format!("invalid --since value '{s}': '{num_part}' is not a number"))?;
        if n <= 0 {
            return Err(format!("invalid --since value '{s}': must be positive"));
        }
        let minutes = match unit {
            "m" | "M" => n,
            "h" | "H" => n * 60,
            "d" | "D" => n * 60 * 24,
            other => {
                return Err(format!(
                    "invalid --since unit '{other}' in '{s}': expected one of m|h|d"
                ))
            }
        };
        Ok(SinceArg { minutes })
    }
}

impl fmt::Display for SinceArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minutes % (60 * 24) == 0 {
            write!(f, "{}d", self.minutes / (60 * 24))
        } else if self.minutes % 60 == 0 {
            write!(f, "{}h", self.minutes / 60)
        } else {
            write!(f, "{}m", self.minutes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_arg_parses_minutes_hours_days() {
        assert_eq!(SinceArg::from_str("30m").unwrap().minutes, 30);
        assert_eq!(SinceArg::from_str("1h").unwrap().minutes, 60);
        assert_eq!(SinceArg::from_str("7d").unwrap().minutes, 7 * 24 * 60);
    }

    #[test]
    fn since_arg_rejects_garbage() {
        assert!(SinceArg::from_str("").is_err());
        assert!(SinceArg::from_str("h").is_err());
        assert!(SinceArg::from_str("7x").is_err());
        assert!(SinceArg::from_str("-1h").is_err());
        assert!(SinceArg::from_str("0h").is_err());
    }

    #[test]
    fn since_arg_days_helper() {
        assert_eq!(SinceArg::from_str("7d").unwrap().days(), 7);
        assert_eq!(SinceArg::from_str("90m").unwrap().days(), 0);
    }

    /// `SinceArg::from_str` is thoroughly tested above; its `Display` impl
    /// (the Xd/Xh/Xm formatting branches) was previously only ever reached
    /// indirectly when a command echoes `args.since.to_string()` back —
    /// never round-tripped through `Display` directly.
    #[test]
    fn since_arg_display_prefers_the_largest_exact_unit() {
        assert_eq!(SinceArg::from_str("7d").unwrap().to_string(), "7d");
        assert_eq!(SinceArg::from_str("24h").unwrap().to_string(), "1d");
        assert_eq!(SinceArg::from_str("2h").unwrap().to_string(), "2h");
        assert_eq!(SinceArg::from_str("90m").unwrap().to_string(), "90m");
        assert_eq!(SinceArg { minutes: 61 }.to_string(), "61m");
        assert_eq!(SinceArg { minutes: 60 }.to_string(), "1h");
        assert_eq!(SinceArg { minutes: 1440 }.to_string(), "1d");
    }

    /// `Region::Us`'s `Display` arm is only ever reached in the
    /// value-*parsing* sense via `--region us` elsewhere — never round-
    /// tripped through `Display` directly (every analytics test uses the
    /// default `de` region).
    #[test]
    fn region_display_both_variants() {
        assert_eq!(Region::De.to_string(), "de");
        assert_eq!(Region::Us.to_string(), "us");
    }

    #[test]
    fn cli_parses_without_error() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
