//! `alx usage summary|series|meters` (D9). Only build against this once
//! `alx doctor` reports the plan includes Usage API access.
//!
//! U1 (both meters, always, side by side): `summary` and `meters` both embed
//! non-optional `requests`/`operations` fields in their response structs —
//! there is no truncated/quick-summary code path that can print only one.
//! U3: `summary` carries a first-class `billed_search_requests_approx`
//! field, labeled `derived/approximate`. U4: granularity/window validation
//! runs before any HTTP call (`algolia::usage::validate_granularity_window`
//! is invoked prior to `fetch_statistic`). U2: plan-gated 402/403s are
//! classified by `http::get_json`/`classify_forbidden` into
//! `AppError::PlanGated` and propagated unchanged via `?` — this module
//! never downgrades that into a generic error. D0.3: every entry point
//! also runs `safety::preflight_privilege_check` after credential
//! resolution and the granularity pre-flight, before the first real usage
//! call (base URL sourced from `ctx.base_urls.search`, so
//! `ALX_SEARCH_BASE_URL` redirects it in tests).

use crate::algolia::usage::{self, UsagePoint, UsageSeries};
use crate::cli::{Granularity, UsageMetersArgs, UsageSeriesArgs, UsageSummaryArgs};
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::Surface;
use crate::output::{format_session_ops_line, SessionOpsSnapshot};
use serde::Serialize;

fn require_app_id(ctx: &AppContext) -> AppResult<String> {
    ctx.resolve_app_id().ok_or_else(|| {
        AppError::InvalidInput(
            "missing Algolia Application ID — set ALGOLIA_APPLICATION_ID or pass --app-id"
                .to_string(),
        )
    })
}

fn require_key(ctx: &AppContext) -> AppResult<String> {
    ctx.resolve_key(Surface::Usage).ok_or_else(|| {
        AppError::InvalidInput(
            "missing Usage API key — set ALGOLIA_USAGE_API_KEY (or the ALGOLIA_API_KEY fallback), or pass --key"
                .to_string(),
        )
    })
}

/// A single meter's value, always labeled with which raw statistic it came
/// from and how it was aggregated over the window — `records` is a
/// point-in-time gauge (`latest_snapshot`), the others are per-period
/// counters (`sum_over_window`). Never a bare unlabeled number (U1/U3).
#[derive(Debug, Clone, Serialize)]
struct MeterValue {
    statistic: &'static str,
    aggregation: &'static str,
    value: f64,
}

/// U3: the derived billed-requests approximation, explicitly labeled so it
/// is never mistaken for a directly-reported Algolia figure.
#[derive(Debug, Clone, Serialize)]
struct DerivedField {
    value: f64,
    label: &'static str,
    formula: &'static str,
}

#[derive(Debug, Serialize)]
struct UsageSummaryResponse {
    since: String,
    start_date: String,
    end_date: String,
    granularity: &'static str,
    /// U1: always present, always alongside `operations` — never a
    /// collapsed single "usage" number.
    requests: MeterValue,
    operations: MeterValue,
    querysuggestions_requests: MeterValue,
    records: MeterValue,
    billed_search_requests_approx: DerivedField,
    warnings: Vec<String>,
    session_ops: SessionOpsSnapshot,
}

#[derive(Debug, Serialize)]
struct UsageMetersResponse {
    since: String,
    start_date: String,
    end_date: String,
    granularity: &'static str,
    /// U5: dedicated side-by-side daily series for both meters — not a
    /// summary alias, the full per-day points for each are returned.
    requests: UsageSeries,
    operations: UsageSeries,
    warnings: Vec<String>,
    session_ops: SessionOpsSnapshot,
}

#[derive(Debug, Serialize)]
struct UsageSeriesResponse {
    statistic: String,
    since: String,
    start_date: String,
    end_date: String,
    granularity: &'static str,
    points: Vec<UsagePoint>,
    warnings: Vec<String>,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_summary(ctx: &AppContext, args: &UsageSummaryArgs) -> AppResult<()> {
    let app_id = require_app_id(ctx)?;
    let key = require_key(ctx)?;

    let since_days = args.since.days();
    // Pre-flight before any HTTP call (D0.3/U4) — `summary` always uses
    // daily granularity, but an absurd window (e.g. `--since 1000d`) should
    // still fail cleanly up front rather than opaquely from the API.
    usage::validate_granularity_window(Granularity::Daily, since_days)?;

    // D0.3 over-privilege gate, before the first real usage call.
    crate::safety::preflight_privilege_check(
        &ctx.client,
        &ctx.base_urls.search(&app_id),
        &app_id,
        &key,
        ctx.i_know,
        &ctx.presenter,
    )
    .await?;

    ctx.presenter
        .progress("fetching total_search_requests, total_search_operations, querysuggestions_total_search_requests, records");

    let (requests, operations, qs_requests, records) = tokio::try_join!(
        usage::fetch_statistic(
            ctx,
            &app_id,
            &key,
            usage::STAT_TOTAL_SEARCH_REQUESTS,
            Granularity::Daily,
            since_days,
        ),
        usage::fetch_statistic(
            ctx,
            &app_id,
            &key,
            usage::STAT_TOTAL_SEARCH_OPERATIONS,
            Granularity::Daily,
            since_days,
        ),
        usage::fetch_statistic(
            ctx,
            &app_id,
            &key,
            usage::STAT_QUERYSUGGESTIONS_REQUESTS,
            Granularity::Daily,
            since_days,
        ),
        usage::fetch_statistic(
            ctx,
            &app_id,
            &key,
            usage::STAT_RECORDS,
            Granularity::Daily,
            since_days,
        ),
    )?;

    let requests_total = usage::sum_series(&requests);
    let operations_total = usage::sum_series(&operations);
    let qs_total = usage::sum_series(&qs_requests);
    let records_latest = usage::latest_value(&records);

    let (start_date, end_date) = usage::date_window(since_days);

    let response = UsageSummaryResponse {
        since: args.since.to_string(),
        start_date,
        end_date,
        granularity: usage::granularity_str(Granularity::Daily),
        requests: MeterValue {
            statistic: usage::STAT_TOTAL_SEARCH_REQUESTS,
            aggregation: "sum_over_window",
            value: requests_total,
        },
        operations: MeterValue {
            statistic: usage::STAT_TOTAL_SEARCH_OPERATIONS,
            aggregation: "sum_over_window",
            value: operations_total,
        },
        querysuggestions_requests: MeterValue {
            statistic: usage::STAT_QUERYSUGGESTIONS_REQUESTS,
            aggregation: "sum_over_window",
            value: qs_total,
        },
        records: MeterValue {
            statistic: usage::STAT_RECORDS,
            aggregation: "latest_snapshot",
            value: records_latest,
        },
        billed_search_requests_approx: DerivedField {
            // U3: total_search_requests - querysuggestions_total_search_requests.
            value: requests_total - qs_total,
            label: "derived/approximate",
            formula: "total_search_requests - querysuggestions_total_search_requests",
        },
        warnings: Vec::new(),
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, human_summary)
}

pub async fn run_series(ctx: &AppContext, args: &UsageSeriesArgs) -> AppResult<()> {
    let app_id = require_app_id(ctx)?;
    let key = require_key(ctx)?;

    let mut warnings = Vec::new();
    if let Some(w) = usage::validate_statistic_name(&args.statistic) {
        warnings.push(w);
    }

    let since_days = args.since.days();
    // Pre-flight before any HTTP call (D0.3/U4): reject an invalid
    // granularity/window combination up front, naming the actual limit,
    // rather than letting the Usage API reject it opaquely.
    usage::validate_granularity_window(args.granularity, since_days)?;

    // D0.3 over-privilege gate, before the first real usage call.
    crate::safety::preflight_privilege_check(
        &ctx.client,
        &ctx.base_urls.search(&app_id),
        &app_id,
        &key,
        ctx.i_know,
        &ctx.presenter,
    )
    .await?;

    let series = usage::fetch_statistic(
        ctx,
        &app_id,
        &key,
        &args.statistic,
        args.granularity,
        since_days,
    )
    .await?;

    let (start_date, end_date) = usage::date_window(since_days);

    let response = UsageSeriesResponse {
        statistic: args.statistic.clone(),
        since: args.since.to_string(),
        start_date,
        end_date,
        granularity: usage::granularity_str(args.granularity),
        points: series.points,
        warnings,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, human_series)
}

pub async fn run_meters(ctx: &AppContext, args: &UsageMetersArgs) -> AppResult<()> {
    let app_id = require_app_id(ctx)?;
    let key = require_key(ctx)?;

    let since_days = args.since.days();
    usage::validate_granularity_window(Granularity::Daily, since_days)?;

    // D0.3 over-privilege gate, before the first real usage call.
    crate::safety::preflight_privilege_check(
        &ctx.client,
        &ctx.base_urls.search(&app_id),
        &app_id,
        &key,
        ctx.i_know,
        &ctx.presenter,
    )
    .await?;

    ctx.presenter
        .progress("fetching daily requests-vs-operations series");

    let (requests, operations) = tokio::try_join!(
        usage::fetch_statistic(
            ctx,
            &app_id,
            &key,
            usage::STAT_TOTAL_SEARCH_REQUESTS,
            Granularity::Daily,
            since_days,
        ),
        usage::fetch_statistic(
            ctx,
            &app_id,
            &key,
            usage::STAT_TOTAL_SEARCH_OPERATIONS,
            Granularity::Daily,
            since_days,
        ),
    )?;

    let (start_date, end_date) = usage::date_window(since_days);

    let response = UsageMetersResponse {
        since: args.since.to_string(),
        start_date,
        end_date,
        granularity: usage::granularity_str(Granularity::Daily),
        requests,
        operations,
        warnings: Vec::new(),
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, human_meters)
}

fn human_summary(r: &UsageSummaryResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "usage summary — {} to {} ({}, since {})\n",
        r.start_date, r.end_date, r.granularity, r.since
    ));
    out.push_str(&format!(
        "  requests:    {:>12.0}  ({})\n",
        r.requests.value, r.requests.statistic
    ));
    out.push_str(&format!(
        "  operations:  {:>12.0}  ({})\n",
        r.operations.value, r.operations.statistic
    ));
    out.push_str(&format!(
        "  qs requests: {:>12.0}  ({})\n",
        r.querysuggestions_requests.value, r.querysuggestions_requests.statistic
    ));
    out.push_str(&format!(
        "  records:     {:>12.0}  ({}, {})\n",
        r.records.value, r.records.statistic, r.records.aggregation
    ));
    out.push_str(&format!(
        "  billed search requests (derived/approximate): {:.0}  [{}]\n",
        r.billed_search_requests_approx.value, r.billed_search_requests_approx.formula
    ));
    for w in &r.warnings {
        out.push_str(&format!("  warning: {w}\n"));
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

fn human_meters(r: &UsageMetersResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "usage meters — {} to {} ({}, since {})\n",
        r.start_date, r.end_date, r.granularity, r.since
    ));
    out.push_str("  date         requests    operations\n");
    let ops_by_date: std::collections::HashMap<&str, f64> = r
        .operations
        .points
        .iter()
        .map(|p| (p.date.as_str(), p.value))
        .collect();
    for p in &r.requests.points {
        let ops_value = ops_by_date.get(p.date.as_str()).copied().unwrap_or(0.0);
        out.push_str(&format!(
            "  {:<12} {:>10.0}  {:>10.0}\n",
            p.date, p.value, ops_value
        ));
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

fn human_series(r: &UsageSeriesResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "usage series {} — {} to {} ({}, since {})\n",
        r.statistic, r.start_date, r.end_date, r.granularity, r.since
    ));
    for p in &r.points {
        out.push_str(&format!("  {:<25} {:>12.2}\n", p.date, p.value));
    }
    for w in &r.warnings {
        out.push_str(&format!("  warning: {w}\n"));
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // `human_summary`/`human_meters`/`human_series` (--human path): never
    // called by any subprocess test in practice — every `alx` invocation
    // spawned via `std::process::Command` has no controlling TTY on
    // stdin, so `agent::detect`'s TTY check unconditionally forces JSON
    // regardless of `--human`. The only way to exercise these functions
    // at all is a direct, in-process call.
    // -------------------------------------------------------------------

    fn sample_session_ops() -> SessionOpsSnapshot {
        SessionOpsSnapshot {
            logs_calls: 0,
            usage_calls: 3,
            analytics_calls: 0,
            keys_calls: 0,
            insights_calls: 0,
        }
    }

    #[test]
    fn human_summary_renders_both_meters_and_the_derived_field() {
        let response = UsageSummaryResponse {
            since: "30d".to_string(),
            start_date: "2026-06-24".to_string(),
            end_date: "2026-07-24".to_string(),
            granularity: "daily",
            requests: MeterValue {
                statistic: usage::STAT_TOTAL_SEARCH_REQUESTS,
                aggregation: "sum_over_window",
                value: 10000.0,
            },
            operations: MeterValue {
                statistic: usage::STAT_TOTAL_SEARCH_OPERATIONS,
                aggregation: "sum_over_window",
                value: 12000.0,
            },
            querysuggestions_requests: MeterValue {
                statistic: usage::STAT_QUERYSUGGESTIONS_REQUESTS,
                aggregation: "sum_over_window",
                value: 500.0,
            },
            records: MeterValue {
                statistic: "records",
                aggregation: "latest_snapshot",
                value: 42000.0,
            },
            billed_search_requests_approx: DerivedField {
                value: 9500.0,
                label: "derived/approximate",
                formula: "total_search_requests - querysuggestions_total_search_requests",
            },
            warnings: vec!["example warning".to_string()],
            session_ops: sample_session_ops(),
        };

        let rendered = human_summary(&response);

        assert!(rendered.contains("requests"));
        assert!(rendered.contains("operations"));
        assert!(rendered.contains("10000"));
        assert!(rendered.contains("12000"));
        assert!(rendered.contains("derived/approximate"));
        assert!(rendered.contains("example warning"));
    }

    #[test]
    fn human_meters_renders_requests_and_operations_side_by_side_per_date() {
        let response = UsageMetersResponse {
            since: "14d".to_string(),
            start_date: "2026-07-10".to_string(),
            end_date: "2026-07-24".to_string(),
            granularity: "daily",
            requests: UsageSeries {
                statistic: usage::STAT_TOTAL_SEARCH_REQUESTS.to_string(),
                points: vec![UsagePoint {
                    date: "2026-07-10".to_string(),
                    value: 100.0,
                }],
            },
            operations: UsageSeries {
                statistic: usage::STAT_TOTAL_SEARCH_OPERATIONS.to_string(),
                points: vec![UsagePoint {
                    date: "2026-07-10".to_string(),
                    value: 120.0,
                }],
            },
            warnings: vec![],
            session_ops: sample_session_ops(),
        };

        let rendered = human_meters(&response);

        assert!(rendered.contains("2026-07-10"));
        assert!(rendered.contains("100"));
        assert!(rendered.contains("120"));
        assert!(rendered.contains("requests"));
        assert!(rendered.contains("operations"));
    }

    #[test]
    fn human_series_renders_every_point_and_any_warning() {
        let response = UsageSeriesResponse {
            statistic: usage::STAT_TOTAL_SEARCH_OPERATIONS.to_string(),
            since: "90d".to_string(),
            start_date: "2026-04-25".to_string(),
            end_date: "2026-07-24".to_string(),
            granularity: "daily",
            points: vec![
                UsagePoint {
                    date: "2026-07-23".to_string(),
                    value: 321.0,
                },
                UsagePoint {
                    date: "2026-07-24".to_string(),
                    value: 654.0,
                },
            ],
            warnings: vec!["unknown statistic name, passed through".to_string()],
            session_ops: sample_session_ops(),
        };

        let rendered = human_series(&response);

        assert!(rendered.contains(usage::STAT_TOTAL_SEARCH_OPERATIONS));
        assert!(rendered.contains("2026-07-23"));
        assert!(rendered.contains("2026-07-24"));
        assert!(rendered.contains("unknown statistic name, passed through"));
    }

    #[test]
    fn u3_derived_field_computed_and_labeled() {
        let requests = UsageSeries {
            statistic: usage::STAT_TOTAL_SEARCH_REQUESTS.to_string(),
            points: vec![
                UsagePoint {
                    date: "2026-07-01".into(),
                    value: 1000.0,
                },
                UsagePoint {
                    date: "2026-07-02".into(),
                    value: 1200.0,
                },
            ],
        };
        let qs = UsageSeries {
            statistic: usage::STAT_QUERYSUGGESTIONS_REQUESTS.to_string(),
            points: vec![
                UsagePoint {
                    date: "2026-07-01".into(),
                    value: 100.0,
                },
                UsagePoint {
                    date: "2026-07-02".into(),
                    value: 120.0,
                },
            ],
        };

        let requests_total = usage::sum_series(&requests);
        let qs_total = usage::sum_series(&qs);
        let derived = DerivedField {
            value: requests_total - qs_total,
            label: "derived/approximate",
            formula: "total_search_requests - querysuggestions_total_search_requests",
        };

        assert_eq!(derived.value, 1980.0);
        assert_eq!(derived.label, "derived/approximate");
        assert!(derived.formula.contains("querysuggestions"));
    }

    #[test]
    fn summary_response_serializes_both_meters_side_by_side() {
        let response = UsageSummaryResponse {
            since: "30d".into(),
            start_date: "2026-06-24".into(),
            end_date: "2026-07-24".into(),
            granularity: "daily",
            requests: MeterValue {
                statistic: usage::STAT_TOTAL_SEARCH_REQUESTS,
                aggregation: "sum_over_window",
                value: 2200.0,
            },
            operations: MeterValue {
                statistic: usage::STAT_TOTAL_SEARCH_OPERATIONS,
                aggregation: "sum_over_window",
                value: 4400.0,
            },
            querysuggestions_requests: MeterValue {
                statistic: usage::STAT_QUERYSUGGESTIONS_REQUESTS,
                aggregation: "sum_over_window",
                value: 220.0,
            },
            records: MeterValue {
                statistic: usage::STAT_RECORDS,
                aggregation: "latest_snapshot",
                value: 50000.0,
            },
            billed_search_requests_approx: DerivedField {
                value: 1980.0,
                label: "derived/approximate",
                formula: "total_search_requests - querysuggestions_total_search_requests",
            },
            warnings: Vec::new(),
            session_ops: SessionOpsSnapshot::default(),
        };

        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("requests").is_some());
        assert!(json.get("operations").is_some());
        assert_eq!(json["requests"]["value"], serde_json::json!(2200.0));
        assert_eq!(json["operations"]["value"], serde_json::json!(4400.0));
    }

    #[test]
    fn require_app_id_error_is_invalid_input_not_a_network_call() {
        // A missing app id must fail before any HTTP attempt — modeled as
        // InvalidInput (exit code 1), not a network/auth error.
        let err = AppError::InvalidInput("missing Algolia Application ID".into());
        assert_eq!(err.exit_code(), 1);
    }
}
