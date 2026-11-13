#![allow(dead_code)]
//! Usage API (D9) — GET `https://usage.algolia.com/1/usage/{statistic}`
//! (optionally `/{index}`), `startDate`/`endDate` as ISO-8601 datetimes,
//! `granularity=hourly|daily`.

use crate::cli::Granularity;
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::{self, Surface};
use serde::Serialize;

/// Statistic names Algolia's Usage API reference documents (D9). Unknown
/// names are NOT rejected — `alx usage series --statistic` passes through
/// any name the operator supplies (Algolia may add statistics this list
/// doesn't know about yet) — see `validate_statistic_name`.
pub const KNOWN_STATISTICS: &[&str] = &[
    "total_search_requests",
    "total_search_operations",
    "querysuggestions_total_search_requests",
    "indexing_operations",
    "indexing_requests",
    "records",
    "storage",
    "ai_requests",
];

/// The four statistics `usage summary`/`usage meters` fetch (D9).
pub const STAT_TOTAL_SEARCH_REQUESTS: &str = "total_search_requests";
pub const STAT_TOTAL_SEARCH_OPERATIONS: &str = "total_search_operations";
pub const STAT_QUERYSUGGESTIONS_REQUESTS: &str = "querysuggestions_total_search_requests";
pub const STAT_RECORDS: &str = "records";

#[derive(Debug, Clone, Serialize)]
pub struct UsagePoint {
    pub date: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageSeries {
    pub statistic: String,
    pub points: Vec<UsagePoint>,
}

/// Pre-flight granularity/window check (D0.3 / U4) — the design spec's
/// numbers: hourly supports <=7 days, daily supports <=365 days. UNVERIFIED
/// against a daily<=90d claim seen in pre-build research; the design spec
/// wins per D0.3. Returns a clean
/// `AppError::InvalidInput` naming the actual limit before any HTTP call,
/// rather than letting the API reject it opaquely.
pub fn validate_granularity_window(granularity: Granularity, since_days: i64) -> AppResult<()> {
    match granularity {
        Granularity::Hourly if since_days > 7 => Err(AppError::InvalidInput(format!(
            "hourly granularity supports at most 7 days, got {since_days}d — use --granularity daily or narrow --since"
        ))),
        Granularity::Daily if since_days > 365 => Err(AppError::InvalidInput(format!(
            "daily granularity supports at most 365 days, got {since_days}d"
        ))),
        _ => Ok(()),
    }
}

/// Not part of the known-statistic list — passthrough allowed (the Usage
/// API reference itself says "documentation states user should check REST API reference
/// for latest additions"), but the caller should surface the returned
/// warning rather than pretend the name was recognized.
pub fn validate_statistic_name(name: &str) -> Option<String> {
    if KNOWN_STATISTICS.contains(&name) {
        None
    } else {
        Some(format!(
            "'{name}' is not in alx's known Usage API statistic list ({}); passing it through as-is — Algolia may support it even though alx doesn't recognize it",
            KNOWN_STATISTICS.join(", ")
        ))
    }
}

pub fn granularity_str(granularity: Granularity) -> &'static str {
    match granularity {
        Granularity::Hourly => "hourly",
        Granularity::Daily => "daily",
    }
}

/// `startDate`/`endDate` for a window of `since_days` ending now (UTC).
/// `since_days` is clamped to >=0 so a sub-day `--since` (e.g. `3h`, which
/// truncates to `0` via `SinceArg::days()`) still yields a valid window
/// rather than an inverted range.
///
/// VERIFIED AGAINST THE LIVE API (2026-07-30) — the Usage API requires a
/// **full ISO-8601 datetime** (`2026-07-23T00:00:00Z`). A date-only value
/// is rejected with a misleading `422 {"message":"Unexpected parameters:
/// \"startDate\", \"endDate\""}` — Algolia reports the *format* failure as
/// if the parameter *names* were unrecognized, which is why this looked
/// like a naming mismatch. Note the Search Analytics API demands the exact
/// opposite (date-only; a datetime there fails with `"must be a date"`) —
/// see `analytics::date_window`. Do not "unify" these two helpers.
pub fn date_window(since_days: i64) -> (String, String) {
    let end = chrono::Utc::now();
    let start = end - chrono::Duration::days(since_days.max(0));
    (
        start.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        end.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

/// Sum of a counter-style statistic's points over the window (e.g.
/// `total_search_requests` — each point is a per-bucket count, so the sum is
/// the window total).
pub fn sum_series(series: &UsageSeries) -> f64 {
    series.points.iter().map(|p| p.value).sum()
}

/// Latest point's value, for gauge/snapshot-style statistics (e.g.
/// `records` — a point-in-time count, not something to sum across days).
/// `0.0` if the series is empty.
pub fn latest_value(series: &UsageSeries) -> f64 {
    series.points.last().map(|p| p.value).unwrap_or(0.0)
}

/// Tolerant parse of the Usage API response. VERIFIED live 2026-07-30: the
/// real shape is keyed by the **statistic name** —
/// `{"total_search_requests": [{"t": <unix MILLIseconds>, "v": <number>}]}`
/// — not the `{"statistics": [...]}` envelope the pre-build research
/// claimed, and `t` is in **milliseconds** (e.g. `1785196800000`), not
/// seconds. Both key shapes are accepted; `t` scale is detected by
/// magnitude so a second-scale value still parses correctly (interpreting
/// ms as seconds rendered dates in the year 58551 — a real defect caught
/// only by running against the live API).
///
/// `v` may arrive as a JSON integer or float — `as_f64()` handles both.
/// Any `t` above this magnitude cannot be a plausible second-scale epoch
/// (1e11 seconds is the year 5138), so it is milliseconds. Algolia sends
/// milliseconds; the second-scale branch exists so hand-written fixtures
/// and any future API change both keep rendering sane dates.
const MILLIS_THRESHOLD: i64 = 100_000_000_000;

fn timestamp_to_rfc3339(t: i64) -> String {
    let parsed = if t.abs() >= MILLIS_THRESHOLD {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t)
    } else {
        chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0)
    };
    parsed
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| t.to_string())
}

pub fn parse_usage_response(body: &serde_json::Value, statistic: &str) -> AppResult<UsageSeries> {
    let arr = body
        .get("statistics")
        .and_then(|v| v.as_array())
        .or_else(|| body.get(statistic).and_then(|v| v.as_array()))
        .ok_or_else(|| AppError::Api {
            status: 200,
            message: format!(
                "unexpected usage API response shape for '{statistic}': missing 'statistics' array"
            ),
            suggestion: None,
        })?;

    let mut points = Vec::with_capacity(arr.len());
    for item in arr {
        let t = item
            .get("t")
            .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
            .ok_or_else(|| AppError::Api {
                status: 200,
                message: format!("usage API point missing/invalid 't' timestamp for '{statistic}'"),
                suggestion: None,
            })?;
        let value = item
            .get("v")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| AppError::Api {
                status: 200,
                message: format!("usage API point missing/invalid 'v' value for '{statistic}'"),
                suggestion: None,
            })?;

        let date = timestamp_to_rfc3339(t);

        points.push(UsagePoint { date, value });
    }

    Ok(UsageSeries {
        statistic: statistic.to_string(),
        points,
    })
}

fn usage_url(
    base: &str,
    statistic: &str,
    start_date: &str,
    end_date: &str,
    granularity: &str,
) -> String {
    // `statistic` is operator-supplied CLI input (--statistic), not
    // untrusted external data, and the four hardcoded stat names never
    // contain URL-meaningful characters — no percent-encoding crate is in
    // the dependency set (D2), matching algosearch's inline `format!` URL
    // convention (shared across these CLIs).
    format!("{base}/1/usage/{statistic}?startDate={start_date}&endDate={end_date}&granularity={granularity}")
}

/// `GET /1/usage/{statistic}` for the given window/granularity.
pub async fn fetch_statistic(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    statistic: &str,
    granularity: Granularity,
    since_days: i64,
) -> AppResult<UsageSeries> {
    let base = ctx.base_urls.usage();
    let (start_date, end_date) = date_window(since_days);
    let url = usage_url(
        &base,
        statistic,
        &start_date,
        &end_date,
        granularity_str(granularity),
    );

    let body = http::get_json(&ctx.client, &url, app_id, key, Surface::Usage, &ctx.ops).await?;
    parse_usage_response(&body, statistic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u4_hourly_beyond_7_days_rejected_preflight() {
        let err = validate_granularity_window(Granularity::Hourly, 30).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(err.to_string().contains('7'));
    }

    #[test]
    fn u4_hourly_within_7_days_ok() {
        assert!(validate_granularity_window(Granularity::Hourly, 7).is_ok());
        assert!(validate_granularity_window(Granularity::Hourly, 1).is_ok());
    }

    #[test]
    fn u4_daily_beyond_365_days_rejected_preflight() {
        let err = validate_granularity_window(Granularity::Daily, 400).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(err.to_string().contains("365"));
    }

    #[test]
    fn u4_daily_within_365_days_ok() {
        assert!(validate_granularity_window(Granularity::Daily, 365).is_ok());
        assert!(validate_granularity_window(Granularity::Daily, 30).is_ok());
    }

    #[test]
    fn validate_statistic_name_known_names_pass_silently() {
        for name in KNOWN_STATISTICS {
            assert!(
                validate_statistic_name(name).is_none(),
                "expected {name} to be known"
            );
        }
    }

    #[test]
    fn validate_statistic_name_unknown_name_passes_through_with_warning() {
        let warning = validate_statistic_name("some_future_stat").expect("expected a warning");
        assert!(warning.contains("some_future_stat"));
        assert!(warning.to_lowercase().contains("pass"));
    }

    #[test]
    fn series_tolerates_float_and_int_values() {
        let body = serde_json::json!({
            "statistics": [
                {"t": 1689859200, "v": 42500},
                {"t": 1689945600, "v": 38200.5}
            ]
        });

        let series = parse_usage_response(&body, "total_search_requests").unwrap();
        assert_eq!(series.statistic, "total_search_requests");
        assert_eq!(series.points.len(), 2);
        assert_eq!(series.points[0].value, 42500.0);
        assert_eq!(series.points[1].value, 38200.5);
    }

    #[test]
    fn parse_usage_response_missing_statistics_array_is_a_clean_error() {
        let body = serde_json::json!({ "message": "not what we expected" });
        let err = parse_usage_response(&body, "records").unwrap_err();
        assert!(matches!(err, AppError::Api { .. }));
    }

    #[test]
    fn parse_usage_response_falls_back_to_statistic_keyed_array() {
        // Tolerant of the wildcard-shaped response (`{"<statistic>": [...]}`)
        // even though alx v0.1 never issues a `*` request itself (D13).
        let body = serde_json::json!({
            "records": [{"t": 1689859200, "v": 150000}]
        });
        let series = parse_usage_response(&body, "records").unwrap();
        assert_eq!(series.points.len(), 1);
        assert_eq!(series.points[0].value, 150000.0);
    }

    #[test]
    fn sum_series_adds_all_points() {
        let series = UsageSeries {
            statistic: "total_search_requests".to_string(),
            points: vec![
                UsagePoint {
                    date: "2026-07-01".into(),
                    value: 100.0,
                },
                UsagePoint {
                    date: "2026-07-02".into(),
                    value: 250.5,
                },
            ],
        };
        assert_eq!(sum_series(&series), 350.5);
    }

    #[test]
    fn latest_value_is_last_point_not_max_or_sum() {
        let series = UsageSeries {
            statistic: "records".to_string(),
            points: vec![
                UsagePoint {
                    date: "2026-07-01".into(),
                    value: 100.0,
                },
                UsagePoint {
                    date: "2026-07-02".into(),
                    value: 90.0,
                },
            ],
        };
        assert_eq!(latest_value(&series), 90.0);
    }

    #[test]
    fn latest_value_empty_series_is_zero() {
        let series = UsageSeries {
            statistic: "records".to_string(),
            points: vec![],
        };
        assert_eq!(latest_value(&series), 0.0);
    }

    #[test]
    fn date_window_clamps_negative_or_zero_since_days_to_same_instant() {
        let (start, end) = date_window(0);
        assert_eq!(start, end);
    }

    #[test]
    fn date_window_spans_requested_days() {
        let (start, end) = date_window(7);
        let start_t = chrono::NaiveDateTime::parse_from_str(&start, "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let end_t = chrono::NaiveDateTime::parse_from_str(&end, "%Y-%m-%dT%H:%M:%SZ").unwrap();
        assert_eq!((end_t - start_t).num_days(), 7);
    }

    /// Live-API regression (2026-07-30): Algolia returns `t` in MILLIseconds
    /// (`1785196800000`). Interpreting that as seconds rendered dates in the
    /// year +58551 — visible nonsense that the second-scale mock fixtures
    /// could never catch. Both scales must render a sane date.
    #[test]
    fn usage_timestamps_parse_as_milliseconds_and_seconds() {
        let from_millis = timestamp_to_rfc3339(1785196800000);
        assert!(
            from_millis.starts_with("2026-"),
            "millisecond epoch must render in 2026, got {from_millis}"
        );
        let from_seconds = timestamp_to_rfc3339(1785196800);
        assert!(
            from_seconds.starts_with("2026-"),
            "second epoch must still render in 2026, got {from_seconds}"
        );
    }

    /// The real response is keyed by statistic name, not `{"statistics": …}`.
    #[test]
    fn parse_accepts_the_real_statistic_keyed_shape_with_millisecond_timestamps() {
        let body = serde_json::json!({
            "total_search_requests": [
                {"t": 1785196800000i64, "v": 400000},
                {"t": 1785283200000i64, "v": 410000}
            ]
        });
        let series = parse_usage_response(&body, "total_search_requests").unwrap();
        assert_eq!(series.points.len(), 2);
        assert!(series.points[0].date.starts_with("2026-"));
        assert_eq!(series.points[1].value, 410000.0);
    }

    /// Live-API regression (2026-07-30): the Usage API rejects a date-only
    /// `startDate`/`endDate` with a misleading `422 "Unexpected parameters"`.
    /// It requires a full ISO-8601 datetime. This pins the format so the
    /// date-only regression cannot return.
    #[test]
    fn date_window_emits_full_iso8601_datetime_not_date_only() {
        let (start, end) = date_window(30);
        for value in [&start, &end] {
            assert!(
                value.ends_with('Z') && value.contains('T') && value.len() == 20,
                "usage API needs a full ISO-8601 datetime (YYYY-MM-DDTHH:MM:SSZ), got {value}"
            );
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%SZ")
                .expect("must parse as an ISO-8601 datetime");
        }
    }

    #[test]
    fn usage_url_omits_index_and_includes_query_params() {
        let url = usage_url(
            "https://usage.algolia.com",
            "total_search_requests",
            "2026-06-24",
            "2026-07-24",
            "daily",
        );
        assert_eq!(
            url,
            "https://usage.algolia.com/1/usage/total_search_requests?startDate=2026-06-24&endDate=2026-07-24&granularity=daily"
        );
    }
}
