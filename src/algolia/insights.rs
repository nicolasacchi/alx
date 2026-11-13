//! Insights API — GET `https://insights.{region}.algolia.io`. Backs the
//! Algolia dashboard's Events -> Health (`/1/metrics`) and Events ->
//! Debugger (`/1/events`) screens. Discovered 2026-08-04 by watching the
//! dashboard's own network traffic — public REST endpoints, not internal;
//! also reachable un-regioned at `https://insights.algolia.io`.
//!
//! Region: verified live 2026-08-04 — `insights.de.algolia.io` -> 200,
//! `insights.us.algolia.io` -> 401. That 401 is an AUTH failure, NOT the
//! "empty region" 200-with-no-data shape `analytics::status`'s `us` region
//! has (see that module's doc comment) — a different failure class
//! entirely, so it must never be modeled as "no data for this region".
//! This app's Insights traffic lives on `de`; every fetcher in this module
//! is called with a hardcoded `"de"` region by `commands::events` (unlike
//! `analytics`, there is no `--region` flag on `events` subcommands).
//!
//! Auth: the **logs** ACL, empirically (measured 2026-08-04):
//! `ALGOLIA_LOGS_API_KEY` -> 200, `ALGOLIA_ADMIN_KEY` -> 200,
//! `ALGOLIA_ANALYTICS_API_KEY` -> 401, `ALGOLIA_USAGE_API_KEY` -> 401.
//! `AppContext::resolve_key` gives `Surface::Insights` an extra fallback
//! tier (`ALGOLIA_INSIGHTS_API_KEY` -> `ALGOLIA_LOGS_API_KEY` ->
//! `ALGOLIA_API_KEY`) for exactly this reason — no new key needs minting if
//! a logs key is already configured.
//!
//! *** THE CRITICAL CONSTRAINT for `/1/events` *** — this is the whole
//! reason `events sample`/`events errors` exist in their aggregated shape:
//! it is a rolling buffer of roughly 3,000 events, NOT a time-windowed
//! query. Measured 2026-08-04: a 10-minute, 1-hour, 1-day, and 30-day
//! window ALL returned ~2,990-2,997 events — the same most-recent ~3,000,
//! regardless of the requested `startDate`/`endDate`. A window entirely
//! older than the buffer returns 0. `offset`, `page`, `length` are NOT
//! supported (all return 0 events, verified live) — there is NO
//! pagination; `limit` only truncates, it cannot page through the buffer.
//! Same class of problem as the Logs API's 1,000-entries-per-server cap —
//! `commands::events` reports the observed buffer span exactly like `logs
//! sample` does for its own ring buffer.

use super::serde_util::null_as_default;
use crate::cli::EventsGranularity;
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::{self, Surface};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `/1/events`'s approximate ring-buffer capacity (measured 2026-08-04,
/// observed 2,990-2,997 across every window tried). `commands::events`
/// treats a fetch landing at or above a threshold near this as evidence of
/// truncation, never as "the complete history for the requested window".
pub const BUFFER_CAP_APPROX: usize = 3000;

/// `granularity=week` measured live 2026-08-04 -> HTTP 422. Reject
/// client-side before the call, mirroring `usage::validate_granularity_
/// window`'s preflight philosophy — even though the CLI's own
/// `EventsGranularity` enum (hour|day only) already makes `week`
/// unrepresentable from the command line, this is the reusable, directly
/// unit-testable guard for any other caller of `fetch_metrics`.
pub fn validate_metrics_granularity(granularity: &str) -> AppResult<()> {
    match granularity {
        "hour" | "day" => Ok(()),
        other => Err(AppError::InvalidInput(format!(
            "invalid Insights metrics granularity '{other}' — only 'hour' or 'day' are accepted \
             ('week' returns HTTP 422 from the live API; verified 2026-08-04)"
        ))),
    }
}

pub fn events_granularity_str(granularity: EventsGranularity) -> &'static str {
    match granularity {
        EventsGranularity::Hour => "hour",
        EventsGranularity::Day => "day",
    }
}

/// `[start, end]` ISO-8601 INSTANT (not date-only) window ending now,
/// `since_minutes` wide. Both `/1/metrics` and `/1/events` want full
/// `startDate`/`endDate` instants (e.g. `2026-08-04T08:00:00Z`) — the same
/// shape `usage::date_window` uses, NOT the date-only shape
/// `analytics::date_window` uses. `since_minutes` is clamped to >=0 so a
/// degenerate input still yields a valid (zero-width) window rather than an
/// inverted range.
pub fn date_window(since_minutes: i64) -> (String, String) {
    let end = Utc::now();
    let start = end - ChronoDuration::minutes(since_minutes.max(0));
    (
        start.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        end.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

// =========================================================================
// /1/metrics — Events -> Health
// =========================================================================

/// One bucket of `GET /1/metrics`. EVERY field is `Option` and carries
/// `#[serde(default)]` — a crash during development came from `/2/status`
/// returning `updatedAt: null` into a required `String` field in a
/// low/no-data window (see `analytics::AnalyticsStatusResponse`'s doc
/// comment). This struct treats every numeric/string field the same
/// defensive way, not just the ones observed null so far, because a
/// low-traffic bucket (an early hour, a quiet region) can plausibly null
/// out any of them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricPoint {
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(rename = "eventCount", default)]
    pub event_count: Option<u64>,
    #[serde(rename = "clickCount", default)]
    pub click_count: Option<u64>,
    #[serde(rename = "viewCount", default)]
    pub view_count: Option<u64>,
    #[serde(rename = "conversionCount", default)]
    pub conversion_count: Option<u64>,
    #[serde(rename = "errorCount", default)]
    pub error_count: Option<u64>,
    #[serde(rename = "errorRate", default)]
    pub error_rate: Option<f64>,
    #[serde(rename = "neuralSearchCount", default)]
    pub neural_search_count: Option<u64>,
    #[serde(rename = "neuralSearchRate", default)]
    pub neural_search_rate: Option<f64>,
    #[serde(rename = "recommendFrequentlyBoughtTogetherCount", default)]
    pub recommend_frequently_bought_together_count: Option<u64>,
    #[serde(rename = "recommendFrequentlyBoughtTogetherRate", default)]
    pub recommend_frequently_bought_together_rate: Option<f64>,
    #[serde(rename = "recommendRelatedProductsCount", default)]
    pub recommend_related_products_count: Option<u64>,
    #[serde(rename = "recommendRelatedProductsRate", default)]
    pub recommend_related_products_rate: Option<f64>,
    #[serde(rename = "recommendTrendingItemsCount", default)]
    pub recommend_trending_items_count: Option<u64>,
    #[serde(rename = "recommendTrendingItemsRate", default)]
    pub recommend_trending_items_rate: Option<f64>,
    #[serde(rename = "recommendTrendingFacetValuesCount", default)]
    pub recommend_trending_facet_values_count: Option<u64>,
    #[serde(rename = "recommendTrendingFacetValuesRate", default)]
    pub recommend_trending_facet_values_rate: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct GetMetricsResponse {
    // BUG-ALX-EVENTS-NULLCOLL: `#[serde(default)]` alone only substitutes
    // for an ABSENT `metrics` key, not an explicit `"metrics": null` — a
    // low/no-data window nulling this out the same way `/2/status` nulled
    // `updatedAt` would otherwise abort the whole fetch. See
    // `serde_util::null_as_default`.
    #[serde(default, deserialize_with = "null_as_default")]
    metrics: Vec<MetricPoint>,
}

/// Pure parse, split out from the fetch so it's testable against synthetic
/// JSON (including nulled-out fields) without a network call.
pub fn parse_metrics_response(value: &serde_json::Value) -> AppResult<Vec<MetricPoint>> {
    let parsed: GetMetricsResponse = serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse /1/metrics response: {e}")))?;
    Ok(parsed.metrics)
}

/// `GET /1/metrics` — Events -> Health. `granularity` is a raw `&str`
/// (`"hour"`/`"day"`) rather than the CLI's typed enum so this stays
/// callable/testable independent of clap, and is re-validated here
/// (`validate_metrics_granularity`) so a future call site can't skip the
/// preflight by accident even if the CLI-level guard is ever loosened.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_metrics(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    since_minutes: i64,
    granularity: &str,
    approximate: bool,
) -> AppResult<Vec<MetricPoint>> {
    validate_metrics_granularity(granularity)?;
    let (start, end) = date_window(since_minutes);
    let url = format!(
        "{}/1/metrics?startDate={start}&endDate={end}&granularity={granularity}&approximate={approximate}",
        ctx.base_urls.insights(region)
    );
    let value = http::get_json(&ctx.client, &url, app_id, key, Surface::Insights, &ctx.ops).await?;
    parse_metrics_response(&value)
}

// =========================================================================
// /1/events — Events -> Debugger
// =========================================================================

/// The payload as received (`event` key of a raw `/1/events` entry).
/// `algolia_source` is `None` for server-side/hand-rolled emitters — never
/// coerced to an empty vec, since "absent" and "empty array" are distinct
/// signals here (see `commands::events::algolia_source_key`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventPayload {
    #[serde(rename = "eventName", default)]
    pub event_name: Option<String>,
    #[serde(rename = "eventType", default)]
    pub event_type: Option<String>,
    #[serde(rename = "eventSubtype", default)]
    pub event_subtype: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    // BUG-ALX-EVENTS-NULLCOLL: array/map fields need the null-tolerant
    // deserializer too, not just `#[serde(default)]` — see
    // `serde_util::null_as_default`'s doc comment for why `default` alone
    // isn't enough here (unlike the `Option<T>` scalar fields around it,
    // which handle `null` for free).
    #[serde(rename = "objectIDs", default, deserialize_with = "null_as_default")]
    pub object_ids: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub positions: Vec<serde_json::Value>,
    #[serde(rename = "queryID", default)]
    pub query_id: Option<String>,
    #[serde(rename = "userToken", default)]
    pub user_token: Option<String>,
    #[serde(rename = "authenticatedUserToken", default)]
    pub authenticated_user_token: Option<String>,
    #[serde(rename = "objectData", default, deserialize_with = "null_as_default")]
    pub object_data: Vec<serde_json::Value>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub timestamp: Option<i64>,
    #[serde(rename = "algoliaSource", default)]
    pub algolia_source: Option<Vec<String>>,
}

/// One raw `/1/events` entry. `received_at` is `Option<DateTime<Utc>>`
/// (not a bare `DateTime<Utc>`) for the same null-tolerance reason as every
/// `MetricPoint` field — this is the field the buffer-turnover/window math
/// in `commands::events` depends on, so a single malformed timestamp must
/// drop out of the window computation, never panic the process. Every
/// collection/map field below (`headers`, `errors`) also pairs
/// `#[serde(default)]` with `deserialize_with = "null_as_default"` — a bare
/// `#[serde(default)]` only substitutes for an ABSENT key, not an explicit
/// `null` (BUG-ALX-EVENTS-NULLCOLL; see `serde_util::null_as_default`).
///
/// Deserializing a SINGLE `RawEvent` can still fail outright (e.g. a
/// genuinely wrong-shaped value where an array/map was expected, not a
/// null-vs-absent ambiguity) — that failure never fails this whole struct's
/// callers, though: `parse_events_response` walks the raw `events` array
/// entry-by-entry and drops only the offending entry (counted in
/// `ParsedEvents::skipped_count`), never the whole ~3,000-event batch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawEvent {
    #[serde(rename = "requestID", default)]
    pub request_id: Option<String>,
    #[serde(rename = "receivedAt", default)]
    pub received_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub headers: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub event: Option<EventPayload>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub errors: Vec<String>,
}

/// Result of a per-event-resilient parse of `/1/events`: `events` is every
/// entry that deserialized cleanly; `skipped_count` is how many raw entries
/// in the response's `events` array failed to deserialize and were dropped
/// rather than aborting the whole fetch. `commands::events` surfaces
/// `skipped_count` in every `sample`/`errors` response so a dropped entry
/// can never be silent (this repo's "no silent failures" discipline).
#[derive(Debug, Clone, Default)]
pub struct ParsedEvents {
    pub events: Vec<RawEvent>,
    pub skipped_count: usize,
}

/// Pure parse, split out for the same synthetic-JSON testability reason as
/// `parse_metrics_response`. PER-EVENT resilient, unlike
/// `parse_metrics_response`/`GetMetricsResponse`: the top-level `events`
/// array is walked entry-by-entry rather than deserialized in one
/// `serde_json::from_value` call, so one malformed event (any shape
/// `RawEvent`'s null-tolerant fields still can't rescue) drops out of the
/// batch — counted in `ParsedEvents::skipped_count` — instead of failing the
/// entire ~3,000-event fetch (the bug this function used to have: a single
/// bad field on a single event aborted the whole response). The `events`
/// key itself being absent or explicitly `null` still means "zero events",
/// matching the old `#[serde(default)]` envelope behavior; `events` present
/// but not an array at all (a genuinely wrong-shaped response, not a
/// null-vs-absent ambiguity) is still a hard parse error.
pub fn parse_events_response(value: &serde_json::Value) -> AppResult<ParsedEvents> {
    let events_value = match value.get("events") {
        None | Some(serde_json::Value::Null) => return Ok(ParsedEvents::default()),
        Some(v) => v,
    };
    let arr = events_value.as_array().ok_or_else(|| {
        AppError::Other(format!(
            "failed to parse /1/events response: 'events' field is not an array (got {events_value})"
        ))
    })?;

    let mut events = Vec::with_capacity(arr.len());
    let mut skipped_count = 0usize;
    for item in arr {
        match serde_json::from_value::<RawEvent>(item.clone()) {
            Ok(e) => events.push(e),
            Err(_) => skipped_count += 1,
        }
    }
    Ok(ParsedEvents {
        events,
        skipped_count,
    })
}

/// `GET /1/events` — Events -> Debugger. `offset`/`page`/`length` are
/// deliberately NEVER sent (verified live 2026-08-04: all three return 0
/// events) — same discipline as `logs::fetch_logs_from_host` never sending
/// `indexName`. `limit`, when `Some`, only truncates the rolling
/// ~`BUFFER_CAP_APPROX`-event buffer; it cannot page through it.
pub async fn fetch_events(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    since_minutes: i64,
    limit: Option<u32>,
) -> AppResult<ParsedEvents> {
    let (start, end) = date_window(since_minutes);
    let mut url = format!(
        "{}/1/events?startDate={start}&endDate={end}",
        ctx.base_urls.insights(region)
    );
    if let Some(l) = limit {
        url.push_str(&format!("&limit={l}"));
    }
    let value = http::get_json(&ctx.client, &url, app_id, key, Surface::Insights, &ctx.ops).await?;
    parse_events_response(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algolia::keys::TEST_ENV_MUTEX;
    use crate::context::BaseUrls;
    use crate::http::SessionOps;
    use crate::output::Presenter;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn base_urls_for(mock_uri: &str) -> BaseUrls {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        std::env::set_var("ALX_INSIGHTS_BASE_URL", mock_uri);
        let b = BaseUrls::from_env();
        std::env::remove_var("ALX_INSIGHTS_BASE_URL");
        b
    }

    fn test_ctx(mock_uri: &str) -> AppContext {
        AppContext {
            client: reqwest::Client::new(),
            presenter: Presenter::new(false, false, false, false, None),
            app_id: Some("testapp".to_string()),
            key_override: Some("testkey".to_string()),
            i_know: false,
            ops: SessionOps::new(),
            base_urls: base_urls_for(mock_uri),
        }
    }

    // ---- granularity=week client-side rejection --------------------------

    #[test]
    fn week_granularity_rejected_client_side() {
        let err = validate_metrics_granularity("week").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(err.to_string().contains("week"));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn hour_and_day_granularity_accepted() {
        assert!(validate_metrics_granularity("hour").is_ok());
        assert!(validate_metrics_granularity("day").is_ok());
    }

    #[test]
    fn events_granularity_str_matches_api_vocabulary() {
        assert_eq!(events_granularity_str(EventsGranularity::Hour), "hour");
        assert_eq!(events_granularity_str(EventsGranularity::Day), "day");
    }

    #[tokio::test]
    async fn fetch_metrics_rejects_week_before_any_http_call() {
        // No mock mounted at all — if the preflight didn't run before the
        // HTTP call, wiremock's default "no matching mock" 500 would
        // surface as a *different* error kind than InvalidInput.
        let mock_server = MockServer::start().await;
        let ctx = test_ctx(&mock_server.uri());
        let err = fetch_metrics(&ctx, "testapp", "testkey", "de", 60, "week", true)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert_eq!(ctx.ops.snapshot().insights_calls, 0);
    }

    // ---- date_window -------------------------------------------------

    #[test]
    fn date_window_emits_full_iso8601_instant_not_date_only() {
        let (start, end) = date_window(30);
        for value in [&start, &end] {
            assert!(
                value.ends_with('Z') && value.contains('T') && value.len() == 20,
                "insights API needs a full ISO-8601 instant, got {value}"
            );
        }
    }

    #[test]
    fn date_window_spans_requested_minutes() {
        let (start, end) = date_window(10);
        let start_t = chrono::NaiveDateTime::parse_from_str(&start, "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let end_t = chrono::NaiveDateTime::parse_from_str(&end, "%Y-%m-%dT%H:%M:%SZ").unwrap();
        assert_eq!((end_t - start_t).num_minutes(), 10);
    }

    #[test]
    fn date_window_clamps_negative_minutes_to_zero_width() {
        let (start, end) = date_window(-5);
        assert_eq!(start, end);
    }

    // ---- /1/metrics null-tolerance -------------------------------------

    #[test]
    fn parse_metrics_response_tolerates_nulls_on_every_field() {
        // A low/no-data bucket — mirrors the /2/status `updatedAt: null`
        // bug (analytics.rs) that crashed the app last week: every field
        // here must round-trip to `None`, never fail to parse or panic.
        let v = json!({
            "metrics": [{
                "timestamp": null,
                "eventCount": null,
                "clickCount": null,
                "viewCount": null,
                "conversionCount": null,
                "errorCount": null,
                "errorRate": null,
                "neuralSearchCount": null,
                "neuralSearchRate": null,
                "recommendFrequentlyBoughtTogetherCount": null,
                "recommendFrequentlyBoughtTogetherRate": null,
                "recommendRelatedProductsCount": null,
                "recommendRelatedProductsRate": null,
                "recommendTrendingItemsCount": null,
                "recommendTrendingItemsRate": null,
                "recommendTrendingFacetValuesCount": null,
                "recommendTrendingFacetValuesRate": null
            }]
        });
        let parsed = parse_metrics_response(&v).unwrap();
        assert_eq!(parsed.len(), 1);
        let p = &parsed[0];
        assert_eq!(p.timestamp, None);
        assert_eq!(p.event_count, None);
        assert_eq!(p.error_count, None);
        assert_eq!(p.error_rate, None);
        assert_eq!(p.recommend_trending_facet_values_rate, None);
    }

    #[test]
    fn parse_metrics_response_tolerates_entirely_missing_fields() {
        // Fields absent from the wire entirely (not even present as
        // `null`) must ALSO parse cleanly, per `#[serde(default)]` on
        // every field.
        let v = json!({ "metrics": [{}] });
        let parsed = parse_metrics_response(&v).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].event_count, None);
    }

    #[test]
    fn parse_metrics_response_real_shape() {
        let v = json!({
            "metrics": [{
                "timestamp": "2026-08-03T00:00:00Z",
                "eventCount": 1000000,
                "clickCount": 90000,
                "viewCount": 850000,
                "conversionCount": 60000,
                "errorCount": 137,
                "errorRate": 0.000137
            }]
        });
        let parsed = parse_metrics_response(&v).unwrap();
        assert_eq!(parsed[0].event_count, Some(1000000));
        assert_eq!(parsed[0].view_count, Some(850000));
        assert_eq!(parsed[0].click_count, Some(90000));
        assert_eq!(parsed[0].conversion_count, Some(60000));
        assert_eq!(parsed[0].error_count, Some(137));
    }

    #[test]
    fn parse_metrics_response_missing_metrics_key_defaults_to_empty() {
        let v = json!({});
        let parsed = parse_metrics_response(&v).unwrap();
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn fetch_metrics_sends_expected_params_and_increments_insights_calls() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/metrics"))
            .and(query_param("granularity", "hour"))
            .and(query_param("approximate", "true"))
            .and(wiremock::matchers::header(
                "X-Algolia-Application-Id",
                "testapp",
            ))
            .and(wiremock::matchers::header("X-Algolia-API-Key", "testkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "metrics": [{"timestamp": "2026-08-03T00:00:00Z", "eventCount": 100}]
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let metrics = fetch_metrics(&ctx, "testapp", "testkey", "de", 60, "hour", true)
            .await
            .unwrap();

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].event_count, Some(100));
        assert_eq!(ctx.ops.snapshot().insights_calls, 1);
    }

    // ---- /1/events -----------------------------------------------------

    #[test]
    fn parse_events_response_real_shape() {
        let v = json!({
            "events": [{
                "requestID": "abc123",
                "receivedAt": "2026-08-04T08:29:00.000Z",
                "path": "/1/events",
                "headers": {
                    "User-Agent": ["Mozilla/5.0"],
                    "X-Algolia-Agent": ["Algolia for JavaScript"]
                },
                "status": 200,
                "errors": [],
                "event": {
                    "eventName": "Product Clicked",
                    "eventType": "click",
                    "eventSubtype": "click",
                    "index": "Product",
                    "objectIDs": ["obj1"],
                    "positions": [3],
                    "queryID": "q1",
                    "userToken": "anonymous-1234",
                    "algoliaSource": ["instantsearch", "instantsearch-internal"]
                }
            }]
        });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.skipped_count, 0);
        let e = &parsed.events[0];
        assert_eq!(e.status, Some(200));
        assert!(e.errors.is_empty());
        let payload = e.event.as_ref().unwrap();
        assert_eq!(payload.event_name.as_deref(), Some("Product Clicked"));
        assert_eq!(
            payload.algolia_source.as_ref().unwrap(),
            &vec![
                "instantsearch".to_string(),
                "instantsearch-internal".to_string()
            ]
        );
        assert!(e.headers.contains_key("User-Agent"));
    }

    #[test]
    fn parse_events_response_error_shape_with_no_algolia_source() {
        // Server-side/hand-rolled emitter: algoliaSource absent entirely —
        // must round-trip to `None`, never an empty vec (the two are
        // distinct signals for `commands::events::algolia_source_key`).
        let v = json!({
            "events": [{
                "requestID": "err1",
                "receivedAt": "2026-08-04T08:30:00.000Z",
                "status": 422,
                "errors": ["The filters should be facet filters"],
                "event": {
                    "eventName": "Filter Applied",
                    "eventType": "click",
                    "userToken": "usr-99"
                }
            }]
        });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.skipped_count, 0);
        let e = &parsed.events[0];
        assert_eq!(e.status, Some(422));
        assert_eq!(
            e.errors,
            vec!["The filters should be facet filters".to_string()]
        );
        assert_eq!(e.event.as_ref().unwrap().algolia_source, None);
    }

    #[test]
    fn parse_events_response_tolerates_entirely_missing_fields() {
        let v = json!({ "events": [{}] });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.skipped_count, 0);
        assert_eq!(parsed.events[0].received_at, None);
        assert!(parsed.events[0].event.is_none());
        assert!(parsed.events[0].errors.is_empty());
    }

    #[test]
    fn parse_events_response_missing_events_key_defaults_to_empty() {
        let v = json!({});
        let parsed = parse_events_response(&v).unwrap();
        assert!(parsed.events.is_empty());
        assert_eq!(parsed.skipped_count, 0);
    }

    #[test]
    fn parse_events_response_null_events_key_defaults_to_empty() {
        // Same envelope-level null-tolerance as `GetMetricsResponse.metrics`
        // — an explicit `"events": null` (not just an absent key) must
        // still parse cleanly as zero events, never error.
        let v = json!({ "events": null });
        let parsed = parse_events_response(&v).unwrap();
        assert!(parsed.events.is_empty());
        assert_eq!(parsed.skipped_count, 0);
    }

    #[test]
    fn parse_events_response_wrong_shaped_events_field_is_a_hard_error() {
        // `events` present but not an array at all — a genuine parse
        // failure, NOT a null-vs-absent ambiguity `null_as_default` should
        // paper over.
        let v = json!({ "events": "not an array" });
        assert!(parse_events_response(&v).is_err());
    }

    // ---- BUG-ALX-EVENTS-NULLCOLL: every collection/map field on RawEvent/
    // EventPayload must tolerate an explicit `null`, not just an absent key
    // -----------------------------------------------------------------

    #[test]
    fn parse_events_response_tolerates_null_headers_and_errors() {
        let v = json!({
            "events": [{
                "requestID": "r1",
                "status": 200,
                "headers": null,
                "errors": null
            }]
        });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.skipped_count, 0);
        let e = &parsed.events[0];
        assert!(e.headers.is_empty());
        assert!(e.errors.is_empty());
    }

    #[test]
    fn parse_events_response_tolerates_null_object_ids_positions_object_data() {
        let v = json!({
            "events": [{
                "requestID": "r1",
                "status": 200,
                "event": {
                    "objectIDs": null,
                    "positions": null,
                    "objectData": null
                }
            }]
        });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.skipped_count, 0);
        let payload = parsed.events[0].event.as_ref().unwrap();
        assert!(payload.object_ids.is_empty());
        assert!(payload.positions.is_empty());
        assert!(payload.object_data.is_empty());
    }

    #[test]
    fn parse_metrics_response_tolerates_null_metrics_envelope() {
        let v = json!({ "metrics": null });
        let parsed = parse_metrics_response(&v).unwrap();
        assert!(parsed.is_empty());
    }

    // ---- per-event resilience: one malformed entry must never abort the
    // whole batch (this is a real, previously fixed bug: a single bad field
    // on a single event used to fail the entire ~3,000-event fetch) ------

    #[test]
    fn parse_events_response_mixed_batch_skips_only_the_malformed_entry() {
        let v = json!({
            "events": [
                {"requestID": "good-1", "status": 200, "errors": []},
                // `status` wrong-shaped (object instead of a u16) — this
                // single entry must be dropped, not abort the batch.
                {"requestID": "bad-1", "status": {"nested": "garbage"}},
                {"requestID": "good-2", "status": 200, "errors": []},
            ]
        });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.skipped_count, 1, "exactly one malformed entry");
        assert_eq!(parsed.events.len(), 2, "both good entries must survive");
        let ids: Vec<&str> = parsed
            .events
            .iter()
            .filter_map(|e| e.request_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["good-1", "good-2"]);
    }

    #[test]
    fn parse_events_response_all_malformed_returns_ok_with_full_skip_count() {
        let v = json!({
            "events": [
                {"status": "not-a-number"},
                {"status": ["also", "not", "a", "number"]},
            ]
        });
        let parsed = parse_events_response(&v).unwrap();
        assert_eq!(parsed.skipped_count, 2);
        assert!(parsed.events.is_empty());
    }

    #[tokio::test]
    async fn fetch_events_never_sends_offset_page_or_length() {
        // Verified live 2026-08-04: all three return 0 events — this
        // codebase never sends them (L1-style discipline, mirroring
        // `logs::fetch_logs_from_host` never sending `indexName`).
        let mock_server = MockServer::start().await;
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let received_clone = received.clone();
        Mock::given(method("GET"))
            .and(path("/1/events"))
            .respond_with(move |req: &wiremock::Request| {
                received_clone
                    .lock()
                    .unwrap()
                    .push(req.url.query().unwrap_or_default().to_string());
                ResponseTemplate::new(200).set_body_json(json!({"events": []}))
            })
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        fetch_events(&ctx, "testapp", "testkey", "de", 10, Some(10))
            .await
            .unwrap();

        let queries = received.lock().unwrap();
        let q = &queries[0];
        assert!(q.contains("limit=10"));
        assert!(!q.contains("offset="));
        assert!(!q.contains("page="));
        assert!(!q.contains("length="));
    }

    #[tokio::test]
    async fn fetch_events_omits_limit_param_when_none() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": []})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let parsed = fetch_events(&ctx, "testapp", "testkey", "de", 10, None)
            .await
            .unwrap();
        assert!(parsed.events.is_empty());
        assert_eq!(parsed.skipped_count, 0);
        assert_eq!(ctx.ops.snapshot().insights_calls, 1);
    }

    #[tokio::test]
    async fn fetch_events_limit_10_returns_10_events() {
        // Measured contract: `limit=10 -> 10 events`.
        let mock_server = MockServer::start().await;
        let events: Vec<serde_json::Value> = (0..10)
            .map(|i| {
                json!({"requestID": format!("r{i}"), "receivedAt": "2026-08-04T08:00:00.000Z", "status": 200, "errors": []})
            })
            .collect();
        Mock::given(method("GET"))
            .and(path("/1/events"))
            .and(query_param("limit", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": events})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let fetched = fetch_events(&ctx, "testapp", "testkey", "de", 10, Some(10))
            .await
            .unwrap();
        assert_eq!(fetched.events.len(), 10);
        assert_eq!(fetched.skipped_count, 0);
    }

    // ---- ~3,000-event buffer cap: fetch layer never lies about it ------

    #[tokio::test]
    async fn fetch_events_near_cap_returns_all_fetched_entries_unfiltered() {
        // The fetch layer itself does not decide "truncated" — it just
        // returns what the API gave back; `commands::events` is the layer
        // that flags near-cap fetches. This pins that `fetch_events` does
        // not silently drop or cap anything on its own.
        let mock_server = MockServer::start().await;
        let events: Vec<serde_json::Value> = (0..BUFFER_CAP_APPROX)
            .map(|i| json!({"requestID": format!("r{i}"), "status": 200, "errors": []}))
            .collect();
        Mock::given(method("GET"))
            .and(path("/1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": events})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let fetched = fetch_events(&ctx, "testapp", "testkey", "de", 30 * 24 * 60, None)
            .await
            .unwrap();
        assert_eq!(fetched.events.len(), BUFFER_CAP_APPROX);
        assert_eq!(fetched.skipped_count, 0);
    }

    #[tokio::test]
    async fn fetch_events_mixed_batch_over_http_reports_skipped_count() {
        // End-to-end (through `fetch_events`, not just `parse_events_
        // response` directly): a malformed entry mixed into a real HTTP
        // response must still surface as a skip, not a fetch-level error.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "events": [
                    {"requestID": "good", "status": 200, "errors": []},
                    {"requestID": "bad", "status": "not-a-number"}
                ]
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let fetched = fetch_events(&ctx, "testapp", "testkey", "de", 10, None)
            .await
            .unwrap();
        assert_eq!(fetched.events.len(), 1);
        assert_eq!(fetched.skipped_count, 1);
    }
}
