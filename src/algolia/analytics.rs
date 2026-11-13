//! Search Analytics API (D9) — GET `https://analytics.{region}.algolia.com`.
//! Endpoints: `/2/searches` (top searches), `/2/searches/noResults`,
//! `/2/searches/noResultRate`, `/2/clicks/clickThroughRate`,
//! `/2/clicks/averageClickPosition`, `/2/clicks/positions`,
//! `/2/conversions/conversionRate`, `/2/conversions/addToCartRate`,
//! `/2/conversions/purchaseRate`, `/2/conversions/revenue`, and `/2/status`
//! (data-freshness timestamp — required on every call including this one,
//! per the "every Search Analytics endpoint requires `index`" gotcha). Rate
//! limit: 100 requests/minute per application (A1) — every fetch in this
//! module first waits on a shared [`Throttle`] gate enforcing a minimum
//! spacing between analytics calls, so a command that fires several
//! requests in a row (e.g. `no-results`'s list + overall-rate pair, or
//! `clicks`'s four-call fan-in) never bursts past the limit.
//!
//! Region handling (D9): Algolia does not disambiguate
//! "index not found" from "wrong region" — both return a bare 404. A 404
//! from any endpoint here is rewritten with a suggestion to retry against
//! the other region (`with_region_suggestion`).

use super::serde_util::null_as_default;
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::{self, Surface};
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A1: minimum interval enforced between analytics HTTP calls in production.
/// 100 requests/minute allows an average of 600ms/request; staying at that
/// floor keeps a multi-call command (e.g. `no-results`) comfortably under
/// the cap even with jitter.
pub const THROTTLE_INTERVAL: Duration = Duration::from_millis(600);

/// Max `limit` the `/2/searches*` endpoints accept (Analytics API reference).
const MAX_PAGE_LIMIT: u32 = 1000;

/// A1: shared async gate enforcing a minimum interval between analytics
/// calls. Reservation-based so concurrent callers still serialize correctly
/// (each `wait()` books the next free slot under the lock, then only that
/// caller's own remaining delta is actually slept) — tests inject a tiny
/// `interval` so they assert ordering/serialization, never real wall-clock
/// time.
#[derive(Debug)]
pub struct Throttle {
    interval: Duration,
    next_slot: Mutex<Option<Instant>>,
}

impl Throttle {
    pub fn new(interval: Duration) -> Self {
        Throttle {
            interval,
            next_slot: Mutex::new(None),
        }
    }

    /// Production throttle: >=600ms between calls (A1).
    pub fn production() -> Self {
        Self::new(THROTTLE_INTERVAL)
    }

    /// Reserve the next slot: returns the slot's start instant and how long
    /// from now the caller must wait for it. Pure bookkeeping (no sleeping),
    /// so tests can assert the slot spacing deterministically instead of
    /// measuring scheduler-dependent wake-up times.
    fn reserve(&self) -> (Instant, Duration) {
        let mut slot = self.next_slot.lock().expect("throttle mutex poisoned");
        let now = Instant::now();
        let target = match *slot {
            Some(prev) if prev > now => prev,
            _ => now,
        };
        *slot = Some(target + self.interval);
        (target, target.saturating_duration_since(now))
    }

    /// Reserve the next slot and sleep only the caller's own remaining
    /// delta. The lock is released before the actual sleep, so it never
    /// blocks other tasks' bookkeeping while this one waits.
    pub async fn wait(&self) {
        let (_, sleep_for) = self.reserve();
        if !sleep_for.is_zero() {
            tokio::time::sleep(sleep_for).await;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopSearchRow {
    pub search: String,
    pub count: u64,
    #[serde(rename = "nbHits", default)]
    pub nb_hits: u64,
}

#[derive(Debug, Deserialize)]
struct TopSearchesResponse {
    // BUG-ALX-ANALYTICS-NULLCOLL: confirmed live 2026-08-04 — a no-data
    // region ("us" region on this app) returns `{"searches": null}`, not an
    // absent key. `#[serde(default)]` alone only substitutes for the
    // latter; see `serde_util::null_as_default`.
    #[serde(default, deserialize_with = "null_as_default")]
    searches: Vec<TopSearchRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoResultRow {
    pub search: String,
    pub count: u64,
    #[serde(rename = "withFilterCount", default)]
    pub with_filter_count: u64,
}

#[derive(Debug, Deserialize)]
struct NoResultsResponse {
    // BUG-ALX-ANALYTICS-NULLCOLL: same confirmed-live null shape as
    // `TopSearchesResponse.searches` above.
    #[serde(default, deserialize_with = "null_as_default")]
    searches: Vec<NoResultRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoResultRateDay {
    pub date: String,
    pub rate: Option<f64>,
    pub count: u64,
    #[serde(rename = "noResultCount")]
    pub no_result_count: u64,
}

/// `GET /2/searches/noResultRate` response. `rate` is `null` (-> `None`)
/// when there were zero searches in the window — never coerced to `0.0`,
/// which would silently claim "0% no-result rate" instead of "no data".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoResultRateResponse {
    pub rate: Option<f64>,
    pub count: u64,
    #[serde(rename = "noResultCount")]
    pub no_result_count: u64,
    // BUG-ALX-ANALYTICS-NULLCOLL: same "zero-searches window" condition that
    // nulls `rate` (see doc comment above) is exactly the condition a
    // no-data region/window could plausibly also null `dates` under —
    // defensive fix per the confirmed `searches`/`updatedAt` precedent, not
    // (yet) independently reproduced live for this specific field.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dates: Vec<NoResultRateDay>,
}

/// Pure parse of a `/2/searches/noResultRate` payload — split out from the
/// fetch so it's testable against synthetic JSON (including `rate: null`)
/// without a network call.
pub fn parse_no_result_rate(value: &serde_json::Value) -> AppResult<NoResultRateResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse noResultRate response: {e}")))
}

// =========================================================================
// clicks (D9 retirement of the "no analytics click/conversion endpoints"
// v0.1 non-goal): `/2/clicks/clickThroughRate`, `/2/clicks/
// averageClickPosition`, `/2/clicks/positions`.
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickThroughRateDay {
    pub date: String,
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "clickCount")]
    pub click_count: u64,
}

/// `GET /2/clicks/clickThroughRate` response. `rate` is `Option<f64>` for
/// the same null-vs-zero reason as `NoResultRateResponse::rate` — the
/// clicks/conversions endpoints share the same "`null` when there were zero
/// tracked searches in the window" convention, never coerced to `0.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickThroughRateResponse {
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "clickCount")]
    pub click_count: u64,
    // BUG-ALX-ANALYTICS-NULLCOLL: defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dates: Vec<ClickThroughRateDay>,
}

pub fn parse_click_through_rate(value: &serde_json::Value) -> AppResult<ClickThroughRateResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse clickThroughRate response: {e}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AverageClickPositionDay {
    pub date: String,
    pub average: Option<f64>,
    #[serde(rename = "clickCount")]
    pub click_count: u64,
}

/// `GET /2/clicks/averageClickPosition` response. Note this shape carries no
/// `trackedSearchCount` (unlike `clickThroughRate`) — only `average` +
/// `clickCount`, so it is a distinct struct rather than a reuse of
/// `ClickThroughRateResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AverageClickPositionResponse {
    pub average: Option<f64>,
    #[serde(rename = "clickCount")]
    pub click_count: u64,
    // BUG-ALX-ANALYTICS-NULLCOLL: defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dates: Vec<AverageClickPositionDay>,
}

pub fn parse_average_click_position(
    value: &serde_json::Value,
) -> AppResult<AverageClickPositionResponse> {
    serde_json::from_value(value.clone()).map_err(|e| {
        AppError::Other(format!(
            "failed to parse averageClickPosition response: {e}"
        ))
    })
}

/// `GET /2/clicks/positions` histogram bucket. `position` is the raw
/// `[start, end]` inclusive range Algolia returns (e.g. `[1, 1]`, `[11,
/// 20]`, `[21, -1]`) — kept as a two-element tuple rather than split into
/// named fields, since the sentinel `end == -1` ("unbounded / 21+") is
/// exactly what callers need to detect and a named-field split would hide
/// that shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickPositionBucket {
    pub position: (i64, i64),
    #[serde(rename = "clickCount")]
    pub click_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickPositionsResponse {
    // BUG-ALX-ANALYTICS-NULLCOLL: defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub positions: Vec<ClickPositionBucket>,
}

pub fn parse_click_positions(value: &serde_json::Value) -> AppResult<ClickPositionsResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse positions response: {e}")))
}

// =========================================================================
// conversions: `/2/conversions/conversionRate`, `/2/conversions/
// addToCartRate`, `/2/conversions/purchaseRate`, `/2/conversions/revenue`.
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionRateDay {
    pub date: String,
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "conversionCount")]
    pub conversion_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionRateResponse {
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "conversionCount")]
    pub conversion_count: u64,
    // BUG-ALX-ANALYTICS-NULLCOLL: defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dates: Vec<ConversionRateDay>,
}

pub fn parse_conversion_rate(value: &serde_json::Value) -> AppResult<ConversionRateResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse conversionRate response: {e}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddToCartRateDay {
    pub date: String,
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "addToCartCount")]
    pub add_to_cart_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddToCartRateResponse {
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "addToCartCount")]
    pub add_to_cart_count: u64,
    // BUG-ALX-ANALYTICS-NULLCOLL: defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dates: Vec<AddToCartRateDay>,
}

pub fn parse_add_to_cart_rate(value: &serde_json::Value) -> AppResult<AddToCartRateResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse addToCartRate response: {e}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseRateDay {
    pub date: String,
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "purchaseCount")]
    pub purchase_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseRateResponse {
    pub rate: Option<f64>,
    #[serde(rename = "trackedSearchCount")]
    pub tracked_search_count: u64,
    #[serde(rename = "purchaseCount")]
    pub purchase_count: u64,
    // BUG-ALX-ANALYTICS-NULLCOLL: defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dates: Vec<PurchaseRateDay>,
}

pub fn parse_purchase_rate(value: &serde_json::Value) -> AppResult<PurchaseRateResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse purchaseRate response: {e}")))
}

/// Per-currency revenue row inside `/2/conversions/revenue`'s `currencies`
/// map. Never assume EUR (a non-negotiable design rule) — this struct
/// carries its own `currency` field precisely so a caller renders whichever
/// currencies the API actually returned, rather than hardcoding a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrencyRevenue {
    pub currency: String,
    pub revenue: f64,
    #[serde(rename = "averageOrderValue")]
    pub average_order_value: f64,
    #[serde(rename = "transactionCount")]
    pub transaction_count: u64,
}

/// `GET /2/conversions/revenue` response. Only the top-level `currencies`
/// map is modeled — the per-day `dates[].currencies` breakdown in the real
/// payload is intentionally left unparsed (serde ignores unknown fields by
/// default; no `deny_unknown_fields` here), since no command surfaces daily
/// revenue granularity. `BTreeMap` (not `HashMap`) so currency rows render
/// in a stable, deterministic order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueResponse {
    // BUG-ALX-ANALYTICS-NULLCOLL: map fields need the same treatment as
    // array fields — defensive fix, same rationale as
    // `NoResultRateResponse.dates`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub currencies: std::collections::BTreeMap<String, CurrencyRevenue>,
}

pub fn parse_revenue(value: &serde_json::Value) -> AppResult<RevenueResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse revenue response: {e}")))
}

/// `GET /2/status` — data-freshness timestamp. Required reading before
/// trusting any other analytics number: a post-deploy re-measurement is
/// worthless if `updatedAt` predates the deploy, since Algolia's analytics
/// pipeline lags live traffic. Every `alx analytics clicks|conversions|
/// revenue` response surfaces this.
///
/// `updated_at` is `Option<String>` for the same null-vs-absent reason as
/// every `rate`/`average` field elsewhere in this module: Algolia returns
/// `{"updatedAt": null}` (HTTP 200, not an error) for a region/index
/// combination with no analytics data yet — confirmed live 2026-08-04
/// against the `us` region, which has none. Coercing that to an empty
/// string or panicking would either lie about freshness or crash a command
/// that has nothing else wrong with it; `None` lets every call site render
/// an honest "no data yet" instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsStatusResponse {
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
}

pub fn parse_status(value: &serde_json::Value) -> AppResult<AnalyticsStatusResponse> {
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::Other(format!("failed to parse status response: {e}")))
}

/// `[start, end]` inclusive `YYYY-MM-DD` window ending today, `since_days`
/// wide (D9 `startDate`/`endDate`).
pub fn date_window(since_days: i64) -> (String, String) {
    let end = Utc::now().date_naive();
    let start = end - ChronoDuration::days(since_days.max(0));
    (
        start.format("%Y-%m-%d").to_string(),
        end.format("%Y-%m-%d").to_string(),
    )
}

/// D9: a 404 from an analytics endpoint is ambiguous — Algolia does not
/// disambiguate "index not found" from "wrong region". Rewrite it with a suggestion to retry against the other region,
/// leaving every other error variant/status untouched.
pub fn with_region_suggestion(err: AppError, region: &str) -> AppError {
    match err {
        AppError::Api {
            status,
            message,
            suggestion: None,
        } if status == 404 => {
            let other = other_region(region);
            AppError::Api {
                status,
                message,
                suggestion: Some(format!(
                    "index not found on region '{region}' — Algolia does not distinguish a wrong-region 404 from a missing index; try --region {other}"
                )),
            }
        }
        other => other,
    }
}

fn other_region(region: &str) -> &'static str {
    match region {
        "de" => "us",
        "us" => "de",
        _ => "de",
    }
}

/// Percent-encode a single query-param value. No `url`/`urlencoding` crate
/// is available (D2) — this is the same minimal RFC 3986 unreserved-set
/// encoder pattern used by `algolia::keys::percent_encode_path_segment`.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn build_url(base: &str, path: &str, params: &[(&str, String)]) -> String {
    let query: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", url_encode(v)))
        .collect();
    format!("{base}{path}?{}", query.join("&"))
}

/// Throttle, fetch, and rewrite region-shaped errors — the one place every
/// public fetcher in this module funnels through, so the gate and the 404
/// handling can't be forgotten at a call site (centralize URL+status
/// handling instead of repeating it).
async fn fetch(
    ctx: &AppContext,
    url: &str,
    app_id: &str,
    key: &str,
    region: &str,
    throttle: &Throttle,
) -> AppResult<serde_json::Value> {
    throttle.wait().await;
    http::get_json(&ctx.client, url, app_id, key, Surface::Analytics, &ctx.ops)
        .await
        .map_err(|e| with_region_suggestion(e, region))
}

/// `GET /2/searches` — top searches for the window (D9).
#[allow(clippy::too_many_arguments)]
pub async fn top_searches(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    limit: Option<u32>,
    offset: Option<u32>,
    throttle: &Throttle,
) -> AppResult<Vec<TopSearchRow>> {
    let (start_date, end_date) = date_window(since_days);
    let mut params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    if let Some(l) = limit {
        params.push(("limit", l.min(MAX_PAGE_LIMIT).to_string()));
    }
    if let Some(o) = offset {
        params.push(("offset", o.to_string()));
    }
    let url = build_url(&ctx.base_urls.analytics(region), "/2/searches", &params);

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    let parsed: TopSearchesResponse = serde_json::from_value(value)
        .map_err(|e| AppError::Other(format!("failed to parse top-searches response: {e}")))?;
    Ok(parsed.searches)
}

/// `GET /2/searches/noResults` — zero-result searches for the window (D9).
#[allow(clippy::too_many_arguments)]
pub async fn no_results(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    limit: Option<u32>,
    offset: Option<u32>,
    throttle: &Throttle,
) -> AppResult<Vec<NoResultRow>> {
    let (start_date, end_date) = date_window(since_days);
    let mut params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    if let Some(l) = limit {
        params.push(("limit", l.min(MAX_PAGE_LIMIT).to_string()));
    }
    if let Some(o) = offset {
        params.push(("offset", o.to_string()));
    }
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/searches/noResults",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    let parsed: NoResultsResponse = serde_json::from_value(value)
        .map_err(|e| AppError::Other(format!("failed to parse no-results response: {e}")))?;
    Ok(parsed.searches)
}

/// `GET /2/searches/noResultRate` — overall no-result rate for the window
/// (D9). Always fetched alongside `no_results` so `alx analytics
/// no-results` never reports only the raw list without the headline rate.
pub async fn no_result_rate(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<NoResultRateResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/searches/noResultRate",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_no_result_rate(&value)
}

/// `GET /2/clicks/clickThroughRate` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn click_through_rate(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<ClickThroughRateResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/clicks/clickThroughRate",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_click_through_rate(&value)
}

/// `GET /2/clicks/averageClickPosition` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn average_click_position(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<AverageClickPositionResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/clicks/averageClickPosition",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_average_click_position(&value)
}

/// `GET /2/clicks/positions` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn click_positions(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<ClickPositionsResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/clicks/positions",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_click_positions(&value)
}

/// `GET /2/conversions/conversionRate` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn conversion_rate(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<ConversionRateResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/conversions/conversionRate",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_conversion_rate(&value)
}

/// `GET /2/conversions/addToCartRate` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn add_to_cart_rate(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<AddToCartRateResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/conversions/addToCartRate",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_add_to_cart_rate(&value)
}

/// `GET /2/conversions/purchaseRate` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn purchase_rate(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<PurchaseRateResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/conversions/purchaseRate",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_purchase_rate(&value)
}

/// `GET /2/conversions/revenue` (D9).
#[allow(clippy::too_many_arguments)]
pub async fn revenue(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<RevenueResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(
        &ctx.base_urls.analytics(region),
        "/2/conversions/revenue",
        &params,
    );

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_revenue(&value)
}

/// `GET /2/status` — data freshness (D9). `index` is required by Algolia on
/// this endpoint too (see the CLAUDE.md gotcha: omitting it 422s with
/// "Index is required"), even though the timestamp it returns isn't
/// per-index in any meaningful sense.
#[allow(clippy::too_many_arguments)]
pub async fn status(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    region: &str,
    index: &str,
    since_days: i64,
    throttle: &Throttle,
) -> AppResult<AnalyticsStatusResponse> {
    let (start_date, end_date) = date_window(since_days);
    let params = vec![
        ("index", index.to_string()),
        ("startDate", start_date),
        ("endDate", end_date),
    ];
    let url = build_url(&ctx.base_urls.analytics(region), "/2/status", &params);

    let value = fetch(ctx, &url, app_id, key, region, throttle).await?;
    parse_status(&value)
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
        std::env::set_var("ALX_ANALYTICS_BASE_URL", mock_uri);
        let b = BaseUrls::from_env();
        std::env::remove_var("ALX_ANALYTICS_BASE_URL");
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

    // ---- A1: throttle serializes calls -----------------------------------

    #[test]
    fn a1_throttle_serializes_calls() {
        // Slot bookkeeping is asserted directly (no sleeping, no wake-up
        // timing), so the result cannot depend on machine load. The
        // interval is far longer than the test runs, so every reservation
        // after the first is necessarily queued behind its predecessor.
        let interval = Duration::from_secs(60);
        let throttle = Throttle::new(interval);
        let slots: Vec<Instant> = (0..5).map(|_| throttle.reserve().0).collect();
        for pair in slots.windows(2) {
            assert_eq!(
                pair[1].duration_since(pair[0]),
                interval,
                "consecutive throttle slots must be exactly one interval apart"
            );
        }
    }

    #[tokio::test]
    async fn a1_throttle_wait_sleeps_only_when_slot_is_in_the_future() {
        let throttle = Throttle::new(Duration::from_secs(60));
        let (_, first) = throttle.reserve();
        let (_, second) = throttle.reserve();
        assert!(first.is_zero(), "first call must not wait: {first:?}");
        assert!(
            second > Duration::from_secs(50),
            "second call must wait for the first slot's interval: {second:?}"
        );
    }

    #[test]
    fn throttle_does_not_delay_calls_already_spaced_out() {
        let throttle = Throttle::new(Duration::from_millis(5));
        let (_, first) = throttle.reserve();
        std::thread::sleep(Duration::from_millis(20)); // sleeps at least 20ms
        let (_, second) = throttle.reserve(); // interval already elapsed
        assert!(first.is_zero());
        assert!(
            second.is_zero(),
            "throttle added unnecessary delay for already-spaced calls: {second:?}"
        );
    }

    // ---- region error suggestion -------------------------------------

    #[test]
    fn region_error_carries_suggestion() {
        let err = AppError::Api {
            status: 404,
            message: "Index not found".to_string(),
            suggestion: None,
        };
        let rewritten = with_region_suggestion(err, "de");
        match rewritten {
            AppError::Api {
                status, suggestion, ..
            } => {
                assert_eq!(status, 404);
                let s = suggestion.expect("expected a region suggestion");
                assert!(s.contains("--region us"), "suggestion was: {s}");
            }
            other => panic!("expected Api variant, got {other:?}"),
        }

        let err = AppError::Api {
            status: 404,
            message: "Index not found".to_string(),
            suggestion: None,
        };
        let rewritten = with_region_suggestion(err, "us");
        match rewritten {
            AppError::Api { suggestion, .. } => {
                let s = suggestion.expect("expected a region suggestion");
                assert!(s.contains("--region de"), "suggestion was: {s}");
            }
            other => panic!("expected Api variant, got {other:?}"),
        }
    }

    #[test]
    fn non_404_errors_pass_through_unmodified() {
        let err = AppError::Api {
            status: 500,
            message: "Internal server error".to_string(),
            suggestion: None,
        };
        let rewritten = with_region_suggestion(err, "de");
        match rewritten {
            AppError::Api {
                status, suggestion, ..
            } => {
                assert_eq!(status, 500);
                assert!(suggestion.is_none());
            }
            other => panic!("expected Api variant, got {other:?}"),
        }
    }

    // ---- noResultRate parsing -----------------------------------------

    #[test]
    fn no_results_rate_parsing() {
        let v = json!({
            "rate": 0.08,
            "count": 12500,
            "noResultCount": 1000,
            "dates": [
                {"date": "2026-07-20", "rate": 0.075, "count": 1200, "noResultCount": 90}
            ]
        });
        let parsed = parse_no_result_rate(&v).unwrap();
        assert_eq!(parsed.rate, Some(0.08));
        assert_eq!(parsed.count, 12500);
        assert_eq!(parsed.no_result_count, 1000);
        assert_eq!(parsed.dates.len(), 1);
        assert_eq!(parsed.dates[0].date, "2026-07-20");
    }

    #[test]
    fn no_results_rate_parsing_null_rate_is_none_not_zero() {
        // Zero searches in the window -> rate is null on the wire. Coercing
        // that to 0.0 would silently claim "0% no-result rate" instead of
        // "no data" — must round-trip to `None`.
        let v = json!({
            "rate": null,
            "count": 0,
            "noResultCount": 0,
            "dates": []
        });
        let parsed = parse_no_result_rate(&v).unwrap();
        assert_eq!(parsed.rate, None);
        assert_eq!(parsed.count, 0);
    }

    #[test]
    fn no_results_rate_parsing_rejects_garbage() {
        let v = json!({"totally": "unexpected shape"});
        assert!(parse_no_result_rate(&v).is_err());
    }

    // ---- BUG-ALX-ANALYTICS-NULLCOLL: `searches: null` for a no-data
    // region. Confirmed live 2026-08-04 against `--region us` on this app:
    // `/2/searches` and `/2/searches/noResults` both return HTTP 200 with
    // `{"searches": null}`, not an absent key — `#[serde(default)]` alone
    // does not rescue that (only `null_as_default` does). Mirrors
    // `status_parses_null_updated_at_as_none_not_error` (analytics.rs) and
    // the equivalent `/1/events`/`/1/metrics` fixes in insights.rs. --------

    #[tokio::test]
    async fn top_searches_tolerates_null_searches_field() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/searches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"searches": null})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let rows = top_searches(
            &ctx, "testapp", "testkey", "us", "Product", 30, None, None, &throttle,
        )
        .await
        .unwrap();

        assert!(
            rows.is_empty(),
            "expected a null 'searches' field to parse as zero rows, not an error"
        );
    }

    #[tokio::test]
    async fn no_results_tolerates_null_searches_field() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/searches/noResults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"searches": null})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let rows = no_results(
            &ctx, "testapp", "testkey", "us", "Product", 30, None, None, &throttle,
        )
        .await
        .unwrap();

        assert!(
            rows.is_empty(),
            "expected a null 'searches' field to parse as zero rows, not an error"
        );
    }

    #[test]
    fn no_results_rate_parsing_tolerates_null_dates() {
        let v = json!({
            "rate": null,
            "count": 0,
            "noResultCount": 0,
            "dates": null
        });
        let parsed = parse_no_result_rate(&v).unwrap();
        assert!(parsed.dates.is_empty());
    }

    // ---- HTTP-level: request shape + throttle over real calls ---------

    #[tokio::test]
    async fn top_searches_sends_index_and_date_params_never_default_limit() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/searches"))
            .and(query_param("index", "Product"))
            .and(wiremock::matchers::header(
                "X-Algolia-Application-Id",
                "testapp",
            ))
            .and(wiremock::matchers::header("X-Algolia-API-Key", "testkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searches": [
                    {"search": "aspirina", "count": 120, "nbHits": 34}
                ]
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let rows = top_searches(
            &ctx, "testapp", "testkey", "de", "Product", 7, None, None, &throttle,
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].search, "aspirina");
        assert_eq!(rows[0].count, 120);
        assert_eq!(rows[0].nb_hits, 34);
        assert_eq!(ctx.ops.snapshot().analytics_calls, 1);
    }

    #[tokio::test]
    async fn wrong_region_404_gets_region_suggestion_end_to_end() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/searches"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"message": "Index not found"})),
            )
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let err = top_searches(
            &ctx, "testapp", "testkey", "de", "Product", 7, None, None, &throttle,
        )
        .await
        .unwrap_err();

        match err {
            AppError::Api {
                status, suggestion, ..
            } => {
                assert_eq!(status, 404);
                assert!(suggestion.unwrap().contains("--region us"));
            }
            other => panic!("expected Api variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_sequential_calls_through_same_throttle_are_spaced() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"searches": []})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(30));

        let start = Instant::now();
        top_searches(
            &ctx, "testapp", "testkey", "de", "Product", 1, None, None, &throttle,
        )
        .await
        .unwrap();
        no_results(
            &ctx, "testapp", "testkey", "de", "Product", 1, None, None, &throttle,
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed + Duration::from_millis(3) >= Duration::from_millis(30),
            "two analytics calls through the same throttle completed in {elapsed:?}, expected >= ~30ms apart"
        );
        assert_eq!(ctx.ops.snapshot().analytics_calls, 2);
    }

    // ---- clicks/conversions/revenue/status: parsing against real shapes -
    // (field names and nesting mirror the live API's responses; every
    // figure is a synthetic fixture value, not real traffic)
    // -----------------------------------------------------------------

    #[test]
    fn click_through_rate_parses_real_shape() {
        let v = json!({
            "rate": 0.105,
            "trackedSearchCount": 120000,
            "clickCount": 12600,
            "dates": [
                {"date": "2026-08-01", "rate": 0.1, "trackedSearchCount": 40000, "clickCount": 4000}
            ]
        });
        let parsed = parse_click_through_rate(&v).unwrap();
        assert_eq!(parsed.rate, Some(0.105));
        assert_eq!(parsed.tracked_search_count, 120000);
        assert_eq!(parsed.click_count, 12600);
        assert_eq!(parsed.dates.len(), 1);
        assert_eq!(parsed.dates[0].date, "2026-08-01");
        assert_eq!(parsed.dates[0].click_count, 4000);
    }

    /// BUG-ALX-ANALYTICS-NULLCOLL sweep: defensive fix — not independently
    /// reproduced live for this specific field, but the same "no data in
    /// window" condition that nulls `rate` elsewhere in this API family
    /// could plausibly also null `dates`.
    #[test]
    fn click_through_rate_tolerates_null_dates() {
        let v = json!({"rate": null, "trackedSearchCount": 0, "clickCount": 0, "dates": null});
        let parsed = parse_click_through_rate(&v).unwrap();
        assert!(parsed.dates.is_empty());
    }

    #[test]
    fn average_click_position_parses_real_shape() {
        let v = json!({
            "average": 6.42,
            "clickCount": 12600,
            "dates": [
                {"date": "2026-08-01", "average": 7.25, "clickCount": 4000}
            ]
        });
        let parsed = parse_average_click_position(&v).unwrap();
        assert_eq!(parsed.average, Some(6.42));
        assert_eq!(parsed.click_count, 12600);
        assert_eq!(parsed.dates.len(), 1);
        assert_eq!(parsed.dates[0].average, Some(7.25));
    }

    #[test]
    fn average_click_position_tolerates_null_dates() {
        let v = json!({"average": null, "clickCount": 0, "dates": null});
        let parsed = parse_average_click_position(&v).unwrap();
        assert!(parsed.dates.is_empty());
    }

    #[test]
    fn click_positions_parses_real_shape_including_unbounded_bucket() {
        let v = json!({
            "positions": [
                {"position": [1, 1], "clickCount": 6000},
                {"position": [11, 20], "clickCount": 1300},
                {"position": [21, -1], "clickCount": 1100}
            ]
        });
        let parsed = parse_click_positions(&v).unwrap();
        assert_eq!(parsed.positions.len(), 3);
        assert_eq!(parsed.positions[0].position, (1, 1));
        assert_eq!(parsed.positions[0].click_count, 6000);
        // -1 is the "21+"/unbounded sentinel — must round-trip as -1, never
        // be clamped or reinterpreted.
        assert_eq!(parsed.positions[2].position, (21, -1));
        assert_eq!(parsed.positions[2].click_count, 1100);
    }

    #[test]
    fn click_positions_tolerates_null_positions() {
        let v = json!({"positions": null});
        let parsed = parse_click_positions(&v).unwrap();
        assert!(parsed.positions.is_empty());
    }

    #[test]
    fn conversion_rate_parses_real_shape() {
        let v = json!({
            "rate": 0.08,
            "trackedSearchCount": 120000,
            "conversionCount": 9600,
            "dates": []
        });
        let parsed = parse_conversion_rate(&v).unwrap();
        assert_eq!(parsed.rate, Some(0.08));
        assert_eq!(parsed.tracked_search_count, 120000);
        assert_eq!(parsed.conversion_count, 9600);
    }

    #[test]
    fn conversion_rate_tolerates_null_dates() {
        let v = json!({"rate": null, "trackedSearchCount": 0, "conversionCount": 0, "dates": null});
        let parsed = parse_conversion_rate(&v).unwrap();
        assert!(parsed.dates.is_empty());
    }

    #[test]
    fn add_to_cart_rate_parses_real_shape() {
        let v = json!({
            "rate": 0.075,
            "trackedSearchCount": 120000,
            "addToCartCount": 9000,
            "dates": []
        });
        let parsed = parse_add_to_cart_rate(&v).unwrap();
        assert_eq!(parsed.rate, Some(0.075));
        assert_eq!(parsed.add_to_cart_count, 9000);
    }

    #[test]
    fn add_to_cart_rate_tolerates_null_dates() {
        let v = json!({"rate": null, "trackedSearchCount": 0, "addToCartCount": 0, "dates": null});
        let parsed = parse_add_to_cart_rate(&v).unwrap();
        assert!(parsed.dates.is_empty());
    }

    #[test]
    fn purchase_rate_parses_real_shape() {
        let v = json!({
            "rate": 0.025,
            "trackedSearchCount": 120000,
            "purchaseCount": 3000,
            "dates": []
        });
        let parsed = parse_purchase_rate(&v).unwrap();
        assert_eq!(parsed.rate, Some(0.025));
        assert_eq!(parsed.purchase_count, 3000);
    }

    #[test]
    fn purchase_rate_tolerates_null_dates() {
        let v = json!({"rate": null, "trackedSearchCount": 0, "purchaseCount": 0, "dates": null});
        let parsed = parse_purchase_rate(&v).unwrap();
        assert!(parsed.dates.is_empty());
    }

    #[test]
    fn revenue_parses_real_single_currency_shape() {
        let v = json!({
            "currencies": {
                "EUR": {
                    "currency": "EUR",
                    "averageOrderValue": 38.58,
                    "revenue": 12345.6,
                    "transactionCount": 320
                }
            },
            "dates": [
                {"date": "2026-08-01", "currencies": {"EUR": {"currency": "EUR", "averageOrderValue": 40.005, "revenue": 4000.5, "transactionCount": 100}}}
            ]
        });
        let parsed = parse_revenue(&v).unwrap();
        assert_eq!(parsed.currencies.len(), 1);
        let eur = parsed.currencies.get("EUR").expect("EUR row");
        assert_eq!(eur.currency, "EUR");
        assert_eq!(eur.revenue, 12345.6);
        assert_eq!(eur.average_order_value, 38.58);
        assert_eq!(eur.transaction_count, 320);
    }

    #[test]
    fn revenue_parses_multi_currency_case() {
        // A2/rule 9: never assume EUR — a synthetic second currency must
        // survive parsing distinctly, not get merged/overwritten/dropped.
        let v = json!({
            "currencies": {
                "EUR": {"currency": "EUR", "averageOrderValue": 38.58, "revenue": 12345.6, "transactionCount": 320},
                "USD": {"currency": "USD", "averageOrderValue": 51.2, "revenue": 9820.5, "transactionCount": 192}
            }
        });
        let parsed = parse_revenue(&v).unwrap();
        assert_eq!(parsed.currencies.len(), 2);
        let eur = parsed.currencies.get("EUR").expect("EUR row");
        let usd = parsed.currencies.get("USD").expect("USD row");
        assert_eq!(eur.transaction_count, 320);
        assert_eq!(usd.currency, "USD");
        assert_eq!(usd.transaction_count, 192);
        assert_eq!(usd.revenue, 9820.5);
    }

    #[test]
    fn revenue_tolerates_null_currencies_map() {
        let v = json!({"currencies": null});
        let parsed = parse_revenue(&v).unwrap();
        assert!(parsed.currencies.is_empty());
    }

    #[test]
    fn status_parses_real_shape() {
        let v = json!({"updatedAt": "2026-08-04T06:00:00.000Z"});
        let parsed = parse_status(&v).unwrap();
        assert_eq!(
            parsed.updated_at,
            Some("2026-08-04T06:00:00.000Z".to_string())
        );
    }

    #[test]
    fn status_parses_null_updated_at_as_none_not_error() {
        // Confirmed live 2026-08-04: a region/index with no analytics data
        // yet (e.g. `--region us` for this app) returns HTTP 200 with
        // `{"updatedAt": null}`, not an error. Coercing null to a required
        // `String` field previously made this fail with "invalid type:
        // null, expected a string" — the exact bug this test guards
        // against.
        let v = json!({"updatedAt": null});
        let parsed = parse_status(&v).unwrap();
        assert_eq!(parsed.updated_at, None);
    }

    #[test]
    fn revenue_parsing_rejects_garbage() {
        let v = json!({"totally": "unexpected shape"});
        // `currencies` has `#[serde(default)]`, so a completely absent
        // field still parses to an empty map rather than erroring — pin
        // that this is the actual (lenient) behavior, not an assumption.
        let parsed = parse_revenue(&v).unwrap();
        assert!(parsed.currencies.is_empty());
    }

    // ---- clicks/conversions/status: HTTP-level path + query param shape -

    #[tokio::test]
    async fn click_through_rate_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/clickThroughRate"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rate": 0.1, "trackedSearchCount": 100, "clickCount": 10, "dates": []
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = click_through_rate(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.click_count, 10);
        assert_eq!(ctx.ops.snapshot().analytics_calls, 1);
    }

    #[tokio::test]
    async fn average_click_position_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/averageClickPosition"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "average": 5.5, "clickCount": 10, "dates": []
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp =
            average_click_position(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
                .await
                .unwrap();

        assert_eq!(resp.average, Some(5.5));
    }

    #[tokio::test]
    async fn click_positions_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/positions"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "positions": [{"position": [1, 1], "clickCount": 5}]
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = click_positions(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.positions.len(), 1);
        assert_eq!(resp.positions[0].position, (1, 1));
    }

    #[tokio::test]
    async fn conversion_rate_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        let (start_date, end_date) = date_window(7);
        Mock::given(method("GET"))
            .and(path("/2/conversions/conversionRate"))
            .and(query_param("index", "Product"))
            .and(query_param("startDate", start_date))
            .and(query_param("endDate", end_date))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rate": 0.05, "trackedSearchCount": 100, "conversionCount": 5, "dates": []
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = conversion_rate(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.conversion_count, 5);
    }

    #[tokio::test]
    async fn add_to_cart_rate_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/conversions/addToCartRate"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rate": 0.05, "trackedSearchCount": 100, "addToCartCount": 5, "dates": []
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = add_to_cart_rate(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.add_to_cart_count, 5);
    }

    #[tokio::test]
    async fn purchase_rate_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/conversions/purchaseRate"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rate": 0.02, "trackedSearchCount": 100, "purchaseCount": 2, "dates": []
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = purchase_rate(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.purchase_count, 2);
    }

    #[tokio::test]
    async fn revenue_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/conversions/revenue"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "currencies": {"EUR": {"currency": "EUR", "averageOrderValue": 10.0, "revenue": 100.0, "transactionCount": 10}}
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = revenue(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.currencies.len(), 1);
    }

    #[tokio::test]
    async fn status_sends_correct_path_and_params() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/status"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "updatedAt": "2026-08-04T06:00:00.000Z"
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = status(&ctx, "testapp", "testkey", "de", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(
            resp.updated_at,
            Some("2026-08-04T06:00:00.000Z".to_string())
        );
        assert_eq!(ctx.ops.snapshot().analytics_calls, 1);
    }

    #[tokio::test]
    async fn status_sends_correct_path_and_params_no_data_region() {
        // The A1/no-data-region case, over HTTP rather than a pure parse:
        // `/2/status` returning `{"updatedAt": null}` must still surface as
        // a successful fetch, not an `AppResult::Err`.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/status"))
            .and(query_param("index", "Product"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"updatedAt": null})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let resp = status(&ctx, "testapp", "testkey", "us", "Product", 7, &throttle)
            .await
            .unwrap();

        assert_eq!(resp.updated_at, None);
    }

    #[tokio::test]
    async fn clicks_wrong_region_404_gets_region_suggestion_end_to_end() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/clickThroughRate"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"message": "Index not found"})),
            )
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(1));
        let err = click_through_rate(&ctx, "testapp", "testkey", "us", "Product", 7, &throttle)
            .await
            .unwrap_err();

        match err {
            AppError::Api {
                status, suggestion, ..
            } => {
                assert_eq!(status, 404);
                assert!(suggestion.unwrap().contains("--region de"));
            }
            other => panic!("expected Api variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn four_sequential_clicks_calls_through_same_throttle_are_spaced() {
        // A1: the `clicks` command fires clickThroughRate +
        // averageClickPosition + positions + status sequentially through
        // ONE shared Throttle instance — pin that this actually serializes
        // rather than bursting all four through near-simultaneously.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/clickThroughRate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rate": 0.1, "trackedSearchCount": 10, "clickCount": 1, "dates": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/averageClickPosition"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "average": 1.0, "clickCount": 1, "dates": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/2/clicks/positions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"positions": []})))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/2/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "updatedAt": "2026-08-04T06:00:00.000Z"
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let throttle = Throttle::new(Duration::from_millis(25));

        let start = Instant::now();
        click_through_rate(&ctx, "testapp", "testkey", "de", "Product", 1, &throttle)
            .await
            .unwrap();
        average_click_position(&ctx, "testapp", "testkey", "de", "Product", 1, &throttle)
            .await
            .unwrap();
        click_positions(&ctx, "testapp", "testkey", "de", "Product", 1, &throttle)
            .await
            .unwrap();
        status(&ctx, "testapp", "testkey", "de", "Product", 1, &throttle)
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed + Duration::from_millis(5) >= Duration::from_millis(75),
            "four throttled analytics calls completed in {elapsed:?}, expected >= ~75ms (3 gaps @ 25ms)"
        );
        assert_eq!(ctx.ops.snapshot().analytics_calls, 4);
    }

    // ---- date window / url encoding sanity -----------------------------

    #[test]
    fn date_window_is_inclusive_and_ends_today() {
        let (start, end) = date_window(7);
        assert_eq!(end, Utc::now().date_naive().format("%Y-%m-%d").to_string());
        let start_date = chrono::NaiveDate::parse_from_str(&start, "%Y-%m-%d").unwrap();
        let end_date = chrono::NaiveDate::parse_from_str(&end, "%Y-%m-%d").unwrap();
        assert_eq!((end_date - start_date).num_days(), 7);
    }

    #[test]
    fn url_encode_leaves_safe_chars_alone_and_escapes_the_rest() {
        assert_eq!(url_encode("Product"), "Product");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("tag1 OR tag2"), "tag1%20OR%20tag2");
    }
}
