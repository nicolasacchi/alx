//! `alx events metrics|sample|errors` — Insights API forensics (Events ->
//! Health / Events -> Debugger). `sample`/`errors` are far closer in shape
//! to `logs sample`/`logs errors` than to anything in `analytics`: both
//! fetch against a rolling, capped buffer (not a real time-windowed query)
//! and both report the observed window span as the operator's *required*
//! sampling interval, per `logs.rs`'s L4 convention. `sample`'s `--persist`
//! follows the EXACT same never-overwrite / `-2`/`-3`-suffix contract as
//! `logs sample --persist` (`claim_event_persist_paths` below is the same
//! `O_CREAT|O_EXCL`-atomic-claim pattern as `logs::claim_persist_paths`,
//! adapted from N per-host files down to the two files — meta + one events
//! jsonl — a single non-fanned-out fetch produces).
//!
//! D0.3: every entry point runs `safety::preflight_privilege_check` (via
//! this module's `preflight` helper) right after credential resolution,
//! before the first real Insights call.
//!
//! No `--region` flag: verified live 2026-08-04, `insights.us.algolia.io`
//! 401s outright (an auth failure, a different app/region class problem —
//! not the analytics API's "empty region" 200) — this app's Insights
//! traffic lives on `de`, hardcoded here.

use crate::algolia::insights::{self as insights_api, EventPayload, MetricPoint, RawEvent};
use crate::cli::{EventsErrorsArgs, EventsMetricsArgs, EventsSampleArgs};
use crate::constants;
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::Surface;
use crate::output::{format_session_ops_line, SessionOpsSnapshot};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

/// Insights traffic for this app lives on `de` (verified live 2026-08-04 —
/// see `algolia::insights`'s module doc). No `--region` flag exists on any
/// `events` subcommand.
const INSIGHTS_REGION: &str = "de";

/// A fetch landing at or above this count is flagged as likely
/// buffer-truncated — near `insights_api::BUFFER_CAP_APPROX` (~3,000),
/// with headroom for the buffer shrinking slightly between the API's
/// internal cap and what a given call happens to return.
const NEAR_CAP_THRESHOLD: usize = 2900;

fn resolve_credentials(ctx: &AppContext) -> AppResult<(String, String)> {
    let app_id = ctx.resolve_app_id().ok_or_else(|| {
        AppError::InvalidInput(
            "ALGOLIA_APPLICATION_ID is not set (and --app-id was not passed)".to_string(),
        )
    })?;
    let key = ctx.resolve_key(Surface::Insights).ok_or_else(|| {
        AppError::InvalidInput(
            "no Insights API key found — set ALGOLIA_INSIGHTS_API_KEY, fall back to \
             ALGOLIA_LOGS_API_KEY (the logs ACL is what the live Insights API accepts), \
             the generic ALGOLIA_API_KEY, or pass --key"
                .to_string(),
        )
    })?;
    Ok((app_id, key))
}

/// D0.3 over-privilege gate, shared by all three entry points. Base URL is
/// sourced from `ctx.base_urls.search(app_id)` (the same search host `keys
/// audit`/`analytics`/`usage`/`logs` all probe), so `ALX_SEARCH_BASE_URL`
/// redirects the self-check at a mock server in tests.
async fn preflight(ctx: &AppContext, app_id: &str, key: &str) -> AppResult<()> {
    crate::safety::preflight_privilege_check(
        &ctx.client,
        &ctx.base_urls.search(app_id),
        app_id,
        key,
        ctx.i_know,
        &ctx.presenter,
    )
    .await
}

// =========================================================================
// events metrics
// =========================================================================

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub since: String,
    pub start_date: String,
    pub end_date: String,
    pub granularity: String,
    pub approximate: bool,
    pub totals: MetricsTotals,
    pub buckets: Vec<MetricPoint>,
    pub session_ops: SessionOpsSnapshot,
}

/// Sums across `buckets`, treating a null/missing bucket value as no
/// contribution (0) rather than an error — the totals are a derived
/// aggregate over whatever the API returned, not a re-fetch of a
/// server-computed total. `error_rate` is likewise derived here
/// (error_count / event_count over the whole window), not an average of
/// per-bucket rates — labeled accordingly so it's never mistaken for a
/// directly-reported Algolia figure (mirrors `usage`'s `DerivedField`
/// convention).
#[derive(Debug, Serialize)]
pub struct MetricsTotals {
    pub event_count: u64,
    pub click_count: u64,
    pub view_count: u64,
    pub conversion_count: u64,
    pub error_count: u64,
    pub error_rate: DerivedRate,
    pub neural_search_count: u64,
    pub recommend_frequently_bought_together_count: u64,
    pub recommend_related_products_count: u64,
    pub recommend_trending_items_count: u64,
    pub recommend_trending_facet_values_count: u64,
}

#[derive(Debug, Serialize)]
pub struct DerivedRate {
    pub value: Option<f64>,
    pub label: &'static str,
    pub formula: &'static str,
}

fn sum_opt(points: &[MetricPoint], f: impl Fn(&MetricPoint) -> Option<u64>) -> u64 {
    points.iter().filter_map(f).sum()
}

fn compute_totals(buckets: &[MetricPoint]) -> MetricsTotals {
    let event_count = sum_opt(buckets, |p| p.event_count);
    let error_count = sum_opt(buckets, |p| p.error_count);
    let error_rate = DerivedRate {
        value: if event_count > 0 {
            Some(error_count as f64 / event_count as f64)
        } else {
            None
        },
        label: "derived/approximate",
        formula: "sum(errorCount) / sum(eventCount) over the window",
    };

    MetricsTotals {
        event_count,
        click_count: sum_opt(buckets, |p| p.click_count),
        view_count: sum_opt(buckets, |p| p.view_count),
        conversion_count: sum_opt(buckets, |p| p.conversion_count),
        error_count,
        error_rate,
        neural_search_count: sum_opt(buckets, |p| p.neural_search_count),
        recommend_frequently_bought_together_count: sum_opt(buckets, |p| {
            p.recommend_frequently_bought_together_count
        }),
        recommend_related_products_count: sum_opt(buckets, |p| p.recommend_related_products_count),
        recommend_trending_items_count: sum_opt(buckets, |p| p.recommend_trending_items_count),
        recommend_trending_facet_values_count: sum_opt(buckets, |p| {
            p.recommend_trending_facet_values_count
        }),
    }
}

pub async fn run_metrics(ctx: &AppContext, args: &EventsMetricsArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;

    let granularity = insights_api::events_granularity_str(args.granularity);
    // Belt-and-suspenders: the CLI enum already makes "week" unrepresentable,
    // but re-run the preflight explicitly here too (D0.3-style discipline —
    // never rely solely on a type constraint elsewhere in the call chain).
    insights_api::validate_metrics_granularity(granularity)?;

    let since_minutes = args.since.minutes;

    ctx.presenter.progress(&format!(
        "fetching insights metrics: region={INSIGHTS_REGION} since={} granularity={granularity} approximate={}",
        args.since, args.approximate
    ));

    let buckets = insights_api::fetch_metrics(
        ctx,
        &app_id,
        &key,
        INSIGHTS_REGION,
        since_minutes,
        granularity,
        args.approximate,
    )
    .await?;

    let totals = compute_totals(&buckets);
    let (start_date, end_date) = insights_api::date_window(since_minutes);

    let response = MetricsResponse {
        since: args.since.to_string(),
        start_date,
        end_date,
        granularity: granularity.to_string(),
        approximate: args.approximate,
        totals,
        buckets,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_metrics_human)
}

fn render_metrics_human(r: &MetricsResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "alx events metrics — {} to {} ({}, since {}, approximate={})\n",
        r.start_date, r.end_date, r.granularity, r.since, r.approximate
    ));
    out.push_str(&format!(
        "  eventCount:      {:>12}\n",
        r.totals.event_count
    ));
    out.push_str(&format!("  viewCount:       {:>12}\n", r.totals.view_count));
    out.push_str(&format!(
        "  clickCount:      {:>12}\n",
        r.totals.click_count
    ));
    out.push_str(&format!(
        "  conversionCount: {:>12}\n",
        r.totals.conversion_count
    ));
    out.push_str(&format!(
        "  errorCount:      {:>12}  errorRate={} [{}]\n",
        r.totals.error_count,
        fmt_opt_pct(r.totals.error_rate.value),
        r.totals.error_rate.formula
    ));
    out.push_str(&format!("  buckets in series: {}\n", r.buckets.len()));
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

fn fmt_opt_pct(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{:.4}%", v * 100.0),
        None => "n/a (no events in window)".to_string(),
    }
}

// =========================================================================
// events sample / errors — shared fetch + aggregation
// =========================================================================

async fn fetch_sample(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    since_minutes: i64,
    limit: Option<u32>,
) -> AppResult<insights_api::ParsedEvents> {
    insights_api::fetch_events(ctx, app_id, key, INSIGHTS_REGION, since_minutes, limit).await
}

#[derive(Debug, Clone, Serialize)]
pub struct EventsWindowSummary {
    pub oldest_received_at: Option<DateTime<Utc>>,
    pub newest_received_at: Option<DateTime<Utc>>,
    pub elapsed_minutes: Option<i64>,
    /// Events per minute OVER THE FETCHED BUFFER WINDOW ONLY — never a rate
    /// extrapolated beyond what was actually observed in this one fetch.
    pub events_per_minute_observed: Option<f64>,
    pub note: String,
}

fn compute_window(events: &[RawEvent]) -> EventsWindowSummary {
    let stamps: Vec<DateTime<Utc>> = events.iter().filter_map(|e| e.received_at).collect();
    let oldest = stamps.iter().min().copied();
    let newest = stamps.iter().max().copied();
    let elapsed_minutes = match (oldest, newest) {
        (Some(a), Some(b)) => Some((b - a).num_minutes().max(0)),
        _ => None,
    };
    let events_per_minute_observed = match elapsed_minutes {
        Some(m) if m > 0 => Some(events.len() as f64 / m as f64),
        _ => None,
    };
    let note = match elapsed_minutes {
        Some(m) if m > 0 => format!(
            "the fetched buffer spans about {m} minute(s) of ingest — sample at least this \
             often to avoid losing evidence, and MORE often as traffic grows: the buffer's \
             wall-clock span SHRINKS as volume rises (it holds a roughly fixed ~{} event count, \
             not a fixed time window).",
            insights_api::BUFFER_CAP_APPROX
        ),
        _ => "fewer than two timestamped events in this fetch — not enough to estimate a \
              required sampling interval; try a wider --since or sample again shortly."
            .to_string(),
    };
    EventsWindowSummary {
        oldest_received_at: oldest,
        newest_received_at: newest,
        elapsed_minutes,
        events_per_minute_observed,
        note,
    }
}

fn is_likely_truncated(fetched: usize) -> bool {
    fetched >= NEAR_CAP_THRESHOLD
}

fn truncation_warning(truncated: bool) -> Option<String> {
    if truncated {
        Some(format!(
            "fetched count is at/near the live ~{} event rolling-buffer cap — older events were \
             SILENTLY DROPPED by the API before this fetch ran. This sample is truncated, not a \
             complete picture of the requested --since window.",
            insights_api::BUFFER_CAP_APPROX
        ))
    } else {
        None
    }
}

fn header_value<'a>(
    headers: &'a std::collections::HashMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(|s| s.as_str())
}

/// browser / Hotwire Native Android / Hotwire Native iOS / server-side
/// Ruby / other — derived from the `User-Agent` header. Reuses
/// `constants::OWN_EGRESS_UA_MARKER` ("Algolia for Rails") since that's
/// this exact codebase's own established server-side-Ruby-egress signature
/// (from `asn::classify`/`logs`'s own-egress detection).
fn classify_client(e: &RawEvent) -> &'static str {
    let Some(ua) = header_value(&e.headers, "User-Agent") else {
        return "unknown (no User-Agent)";
    };
    if ua.is_empty() {
        return "unknown (no User-Agent)";
    }
    let lower = ua.to_lowercase();
    if lower.contains("hotwire native") {
        if lower.contains("android") {
            return "Hotwire Native Android";
        }
        if lower.contains("ios") || lower.contains("iphone") || lower.contains("ipad") {
            return "Hotwire Native iOS";
        }
    }
    if ua.contains(constants::OWN_EGRESS_UA_MARKER) {
        return "server-side Ruby";
    }
    if lower.contains("mozilla") {
        return "browser";
    }
    "other"
}

fn payload(e: &RawEvent) -> Option<&EventPayload> {
    e.event.as_ref()
}

fn event_name_key(e: &RawEvent) -> String {
    payload(e)
        .and_then(|p| p.event_name.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn event_type_key(e: &RawEvent) -> String {
    payload(e)
        .and_then(|p| p.event_type.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn event_subtype_key(e: &RawEvent) -> String {
    payload(e)
        .and_then(|p| p.event_subtype.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(none)".to_string())
}

/// `None`/absent `algoliaSource` (server-side/hand-rolled emitter) is a
/// DISTINCT bucket from any real value — never merged with an empty-array
/// case, since the API contract is "absent for server-side", not "empty
/// array for server-side".
fn algolia_source_key(e: &RawEvent) -> String {
    match payload(e).and_then(|p| p.algolia_source.as_ref()) {
        Some(v) if !v.is_empty() => v.join(","),
        _ => "(none — server-side/hand-rolled emitter)".to_string(),
    }
}

fn status_key(e: &RawEvent) -> String {
    e.status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn is_uuid_shaped(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(&len, p)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// plain uuid / anonymous-<uuid> / numeric / other / missing.
fn classify_user_token(token: Option<&str>) -> &'static str {
    let Some(t) = token else {
        return "missing";
    };
    if t.is_empty() {
        return "missing";
    }
    if let Some(rest) = t.strip_prefix("anonymous-") {
        if is_uuid_shaped(rest) {
            return "anonymous-<uuid>";
        }
    }
    if is_uuid_shaped(t) {
        return "plain uuid";
    }
    if t.chars().all(|c| c.is_ascii_digit()) {
        return "numeric";
    }
    "other"
}

fn user_token_shape_key(e: &RawEvent) -> String {
    classify_user_token(payload(e).and_then(|p| p.user_token.as_deref())).to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct CountRow {
    pub key: String,
    pub count: usize,
}

fn count_by(events: &[RawEvent], keyfn: impl Fn(&RawEvent) -> String) -> Vec<CountRow> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in events {
        *counts.entry(keyfn(e)).or_insert(0) += 1;
    }
    let mut rows: Vec<CountRow> = counts
        .into_iter()
        .map(|(key, count)| CountRow { key, count })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    rows
}

fn count_error_messages(events: &[RawEvent]) -> Vec<CountRow> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in events {
        for msg in &e.errors {
            *counts.entry(msg.clone()).or_insert(0) += 1;
        }
    }
    let mut rows: Vec<CountRow> = counts
        .into_iter()
        .map(|(key, count)| CountRow { key, count })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    rows
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryIdPresenceRow {
    pub event_type: String,
    pub with_query_id: usize,
    pub without_query_id: usize,
}

/// A view event correctly never carries a `queryID` — a single blended
/// percentage across all event types would be a misleading number, so this
/// is reported per `eventType`.
fn query_id_presence_by_event_type(events: &[RawEvent]) -> Vec<QueryIdPresenceRow> {
    let mut map: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for e in events {
        let event_type = event_type_key(e);
        let has_query_id = payload(e)
            .and_then(|p| p.query_id.as_deref())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let entry = map.entry(event_type).or_insert((0, 0));
        if has_query_id {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    map.into_iter()
        .map(
            |(event_type, (with_query_id, without_query_id))| QueryIdPresenceRow {
                event_type,
                with_query_id,
                without_query_id,
            },
        )
        .collect()
}

// =========================================================================
// events sample
// =========================================================================

#[derive(Debug, Serialize)]
pub struct SampleResponse {
    pub since: String,
    pub requested_limit: Option<u32>,
    pub fetched: usize,
    /// Entries in the raw `/1/events` response that failed to deserialize
    /// and were dropped rather than aborting the whole fetch (see
    /// `insights_api::ParsedEvents`). Always present, even when `0` — a
    /// silently-omitted-when-zero field would defeat the point of
    /// surfacing it (this repo's "no silent failures" discipline).
    pub skipped_count: usize,
    pub window: EventsWindowSummary,
    pub truncated: bool,
    pub truncation_warning: Option<String>,
    pub by_event_name: Vec<CountRow>,
    pub by_event_type: Vec<CountRow>,
    pub by_event_subtype: Vec<CountRow>,
    pub by_algolia_source: Vec<CountRow>,
    pub by_client: Vec<CountRow>,
    pub by_status: Vec<CountRow>,
    pub by_error_message: Vec<CountRow>,
    pub query_id_presence_by_event_type: Vec<QueryIdPresenceRow>,
    pub user_token_shape: Vec<CountRow>,
    pub persisted: Option<PersistSummary>,
    pub session_ops: SessionOpsSnapshot,
}

pub async fn run_sample(ctx: &AppContext, args: &EventsSampleArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;

    let since_minutes = args.since.minutes;

    ctx.presenter.progress(&format!(
        "fetching insights events sample: region={INSIGHTS_REGION} since={} limit={:?}",
        args.since, args.limit
    ));

    let parsed = fetch_sample(ctx, &app_id, &key, since_minutes, args.limit).await?;
    let events = parsed.events;
    let skipped_count = parsed.skipped_count;
    // `fetched` is the RAW count the API returned (survivors + skipped) —
    // what actually decides buffer-truncation, since the ~3,000-event cap
    // is about what Algolia sent back, not how many of those happened to
    // deserialize cleanly.
    let fetched = events.len() + skipped_count;

    let window = compute_window(&events);
    let truncated = is_likely_truncated(fetched);
    let truncation_warning = truncation_warning(truncated);

    let persisted = match &args.persist {
        Some(dir) => Some(persist_events(
            dir,
            &events,
            args.since.to_string(),
            args.limit,
            &window,
            truncated,
            fetched,
            skipped_count,
        )?),
        None => None,
    };

    let response = SampleResponse {
        since: args.since.to_string(),
        requested_limit: args.limit,
        fetched,
        skipped_count,
        window,
        truncated,
        truncation_warning,
        by_event_name: count_by(&events, event_name_key),
        by_event_type: count_by(&events, event_type_key),
        by_event_subtype: count_by(&events, event_subtype_key),
        by_algolia_source: count_by(&events, algolia_source_key),
        by_client: count_by(&events, |e| classify_client(e).to_string()),
        by_status: count_by(&events, status_key),
        by_error_message: count_error_messages(&events),
        query_id_presence_by_event_type: query_id_presence_by_event_type(&events),
        user_token_shape: count_by(&events, user_token_shape_key),
        persisted,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_sample_human)
}

fn render_sample_human(r: &SampleResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!("alx events sample — since {}\n", r.since));
    out.push_str(&format!(
        "buffer window (unfiltered): {} -> {} ({})\n",
        fmt_ts(r.window.oldest_received_at),
        fmt_ts(r.window.newest_received_at),
        fmt_minutes(r.window.elapsed_minutes)
    ));
    out.push_str(&format!("  {}\n", r.window.note));
    out.push_str(&format!("fetched: {}\n", r.fetched));
    if r.skipped_count > 0 {
        out.push_str(&format!(
            "  !! {} event(s) dropped — malformed, could not be parsed (never silently lost)\n",
            r.skipped_count
        ));
    }
    if let Some(w) = &r.truncation_warning {
        out.push_str(&format!("  !! {w}\n"));
    }
    out.push_str("by event name:\n");
    render_rows(&mut out, &r.by_event_name);
    out.push_str("by event type:\n");
    render_rows(&mut out, &r.by_event_type);
    out.push_str("by algolia source:\n");
    render_rows(&mut out, &r.by_algolia_source);
    out.push_str("by client:\n");
    render_rows(&mut out, &r.by_client);
    out.push_str("by status:\n");
    render_rows(&mut out, &r.by_status);
    if !r.by_error_message.is_empty() {
        out.push_str("by error message:\n");
        render_rows(&mut out, &r.by_error_message);
    }
    out.push_str("queryID presence by event type:\n");
    for row in &r.query_id_presence_by_event_type {
        out.push_str(&format!(
            "  {:<20} with={:<6} without={}\n",
            row.event_type, row.with_query_id, row.without_query_id
        ));
    }
    out.push_str("user token shape:\n");
    render_rows(&mut out, &r.user_token_shape);
    if let Some(p) = &r.persisted {
        out.push_str(&format!("persisted to {}\n", p.dir));
        out.push_str(&format!("  meta: {}\n", p.meta_file));
        out.push_str(&format!("  events: {}\n", p.events_file));
    }
    out.push('\n');
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

fn render_rows(out: &mut String, rows: &[CountRow]) {
    if rows.is_empty() {
        out.push_str("  (none)\n");
        return;
    }
    for row in rows.iter().take(20) {
        out.push_str(&format!("  {:>6}x  {}\n", row.count, row.key));
    }
}

fn fmt_ts(ts: Option<DateTime<Utc>>) -> String {
    ts.map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "-".to_string())
}

fn fmt_minutes(m: Option<i64>) -> String {
    m.map(|m| format!("{m} min"))
        .unwrap_or_else(|| "n/a".to_string())
}

// ---- --persist: same never-overwrite contract as logs sample --------

#[derive(Debug, Serialize)]
pub struct PersistSummary {
    pub dir: String,
    pub meta_file: String,
    pub events_file: String,
}

#[derive(Debug, Serialize)]
struct PersistMeta {
    generated_at: DateTime<Utc>,
    since: String,
    requested_limit: Option<u32>,
    window: EventsWindowSummary,
    truncated: bool,
    fetched: usize,
    skipped_count: usize,
}

#[allow(clippy::too_many_arguments)]
fn persist_events(
    dir: &str,
    events: &[RawEvent],
    since: String,
    requested_limit: Option<u32>,
    window: &EventsWindowSummary,
    truncated: bool,
    fetched: usize,
    skipped_count: usize,
) -> AppResult<PersistSummary> {
    let dir_path = Path::new(dir);
    std::fs::create_dir_all(dir_path)?;

    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (meta_path, mut meta_file, events_path, mut events_file) =
        claim_event_persist_paths(dir_path, &ts)?;

    let mut body = String::new();
    for e in events {
        let line = serde_json::to_string(e)
            .map_err(|err| AppError::Other(format!("failed to serialize event: {err}")))?;
        body.push_str(&line);
        body.push('\n');
    }
    IoWrite::write_all(&mut events_file, body.as_bytes())?;

    let meta = PersistMeta {
        generated_at: Utc::now(),
        since,
        requested_limit,
        window: window.clone(),
        truncated,
        fetched,
        skipped_count,
    };
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| AppError::Other(format!("failed to serialize persist meta: {e}")))?;
    IoWrite::write_all(&mut meta_file, meta_json.as_bytes())?;

    Ok(PersistSummary {
        dir: dir.to_string(),
        meta_file: meta_path.display().to_string(),
        events_file: events_path.display().to_string(),
    })
}

/// Atomically claims the first unused `-N` suffix (starting unsuffixed) for
/// BOTH the meta file and the events jsonl together, by exclusively
/// creating each (`O_CREAT|O_EXCL`) — the exact TOCTOU-safe pattern
/// `logs::claim_persist_paths` uses (ADV-3), adapted from N per-host files
/// down to these two. A losing attempt (either path already exists) undoes
/// anything it already claimed under that suffix and retries the next one,
/// so a partial claim never blocks the eventual winner.
fn claim_event_persist_paths(
    dir: &Path,
    ts: &str,
) -> AppResult<(PathBuf, std::fs::File, PathBuf, std::fs::File)> {
    let mut n: u32 = 1;
    loop {
        let suffix = if n == 1 {
            String::new()
        } else {
            format!("-{n}")
        };
        let meta_path = dir.join(format!("alx-events-{ts}{suffix}-meta.json"));
        let events_path = dir.join(format!("alx-events-{ts}{suffix}-events.jsonl"));

        let meta_file = match create_new_exclusive(&meta_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                n += 1;
                continue;
            }
            Err(e) => return Err(AppError::Io(e)),
        };

        match create_new_exclusive(&events_path) {
            Ok(events_file) => return Ok((meta_path, meta_file, events_path, events_file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                drop(meta_file);
                let _ = std::fs::remove_file(&meta_path);
                n += 1;
                continue;
            }
            Err(e) => return Err(AppError::Io(e)),
        }
    }
}

fn create_new_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

// =========================================================================
// events errors
// =========================================================================

#[derive(Debug, Serialize)]
pub struct ErrorsResponse {
    pub since: String,
    pub total_checked: usize,
    /// Entries in the raw `/1/events` response that failed to deserialize
    /// and were dropped rather than aborting the whole fetch — see
    /// `SampleResponse::skipped_count`'s doc comment (same field, same
    /// "always present, never silently omitted" rationale).
    pub skipped_count: usize,
    pub error_count: usize,
    pub window: EventsWindowSummary,
    pub truncated: bool,
    pub truncation_warning: Option<String>,
    pub groups: Vec<ErrorGroupRow>,
    pub session_ops: SessionOpsSnapshot,
}

/// (error message -> emitting eventName -> algoliaSource -> client) — this
/// row IS the "error class -> emitting component -> cause" table.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorGroupRow {
    pub error_message: String,
    pub event_name: String,
    pub algolia_source: String,
    pub client: String,
    pub count: usize,
    pub example_status: Option<u16>,
}

/// (error message, eventName, algoliaSource, client) -> (count, an example
/// status code). Named alias per clippy's type-complexity lint — this is
/// the exact grouping key the "error class -> emitting component -> cause"
/// table is built from.
type ErrorGroupKey = (String, String, String, String);
type ErrorGroupValue = (usize, Option<u16>);

fn is_error_event(e: &RawEvent) -> bool {
    e.status.map(|s| s != 200).unwrap_or(false) || !e.errors.is_empty()
}

fn error_message_of(e: &RawEvent) -> String {
    if !e.errors.is_empty() {
        e.errors.join("; ")
    } else {
        format!(
            "HTTP {} (no error message returned)",
            e.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".to_string())
        )
    }
}

fn group_errors(events: &[RawEvent]) -> Vec<ErrorGroupRow> {
    let mut groups: BTreeMap<ErrorGroupKey, ErrorGroupValue> = BTreeMap::new();
    for e in events.iter().filter(|e| is_error_event(e)) {
        let key = (
            error_message_of(e),
            event_name_key(e),
            algolia_source_key(e),
            classify_client(e).to_string(),
        );
        let entry = groups.entry(key).or_insert((0, e.status));
        entry.0 += 1;
    }
    let mut rows: Vec<ErrorGroupRow> = groups
        .into_iter()
        .map(
            |((error_message, event_name, algolia_source, client), (count, example_status))| {
                ErrorGroupRow {
                    error_message,
                    event_name,
                    algolia_source,
                    client,
                    count,
                    example_status,
                }
            },
        )
        .collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.count));
    rows
}

pub async fn run_errors(ctx: &AppContext, args: &EventsErrorsArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;

    let since_minutes = args.since.minutes;

    ctx.presenter.progress(&format!(
        "fetching insights events errors: region={INSIGHTS_REGION} since={}",
        args.since
    ));

    let parsed = fetch_sample(ctx, &app_id, &key, since_minutes, None).await?;
    let events = parsed.events;
    let skipped_count = parsed.skipped_count;
    let total_checked = events.len() + skipped_count;
    let window = compute_window(&events);
    let truncated = is_likely_truncated(total_checked);
    let error_count = events.iter().filter(|e| is_error_event(e)).count();
    let groups = group_errors(&events);

    let response = ErrorsResponse {
        since: args.since.to_string(),
        total_checked,
        skipped_count,
        error_count,
        window,
        truncated,
        truncation_warning: truncation_warning(truncated),
        groups,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_errors_human)
}

fn render_errors_human(r: &ErrorsResponse) -> String {
    let mut out = String::new();
    out.push_str(&format!("alx events errors — since {}\n", r.since));
    out.push_str(&format!(
        "checked {} events, {} failing (status != 200 or errors[] non-empty)\n",
        r.total_checked, r.error_count
    ));
    if r.skipped_count > 0 {
        out.push_str(&format!(
            "  !! {} event(s) dropped — malformed, could not be parsed (never silently lost)\n",
            r.skipped_count
        ));
    }
    if let Some(w) = &r.truncation_warning {
        out.push_str(&format!("  !! {w}\n"));
    }
    for g in r.groups.iter().take(50) {
        out.push_str(&format!(
            "  {:>6}x  status={:<5} error={:<40} event={:<20} source={:<30} client={}\n",
            g.count,
            g.example_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".to_string()),
            g.error_message,
            g.event_name,
            g.algolia_source,
            g.client
        ));
    }
    out.push('\n');
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn event(
        request_id: &str,
        minutes_ago: i64,
        status: Option<u16>,
        errors: Vec<&str>,
        payload: Option<EventPayload>,
        ua: Option<&str>,
    ) -> RawEvent {
        let mut headers = HashMap::new();
        if let Some(ua) = ua {
            headers.insert("User-Agent".to_string(), vec![ua.to_string()]);
        }
        RawEvent {
            request_id: Some(request_id.to_string()),
            received_at: Some(Utc::now() - chrono::Duration::minutes(minutes_ago)),
            path: Some("/1/events".to_string()),
            headers,
            status,
            event: payload,
            errors: errors.into_iter().map(str::to_string).collect(),
        }
    }

    fn simple_payload(
        event_name: &str,
        event_type: &str,
        algolia_source: Option<Vec<&str>>,
        query_id: Option<&str>,
        user_token: Option<&str>,
    ) -> EventPayload {
        EventPayload {
            event_name: Some(event_name.to_string()),
            event_type: Some(event_type.to_string()),
            event_subtype: None,
            index: Some("Product".to_string()),
            object_ids: vec!["obj1".to_string()],
            positions: vec![],
            query_id: query_id.map(str::to_string),
            user_token: user_token.map(str::to_string),
            authenticated_user_token: None,
            object_data: vec![],
            currency: None,
            timestamp: None,
            algolia_source: algolia_source.map(|v| v.into_iter().map(str::to_string).collect()),
        }
    }

    // ---- classify_client -------------------------------------------------

    #[test]
    fn classify_client_browser() {
        let e = event(
            "r1",
            1,
            Some(200),
            vec![],
            None,
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        );
        assert_eq!(classify_client(&e), "browser");
    }

    #[test]
    fn classify_client_hotwire_android() {
        let e = event(
            "r2",
            1,
            Some(200),
            vec![],
            None,
            Some("Hotwire Native Android/1.2 (1000farmacie)"),
        );
        assert_eq!(classify_client(&e), "Hotwire Native Android");
    }

    #[test]
    fn classify_client_hotwire_ios() {
        let e = event(
            "r3",
            1,
            Some(200),
            vec![],
            None,
            Some("Hotwire Native iOS/1.0 (iPhone; iOS 17.0)"),
        );
        assert_eq!(classify_client(&e), "Hotwire Native iOS");
    }

    #[test]
    fn classify_client_server_side_ruby_reuses_own_egress_marker() {
        let e = event(
            "r4",
            1,
            Some(200),
            vec![],
            None,
            Some("Algolia for Rails (3.12.2); Ruby (3.4.8)"),
        );
        assert_eq!(classify_client(&e), "server-side Ruby");
    }

    #[test]
    fn classify_client_missing_user_agent() {
        let e = event("r5", 1, Some(200), vec![], None, None);
        assert_eq!(classify_client(&e), "unknown (no User-Agent)");
    }

    #[test]
    fn classify_client_other_for_unrecognized_ua() {
        let e = event("r6", 1, Some(200), vec![], None, Some("curl/8.0"));
        assert_eq!(classify_client(&e), "other");
    }

    // ---- classify_user_token ---------------------------------------------

    #[test]
    fn user_token_shapes() {
        assert_eq!(
            classify_user_token(Some("anonymous-550e8400-e29b-41d4-a716-446655440000")),
            "anonymous-<uuid>"
        );
        assert_eq!(
            classify_user_token(Some("550e8400-e29b-41d4-a716-446655440000")),
            "plain uuid"
        );
        assert_eq!(classify_user_token(Some("1234567")), "numeric");
        assert_eq!(classify_user_token(Some("weird_token_xyz")), "other");
        assert_eq!(classify_user_token(None), "missing");
        assert_eq!(classify_user_token(Some("")), "missing");
    }

    // ---- algolia_source_key: absent vs empty are distinct -----------------

    #[test]
    fn algolia_source_key_absent_is_server_side_bucket() {
        let e = event(
            "r7",
            1,
            Some(200),
            vec![],
            Some(simple_payload("View", "view", None, None, None)),
            None,
        );
        assert_eq!(
            algolia_source_key(&e),
            "(none — server-side/hand-rolled emitter)"
        );
    }

    #[test]
    fn algolia_source_key_joins_multi_value_array() {
        let e = event(
            "r8",
            1,
            Some(200),
            vec![],
            Some(simple_payload(
                "Product Clicked",
                "click",
                Some(vec!["instantsearch", "instantsearch-internal"]),
                None,
                None,
            )),
            None,
        );
        assert_eq!(
            algolia_source_key(&e),
            "instantsearch,instantsearch-internal"
        );
    }

    // ---- count_by / count_error_messages -----------------------------------

    #[test]
    fn count_by_sorts_descending_by_count_then_key() {
        let events = vec![
            event(
                "a",
                1,
                Some(200),
                vec![],
                Some(simple_payload("View", "view", None, None, None)),
                None,
            ),
            event(
                "b",
                1,
                Some(200),
                vec![],
                Some(simple_payload("View", "view", None, None, None)),
                None,
            ),
            event(
                "c",
                1,
                Some(200),
                vec![],
                Some(simple_payload("Click", "click", None, None, None)),
                None,
            ),
        ];
        let rows = count_by(&events, event_name_key);
        assert_eq!(rows[0].key, "View");
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[1].key, "Click");
        assert_eq!(rows[1].count, 1);
    }

    #[test]
    fn count_error_messages_only_counts_events_with_errors() {
        let events = vec![
            event("a", 1, Some(200), vec![], None, None),
            event(
                "b",
                1,
                Some(422),
                vec!["The filters should be facet filters"],
                None,
                None,
            ),
            event(
                "c",
                1,
                Some(422),
                vec!["The filters should be facet filters"],
                None,
                None,
            ),
        ];
        let rows = count_error_messages(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "The filters should be facet filters");
        assert_eq!(rows[0].count, 2);
    }

    // ---- query_id_presence_by_event_type: per-type, never blended -----------

    #[test]
    fn query_id_presence_reported_per_event_type_not_blended() {
        let events = vec![
            // view: correctly never carries a queryID.
            event(
                "a",
                1,
                Some(200),
                vec![],
                Some(simple_payload("View", "view", None, None, None)),
                None,
            ),
            event(
                "b",
                1,
                Some(200),
                vec![],
                Some(simple_payload("View", "view", None, None, None)),
                None,
            ),
            // click: usually carries one.
            event(
                "c",
                1,
                Some(200),
                vec![],
                Some(simple_payload("Click", "click", None, Some("q1"), None)),
                None,
            ),
        ];
        let rows = query_id_presence_by_event_type(&events);
        let view_row = rows.iter().find(|r| r.event_type == "view").unwrap();
        assert_eq!(view_row.with_query_id, 0);
        assert_eq!(view_row.without_query_id, 2);
        let click_row = rows.iter().find(|r| r.event_type == "click").unwrap();
        assert_eq!(click_row.with_query_id, 1);
        assert_eq!(click_row.without_query_id, 0);
    }

    // ---- compute_window / truncation ---------------------------------------

    #[test]
    fn compute_window_computes_span_and_rate() {
        let events = vec![
            event("a", 10, Some(200), vec![], None, None),
            event("b", 0, Some(200), vec![], None, None),
        ];
        let w = compute_window(&events);
        assert_eq!(w.elapsed_minutes, Some(10));
        assert!(w.events_per_minute_observed.is_some());
        assert!(w.note.contains("sample at least"));
    }

    #[test]
    fn compute_window_handles_no_timestamped_events() {
        let events: Vec<RawEvent> = vec![];
        let w = compute_window(&events);
        assert_eq!(w.oldest_received_at, None);
        assert_eq!(w.elapsed_minutes, None);
        assert!(w.note.contains("not enough"));
    }

    #[test]
    fn is_likely_truncated_at_near_cap_threshold() {
        assert!(!is_likely_truncated(100));
        assert!(!is_likely_truncated(NEAR_CAP_THRESHOLD - 1));
        assert!(is_likely_truncated(NEAR_CAP_THRESHOLD));
        assert!(is_likely_truncated(3000));
    }

    #[test]
    fn truncation_warning_present_only_when_truncated() {
        assert!(truncation_warning(false).is_none());
        let w = truncation_warning(true).unwrap();
        assert!(w.to_lowercase().contains("silently dropped"));
        assert!(w.contains("3000"));
    }

    // ---- group_errors: the error-class -> component -> cause table --------

    #[test]
    fn group_errors_groups_by_all_four_dimensions() {
        let events = vec![
            event(
                "a",
                1,
                Some(422),
                vec!["The filters should be facet filters"],
                Some(simple_payload(
                    "Filter Applied",
                    "click",
                    Some(vec!["instantsearch-internal"]),
                    None,
                    None,
                )),
                Some("Mozilla/5.0"),
            ),
            event(
                "b",
                1,
                Some(422),
                vec!["The filters should be facet filters"],
                Some(simple_payload(
                    "Filter Applied",
                    "click",
                    Some(vec!["instantsearch-internal"]),
                    None,
                    None,
                )),
                Some("Mozilla/5.0"),
            ),
            event("c", 1, Some(200), vec![], None, None),
        ];
        let groups = group_errors(&events);
        assert_eq!(groups.len(), 1, "only the 422 pair should be grouped");
        assert_eq!(groups[0].count, 2);
        assert_eq!(
            groups[0].error_message,
            "The filters should be facet filters"
        );
        assert_eq!(groups[0].event_name, "Filter Applied");
        assert_eq!(groups[0].algolia_source, "instantsearch-internal");
        assert_eq!(groups[0].client, "browser");
        assert_eq!(groups[0].example_status, Some(422));
    }

    #[test]
    fn group_errors_ignores_status_200_with_no_error_array() {
        let events = vec![event("a", 1, Some(200), vec![], None, None)];
        assert!(group_errors(&events).is_empty());
    }

    #[test]
    fn group_errors_includes_non_200_even_with_empty_errors_array() {
        let events = vec![event("a", 1, Some(500), vec![], None, None)];
        let groups = group_errors(&events);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].error_message.contains("HTTP 500"));
    }

    // ---- --persist: never-overwrite contract -------------------------------

    fn unique_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "alx-events-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn claim_event_persist_paths_never_clobbers_sequential_runs() {
        let dir = unique_temp_dir("persist-sequential");
        std::fs::create_dir_all(&dir).unwrap();
        let ts = "20260804T120000Z";

        let (meta1, meta_file1, events1, events_file1) =
            claim_event_persist_paths(&dir, ts).unwrap();
        drop(meta_file1);
        drop(events_file1);

        let (meta2, meta_file2, events2, events_file2) =
            claim_event_persist_paths(&dir, ts).unwrap();
        drop(meta_file2);
        drop(events_file2);

        assert_ne!(meta1, meta2);
        assert_ne!(events1, events2);
        assert!(meta2.to_string_lossy().contains("-2-meta.json"));
        assert!(events2.to_string_lossy().contains("-2-events.jsonl"));
        assert!(meta1.exists());
        assert!(meta2.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_event_persist_paths_concurrent_runs_never_clobber_each_other() {
        let dir = unique_temp_dir("persist-concurrent");
        std::fs::create_dir_all(&dir).unwrap();
        let ts = "20260804T130000Z";
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let run =
            |marker: &'static str, dir: PathBuf, barrier: std::sync::Arc<std::sync::Barrier>| {
                std::thread::spawn(move || {
                    barrier.wait();
                    let (meta_path, mut meta_file, _events_path, mut events_file) =
                        claim_event_persist_paths(&dir, ts).unwrap();
                    std::thread::yield_now();
                    IoWrite::write_all(&mut meta_file, marker.as_bytes()).unwrap();
                    IoWrite::write_all(&mut events_file, marker.as_bytes()).unwrap();
                    meta_path
                })
            };

        let t1 = run("run-A", dir.clone(), barrier.clone());
        let t2 = run("run-B", dir.clone(), barrier);

        let meta1 = t1.join().unwrap();
        let meta2 = t2.join().unwrap();

        assert_ne!(meta1, meta2);
        let content1 = std::fs::read_to_string(&meta1).unwrap();
        let content2 = std::fs::read_to_string(&meta2).unwrap();
        assert_ne!(content1, content2);
        let mut markers = [content1.as_str(), content2.as_str()];
        markers.sort_unstable();
        assert_eq!(markers, ["run-A", "run-B"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_events_writes_meta_and_jsonl() {
        let dir = unique_temp_dir("persist-write");
        let events = vec![event("a", 1, Some(200), vec![], None, None)];
        let window = compute_window(&events);

        let summary = persist_events(
            dir.to_str().unwrap(),
            &events,
            "10m".to_string(),
            Some(5),
            &window,
            false,
            1,
            0,
        )
        .unwrap();

        let events_body = std::fs::read_to_string(&summary.events_file).unwrap();
        assert_eq!(events_body.lines().count(), 1);
        let meta_body = std::fs::read_to_string(&summary.meta_file).unwrap();
        assert!(meta_body.contains("\"fetched\": 1"));
        assert!(meta_body.contains("\"requested_limit\": 5"));
        assert!(meta_body.contains("\"skipped_count\": 0"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- totals / metrics ----------------------------------------------

    #[test]
    fn compute_totals_sums_null_buckets_as_zero_contribution() {
        let buckets = vec![
            MetricPoint {
                event_count: Some(100),
                error_count: Some(2),
                ..Default::default()
            },
            MetricPoint {
                event_count: None, // low/no-data bucket
                error_count: None,
                ..Default::default()
            },
            MetricPoint {
                event_count: Some(50),
                error_count: Some(1),
                ..Default::default()
            },
        ];
        let totals = compute_totals(&buckets);
        assert_eq!(totals.event_count, 150);
        assert_eq!(totals.error_count, 3);
        assert_eq!(totals.error_rate.value, Some(3.0 / 150.0));
        assert_eq!(totals.error_rate.label, "derived/approximate");
    }

    #[test]
    fn compute_totals_zero_events_yields_no_error_rate_not_nan() {
        let buckets = vec![MetricPoint::default()];
        let totals = compute_totals(&buckets);
        assert_eq!(totals.event_count, 0);
        assert_eq!(
            totals.error_rate.value, None,
            "must never divide by zero into NaN"
        );
    }

    // ---- human renderers (never exercised by any subprocess test — see
    // logs.rs's identical note: no controlling TTY under `std::process::
    // Command`, so `--human` is always overridden back to JSON there) ------

    fn sample_ops() -> SessionOpsSnapshot {
        SessionOpsSnapshot {
            logs_calls: 0,
            usage_calls: 0,
            analytics_calls: 0,
            keys_calls: 0,
            insights_calls: 1,
        }
    }

    #[test]
    fn render_metrics_human_shows_totals() {
        let response = MetricsResponse {
            since: "30d".to_string(),
            start_date: "2026-07-05".to_string(),
            end_date: "2026-08-03".to_string(),
            granularity: "hour".to_string(),
            approximate: true,
            totals: MetricsTotals {
                event_count: 1_000_000,
                click_count: 90_000,
                view_count: 850_000,
                conversion_count: 60_000,
                error_count: 137,
                error_rate: DerivedRate {
                    value: Some(137.0 / 1_000_000.0),
                    label: "derived/approximate",
                    formula: "sum(errorCount) / sum(eventCount) over the window",
                },
                neural_search_count: 0,
                recommend_frequently_bought_together_count: 0,
                recommend_related_products_count: 0,
                recommend_trending_items_count: 0,
                recommend_trending_facet_values_count: 0,
            },
            buckets: vec![],
            session_ops: sample_ops(),
        };
        let rendered = render_metrics_human(&response);
        assert!(rendered.contains("1000000"));
        assert!(rendered.contains("137"));
        assert!(rendered.contains("sum(errorCount)"));
    }

    #[test]
    fn render_sample_human_includes_truncation_warning_when_present() {
        let response = SampleResponse {
            since: "10m".to_string(),
            requested_limit: None,
            fetched: 2990,
            skipped_count: 0,
            window: EventsWindowSummary {
                oldest_received_at: Some(Utc::now()),
                newest_received_at: Some(Utc::now()),
                elapsed_minutes: Some(7),
                events_per_minute_observed: Some(400.0),
                note: "sample at least this often".to_string(),
            },
            truncated: true,
            truncation_warning: Some(
                "fetched count is at/near the live ~3000 event rolling-buffer cap".to_string(),
            ),
            by_event_name: vec![],
            by_event_type: vec![],
            by_event_subtype: vec![],
            by_algolia_source: vec![],
            by_client: vec![],
            by_status: vec![],
            by_error_message: vec![],
            query_id_presence_by_event_type: vec![],
            user_token_shape: vec![],
            persisted: None,
            session_ops: sample_ops(),
        };
        let rendered = render_sample_human(&response);
        assert!(rendered.contains("!!"));
        assert!(rendered.contains("rolling-buffer cap"));
        assert!(rendered.contains("2990"));
    }

    #[test]
    fn render_sample_human_shows_skipped_count_when_present() {
        let mut response = SampleResponse {
            since: "10m".to_string(),
            requested_limit: None,
            fetched: 5,
            skipped_count: 2,
            window: EventsWindowSummary {
                oldest_received_at: None,
                newest_received_at: None,
                elapsed_minutes: None,
                events_per_minute_observed: None,
                note: "n/a".to_string(),
            },
            truncated: false,
            truncation_warning: None,
            by_event_name: vec![],
            by_event_type: vec![],
            by_event_subtype: vec![],
            by_algolia_source: vec![],
            by_client: vec![],
            by_status: vec![],
            by_error_message: vec![],
            query_id_presence_by_event_type: vec![],
            user_token_shape: vec![],
            persisted: None,
            session_ops: sample_ops(),
        };
        let rendered = render_sample_human(&response);
        assert!(
            rendered.contains("2 event(s) dropped"),
            "skipped_count must be surfaced in the human render, never silent: {rendered}"
        );

        response.skipped_count = 0;
        let rendered_no_skips = render_sample_human(&response);
        assert!(
            !rendered_no_skips.contains("dropped"),
            "must not show a skip warning when skipped_count is zero: {rendered_no_skips}"
        );
    }

    #[test]
    fn render_errors_human_lists_groups() {
        let response = ErrorsResponse {
            since: "10m".to_string(),
            total_checked: 100,
            skipped_count: 0,
            error_count: 2,
            window: EventsWindowSummary {
                oldest_received_at: None,
                newest_received_at: None,
                elapsed_minutes: None,
                events_per_minute_observed: None,
                note: "n/a".to_string(),
            },
            truncated: false,
            truncation_warning: None,
            groups: vec![ErrorGroupRow {
                error_message: "The filters should be facet filters".to_string(),
                event_name: "Filter Applied".to_string(),
                algolia_source: "instantsearch-internal".to_string(),
                client: "browser".to_string(),
                count: 2,
                example_status: Some(422),
            }],
            session_ops: sample_ops(),
        };
        let rendered = render_errors_human(&response);
        assert!(rendered.contains("The filters should be facet filters"));
        assert!(rendered.contains("Filter Applied"));
        assert!(rendered.contains("422"));
    }
}
