//! `alx analytics top-searches|no-results|scrape-signals` (D9). The
//! scrape-signal heuristics (A2) are the least certain part of the design
//! (A3) — every signal is reported as a distinct, independently-fired
//! "suspicious pattern", never as a confirmed finding. Do not add wording
//! anywhere in this file that asserts abuse as fact.
//!
//! D0.3: every entry point runs `safety::preflight_privilege_check` (via
//! this module's `preflight` helper) right after credential resolution,
//! before the first real analytics call.

use crate::algolia::analytics::{
    self, AddToCartRateResponse, AverageClickPositionResponse, ClickPositionBucket,
    ClickThroughRateResponse, ConversionRateResponse, NoResultRateResponse, NoResultRow,
    PurchaseRateResponse, Throttle, TopSearchRow,
};
use crate::cli::{
    AnalyticsClicksArgs, AnalyticsConversionsArgs, AnalyticsNoResultsArgs, AnalyticsRevenueArgs,
    AnalyticsScrapeSignalsArgs, AnalyticsTopSearchesArgs,
};
use crate::constants;
use crate::context::AppContext;
use crate::display;
use crate::error::{AppError, AppResult};
use crate::http::Surface;
use crate::output::{format_session_ops_line, SessionOpsSnapshot};
use serde::Serialize;

/// `scrape-signals` samples this many rows off `/2/searches` — the max the
/// endpoint allows (Analytics API reference) — so the enumeration/flat-
/// distribution heuristics see as much of the query shape as Algolia will
/// hand back in one page.
const SCRAPE_SIGNALS_SAMPLE_LIMIT: u32 = 1000;

fn resolve_credentials(ctx: &AppContext) -> AppResult<(String, String)> {
    let app_id = ctx.resolve_app_id().ok_or_else(|| {
        AppError::InvalidInput(
            "ALGOLIA_APPLICATION_ID is not set (and --app-id was not passed)".to_string(),
        )
    })?;
    let key = ctx.resolve_key(Surface::Analytics).ok_or_else(|| {
        AppError::InvalidInput(
            "no Analytics API key found — set ALGOLIA_ANALYTICS_API_KEY (or the generic ALGOLIA_API_KEY, or pass --key)"
                .to_string(),
        )
    })?;
    Ok((app_id, key))
}

/// D0.3 over-privilege gate, shared by all three entry points. Base URL is
/// sourced from `ctx.base_urls.search(app_id)` (the same search host `keys
/// audit` probes), so `ALX_SEARCH_BASE_URL` redirects the self-check at a
/// mock server in tests.
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
// top-searches
// =========================================================================

#[derive(Debug, Serialize)]
struct TopSearchesOut {
    index: String,
    region: String,
    since: String,
    rows: Vec<TopSearchRow>,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_top_searches(ctx: &AppContext, args: &AnalyticsTopSearchesArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;
    // No --index flag exists on this subcommand (by design): the
    // frontend's primary search index is the sole documented default.
    let index = constants::FRONTEND_INDEXES[0];
    let region = args.region.to_string();
    let since_days = args.since.days();
    let throttle = Throttle::production();

    ctx.presenter.progress(&format!(
        "fetching top searches: index={index} region={region} since_days={since_days}"
    ));

    let rows = analytics::top_searches(
        ctx, &app_id, &key, &region, index, since_days, args.limit, None, &throttle,
    )
    .await?;

    let response = TopSearchesOut {
        index: index.to_string(),
        region,
        since: args.since.to_string(),
        rows,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_top_searches_human)
}

fn render_top_searches_human(r: &TopSearchesOut) -> String {
    let mut out = String::new();
    out.push_str(&display::heading(&format!(
        "alx analytics top-searches — {} ({}, since {})",
        r.index, r.region, r.since
    )));
    out.push('\n');
    if r.rows.is_empty() {
        out.push_str("  (no searches in window)\n");
    } else {
        for row in &r.rows {
            out.push_str(&format!(
                "  {:>7}  nbHits={:<6}  {}\n",
                row.count, row.nb_hits, row.search
            ));
        }
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

// =========================================================================
// no-results
// =========================================================================

#[derive(Debug, Serialize)]
struct NoResultsOut {
    index: String,
    region: String,
    since: String,
    rows: Vec<NoResultRow>,
    overall_rate: NoResultRateResponse,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_no_results(ctx: &AppContext, args: &AnalyticsNoResultsArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;
    let index = constants::FRONTEND_INDEXES[0];
    let region = args.region.to_string();
    let since_days = args.since.days();
    let throttle = Throttle::production();

    // Sequential through the same throttle instance (A1) — this command's
    // whole point is pairing the list with the overall rate (U-style "never
    // show only one meter" instinct applied to no-results: never show the
    // list without the headline noResultRate).
    let rows = analytics::no_results(
        ctx, &app_id, &key, &region, index, since_days, args.limit, None, &throttle,
    )
    .await?;

    let overall_rate =
        analytics::no_result_rate(ctx, &app_id, &key, &region, index, since_days, &throttle)
            .await?;

    let response = NoResultsOut {
        index: index.to_string(),
        region,
        since: args.since.to_string(),
        rows,
        overall_rate,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_no_results_human)
}

fn render_no_results_human(r: &NoResultsOut) -> String {
    let mut out = String::new();
    out.push_str(&display::heading(&format!(
        "alx analytics no-results — {} ({}, since {})",
        r.index, r.region, r.since
    )));
    out.push('\n');
    let rate_str = match r.overall_rate.rate {
        Some(rate) => format!("{:.2}%", rate * 100.0),
        None => "n/a (no searches in window)".to_string(),
    };
    out.push_str(&display::kv_line(
        "overall noResultRate",
        format!(
            "{rate_str} ({} of {} searches)",
            r.overall_rate.no_result_count, r.overall_rate.count
        ),
    ));
    out.push('\n');
    if r.rows.is_empty() {
        out.push_str("  (no zero-result queries in window)\n");
    } else {
        for row in &r.rows {
            out.push_str(&format!(
                "  {:>7}  withFilterCount={:<6}  {}\n",
                row.count, row.with_filter_count, row.search
            ));
        }
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

// =========================================================================
// clicks (retires the v0.1 "no analytics click/conversion endpoints"
// non-goal): clickThroughRate + averageClickPosition + positions, plus the
// /2/status freshness stamp every clicks/conversions/revenue response
// carries — a post-deploy re-measurement is worthless if the analytics data
// has not refreshed yet.
// =========================================================================

#[derive(Debug, Serialize)]
struct ClicksOut {
    index: String,
    region: String,
    since: String,
    updated_at: Option<String>,
    click_through_rate: ClickThroughRateResponse,
    average_click_position: AverageClickPositionResponse,
    positions: Vec<ClickPositionBucket>,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_clicks(ctx: &AppContext, args: &AnalyticsClicksArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;
    let index = constants::FRONTEND_INDEXES[0];
    let region = args.region.to_string();
    let since_days = args.since.days();
    let throttle = Throttle::production();

    ctx.presenter.progress(&format!(
        "fetching clicks: index={index} region={region} since_days={since_days}"
    ));

    // Sequential through ONE shared throttle (A1) — four calls, so this
    // command alone is a third of the 100req/min ceiling's per-minute
    // budget at the floor spacing; never fire these concurrently.
    let click_through_rate =
        analytics::click_through_rate(ctx, &app_id, &key, &region, index, since_days, &throttle)
            .await?;
    let average_click_position = analytics::average_click_position(
        ctx, &app_id, &key, &region, index, since_days, &throttle,
    )
    .await?;
    let positions =
        analytics::click_positions(ctx, &app_id, &key, &region, index, since_days, &throttle)
            .await?;
    let status =
        analytics::status(ctx, &app_id, &key, &region, index, since_days, &throttle).await?;

    let response = ClicksOut {
        index: index.to_string(),
        region,
        since: args.since.to_string(),
        updated_at: status.updated_at,
        click_through_rate,
        average_click_position,
        positions: positions.positions,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_clicks_human)
}

/// `[start, end]` bucket -> a human-friendly label, decoding the `end ==
/// -1` "unbounded" sentinel (see `ClickPositionBucket` doc comment) instead
/// of printing a confusing literal `-1`.
fn format_position_bucket(start: i64, end: i64) -> String {
    if end == -1 {
        format!("{start}+")
    } else if start == end {
        format!("{start}")
    } else {
        format!("{start}-{end}")
    }
}

fn format_rate_pct(rate: Option<f64>) -> String {
    match rate {
        Some(r) => format!("{:.2}%", r * 100.0),
        None => "n/a (no data)".to_string(),
    }
}

/// `/2/status`'s `updatedAt` is `None` when Algolia has no analytics data
/// for this region/index yet (confirmed live 2026-08-04: HTTP 200 with
/// `{"updatedAt": null}`, not an error) — render that honestly rather than
/// as an empty line or the literal text "None". Shared by `clicks`,
/// `conversions`, and `revenue`, the three commands that surface freshness.
fn format_freshness(updated_at: &Option<String>) -> String {
    match updated_at {
        Some(ts) => ts.clone(),
        None => "freshness: no analytics data in this region yet".to_string(),
    }
}

fn render_clicks_human(r: &ClicksOut) -> String {
    let mut out = String::new();
    out.push_str(&display::heading(&format!(
        "alx analytics clicks — {} ({}, since {})",
        r.index, r.region, r.since
    )));
    out.push('\n');
    out.push_str(&display::kv_line(
        "data freshness (updatedAt)",
        format_freshness(&r.updated_at),
    ));
    out.push('\n');
    out.push_str(&display::kv_line(
        "click-through rate",
        format!(
            "{} ({} of {} tracked searches)",
            format_rate_pct(r.click_through_rate.rate),
            r.click_through_rate.click_count,
            r.click_through_rate.tracked_search_count
        ),
    ));
    out.push('\n');
    out.push_str(&display::kv_line(
        "average click position",
        match r.average_click_position.average {
            Some(avg) => format!("{avg:.2} ({} clicks)", r.average_click_position.click_count),
            None => "n/a (no clicks in window)".to_string(),
        },
    ));
    out.push('\n');
    out.push_str("  position histogram:\n");
    if r.positions.is_empty() {
        out.push_str("    (no click position data in window)\n");
    } else {
        for bucket in &r.positions {
            out.push_str(&format!(
                "    {:>8}  {}\n",
                format_position_bucket(bucket.position.0, bucket.position.1),
                bucket.click_count
            ));
        }
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

// =========================================================================
// conversions: conversionRate + addToCartRate + purchaseRate side by side,
// plus /2/status freshness.
// =========================================================================

#[derive(Debug, Serialize)]
struct ConversionsOut {
    index: String,
    region: String,
    since: String,
    updated_at: Option<String>,
    conversion_rate: ConversionRateResponse,
    add_to_cart_rate: AddToCartRateResponse,
    purchase_rate: PurchaseRateResponse,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_conversions(ctx: &AppContext, args: &AnalyticsConversionsArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;
    let index = constants::FRONTEND_INDEXES[0];
    let region = args.region.to_string();
    let since_days = args.since.days();
    let throttle = Throttle::production();

    ctx.presenter.progress(&format!(
        "fetching conversions: index={index} region={region} since_days={since_days}"
    ));

    // Sequential through ONE shared throttle (A1) — same reasoning as
    // `clicks`: four calls, never fired concurrently.
    let conversion_rate =
        analytics::conversion_rate(ctx, &app_id, &key, &region, index, since_days, &throttle)
            .await?;
    let add_to_cart_rate =
        analytics::add_to_cart_rate(ctx, &app_id, &key, &region, index, since_days, &throttle)
            .await?;
    let purchase_rate =
        analytics::purchase_rate(ctx, &app_id, &key, &region, index, since_days, &throttle).await?;
    let status =
        analytics::status(ctx, &app_id, &key, &region, index, since_days, &throttle).await?;

    let response = ConversionsOut {
        index: index.to_string(),
        region,
        since: args.since.to_string(),
        updated_at: status.updated_at,
        conversion_rate,
        add_to_cart_rate,
        purchase_rate,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_conversions_human)
}

fn render_conversions_human(r: &ConversionsOut) -> String {
    let mut out = String::new();
    out.push_str(&display::heading(&format!(
        "alx analytics conversions — {} ({}, since {})",
        r.index, r.region, r.since
    )));
    out.push('\n');
    out.push_str(&display::kv_line(
        "data freshness (updatedAt)",
        format_freshness(&r.updated_at),
    ));
    out.push('\n');
    out.push_str(&display::kv_line(
        "conversion rate",
        format!(
            "{} ({} of {} tracked searches)",
            format_rate_pct(r.conversion_rate.rate),
            r.conversion_rate.conversion_count,
            r.conversion_rate.tracked_search_count
        ),
    ));
    out.push('\n');
    out.push_str(&display::kv_line(
        "add-to-cart rate",
        format!(
            "{} ({} of {} tracked searches)",
            format_rate_pct(r.add_to_cart_rate.rate),
            r.add_to_cart_rate.add_to_cart_count,
            r.add_to_cart_rate.tracked_search_count
        ),
    ));
    out.push('\n');
    out.push_str(&display::kv_line(
        "purchase rate",
        format!(
            "{} ({} of {} tracked searches)",
            format_rate_pct(r.purchase_rate.rate),
            r.purchase_rate.purchase_count,
            r.purchase_rate.tracked_search_count
        ),
    ));
    out.push('\n');
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

// =========================================================================
// revenue: the `currencies` map flattened to a row per currency (rule 9:
// never assume EUR), plus /2/status freshness.
// =========================================================================

#[derive(Debug, Clone, Serialize)]
struct RevenueRow {
    currency: String,
    revenue: f64,
    average_order_value: f64,
    transaction_count: u64,
}

#[derive(Debug, Serialize)]
struct RevenueOut {
    index: String,
    region: String,
    since: String,
    updated_at: Option<String>,
    currencies: Vec<RevenueRow>,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_revenue(ctx: &AppContext, args: &AnalyticsRevenueArgs) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;
    let index = constants::FRONTEND_INDEXES[0];
    let region = args.region.to_string();
    let since_days = args.since.days();
    let throttle = Throttle::production();

    ctx.presenter.progress(&format!(
        "fetching revenue: index={index} region={region} since_days={since_days}"
    ));

    let revenue =
        analytics::revenue(ctx, &app_id, &key, &region, index, since_days, &throttle).await?;
    let status =
        analytics::status(ctx, &app_id, &key, &region, index, since_days, &throttle).await?;

    // BTreeMap iteration is already key-sorted (deterministic); the row's
    // own `currency` field (not the map key) drives the label, per rule 9 —
    // never assume EUR, render whatever Algolia actually returned.
    let currencies: Vec<RevenueRow> = revenue
        .currencies
        .into_values()
        .map(|cr| RevenueRow {
            currency: cr.currency,
            revenue: cr.revenue,
            average_order_value: cr.average_order_value,
            transaction_count: cr.transaction_count,
        })
        .collect();

    let response = RevenueOut {
        index: index.to_string(),
        region,
        since: args.since.to_string(),
        updated_at: status.updated_at,
        currencies,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_revenue_human)
}

fn render_revenue_human(r: &RevenueOut) -> String {
    let mut out = String::new();
    out.push_str(&display::heading(&format!(
        "alx analytics revenue — {} ({}, since {})",
        r.index, r.region, r.since
    )));
    out.push('\n');
    out.push_str(&display::kv_line(
        "data freshness (updatedAt)",
        format_freshness(&r.updated_at),
    ));
    out.push('\n');
    if r.currencies.is_empty() {
        out.push_str("  (no revenue in window)\n");
    } else {
        for row in &r.currencies {
            out.push_str(&format!(
                "  {:<4}  revenue={:>12.2}  avg_order_value={:>8.2}  transactions={}\n",
                row.currency, row.revenue, row.average_order_value, row.transaction_count
            ));
        }
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

// =========================================================================
// scrape-signals (A2/A3)
// =========================================================================

#[derive(Debug, Clone, Serialize)]
pub struct ScrapeSignal {
    pub signal: &'static str,
    pub fired: bool,
    pub evidence: Vec<String>,
    pub explanation: String,
}

#[derive(Debug, Serialize)]
struct ScrapeSignalsOut {
    index: String,
    region: String,
    since: String,
    sampled_queries: usize,
    signals: Vec<ScrapeSignal>,
    session_ops: SessionOpsSnapshot,
}

pub async fn run_scrape_signals(
    ctx: &AppContext,
    args: &AnalyticsScrapeSignalsArgs,
) -> AppResult<()> {
    let (app_id, key) = resolve_credentials(ctx)?;
    preflight(ctx, &app_id, &key).await?;
    let index = constants::FRONTEND_INDEXES[0];
    let region = args.region.to_string();
    let since_days = args.since.days();
    let throttle = Throttle::production();

    let rows = analytics::top_searches(
        ctx,
        &app_id,
        &key,
        &region,
        index,
        since_days,
        Some(SCRAPE_SIGNALS_SAMPLE_LIMIT),
        None,
        &throttle,
    )
    .await?;

    let signals = compute_scrape_signals(&rows);

    let response = ScrapeSignalsOut {
        index: index.to_string(),
        region,
        since: args.since.to_string(),
        sampled_queries: rows.len(),
        signals,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter
        .success(&response, render_scrape_signals_human)
}

fn render_scrape_signals_human(r: &ScrapeSignalsOut) -> String {
    let mut out = String::new();
    out.push_str(&display::heading(&format!(
        "alx analytics scrape-signals — {} ({}, since {}, {} sampled queries)",
        r.index, r.region, r.since, r.sampled_queries
    )));
    out.push('\n');
    for s in &r.signals {
        out.push_str(&format!(
            "  [{}] {}\n",
            display::status_marker(!s.fired),
            s.signal
        ));
        out.push_str(&format!("      {}\n", s.explanation));
        for e in &s.evidence {
            out.push_str(&format!("      - {e}\n"));
        }
    }
    out.push_str(&format_session_ops_line(&r.session_ops));
    out
}

/// A2: the four DISTINCT heuristics, each independently fired and reported
/// — never merged into one generic "anomaly" bucket, so an operator can
/// tell exactly which pattern(s) matched.
fn compute_scrape_signals(rows: &[TopSearchRow]) -> Vec<ScrapeSignal> {
    vec![
        detect_enumeration(rows),
        detect_empty_query_high_volume(rows),
        detect_test_or_foreign_strings(rows),
        detect_flat_distribution(rows),
    ]
}

const ENUMERATION_RUN_THRESHOLD: usize = 4;

/// (1) Systematic/alphabetical enumeration: the longest run of distinct
/// queries that are lexicographic successors of each other (same length,
/// identical prefix, last character advancing by exactly one — "aa", "ab",
/// "ac", ...). A long run is a suspicious pattern consistent with a
/// systematic enumeration sweep; it is not proof on its own.
fn detect_enumeration(rows: &[TopSearchRow]) -> ScrapeSignal {
    let mut terms: Vec<String> = rows
        .iter()
        .map(|r| r.search.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    terms.sort();
    terms.dedup();

    let mut best_run: Vec<String> = Vec::new();
    let mut current_run: Vec<String> = Vec::new();

    for term in &terms {
        let extends = match current_run.last() {
            Some(prev) => is_alpha_successor(prev, term),
            None => true,
        };
        if extends {
            current_run.push(term.clone());
        } else {
            if current_run.len() > best_run.len() {
                best_run = std::mem::take(&mut current_run);
            } else {
                current_run.clear();
            }
            current_run.push(term.clone());
        }
    }
    if current_run.len() > best_run.len() {
        best_run = current_run;
    }

    let fired = best_run.len() >= ENUMERATION_RUN_THRESHOLD;

    ScrapeSignal {
        signal: "systematic_enumeration",
        fired,
        evidence: if fired { best_run.clone() } else { Vec::new() },
        explanation: format!(
            "longest alphabetically-sequential run of distinct queries: {} term(s) (threshold {ENUMERATION_RUN_THRESHOLD}) — a long run is a suspicious pattern consistent with a systematic enumeration sweep, not proof on its own",
            best_run.len()
        ),
    }
}

/// True if `b` is the lexicographic successor of `a`: same character
/// length, identical prefix up to the last character, and the last
/// character advances by exactly one code point (e.g. "aa" -> "ab").
fn is_alpha_successor(a: &str, b: &str) -> bool {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    if a_chars.is_empty() || a_chars.len() != b_chars.len() {
        return false;
    }
    let n = a_chars.len();
    if a_chars[..n - 1] != b_chars[..n - 1] {
        return false;
    }
    (b_chars[n - 1] as u32).wrapping_sub(a_chars[n - 1] as u32) == 1
}

const EMPTY_QUERY_SHARE_THRESHOLD: f64 = 0.20;

/// (2) High-volume empty-string query: an empty search string carrying an
/// outsized share of sampled volume (or ranking #1 outright) is consistent
/// with systematic catalogue-walking / deep-offset pagination rather than
/// organic search, since there is no query term driving the traffic — a
/// suspicious pattern, not proof of abuse.
fn detect_empty_query_high_volume(rows: &[TopSearchRow]) -> ScrapeSignal {
    let total: u64 = rows.iter().map(|r| r.count).sum();
    let empty = rows.iter().find(|r| r.search.trim().is_empty());

    let mut evidence = Vec::new();
    let mut fired = false;

    if let Some(row) = empty {
        let share = if total > 0 {
            row.count as f64 / total as f64
        } else {
            0.0
        };
        let is_top = rows
            .iter()
            .all(|r| r.search.trim().is_empty() || r.count <= row.count);
        if is_top || share >= EMPTY_QUERY_SHARE_THRESHOLD {
            fired = true;
            evidence.push(format!(
                "empty-string query: count={}, share of sampled volume={:.1}%, rank #1={is_top}",
                row.count,
                share * 100.0
            ));
        }
    }

    ScrapeSignal {
        signal: "empty_query_high_volume_pagination",
        fired,
        evidence,
        explanation: "an empty-string query dominating search volume is a suspicious pattern consistent with systematic catalogue-walking / deep-offset pagination rather than organic search — not proof of abuse on its own"
            .to_string(),
    }
}

const TEST_STRING_LITERALS: [&str; 10] = [
    "test", "testing", "testtest", "asdf", "asdfasdf", "qwerty", "1234", "12345", "xxxx", "foobar",
];

fn is_test_string(q: &str) -> bool {
    let lower = q.trim().to_lowercase();
    if lower.is_empty() {
        return false;
    }
    if TEST_STRING_LITERALS.contains(&lower.as_str()) {
        return true;
    }
    // A single character repeated 3+ times ("aaaa", "zzzz") — keyboard-mash
    // shaped, not an organic search term.
    let chars: Vec<char> = lower.chars().collect();
    chars.len() >= 3 && chars.iter().all(|c| *c == chars[0])
}

/// Characters from a script this Italian storefront does not serve
/// (Cyrillic, Hebrew, Arabic, Devanagari, CJK, Hangul, ...). Broad,
/// deliberately non-exhaustive ranges — good enough to flag as evidence,
/// not to assert with certainty.
fn is_non_latin_script(q: &str) -> bool {
    q.chars().any(|c| {
        let cp = c as u32;
        matches!(cp,
            0x0400..=0x04FF   // Cyrillic
            | 0x0530..=0x058F // Armenian
            | 0x0590..=0x05FF // Hebrew
            | 0x0600..=0x06FF // Arabic
            | 0x0900..=0x097F // Devanagari
            | 0x3040..=0x30FF // Hiragana/Katakana
            | 0x4E00..=0x9FFF // CJK unified
            | 0xAC00..=0xD7A3 // Hangul
        )
    })
}

const TEST_STRING_RATIO_THRESHOLD: f64 = 0.10;
const TEST_STRING_COUNT_THRESHOLD: usize = 3;

/// (3) Non-served-language / test-string queries: a meaningful fraction of
/// sampled queries look like keyboard-mash test strings, or use a script
/// the storefront doesn't serve (site content is Italian). A suspicious
/// pattern, not proof of a non-organic source.
fn detect_test_or_foreign_strings(rows: &[TopSearchRow]) -> ScrapeSignal {
    let mut evidence = Vec::new();
    let mut flagged = 0usize;
    let mut sampled = 0usize;

    for row in rows {
        let q = row.search.trim();
        if q.is_empty() {
            continue;
        }
        sampled += 1;
        if is_test_string(q) {
            flagged += 1;
            evidence.push(format!(
                "\"{}\" (count={}) — test/keyboard-mash pattern",
                row.search, row.count
            ));
        } else if is_non_latin_script(q) {
            flagged += 1;
            evidence.push(format!(
                "\"{}\" (count={}) — script the storefront does not serve",
                row.search, row.count
            ));
        }
    }

    let ratio = if sampled > 0 {
        flagged as f64 / sampled as f64
    } else {
        0.0
    };
    let fired = flagged > 0
        && (ratio >= TEST_STRING_RATIO_THRESHOLD || flagged >= TEST_STRING_COUNT_THRESHOLD);

    ScrapeSignal {
        signal: "non_served_language_or_test_strings",
        fired,
        evidence: evidence.into_iter().take(20).collect(),
        explanation: format!(
            "{flagged}/{sampled} sampled queries ({:.1}%) look like test/keyboard-mash strings or use a script this storefront doesn't serve — a suspicious pattern, not proof of a non-organic source",
            ratio * 100.0
        ),
    }
}

const FLAT_TOP1_SHARE_THRESHOLD: f64 = 0.15;
const FLAT_GINI_THRESHOLD: f64 = 0.15;
const FLAT_MIN_SAMPLE: usize = 5;

/// (4) Flat distribution: organic search popularity is normally
/// heavy-tailed (a handful of dominant terms, then a long tail). Counts
/// unusually close to uniform across the sample — measured as both a low
/// top-1/top-10 share and a low Gini coefficient — is a suspicious pattern
/// consistent with programmatic/systematic querying, not proof of abuse.
fn detect_flat_distribution(rows: &[TopSearchRow]) -> ScrapeSignal {
    let mut counts: Vec<u64> = rows.iter().map(|r| r.count).collect();
    counts.sort_unstable_by(|a, b| b.cmp(a)); // descending

    if counts.len() < FLAT_MIN_SAMPLE {
        return ScrapeSignal {
            signal: "flat_distribution",
            fired: false,
            evidence: Vec::new(),
            explanation: format!(
                "fewer than {FLAT_MIN_SAMPLE} distinct queries sampled — not enough data to assess distribution shape"
            ),
        };
    }

    let top1 = counts[0] as f64;
    let top10_sum: f64 = counts.iter().take(10).sum::<u64>() as f64;
    let top1_over_top10 = if top10_sum > 0.0 {
        top1 / top10_sum
    } else {
        0.0
    };
    let gini = gini_coefficient(&counts);

    let fired = top1_over_top10 < FLAT_TOP1_SHARE_THRESHOLD && gini < FLAT_GINI_THRESHOLD;

    ScrapeSignal {
        signal: "flat_distribution",
        fired,
        evidence: vec![format!(
            "top1/top10 share={top1_over_top10:.3} (threshold <{FLAT_TOP1_SHARE_THRESHOLD:.2}), gini={gini:.3} (threshold <{FLAT_GINI_THRESHOLD:.2}), sampled queries={}",
            counts.len()
        )],
        explanation: "search counts unusually close to uniform across the sample — organic query popularity is normally heavy-tailed, so a flat shape is a suspicious pattern consistent with programmatic/systematic querying, not proof of abuse"
            .to_string(),
    }
}

/// Standard discrete Gini coefficient over non-negative counts: 0.0 =
/// perfectly flat (every query equally popular), closer to 1.0 = a classic
/// long tail dominated by a few terms.
fn gini_coefficient(counts: &[u64]) -> f64 {
    let n = counts.len();
    if n == 0 {
        return 0.0;
    }
    let mut asc: Vec<f64> = counts.iter().map(|&c| c as f64).collect();
    asc.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let sum: f64 = asc.iter().sum();
    if sum <= 0.0 {
        return 0.0;
    }
    let weighted: f64 = asc
        .iter()
        .enumerate()
        .map(|(idx, x)| (idx as f64 + 1.0) * x)
        .sum();
    let n_f = n as f64;
    ((2.0 * weighted - (n_f + 1.0) * sum) / (n_f * sum)).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(search: &str, count: u64) -> TopSearchRow {
        TopSearchRow {
            search: search.to_string(),
            count,
            nb_hits: 10,
        }
    }

    // -------------------------------------------------------------------
    // `render_top_searches_human`/`render_no_results_human`/
    // `render_scrape_signals_human` (--human path): never called by any
    // subprocess test in practice — every `alx` invocation spawned via
    // `std::process::Command` has no controlling TTY on stdin, so
    // `agent::detect`'s TTY check unconditionally forces JSON regardless
    // of `--human`. The only way to exercise these functions at all is a
    // direct, in-process call.
    // -------------------------------------------------------------------

    fn sample_session_ops() -> SessionOpsSnapshot {
        SessionOpsSnapshot {
            logs_calls: 0,
            usage_calls: 0,
            analytics_calls: 2,
            keys_calls: 0,
            insights_calls: 0,
        }
    }

    #[test]
    fn render_top_searches_human_lists_every_row() {
        let response = TopSearchesOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            rows: vec![row("scarpe da corsa", 300), row("crema solare", 210)],
            session_ops: sample_session_ops(),
        };

        let rendered = render_top_searches_human(&response);

        assert!(rendered.contains("Product"));
        assert!(rendered.contains("scarpe da corsa"));
        assert!(rendered.contains("crema solare"));
        assert!(rendered.contains("300"));
    }

    #[test]
    fn render_top_searches_human_handles_empty_rows() {
        let response = TopSearchesOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            rows: vec![],
            session_ops: sample_session_ops(),
        };

        let rendered = render_top_searches_human(&response);
        assert!(rendered.contains("no searches"));
    }

    #[test]
    fn render_no_results_human_shows_overall_rate_and_rows() {
        let mut r = row("query inesistente", 42);
        r.nb_hits = 0;
        let response = NoResultsOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            rows: vec![NoResultRow {
                search: "query inesistente".to_string(),
                count: 42,
                with_filter_count: 3,
            }],
            overall_rate: NoResultRateResponse {
                rate: Some(0.123),
                count: 1000,
                no_result_count: 123,
                dates: vec![],
            },
            session_ops: sample_session_ops(),
        };

        let rendered = render_no_results_human(&response);

        assert!(rendered.contains("12.30%"));
        assert!(rendered.contains("query inesistente"));
        assert!(rendered.contains("123"));
        assert!(rendered.contains("1000"));
    }

    #[test]
    fn render_no_results_human_handles_no_searches_in_window() {
        let response = NoResultsOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            rows: vec![],
            overall_rate: NoResultRateResponse {
                rate: None,
                count: 0,
                no_result_count: 0,
                dates: vec![],
            },
            session_ops: sample_session_ops(),
        };

        let rendered = render_no_results_human(&response);
        assert!(rendered.contains("n/a"));
        assert!(rendered.contains("no zero-result queries"));
    }

    #[test]
    fn render_scrape_signals_human_renders_fired_and_unfired_signals() {
        let response = ScrapeSignalsOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            sampled_queries: 1000,
            signals: vec![
                ScrapeSignal {
                    signal: "systematic_enumeration",
                    fired: true,
                    evidence: vec!["aa -> ab -> ac".to_string()],
                    explanation: "suspicious pattern: alphabetical run detected".to_string(),
                },
                ScrapeSignal {
                    signal: "flat_distribution",
                    fired: false,
                    evidence: vec![],
                    explanation: "distribution looks organic".to_string(),
                },
            ],
            session_ops: sample_session_ops(),
        };

        let rendered = render_scrape_signals_human(&response);

        assert!(rendered.contains("systematic_enumeration"));
        assert!(rendered.contains("flat_distribution"));
        assert!(rendered.contains("aa -> ab -> ac"));
        assert!(rendered.contains("suspicious pattern"));
        assert!(rendered.contains("1000 sampled queries"));
    }

    // ---- clicks/conversions/revenue human renderers ---------------------
    // (ClickThroughRateResponse etc. already in scope via `use super::*;`
    // above, since this module's outer `use crate::algolia::analytics::{...}`
    // brought them in.)

    #[test]
    fn render_clicks_human_shows_freshness_rates_and_histogram() {
        let response = ClicksOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            updated_at: Some("2026-08-04T06:00:00.000Z".to_string()),
            click_through_rate: ClickThroughRateResponse {
                rate: Some(0.105),
                tracked_search_count: 120000,
                click_count: 12600,
                dates: vec![],
            },
            average_click_position: AverageClickPositionResponse {
                average: Some(6.42),
                click_count: 12600,
                dates: vec![],
            },
            positions: vec![
                ClickPositionBucket {
                    position: (1, 1),
                    click_count: 6000,
                },
                ClickPositionBucket {
                    position: (21, -1),
                    click_count: 1100,
                },
            ],
            session_ops: sample_session_ops(),
        };

        let rendered = render_clicks_human(&response);

        assert!(rendered.contains("2026-08-04T06:00:00.000Z"));
        assert!(rendered.contains("10.50%"));
        assert!(rendered.contains("12600"));
        assert!(rendered.contains("6.42"));
        assert!(
            rendered.contains("21+"),
            "expected unbounded bucket label: {rendered}"
        );
        assert!(rendered.contains("6000"));
    }

    #[test]
    fn render_clicks_human_handles_null_rate_and_empty_positions() {
        let response = ClicksOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            updated_at: Some("2026-08-04T06:00:00.000Z".to_string()),
            click_through_rate: ClickThroughRateResponse {
                rate: None,
                tracked_search_count: 0,
                click_count: 0,
                dates: vec![],
            },
            average_click_position: AverageClickPositionResponse {
                average: None,
                click_count: 0,
                dates: vec![],
            },
            positions: vec![],
            session_ops: sample_session_ops(),
        };

        let rendered = render_clicks_human(&response);
        assert!(rendered.contains("n/a"));
        assert!(rendered.contains("no click position data"));
    }

    #[test]
    fn render_clicks_human_handles_missing_status_no_data_region() {
        // `/2/status` returns `{"updatedAt": null}` (HTTP 200) for a
        // region/index combo with no analytics data yet — confirmed live
        // 2026-08-04 for `--region us`. Must render an honest sentence,
        // never the literal "None", never an empty/blank line.
        let response = ClicksOut {
            index: "Product".to_string(),
            region: "us".to_string(),
            since: "30d".to_string(),
            updated_at: None,
            click_through_rate: ClickThroughRateResponse {
                rate: None,
                tracked_search_count: 0,
                click_count: 0,
                dates: vec![],
            },
            average_click_position: AverageClickPositionResponse {
                average: None,
                click_count: 0,
                dates: vec![],
            },
            positions: vec![],
            session_ops: sample_session_ops(),
        };

        let rendered = render_clicks_human(&response);
        assert!(
            rendered.contains("no analytics data in this region yet"),
            "rendered: {rendered}"
        );
        assert!(
            !rendered.contains("None"),
            "must never render the literal 'None': {rendered}"
        );
    }

    #[test]
    fn render_conversions_human_shows_all_three_rates_side_by_side() {
        let response = ConversionsOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            updated_at: Some("2026-08-04T06:00:00.000Z".to_string()),
            conversion_rate: ConversionRateResponse {
                rate: Some(0.08),
                tracked_search_count: 120000,
                conversion_count: 9600,
                dates: vec![],
            },
            add_to_cart_rate: AddToCartRateResponse {
                rate: Some(0.075),
                tracked_search_count: 120000,
                add_to_cart_count: 9000,
                dates: vec![],
            },
            purchase_rate: PurchaseRateResponse {
                rate: Some(0.025),
                tracked_search_count: 120000,
                purchase_count: 3000,
                dates: vec![],
            },
            session_ops: sample_session_ops(),
        };

        let rendered = render_conversions_human(&response);

        assert!(rendered.contains("8.00%"));
        assert!(rendered.contains("9600"));
        assert!(rendered.contains("7.50%"));
        assert!(rendered.contains("9000"));
        assert!(rendered.contains("2.50%"));
        assert!(rendered.contains("3000"));
        assert!(rendered.contains("2026-08-04T06:00:00.000Z"));
    }

    #[test]
    fn render_conversions_human_handles_missing_status_no_data_region() {
        let response = ConversionsOut {
            index: "Product".to_string(),
            region: "us".to_string(),
            since: "30d".to_string(),
            updated_at: None,
            conversion_rate: ConversionRateResponse {
                rate: None,
                tracked_search_count: 0,
                conversion_count: 0,
                dates: vec![],
            },
            add_to_cart_rate: AddToCartRateResponse {
                rate: None,
                tracked_search_count: 0,
                add_to_cart_count: 0,
                dates: vec![],
            },
            purchase_rate: PurchaseRateResponse {
                rate: None,
                tracked_search_count: 0,
                purchase_count: 0,
                dates: vec![],
            },
            session_ops: sample_session_ops(),
        };

        let rendered = render_conversions_human(&response);
        assert!(
            rendered.contains("no analytics data in this region yet"),
            "rendered: {rendered}"
        );
        assert!(
            !rendered.contains("None"),
            "must never render the literal 'None': {rendered}"
        );
    }

    #[test]
    fn render_revenue_human_renders_a_row_per_currency() {
        let response = RevenueOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            updated_at: Some("2026-08-04T06:00:00.000Z".to_string()),
            currencies: vec![
                RevenueRow {
                    currency: "EUR".to_string(),
                    revenue: 12345.6,
                    average_order_value: 38.58,
                    transaction_count: 320,
                },
                RevenueRow {
                    currency: "USD".to_string(),
                    revenue: 9820.5,
                    average_order_value: 51.2,
                    transaction_count: 192,
                },
            ],
            session_ops: sample_session_ops(),
        };

        let rendered = render_revenue_human(&response);

        assert!(rendered.contains("EUR"));
        assert!(rendered.contains("12345.60"));
        assert!(
            rendered.contains("USD"),
            "must not assume EUR-only: {rendered}"
        );
        assert!(rendered.contains("9820.50"));
        assert!(rendered.contains("320"));
        assert!(rendered.contains("192"));
    }

    #[test]
    fn render_revenue_human_handles_no_revenue_in_window() {
        let response = RevenueOut {
            index: "Product".to_string(),
            region: "de".to_string(),
            since: "30d".to_string(),
            updated_at: Some("2026-08-04T06:00:00.000Z".to_string()),
            currencies: vec![],
            session_ops: sample_session_ops(),
        };

        let rendered = render_revenue_human(&response);
        assert!(rendered.contains("no revenue"));
    }

    #[test]
    fn render_revenue_human_handles_missing_status_no_data_region() {
        let response = RevenueOut {
            index: "Product".to_string(),
            region: "us".to_string(),
            since: "30d".to_string(),
            updated_at: None,
            currencies: vec![],
            session_ops: sample_session_ops(),
        };

        let rendered = render_revenue_human(&response);
        assert!(
            rendered.contains("no analytics data in this region yet"),
            "rendered: {rendered}"
        );
        assert!(
            !rendered.contains("None"),
            "must never render the literal 'None': {rendered}"
        );
    }

    #[test]
    fn format_freshness_renders_honest_no_data_message() {
        assert_eq!(
            format_freshness(&Some("2026-08-04T06:00:00.000Z".to_string())),
            "2026-08-04T06:00:00.000Z"
        );
        let none_rendered = format_freshness(&None);
        assert_eq!(
            none_rendered,
            "freshness: no analytics data in this region yet"
        );
        assert!(!none_rendered.contains("None"));
        assert!(!none_rendered.is_empty());
    }

    #[test]
    fn format_position_bucket_decodes_unbounded_sentinel() {
        assert_eq!(format_position_bucket(1, 1), "1");
        assert_eq!(format_position_bucket(11, 20), "11-20");
        assert_eq!(format_position_bucket(21, -1), "21+");
    }

    // ---- A2: enumeration ------------------------------------------------

    #[test]
    fn a2_enumeration_fired_on_synthetic() {
        let rows = vec![
            row("aa", 5),
            row("ab", 5),
            row("ac", 5),
            row("ad", 5),
            row("ae", 5),
            row("scarpe da corsa", 300),
            row("crema solare", 210),
        ];
        let signal = detect_enumeration(&rows);
        assert!(signal.fired, "expected enumeration to fire: {signal:?}");
        assert_eq!(signal.signal, "systematic_enumeration");
        assert!(signal.evidence.len() >= ENUMERATION_RUN_THRESHOLD);
        for term in ["aa", "ab", "ac", "ad", "ae"] {
            assert!(
                signal.evidence.contains(&term.to_string()),
                "evidence missing {term}: {:?}",
                signal.evidence
            );
        }
    }

    #[test]
    fn enumeration_does_not_fire_on_organic_looking_queries() {
        let rows = vec![
            row("scarpe da corsa", 300),
            row("crema solare", 210),
            row("vitamina c", 180),
            row("integratori", 90),
        ];
        let signal = detect_enumeration(&rows);
        assert!(!signal.fired);
        assert!(signal.evidence.is_empty());
    }

    // ---- A2: empty-query high volume ------------------------------------

    #[test]
    fn empty_query_dominant_volume_fires() {
        let rows = vec![
            row("", 5000),
            row("scarpe", 40),
            row("borsa", 30),
            row("profumo", 20),
        ];
        let signal = detect_empty_query_high_volume(&rows);
        assert!(signal.fired);
        assert!(!signal.evidence.is_empty());
    }

    #[test]
    fn no_empty_query_present_does_not_fire() {
        let rows = vec![row("scarpe", 40), row("borsa", 30)];
        let signal = detect_empty_query_high_volume(&rows);
        assert!(!signal.fired);
    }

    // ---- A2: test strings -------------------------------------------------

    #[test]
    fn a2_test_strings_fired() {
        let rows = vec![
            row("test", 40),
            row("asdf", 35),
            row("qwerty", 30),
            row("scarpe da corsa", 300),
            row("crema solare", 210),
        ];
        let signal = detect_test_or_foreign_strings(&rows);
        assert!(signal.fired, "expected test-strings to fire: {signal:?}");
        assert_eq!(signal.signal, "non_served_language_or_test_strings");
        assert!(signal.evidence.len() >= 3);
    }

    #[test]
    fn non_latin_script_query_is_flagged() {
        let rows = vec![
            row("鞋子", 40), // "shoes" in Chinese
            row("scarpe da corsa", 300),
            row("crema solare", 210),
        ];
        let signal = detect_test_or_foreign_strings(&rows);
        assert!(signal.fired);
        assert!(signal.evidence.iter().any(|e| e.contains("鞋子")));
    }

    #[test]
    fn organic_italian_queries_do_not_fire_test_strings() {
        let rows = vec![
            row("scarpe da corsa", 300),
            row("crema solare", 210),
            row("vitamina c effervescente", 90),
        ];
        let signal = detect_test_or_foreign_strings(&rows);
        assert!(!signal.fired);
        assert!(signal.evidence.is_empty());
    }

    // ---- A2: flat distribution --------------------------------------------

    #[test]
    fn a2_flat_distribution_fired() {
        let rows: Vec<TopSearchRow> = (0..20).map(|i| row(&format!("query{i}"), 100)).collect();
        let signal = detect_flat_distribution(&rows);
        assert!(
            signal.fired,
            "expected flat distribution to fire: {signal:?}"
        );
        assert_eq!(signal.signal, "flat_distribution");
        assert!(!signal.evidence.is_empty());
    }

    #[test]
    fn heavy_tailed_distribution_does_not_fire_flat() {
        // Classic long tail: one dominant term, then a steep drop-off.
        let mut rows = vec![row("scarpe", 5000)];
        for i in 0..15 {
            rows.push(row(&format!("query{i}"), 20 - i as u64));
        }
        let signal = detect_flat_distribution(&rows);
        assert!(
            !signal.fired,
            "long-tail distribution should not fire flat: {signal:?}"
        );
    }

    #[test]
    fn flat_distribution_needs_minimum_sample_size() {
        let rows = vec![row("a", 100), row("b", 100)];
        let signal = detect_flat_distribution(&rows);
        assert!(!signal.fired);
    }

    // ---- A2: all four reported distinctly ---------------------------------

    #[test]
    fn a2_signals_reported_distinctly() {
        // Engineer exactly two of the four signals: test-strings +
        // flat-distribution. No alphabetical run of >=4, no empty-string
        // query — enumeration and empty-query-pagination must stay false.
        let mut rows: Vec<TopSearchRow> = [
            "scarpe",
            "borsa",
            "profumo",
            "crema",
            "vitamine",
            "integratore",
            "occhiali",
            "orologio",
            "cappello",
            "sciarpa",
            "zaino",
            "valigia",
        ]
        .iter()
        .map(|q| row(q, 50))
        .collect();
        rows.push(row("test", 45));
        rows.push(row("asdf", 45));
        rows.push(row("qwerty", 45));

        let signals = compute_scrape_signals(&rows);
        assert_eq!(signals.len(), 4, "expected exactly 4 signals reported");

        let names: Vec<&str> = signals.iter().map(|s| s.signal).collect();
        assert!(names.contains(&"systematic_enumeration"));
        assert!(names.contains(&"empty_query_high_volume_pagination"));
        assert!(names.contains(&"non_served_language_or_test_strings"));
        assert!(names.contains(&"flat_distribution"));

        let fired: std::collections::HashMap<&str, bool> =
            signals.iter().map(|s| (s.signal, s.fired)).collect();
        assert!(
            !fired["systematic_enumeration"],
            "not engineered — must stay false"
        );
        assert!(
            !fired["empty_query_high_volume_pagination"],
            "not engineered — must stay false"
        );
        assert!(
            fired["non_served_language_or_test_strings"],
            "engineered — must fire"
        );
        assert!(fired["flat_distribution"], "engineered — must fire");
    }

    // ---- A3: no over-confident wording -------------------------------------

    #[test]
    fn a3_no_confident_wording() {
        // Exercise every signal's explanation/evidence text paths at once:
        // an enumeration run, a dominant empty query, test strings, and a
        // roughly-flat remainder.
        let mut rows = vec![
            row("aa", 10),
            row("ab", 10),
            row("ac", 10),
            row("ad", 10),
            row("", 9000),
            row("test", 60),
            row("asdf", 55),
        ];
        for i in 0..10 {
            rows.push(row(&format!("longtailquery{i}"), 62));
        }

        let signals = compute_scrape_signals(&rows);
        assert_eq!(signals.len(), 4);

        let serialized = serde_json::to_string(&signals).unwrap();
        let lower = serialized.to_lowercase();
        assert!(
            !lower.contains("confirmed"),
            "output must never assert a signal as confirmed: {serialized}"
        );
        assert!(
            !lower.contains("scraper detected"),
            "output must never assert a scraper as detected: {serialized}"
        );

        // Belt-and-suspenders: check each signal's own explanation text
        // directly too, independent of which ones fired.
        for s in &signals {
            let e = s.explanation.to_lowercase();
            assert!(
                !e.contains("confirmed"),
                "signal {}: {}",
                s.signal,
                s.explanation
            );
            assert!(
                !e.contains("scraper detected"),
                "signal {}: {}",
                s.signal,
                s.explanation
            );
        }
    }

    #[test]
    fn gini_coefficient_zero_for_uniform_and_positive_for_skewed() {
        assert_eq!(gini_coefficient(&[10, 10, 10, 10, 10]), 0.0);
        let skewed = gini_coefficient(&[0, 0, 0, 0, 100]);
        assert!(
            skewed > 0.5,
            "expected a strongly skewed gini, got {skewed}"
        );
    }

    #[test]
    fn is_alpha_successor_basic_cases() {
        assert!(is_alpha_successor("aa", "ab"));
        assert!(is_alpha_successor("a", "b"));
        assert!(!is_alpha_successor("aa", "ba"));
        assert!(!is_alpha_successor("aa", "ac"));
        assert!(!is_alpha_successor("a", "aa"));
        assert!(!is_alpha_successor("", ""));
    }
}
