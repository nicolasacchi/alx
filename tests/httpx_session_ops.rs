//! `session_ops` accuracy + the A1 analytics throttle, driven end-to-end
//! through the compiled `alx` binary against `wiremock` servers (bin-only
//! crate — no `[lib]` target, so `tests/` can only reach `SessionOps`/
//! `Throttle` through a real subprocess + CLI invocation, exactly like every
//! sibling `tests/*.rs` file and `tests/httpx_contract.rs`).
//!
//! D0.4 quota honesty: `session_ops` in every response envelope is meant to
//! be the operator's one trustworthy count of how many real Algolia calls a
//! session made. This file pins that count against several concrete,
//! multi-call code paths a pre-release coverage audit and the design call out by
//! name (D7's 3-host logs fan-out, D9/U1's 4-statistic `usage summary`
//! fetch, A1's throttle) rather than just asserting `>= 1` as
//! `tests/logs_wiremock.rs`'s existing `session_ops_present_in_every_response`
//! does.

use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn spawn_alx(args: &[String], envs: &[(String, String)]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn the alx binary")
}

async fn run_alx_json(args: Vec<String>, envs: Vec<(String, String)>) -> (i32, Value) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, &envs))
        .await
        .expect("spawn_blocking join failed");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let json: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected JSON stdout (exit={code}): {e}\nstdout={stdout:?}\nstderr={stderr:?}")
    });
    (code, json)
}

fn base_args(sub: &[&str]) -> Vec<String> {
    let mut a = sv(&["--app-id", "test-app", "--key", "test-key"]);
    a.extend(sv(sub));
    a
}

/// D0.3's over-privilege self-read is redirected at a guaranteed-closed
/// loopback port (never the mock server under test), so it fails fast via
/// the network-error-skip branch and never lands in any
/// `server.received_requests()`/receipt-timestamp assertion below.
fn closed_search_env() -> (String, String) {
    (
        "ALX_SEARCH_BASE_URL".to_string(),
        "http://127.0.0.1:1".to_string(),
    )
}

// =========================================================================
// logs: 3-host fan-out increments logs_calls by exactly 3 (one per host)
// =========================================================================

#[tokio::test]
async fn session_ops_logs_sample_across_three_hosts_increments_logs_calls_by_three() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    let c = MockServer::start().await;
    for s in [&a, &b, &c] {
        Mock::given(method("GET"))
            .and(path("/1/logs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
            .mount(s)
            .await;
    }
    let base_urls = format!("{},{},{}", a.uri(), b.uri(), c.uri());

    let (code, json) = run_alx_json(
        base_args(&["logs", "sample"]),
        vec![
            ("ALX_LOGS_BASE_URLS".to_string(), base_urls),
            closed_search_env(),
        ],
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");
    assert_eq!(
        json["session_ops"]["logs_calls"], 3,
        "3 hosts, all reachable, must count as exactly 3 completed logs calls: {json}"
    );
    // Sanity: the other three counters must stay untouched by a logs-only run.
    assert_eq!(json["session_ops"]["usage_calls"], 0);
    assert_eq!(json["session_ops"]["analytics_calls"], 0);
    assert_eq!(json["session_ops"]["keys_calls"], 0);
}

/// Companion to the all-succeed case above: when 2 of 3 hosts are reachable
/// and 1 genuinely errors, `logs_calls` must still land at exactly 3 — every
/// host's GET is a real completed HTTP round trip (success or per-host
/// error) that consumes Algolia operations quota (D0.4), so a failed host
/// must still be counted, not silently excluded from the tally.
#[tokio::test]
async fn session_ops_logs_sample_counts_failed_hosts_too() {
    let ok = MockServer::start().await;
    let bad = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
        .mount(&ok)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&bad)
        .await;

    let base_urls = format!("{},{}", ok.uri(), bad.uri());
    let (code, json) = run_alx_json(
        base_args(&["logs", "sample"]),
        vec![
            ("ALX_LOGS_BASE_URLS".to_string(), base_urls),
            closed_search_env(),
        ],
    )
    .await;

    assert_eq!(
        code, 0,
        "1 of 2 hosts succeeding must still succeed overall: {json}"
    );
    assert_eq!(
        json["session_ops"]["logs_calls"], 2,
        "both hosts (1 success + 1 error) must count as 2 completed calls, not just the successful one: {json}"
    );
}

// =========================================================================
// usage summary: 4 statistics fetched concurrently -> usage_calls == 4
// =========================================================================

fn stat_response(points: &[(i64, Value)]) -> Value {
    json!({
        "statistics": points
            .iter()
            .map(|(t, v)| json!({"t": t, "v": v}))
            .collect::<Vec<_>>()
    })
}

async fn mount_all_four_summary_statistics(server: &MockServer) {
    for stat in [
        "total_search_requests",
        "total_search_operations",
        "querysuggestions_total_search_requests",
        "records",
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/1/usage/{stat}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(stat_response(&[(1_690_000_000, json!(10))])),
            )
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn session_ops_usage_summary_increments_usage_calls_by_four() {
    let server = MockServer::start().await;
    mount_all_four_summary_statistics(&server).await;

    let (code, json) = run_alx_json(
        base_args(&["usage", "summary", "--since", "7d"]),
        vec![
            ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
            closed_search_env(),
        ],
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");
    // U1: `usage summary` always fetches exactly 4 statistics
    // (total_search_requests, total_search_operations,
    // querysuggestions_total_search_requests, records) — session_ops must
    // reflect exactly that count, never fewer (a silently-skipped meter)
    // nor more (a duplicated fetch).
    assert_eq!(
        json["session_ops"]["usage_calls"], 4,
        "usage summary fetches exactly 4 statistics: {json}"
    );
}

/// `usage meters` (U5) is a narrower, 2-statistic sibling of `summary` —
/// pinning it separately so a future change that accidentally routes it
/// through the 4-statistic `summary` path (or vice versa) shows up as a
/// wrong `usage_calls` count immediately.
#[tokio::test]
async fn session_ops_usage_meters_increments_usage_calls_by_two() {
    let server = MockServer::start().await;
    for stat in ["total_search_requests", "total_search_operations"] {
        Mock::given(method("GET"))
            .and(path(format!("/1/usage/{stat}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(stat_response(&[(1_690_000_000, json!(5))])),
            )
            .mount(&server)
            .await;
    }

    let (code, json) = run_alx_json(
        base_args(&["usage", "meters", "--since", "7d"]),
        vec![
            ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
            closed_search_env(),
        ],
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");
    assert_eq!(
        json["session_ops"]["usage_calls"], 2,
        "usage meters fetches exactly requests + operations (2 statistics): {json}"
    );
}

// =========================================================================
// 429 retry + session_ops: does a retried attempt count once or per-attempt?
//
// Reading `src/http.rs::get_json`'s loop: the 429-retry branch
// (`attempt += 1; ...; sleep; continue;`) sits BEFORE `ops.increment
// (surface)`, and `continue` skips straight back to the top of the loop —
// so a retried 429 response never reaches the increment call at all. Only
// the loop's terminal iteration (the first response that is NOT a retried
// 429 — i.e. either an eventual success, or a final 429 once
// `attempt == MAX_RETRIES`) falls through to `ops.increment(surface)`.
// ACTUAL behavior: session_ops counts once per COMPLETED `get_json` call,
// never once per HTTP attempt — a caller that retried 429 internally 2
// times before succeeding still shows `usage_calls: 1`, not 3. This exact
// question is also pinned directly against `get_json` in-process by
// `src/http.rs`'s own inline test
// (`retry_429_then_success_increments_session_ops_exactly_once`, using 2
// retried 429s); this test re-confirms the SAME invariant one layer up, at
// the real JSON envelope a user/operator actually sees, using only ONE
// retried attempt (the minimum that can exercise the branch at all) to keep
// the unavoidable real backoff sleep as short as possible (~1s, not the
// ~3-7s a 2-or-3-retry chain would cost) — design decision D12 keeps
// real-sleep tests to a minimum.
// =========================================================================

#[tokio::test]
async fn retry_429_then_success_session_ops_counts_once_not_per_attempt() {
    let server = MockServer::start().await;
    // First matching request: 429 (triggers exactly one retry+backoff).
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Every subsequent matching request: success.
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(stat_response(&[(1_690_000_000, json!(42))])),
        )
        .mount(&server)
        .await;

    let (code, json) = run_alx_json(
        vec![
            "--app-id".to_string(),
            "test-app".to_string(),
            "--key".to_string(),
            "test-key".to_string(),
            "usage".to_string(),
            "series".to_string(),
            "--statistic".to_string(),
            "total_search_requests".to_string(),
            "--granularity".to_string(),
            "daily".to_string(),
            "--since".to_string(),
            "7d".to_string(),
        ],
        vec![
            ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
            closed_search_env(),
        ],
    )
    .await;

    assert_eq!(
        code, 0,
        "the retried request must still eventually succeed: {json}"
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        2,
        "expected exactly 1 retried 429 attempt + 1 successful attempt: {requests:?}"
    );

    assert_eq!(
        json["session_ops"]["usage_calls"], 1,
        "ACTUAL behavior (pinned): session_ops counts once per COMPLETED \
         get_json call, not once per HTTP attempt — 2 real attempts (1 \
         retried 429 + 1 success) must still show usage_calls: 1: {json}"
    );
}

// =========================================================================
// A1 analytics throttle: calls through the same production Throttle
// instance serialize with >= the configured ~600ms minimum interval,
// measured via mock-server-side receipt timestamps (a custom `Respond`
// closure records `Instant::now()` the moment the mock server handles each
// request), not merely the calling process's own wall clock.
//
// N=4 note: `Throttle::production()` (`src/algolia/analytics.rs`,
// `THROTTLE_INTERVAL = 600ms`) is instantiated fresh inside each
// `run_top_searches`/`run_no_results`/`run_scrape_signals` call and has no
// cross-process persistence (this is a bin-only crate — every `alx`
// invocation is an independent OS process with its own in-memory Throttle,
// by design; there is no shared lock file or daemon). No single documented
// `alx analytics` subcommand fires more than 2 real HTTP calls through one
// Throttle instance: `top-searches`/`scrape-signals` fire 1, `no-results`
// fires exactly 2 (the zero-result list, then the overall `noResultRate`,
// sequentially through the SAME throttle — see
// `commands/analytics.rs::run_no_results`). N=2 (via `no-results`) is
// therefore the maximum "rapid calls serialize" scenario reachable through
// the compiled binary end-to-end; the N=5-way version of this same
// assertion already exists in-process, directly against `Throttle::wait()`,
// with a fast synthetic interval, in `src/algolia/analytics.rs`'s own
// `a1_throttle_serializes_calls` unit test. This test's job is different:
// confirm the real, un-shortened 600ms production constant actually gates
// two sequential real HTTP calls end-to-end, not just the `Throttle` type
// in isolation.
// =========================================================================

#[tokio::test]
async fn analytics_no_results_two_calls_respect_production_throttle_interval() {
    let server = MockServer::start().await;
    let receipts: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));

    let receipts_rows = receipts.clone();
    Mock::given(method("GET"))
        .and(path("/2/searches/noResults"))
        .respond_with(move |_req: &wiremock::Request| {
            receipts_rows.lock().unwrap().push(Instant::now());
            ResponseTemplate::new(200).set_body_json(json!({"searches": []}))
        })
        .mount(&server)
        .await;

    let receipts_rate = receipts.clone();
    Mock::given(method("GET"))
        .and(path("/2/searches/noResultRate"))
        .respond_with(move |_req: &wiremock::Request| {
            receipts_rate.lock().unwrap().push(Instant::now());
            ResponseTemplate::new(200).set_body_json(json!({
                "rate": 0.1, "count": 10, "noResultCount": 1, "dates": []
            }))
        })
        .mount(&server)
        .await;

    let (code, json) = run_alx_json(
        base_args(&["analytics", "no-results", "--since", "7d"]),
        vec![
            ("ALX_ANALYTICS_BASE_URL".to_string(), server.uri()),
            closed_search_env(),
        ],
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");
    assert_eq!(json["session_ops"]["analytics_calls"], 2);

    let mut hits = receipts.lock().unwrap().clone();
    hits.sort();
    assert_eq!(
        hits.len(),
        2,
        "expected exactly 2 real analytics calls to have reached the mock server"
    );
    let gap = hits[1].duration_since(hits[0]);

    // Generous lower bound (half the nominal 600ms interval) to stay
    // deterministic under parallel test execution / CI scheduling jitter —
    // same tolerance convention as `src/algolia/analytics.rs`'s own
    // `a1_throttle_serializes_calls` (`gap >= interval / 2`). Still easily
    // distinguishes real serialization from an unthrottled/buggy gate,
    // which would show a sub-millisecond gap.
    let interval = Duration::from_millis(600);
    assert!(
        gap >= interval / 2,
        "the two analytics calls landed on the mock server only {gap:?} apart, \
         expected at least ~{:?} if the production throttle were truly gating \
         them: {json}",
        interval / 2
    );
}
