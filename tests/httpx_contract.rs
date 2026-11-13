//! HTTP/transport-layer contract tests for `src/http.rs`'s `get_json` (the
//! sole GET executor — D11) and `classify_forbidden`, driven end-to-end
//! through the compiled `alx` binary against `wiremock` servers. `alx` is a
//! bin-only crate (no `[lib]` target in `Cargo.toml`), so `tests/` can only
//! reach the HTTP layer through a real subprocess + CLI invocation, never a
//! direct `use alx::http::...` — every helper below spawns
//! `CARGO_BIN_EXE_alx` exactly like every sibling `tests/*.rs` file.
//!
//! A pre-release coverage audit's single biggest flagged gap in `http.rs` was the
//! 429-retry branch inside `get_json`'s loop (`attempt += 1; backoff_ms =
//! ...; sleep; continue;`) — "no test anywhere (unit or subprocess) mounts
//! a 429 response". This file closes that plus the 5xx/timeout/
//! malformed-body/multi-host-classification gaps design decision D12 calls
//! out ("429->backoff, error mapping... never a raw error dump").
//!
//! `usage series` is the preferred surface for exit-code-sensitive
//! assertions here: it fires exactly one `fetch_statistic` call whose
//! `AppError` propagates to `main()` unmodified via `?`
//! (`commands/usage.rs::run_series`). `logs sample`/`offsite`/`errors`
//! fan out across multiple hosts and, per `fetch_logs_all_hosts`
//! (`src/algolia/logs.rs`), used to collapse EVERY per-host failure reason
//! (401, 402, 403, 5xx, a genuine network-down host) into one generic
//! `AppError::Other` (exit code 1) once all hosts failed — discarding the
//! underlying Auth/PlanGated/Network classification entirely. That was a
//! real, reproducible defect against D5's exit-code contract (BUG
//! ALX-LOGS-ERRCLASS); `classify_all_hosts_error` in `src/algolia/logs.rs`
//! now reclassifies a *homogeneous* all-hosts failure (every host failing
//! with the same Network/Auth/PlanGated kind) into that kind, while a mixed
//! or generic (e.g. all-5xx) failure set still collapses to `Other` — see
//! the two `bug_logs_*` regression tests at the bottom of this file, which
//! encode the fixed behavior.

use serde_json::{json, Value};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

async fn run_alx(args: Vec<String>, envs: Vec<(String, String)>) -> (i32, String, String) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, &envs))
        .await
        .expect("spawn_blocking join failed");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn sv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// `usage series` fires exactly ONE HTTP call to the usage host, and
/// propagates whatever `AppError` that call produces unmodified — the
/// cleanest surface in the whole command set for asserting exact exit-code
/// classification without any multi-call/multi-host aggregation in the way.
fn usage_series_args() -> Vec<String> {
    sv(&[
        "--app-id",
        "test-app",
        "--key",
        "test-key",
        "usage",
        "series",
        "--statistic",
        "total_search_requests",
        "--granularity",
        "daily",
        "--since",
        "7d",
    ])
}

/// `ALX_SEARCH_BASE_URL` is redirected to a guaranteed-closed loopback port
/// — never the mock server under test itself — so the D0.3 over-privilege
/// preflight's self-read GET can never land in `received_requests()` and
/// pollute the request-count assertions every test in this file relies on.
fn usage_envs(base_url: &str) -> Vec<(String, String)> {
    vec![
        ("ALX_USAGE_BASE_URL".to_string(), base_url.to_string()),
        (
            "ALX_SEARCH_BASE_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        ),
    ]
}

fn logs_sample_args() -> Vec<String> {
    sv(&[
        "--app-id", "test-app", "--key", "test-key", "logs", "sample",
    ])
}

fn logs_envs(base_urls: &str) -> Vec<(String, String)> {
    vec![
        ("ALX_LOGS_BASE_URLS".to_string(), base_urls.to_string()),
        (
            "ALX_SEARCH_BASE_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        ),
    ]
}

fn stat_body() -> Value {
    json!({"statistics": [{"t": 1_690_000_000, "v": 10}]})
}

// ---------------------------------------------------------------------
// 429 retry: exactly 3 retries (4 total requests), then a typed error.
//
// This is the ONE test in this file with real (unmocked) 1s/2s/4s backoff
// sleeps (~7s total, per `http.rs`'s `BACKOFF_BASE_MS = 1000` /
// `MAX_RETRIES = 3`). `tokio::time::pause`-style time control cannot reach
// a *subprocess's own* runtime, and design decision D12 explicitly
// requires a 429->backoff acceptance test, so a real sleep is unavoidable here — kept to exactly one such test, asserting only
// the request COUNT and the terminal error class, never wall-clock
// duration (loose timing tolerance).
// ---------------------------------------------------------------------

#[tokio::test]
async fn retry_429_exactly_three_times_then_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_alx(usage_series_args(), usage_envs(&server.uri())).await;

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        4,
        "expected 1 initial attempt + exactly 3 retries (D12's '429->backoff'): {requests:?}"
    );

    assert_ne!(
        code, 101,
        "must be a typed error, not a Rust panic: stderr={stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr={stderr}");
    assert_eq!(
        code, 1,
        "a persistent 429 exhausts retries into a generic AppError::Api (exit 1): stdout={stdout}"
    );
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected a JSON error envelope, got parse error {e}: stdout={stdout:?}")
    });
    assert!(v.get("error").is_some(), "missing error envelope: {v}");
}

// ---------------------------------------------------------------------
// 5xx: 500/502/503 -> AppError::Api (generic, exit code 1), no retry
// storm — get_json's retry loop only special-cases 429; every other
// non-2xx status (including every 5xx) falls straight to the terminal
// AppError::Api branch on the FIRST response.
// ---------------------------------------------------------------------

#[tokio::test]
async fn http_5xx_maps_to_api_error_without_retry_storm() {
    for status in [500u16, 502, 503] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/usage/total_search_requests"))
            .respond_with(ResponseTemplate::new(status).set_body_string("upstream error"))
            .mount(&server)
            .await;

        let (code, stdout, stderr) = run_alx(usage_series_args(), usage_envs(&server.uri())).await;

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "HTTP {status} must not trigger any retry (only 429 does): {requests:?}"
        );
        assert!(
            !stderr.contains("panicked"),
            "HTTP {status}: stderr={stderr}"
        );
        assert_eq!(
            code, 1,
            "HTTP {status} should map to a generic Api error (exit 1): stdout={stdout}"
        );
        let v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("HTTP {status}: expected JSON error envelope, got {e}: stdout={stdout:?}")
        });
        assert!(
            v.get("error").is_some(),
            "HTTP {status}: missing error field: {v}"
        );
    }
}

// ---------------------------------------------------------------------
// classify_forbidden fingerprint table, end to end. http.rs's own inline
// `#[cfg(test)]` module already covers the PURE function in isolation
// (`classify_forbidden_402_is_always_plan_gated`, etc.) — these assert the
// same fingerprints through the actual exit-code class an operator would
// see from a real run, per D8/D0.2's "never a raw error dump either way".
// ---------------------------------------------------------------------

async fn assert_classification(body: &str, status: u16, expected_exit: i32, label: &str) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(&server)
        .await;

    let (code, stdout, _stderr) = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_eq!(
        code, expected_exit,
        "{label}: HTTP {status} body={body:?} expected exit {expected_exit}, got {code}: stdout={stdout}"
    );
}

#[tokio::test]
async fn classify_402_is_always_plan_gated() {
    assert_classification("", 402, 5, "bare 402, no body wording needed").await;
    assert_classification("Payment Required", 402, 5, "402 with a body present too").await;
}

#[tokio::test]
async fn classify_403_not_available_wording_is_plan_gated() {
    assert_classification(
        "This API is not available.",
        403,
        5,
        "not-available wording",
    )
    .await;
}

#[tokio::test]
async fn classify_403_feature_wording_is_plan_gated() {
    assert_classification(
        "Feature not enabled for this key.",
        403,
        5,
        "feature wording",
    )
    .await;
}

#[tokio::test]
async fn classify_403_plain_wording_is_auth_not_plan_gated() {
    assert_classification("Invalid API key", 403, 4, "plain 403 (Invalid API key)").await;
}

#[tokio::test]
async fn classify_401_is_auth() {
    assert_classification("Invalid API key", 401, 4, "401").await;
}

// ---------------------------------------------------------------------
// timeout: a response delayed beyond --timeout must surface as a Network
// error (exit 3), never hang past the configured limit or panic.
// ---------------------------------------------------------------------

#[tokio::test]
async fn timeout_beyond_configured_limit_maps_to_network_class() {
    // The mock delay is deliberately far longer than any plausible
    // process-start/scheduling overhead on a loaded CI box: the assertion
    // below is "gave up well before the delay elapsed", and the run itself
    // (spawn + runtime start in a debug binary, with many sibling test
    // binaries competing) can take several seconds under load, which made
    // the previous 3s-delay / <3s bound flaky without any client defect.
    const MOCK_DELAY: Duration = Duration::from_secs(30);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(stat_body())
                .set_delay(MOCK_DELAY),
        )
        .mount(&server)
        .await;

    let mut args = sv(&["--timeout", "1"]);
    args.extend(usage_series_args());

    let start = Instant::now();
    let (code, stdout, stderr) = run_alx(args, usage_envs(&server.uri())).await;
    let elapsed = start.elapsed();

    assert_eq!(
        code, 3,
        "a timed-out request must map to AppError::Network (exit 3): stdout={stdout} stderr={stderr}"
    );
    assert!(
        elapsed < MOCK_DELAY / 2,
        "the client should give up around --timeout 1s, not wait for the full {MOCK_DELAY:?} mock delay: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------
// malformed / empty / wrong-content-type response bodies — must fail as a
// typed error (never panic), and the JSON *shape* alone must drive whether
// parsing succeeds, not the Content-Type header (reqwest's `.json()` does
// not inspect it).
// ---------------------------------------------------------------------

#[tokio::test]
async fn malformed_json_body_200_status_is_typed_error_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not valid json"))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_alx(usage_series_args(), usage_envs(&server.uri())).await;

    assert_ne!(
        code, 101,
        "must not panic on an unparseable 200 body: stderr={stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr={stderr}");
    assert_eq!(
        code, 3,
        "an unparseable JSON body fails inside reqwest's own decode step -> AppError::Network: stdout={stdout}"
    );
    let v: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected a JSON error envelope, got {e}: stdout={stdout:?}"));
    assert!(v.get("error").is_some());
}

#[tokio::test]
async fn empty_body_200_status_is_typed_error_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_alx(usage_series_args(), usage_envs(&server.uri())).await;

    assert_ne!(
        code, 101,
        "must not panic on an empty 200 body: stderr={stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr={stderr}");
    assert_eq!(
        code, 3,
        "an empty body fails JSON decoding -> AppError::Network: stdout={stdout}"
    );
}

#[tokio::test]
async fn wrong_content_type_header_does_not_block_valid_json_parsing() {
    let server = MockServer::start().await;
    // `set_body_string` sets Content-Type: text/plain (see wiremock's
    // response_template.rs) — the body itself is still valid JSON.
    // `reqwest::Response::json()` parses the raw bytes regardless of the
    // declared Content-Type, so this must succeed exactly like an
    // equivalent `set_body_json` response would.
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_string(stat_body().to_string()))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_eq!(
        code, 0,
        "a valid JSON body with the wrong Content-Type must still parse: stdout={stdout} stderr={stderr}"
    );
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["points"][0]["value"], json!(10.0));
}

// ---------------------------------------------------------------------
// multi-host logs: per-host error isolation
// ---------------------------------------------------------------------

#[tokio::test]
async fn multi_host_one_of_three_500s_still_succeeds_with_per_host_error_isolated() {
    let ok_a = MockServer::start().await;
    let ok_b = MockServer::start().await;
    let bad = MockServer::start().await;

    for s in [&ok_a, &ok_b] {
        Mock::given(method("GET"))
            .and(path("/1/logs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
            .mount(s)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&bad)
        .await;

    let base_urls = format!("{},{},{}", ok_a.uri(), ok_b.uri(), bad.uri());
    let (code, stdout, stderr) = run_alx(logs_sample_args(), logs_envs(&base_urls)).await;

    assert_eq!(
        code, 0,
        "2 of 3 hosts succeeding must still succeed overall: stdout={stdout} stderr={stderr}"
    );
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let hosts = v["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 3);
    let failed_count = hosts.iter().filter(|h| h["error"].is_string()).count();
    assert_eq!(
        failed_count, 1,
        "exactly the 500-returning host should carry a per-host error: {v}"
    );
    let ok_count = hosts.iter().filter(|h| h["error"].is_null()).count();
    assert_eq!(
        ok_count, 2,
        "the two healthy hosts must report no error: {v}"
    );
}

/// Documents the CURRENT, actual exit-code behavior when every logs host
/// fails (all three 500 here) — `fetch_logs_all_hosts` aggregates every
/// per-host error into one `AppError::Other` (generic, exit 1), NOT a
/// classified `AppError::Network`/`Auth`/`PlanGated`. Asserted here as
/// exactly `code == 1` (not merely `assert_ne!(code, 0)`, which is all the
/// pre-existing `all_hosts_down_fails_the_command` in logs_wiremock.rs
/// checks) so that a future change to this aggregation is a visible,
/// deliberate decision rather than a silent regression either way. See the
/// `bug_logs_*` tests below for why this collapsing is arguably wrong.
#[tokio::test]
async fn multi_host_all_three_fail_command_fails_with_generic_exit_code() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    let c = MockServer::start().await;
    for s in [&a, &b, &c] {
        Mock::given(method("GET"))
            .and(path("/1/logs"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(s)
            .await;
    }

    let base_urls = format!("{},{},{}", a.uri(), b.uri(), c.uri());
    let (code, stdout, _stderr) = run_alx(logs_sample_args(), logs_envs(&base_urls)).await;

    assert_eq!(
        code, 1,
        "current behavior: all-hosts-failed collapses into AppError::Other (exit 1), not a \
         specific Network/Auth/PlanGated class: stdout={stdout}"
    );
}

// ---------------------------------------------------------------------
// BUG (FIXED): `fetch_logs_all_hosts` (src/algolia/logs.rs) used to discard
// error classification when every logs host failed — its
// `if !any_ok { return Err(AppError::Other(...)) }` branch unconditionally
// overwrote whatever the per-host errors actually were with a generic
// message, so `logs sample`/`offsite`/`errors` could never surface exit
// codes 3/4 when every host failed for the exact same auth/network reason.
// Fixed via `classify_all_hosts_error`, which reclassifies a homogeneous
// all-hosts failure into its shared kind. Both tests below (filed as bug id
// ALX-LOGS-ERRCLASS) now pass as regression pins.
// ---------------------------------------------------------------------

#[tokio::test]
async fn bug_logs_auth_failure_on_all_hosts_should_exit_4_not_1() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;

    let (code, stdout, _stderr) = run_alx(logs_sample_args(), logs_envs(&server.uri())).await;
    assert_eq!(
        code, 4,
        "a genuine auth failure on every logs host should surface as exit 4 (AppError::Auth), per D5: stdout={stdout}"
    );
}

#[tokio::test]
async fn bug_logs_network_failure_on_all_hosts_should_exit_3_not_1() {
    // Three distinct host slots, all pointed at the same guaranteed-closed
    // loopback port — genuine connection-refused on every host, no HTTP
    // response of any kind (not even a 500).
    let base_urls = "http://127.0.0.1:1,http://127.0.0.1:1,http://127.0.0.1:1";
    let (code, stdout, _stderr) = run_alx(logs_sample_args(), logs_envs(base_urls)).await;
    assert_eq!(
        code, 3,
        "a genuine network failure on every logs host should surface as exit 3 (AppError::Network), per D5: stdout={stdout}"
    );
}
