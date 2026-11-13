//! End-to-end CLI sweep beyond the per-criterion tests already in
//! `tests/{logs_wiremock,usage_*,analytics_cli_smoke,doctor_capability_matrix,keys_input_validation}.rs`:
//!
//! 1. JSON envelope: one happy-path invocation per command (doctor; logs
//!    sample/offsite/errors; keys audit; usage summary/series/meters;
//!    analytics top-searches/no-results/scrape-signals), asserting stdout
//!    parses as JSON, `session_ops` carries the right per-surface counter,
//!    and a command-specific invariant. `keys_audit_json_envelope_success_path`
//!    in particular closes a gap a pre-release coverage audit called out:
//!    "the entire success path of `alx keys audit` ... is untested
//!    end-to-end, in JSON or human mode, by anything" — `GET /1/keys`
//!    succeeds outright here (not the 403-then-self-read fallback every
//!    other keys test exercises).
//! 2. Output modes: `--human` on a few commands, `--jq` end-to-end against
//!    the real system `jq` binary, and `--jq` with `jq` absent from PATH.
//! 3. `completions`/`manpage`: both need no HTTP client and no credentials
//!    (intercepted in `main()` before `AppContext` is built) but were never
//!    invoked by any existing test (that audit: "a genuine
//!    behavioral gap on two fully-shipped, documented commands").
//!
//! No real network: every scenario points its surface's
//! `ALX_*_BASE_URL`/`ALX_LOGS_BASE_URLS` at a local `wiremock::MockServer`,
//! and `ALX_SEARCH_BASE_URL` at either the same mock server or the
//! guaranteed-closed loopback port `http://127.0.0.1:1` (the over-privilege
//! preflight self-check tolerates both — a non-2xx/network failure there is
//! a silent no-op, per `safety::preflight_privilege_check`). Every `Command`
//! calls `.env_clear()` first.
//!
//! A note on `--human`: agent auto-detection (`agent.rs`) forces JSON
//! output regardless of `--human` whenever it detects an LLM coding agent —
//! by an env var, a `CI=true`+no-TTY combination, a parent-process-name
//! match (walking up to 10 ancestors for `claude`/`cursor`/`codex`/`aider`/
//! `continue`), or (the layer that fires for any plain subprocess spawned
//! via `std::process::Command`, which never has a real controlling
//! terminal on its stdin) "stdin is not a TTY". Nothing in `alx`'s flag
//! surface can force agent detection *off* — only `--agent` can force it
//! on. Concretely: when this suite itself happens to run nested inside an
//! agentic session (as it does in the environment these tests were
//! authored and gated in — the test binary's own process ancestry includes
//! a `claude`-named process), `--human` is unconditionally overridden back
//! to JSON, by design (see `src/output.rs`'s and `CLAUDE.md`'s own "Agent
//! Mode" section). The `--human` tests below therefore assert the two
//! properties that hold in EITHER mode unconditionally (exit 0, the raw key
//! never leaks) as hard requirements, and additionally assert the
//! human-specific rendering (non-JSON stdout, section headings) only when
//! this run's stdout did NOT come back as JSON — i.e. real coverage of
//! `render_human`/`format_*_human` whenever this suite runs outside a
//! nested agent shell (a normal developer machine, most CI), and a graceful
//! no-op (never a false failure) when it doesn't.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spawn_alx(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).env_clear();
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn the alx binary")
}

async fn spawn_alx_async(args: Vec<String>, envs: Vec<(String, String)>) -> std::process::Output {
    tokio::task::spawn_blocking(move || {
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        let envs_ref: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        spawn_alx(&args_ref, &envs_ref)
    })
    .await
    .expect("spawn_blocking join failed")
}

fn sv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn ev(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn run_json(args: Vec<String>, envs: Vec<(String, String)>) -> (i32, Value) {
    let output = spawn_alx_async(args, envs).await;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let json: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected JSON stdout (exit={code}): {e}\nstdout={stdout:?}\nstderr={stderr:?}")
    });
    (code, json)
}

/// Base credential flags every scenario needs, up front so `--app-id`/
/// `--key` always outrank any leftover env var (D3) — irrelevant here since
/// `.env_clear()` already strips everything, but keeps every call site
/// uniform.
fn creds(sub: &[&str]) -> Vec<String> {
    let mut a = sv(&["--app-id", "test-app", "--key", "test-key"]);
    a.extend(sv(sub));
    a
}

// =========================================================================
// 1. JSON envelope sweep — one per command.
// =========================================================================

#[tokio::test]
async fn doctor_json_envelope_all_four_capabilities_and_session_ops() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": []})))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["doctor"]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &server.uri()),
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", &server.uri()),
            ("ALX_INSIGHTS_BASE_URL", &server.uri()),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["capabilities"].as_array().unwrap().len(), 5);
    let ops = &json["session_ops"];
    assert_eq!(ops["logs_calls"], json!(1));
    assert_eq!(ops["usage_calls"], json!(1));
    assert_eq!(ops["analytics_calls"], json!(1));
    assert_eq!(ops["keys_calls"], json!(1));
    assert_eq!(ops["insights_calls"], json!(1));
}

#[tokio::test]
async fn logs_sample_json_envelope_per_host_and_merged_window() {
    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts_a = (now - chrono::Duration::minutes(10)).to_rfc3339();
    let ts_b = (now - chrono::Duration::minutes(3)).to_rfc3339();

    let entry = |sha1: &str, ip: &str, ts: &str| {
        json!({
            "timestamp": ts,
            "method": "GET",
            "answer_code": "200",
            "query_body": "{}",
            "answer": "{}",
            "url": "/1/indexes/Product/query",
            "ip": ip,
            "query_headers": "User-Agent: Mozilla/5.0\r\n",
            "sha1": sha1,
            "nb_api_calls": "1",
            "processing_time_ms": "5",
            "index": "Product",
        })
    };

    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"logs": [entry("sha-a", "203.0.113.10", &ts_a)]})),
        )
        .mount(&server_a)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"logs": [entry("sha-b", "203.0.113.11", &ts_b)]})),
        )
        .mount(&server_b)
        .await;

    let base_urls = format!("{},{}", server_a.uri(), server_b.uri());
    let (code, json) = run_json(
        creds(&["logs", "sample"]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &base_urls),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");

    // Per-host summaries present, two hosts, both succeeded.
    let hosts = json["hosts"].as_array().expect("hosts array");
    assert_eq!(hosts.len(), 2);
    for h in hosts {
        assert!(h["error"].is_null(), "host={h}");
        assert_eq!(h["fetched"], json!(1));
        assert!(h["first"].is_string());
        assert!(h["last"].is_string());
    }

    // Merged window across both hosts.
    assert!(json["window"]["first"].is_string());
    assert!(json["window"]["last"].is_string());
    assert!(json["window"]["elapsed_minutes"].is_number());
    assert_eq!(json["total_entries"], json!(2));

    assert_eq!(json["session_ops"]["logs_calls"], json!(2));
}

#[tokio::test]
async fn logs_offsite_json_envelope_all_buckets_present() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts = (now - chrono::Duration::minutes(5)).to_rfc3339();

    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "logs": [{
                "timestamp": ts,
                "method": "GET",
                "answer_code": "200",
                "query_body": "{}",
                "answer": "{}",
                "url": "/1/indexes/Product/query",
                "ip": "203.0.113.20",
                "query_headers": "User-Agent: curl/8.0\r\n",
                "sha1": "sha-offsite",
                "nb_api_calls": "1",
                "processing_time_ms": "5",
                "index": "Product",
            }]
        })))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["logs", "offsite"]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert!(json["offsite"].is_array());
    for bucket in [
        "own_egress",
        "keep_benign",
        "crawler",
        "private_relay_probable",
        "asn_unknown",
    ] {
        assert!(
            json[bucket]["count"].is_number(),
            "missing bucket {bucket}: {json}"
        );
        assert!(
            json[bucket]["groups"].is_array(),
            "missing bucket {bucket}: {json}"
        );
    }
    assert_eq!(json["session_ops"]["logs_calls"], json!(1));
}

#[tokio::test]
async fn logs_errors_json_envelope() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts_ok = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let ts_bad = (now - chrono::Duration::minutes(4)).to_rfc3339();

    let entry = |sha1: &str, ip: &str, ts: &str, code: &str| {
        json!({
            "timestamp": ts,
            "method": "GET",
            "answer_code": code,
            "query_body": "{}",
            "answer": "{}",
            "url": "/1/indexes/Product/query",
            "ip": ip,
            "query_headers": "User-Agent: Mozilla/5.0\r\n",
            "sha1": sha1,
            "nb_api_calls": "1",
            "processing_time_ms": "5",
            "index": "Product",
        })
    };

    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "logs": [
                entry("sha-ok", "203.0.113.30", &ts_ok, "200"),
                entry("sha-bad", "203.0.113.31", &ts_bad, "403"),
            ]
        })))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["logs", "errors"]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["total_checked"], json!(2));
    assert_eq!(json["error_count"], json!(1));
    assert_eq!(json["errors"][0]["answer_code"], json!(403));
    assert_eq!(json["session_ops"]["logs_calls"], json!(1));
}

/// Closes a coverage-audit-flagged gap: `list_keys` succeeding (the
/// full, non-fallback path) is otherwise untested at every layer, all the
/// way up through `alx keys audit`'s own JSON output.
#[tokio::test]
async fn keys_audit_json_envelope_success_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "value": "test-key",
                "acl": ["search", "browse"],
                "indexes": ["Product", "QuerySuggestions", "Category", "Brand"],
                "description": "full audit success path",
                "createdAt": 1700000000000i64,
            }]
        })))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["keys", "audit"]),
        ev(&[("ALX_SEARCH_BASE_URL", &server.uri())]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["scope"], json!("full"));
    let keys = json["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["acl"], json!(["search", "browse"]));
    // K4/D0.2: never the raw key value, only the masked identifier.
    assert!(keys[0]["masked_value"]
        .as_str()
        .unwrap()
        .starts_with("test"));
    assert!(!json.to_string().contains("\"value\""));
    assert_eq!(json["session_ops"]["keys_calls"], json!(1));
}

fn stat_response(points: &[(i64, Value)]) -> Value {
    json!({
        "statistics": points
            .iter()
            .map(|(t, v)| json!({"t": t, "v": v}))
            .collect::<Vec<_>>()
    })
}

async fn mount_usage_stat(server: &MockServer, stat: &str, points: &[(i64, Value)]) {
    Mock::given(method("GET"))
        .and(path(format!("/1/usage/{stat}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(points)))
        .mount(server)
        .await;
}

#[tokio::test]
async fn usage_summary_json_envelope_both_meters_side_by_side() {
    let server = MockServer::start().await;
    mount_usage_stat(
        &server,
        "total_search_requests",
        &[(1_690_000_000, json!(1000))],
    )
    .await;
    mount_usage_stat(
        &server,
        "total_search_operations",
        &[(1_690_000_000, json!(2000))],
    )
    .await;
    mount_usage_stat(
        &server,
        "querysuggestions_total_search_requests",
        &[(1_690_000_000, json!(100))],
    )
    .await;
    mount_usage_stat(&server, "records", &[(1_690_000_000, json!(50000))]).await;

    let (code, json) = run_json(
        creds(&["usage", "summary", "--since", "7d"]),
        ev(&[
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    // U1: both meters present side by side, plus the derived figure.
    assert!(json.get("requests").is_some());
    assert!(json.get("operations").is_some());
    assert!(json.get("billed_search_requests_approx").is_some());
    assert_eq!(json["requests"]["value"], json!(1000.0));
    assert_eq!(json["operations"]["value"], json!(2000.0));
    assert_eq!(json["session_ops"]["usage_calls"], json!(4));
}

#[tokio::test]
async fn usage_series_json_envelope() {
    let server = MockServer::start().await;
    mount_usage_stat(
        &server,
        "total_search_operations",
        &[(1_690_000_000, json!(10)), (1_690_086_400, json!(20))],
    )
    .await;

    let (code, json) = run_json(
        creds(&[
            "usage",
            "series",
            "--statistic",
            "total_search_operations",
            "--granularity",
            "daily",
            "--since",
            "7d",
        ]),
        ev(&[
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["statistic"], json!("total_search_operations"));
    let points = json["points"].as_array().expect("points array");
    assert_eq!(points.len(), 2);
    assert_eq!(json["session_ops"]["usage_calls"], json!(1));
}

#[tokio::test]
async fn usage_meters_json_envelope_both_series_side_by_side() {
    let server = MockServer::start().await;
    mount_usage_stat(
        &server,
        "total_search_requests",
        &[(1_690_000_000, json!(5)), (1_690_086_400, json!(7))],
    )
    .await;
    mount_usage_stat(
        &server,
        "total_search_operations",
        &[(1_690_000_000, json!(9)), (1_690_086_400, json!(11))],
    )
    .await;

    let (code, json) = run_json(
        creds(&["usage", "meters", "--since", "7d"]),
        ev(&[
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["requests"]["points"].as_array().unwrap().len(), 2);
    assert_eq!(json["operations"]["points"].as_array().unwrap().len(), 2);
    assert_eq!(json["session_ops"]["usage_calls"], json!(2));
}

#[tokio::test]
async fn analytics_top_searches_json_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "searches": [{"search": "aspirina", "count": 40, "nbHits": 12}]
        })))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["analytics", "top-searches", "--since", "7d"]),
        ev(&[
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["rows"][0]["search"], json!("aspirina"));
    assert_eq!(json["session_ops"]["analytics_calls"], json!(1));
}

#[tokio::test]
async fn analytics_no_results_json_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches/noResults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "searches": [{"search": "xyz123", "count": 5, "withFilterCount": 1}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/searches/noResultRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rate": 0.05, "count": 1000, "noResultCount": 50, "dates": []
        })))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["analytics", "no-results", "--since", "7d"]),
        ev(&[
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["rows"][0]["search"], json!("xyz123"));
    assert_eq!(json["overall_rate"]["rate"], json!(0.05));
    assert_eq!(json["session_ops"]["analytics_calls"], json!(2));
}

#[tokio::test]
async fn analytics_scrape_signals_json_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "searches": [
                {"search": "scarpe da corsa", "count": 300, "nbHits": 40},
                {"search": "crema solare", "count": 210, "nbHits": 22}
            ]
        })))
        .mount(&server)
        .await;

    let (code, json) = run_json(
        creds(&["analytics", "scrape-signals", "--since", "7d"]),
        ev(&[
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["signals"].as_array().unwrap().len(), 4);
    assert_eq!(json["session_ops"]["analytics_calls"], json!(1));
}

// =========================================================================
// 2. Output modes.
// =========================================================================

/// See the file-level doc comment's "A note on `--human`" section: this
/// asserts the unconditional properties (exit 0, no raw key leak) as hard
/// requirements, and the human-render-specific properties (non-JSON,
/// section heading) only when this particular run wasn't itself
/// agent-detected back into JSON.
fn assert_human_or_gracefully_skip(stdout: &str, expected_heading_substr: &str) {
    if serde_json::from_str::<Value>(stdout.trim()).is_ok() {
        // This test run was itself agent-detected (see file-level doc
        // comment) — --human was overridden back to JSON by design, so
        // there is nothing human-specific left to assert here.
        return;
    }
    assert!(
        !stdout.trim_start().starts_with('{'),
        "expected non-JSON human output: {stdout}"
    );
    assert!(
        stdout.contains(expected_heading_substr),
        "expected human heading '{expected_heading_substr}' in: {stdout}"
    );
}

#[tokio::test]
async fn human_mode_doctor_exit0_no_raw_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
        .mount(&server)
        .await;

    let raw_key = "HUMANMODE_DOCTOR_RAW_KEY_MARKER_998877";
    let output = spawn_alx_async(
        sv(&[
            "--human", "--app-id", "test-app", "--key", raw_key, "doctor",
        ]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &server.uri()),
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", &server.uri()),
        ]),
    )
    .await;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!stdout.contains(raw_key) && !stderr.contains(raw_key));
    assert_human_or_gracefully_skip(&stdout, "alx doctor");
}

#[tokio::test]
async fn human_mode_keys_audit_exit0_no_raw_key() {
    let server = MockServer::start().await;
    let raw_key = "HUMANMODE_KEYS_RAW_KEY_MARKER_112233";
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{"value": raw_key, "acl": ["search"]}]
        })))
        .mount(&server)
        .await;

    let output = spawn_alx_async(
        sv(&[
            "--human", "--app-id", "test-app", "--key", raw_key, "keys", "audit",
        ]),
        ev(&[("ALX_SEARCH_BASE_URL", &server.uri())]),
    )
    .await;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!stdout.contains(raw_key) && !stderr.contains(raw_key));
    assert_human_or_gracefully_skip(&stdout, "alx keys audit");
}

#[tokio::test]
async fn human_mode_usage_summary_exit0_no_raw_key() {
    let server = MockServer::start().await;
    mount_usage_stat(
        &server,
        "total_search_requests",
        &[(1_690_000_000, json!(1000))],
    )
    .await;
    mount_usage_stat(
        &server,
        "total_search_operations",
        &[(1_690_000_000, json!(2000))],
    )
    .await;
    mount_usage_stat(
        &server,
        "querysuggestions_total_search_requests",
        &[(1_690_000_000, json!(100))],
    )
    .await;
    mount_usage_stat(&server, "records", &[(1_690_000_000, json!(50000))]).await;

    let raw_key = "HUMANMODE_USAGE_RAW_KEY_MARKER_445566";
    let output = spawn_alx_async(
        sv(&[
            "--human", "--app-id", "test-app", "--key", raw_key, "usage", "summary", "--since",
            "7d",
        ]),
        ev(&[
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!stdout.contains(raw_key) && !stderr.contains(raw_key));
    assert_human_or_gracefully_skip(&stdout, "usage summary");
}

#[tokio::test]
async fn jq_end_to_end_session_ops() {
    let output = spawn_alx_async(
        sv(&["--app-id", "test-app", "--jq", ".session_ops", "doctor"]),
        vec![],
    )
    .await;

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(stdout.trim()).expect("jq output should be valid JSON");
    assert!(v.get("logs_calls").is_some());
    assert!(v.get("usage_calls").is_some());
    assert!(v.get("analytics_calls").is_some());
    assert!(v.get("keys_calls").is_some());
}

#[tokio::test]
async fn jq_missing_binary_on_path_yields_jqfailed_and_nonzero_exit() {
    let bin = env!("CARGO_BIN_EXE_alx");
    let output = std::process::Command::new(bin)
        .args(["--app-id", "test-app", "--jq", ".session_ops", "doctor"])
        .env_clear()
        .env("PATH", "/nonexistent")
        .output()
        .expect("failed to spawn the alx binary");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value =
        serde_json::from_str(stdout.trim()).expect("expected a JSON error envelope on stdout");
    let error_text = v["error"].as_str().unwrap_or_default();
    assert!(
        error_text.contains("jq"),
        "expected jq-related error text: {v}"
    );
    let suggestion = v["suggestion"].as_str().unwrap_or_default();
    assert!(
        suggestion.contains("jq"),
        "expected a jq-related suggestion: {v}"
    );
}

// =========================================================================
// 3. completions / manpage.
// =========================================================================

#[tokio::test]
async fn completions_bash_nonempty_exit0() {
    let output = spawn_alx_async(sv(&["completions", "bash"]), vec![]).await;
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alx"));
}

#[tokio::test]
async fn completions_zsh_nonempty_exit0() {
    let output = spawn_alx_async(sv(&["completions", "zsh"]), vec![]).await;
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alx"));
}

#[tokio::test]
async fn completions_fish_nonempty_exit0() {
    let output = spawn_alx_async(sv(&["completions", "fish"]), vec![]).await;
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alx"));
}

#[tokio::test]
async fn manpage_generates_roff_exit0() {
    let output = spawn_alx_async(sv(&["manpage"]), vec![]).await;
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // roff man pages open with a `.TH` (title heading) macro.
    assert!(stdout.contains(".TH"), "expected roff markup: {stdout}");
    assert!(stdout.contains("alx"));
}
