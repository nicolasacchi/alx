//! Black-box integration tests for `alx events ...`. This package has no
//! library target (bin-only, see `Cargo.toml`) so an integration test in
//! `tests/` cannot `use` crate internals directly — instead these spawn the
//! actual compiled binary (`CARGO_BIN_EXE_alx`) against a local wiremock
//! server, exercising the full CLI -> AppContext -> command -> algolia ->
//! http pipeline end to end. Pure-function/HTTP-request-shape coverage
//! lives inline in `src/algolia/insights.rs` / `src/commands/events.rs` per
//! D12 ("inline `#[cfg(test)]` for pure functions"); this file covers
//! process-level concerns those inline tests structurally can't: real exit
//! codes, clap-level argument rejection, and env-var credential precedence.

use serde_json::Value;
use std::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn alx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_alx")
}

/// Every `events` test needs the D0.3 over-privilege preflight redirected
/// at a guaranteed-closed loopback port, exactly like `analytics_cli_smoke.rs`
/// does — otherwise it would attempt a real network call against
/// `https://{app_id}.algolia.net`.
const CLOSED_SEARCH_BASE_URL: &str = "http://127.0.0.1:1";

#[tokio::test]
async fn events_metrics_end_to_end_json() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "metrics": [
                {"timestamp": "2026-08-03T00:00:00Z", "eventCount": 300000, "clickCount": 25000, "viewCount": 260000, "conversionCount": 19000, "errorCount": 35, "errorRate": 0.0001},
                {"timestamp": "2026-08-02T00:00:00Z", "eventCount": 290000, "clickCount": 24000, "viewCount": 250000, "conversionCount": 18500, "errorCount": 40, "errorRate": 0.00014}
            ]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "metrics", "--since", "2d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["totals"]["event_count"], 590000);
    assert_eq!(v["totals"]["error_count"], 75);
    assert!(v["totals"]["error_rate"]["value"].as_f64().unwrap() > 0.0);
    assert_eq!(v["totals"]["error_rate"]["label"], "derived/approximate");
    assert_eq!(v["buckets"].as_array().unwrap().len(), 2);
    assert_eq!(v["granularity"], "hour");
    assert_eq!(v["approximate"], true);
    assert_eq!(v["session_ops"]["insights_calls"], 1);
}

#[tokio::test]
async fn events_metrics_day_granularity_and_approximate_false() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/metrics"))
        .and(wiremock::matchers::query_param("granularity", "day"))
        .and(wiremock::matchers::query_param("approximate", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"metrics": []})))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args([
            "events",
            "metrics",
            "--since",
            "7d",
            "--granularity",
            "day",
            "--approximate",
            "false",
        ])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["granularity"], "day");
    assert_eq!(v["approximate"], false);
    assert_eq!(v["totals"]["event_count"], 0);
    assert!(v["totals"]["error_rate"]["value"].is_null());
}

/// The whole point of the CLI-level `EventsGranularity` enum (hour|day
/// only): `week` is rejected by clap itself, at parse time, before
/// `AppContext` — let alone the HTTP layer — is ever constructed. No
/// wiremock server is even started, since this must never touch the
/// network.
#[test]
fn events_metrics_granularity_week_rejected_before_any_http_call() {
    let output = Command::new(alx_bin())
        .args(["events", "metrics", "--granularity", "week"])
        .env_remove("ALGOLIA_APPLICATION_ID")
        .env_remove("ALGOLIA_INSIGHTS_API_KEY")
        .output()
        .expect("failed to run alx binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "an invalid --granularity value is a clap usage error (exit 2), stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.to_lowercase().contains("granularity") || stderr.contains("week"));
}

#[tokio::test]
async fn events_sample_aggregates_by_event_name_type_source_client_and_reports_window() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [
                {
                    "requestID": "r1",
                    "receivedAt": "2026-08-04T08:00:00.000Z",
                    "status": 200,
                    "errors": [],
                    "headers": {"User-Agent": ["Mozilla/5.0 (Macintosh)"]},
                    "event": {
                        "eventName": "Product Viewed", "eventType": "view",
                        "userToken": "anonymous-550e8400-e29b-41d4-a716-446655440000"
                    }
                },
                {
                    "requestID": "r2",
                    "receivedAt": "2026-08-04T08:03:00.000Z",
                    "status": 200,
                    "errors": [],
                    "headers": {"User-Agent": ["Hotwire Native Android/2.0"]},
                    "event": {
                        "eventName": "Product Clicked", "eventType": "click",
                        "queryID": "q1", "algoliaSource": ["instantsearch", "instantsearch-internal"],
                        "userToken": "12345678"
                    }
                },
                {
                    "requestID": "r3",
                    "receivedAt": "2026-08-04T08:07:00.000Z",
                    "status": 422,
                    "errors": ["The filters should be facet filters"],
                    "headers": {"User-Agent": ["Algolia for Rails (3.12.2)"]},
                    "event": {
                        "eventName": "Filter Applied", "eventType": "click",
                        "algoliaSource": ["instantsearch-internal"]
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "sample", "--since", "10m"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(v["fetched"], 3);
    assert_eq!(v["truncated"], false);
    assert!(v["truncation_warning"].is_null());

    // window: oldest 08:00:00, newest 08:07:00 -> 7 minutes.
    assert_eq!(v["window"]["elapsed_minutes"], 7);
    assert!(v["window"]["note"]
        .as_str()
        .unwrap()
        .contains("sample at least"));

    let by_name: Vec<&str> = v["by_event_name"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert!(by_name.contains(&"Product Viewed"));
    assert!(by_name.contains(&"Product Clicked"));
    assert!(by_name.contains(&"Filter Applied"));

    let by_client: std::collections::HashMap<&str, u64> = v["by_client"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["key"].as_str().unwrap(), r["count"].as_u64().unwrap()))
        .collect();
    assert_eq!(by_client.get("browser"), Some(&1));
    assert_eq!(by_client.get("Hotwire Native Android"), Some(&1));
    assert_eq!(by_client.get("server-side Ruby"), Some(&1));

    let by_source: std::collections::HashMap<&str, u64> = v["by_algolia_source"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["key"].as_str().unwrap(), r["count"].as_u64().unwrap()))
        .collect();
    assert_eq!(
        by_source.get("(none — server-side/hand-rolled emitter)"),
        Some(&1)
    );
    assert_eq!(
        by_source.get("instantsearch,instantsearch-internal"),
        Some(&1)
    );
    assert_eq!(by_source.get("instantsearch-internal"), Some(&1));

    // queryID presence broken down by eventType — view never carries one.
    let qid_rows = v["query_id_presence_by_event_type"].as_array().unwrap();
    let view_row = qid_rows.iter().find(|r| r["event_type"] == "view").unwrap();
    assert_eq!(view_row["with_query_id"], 0);
    assert_eq!(view_row["without_query_id"], 1);
    let click_row = qid_rows
        .iter()
        .find(|r| r["event_type"] == "click")
        .unwrap();
    assert_eq!(click_row["with_query_id"], 1);
    assert_eq!(click_row["without_query_id"], 1);

    // userToken shape.
    let token_shapes: Vec<&str> = v["user_token_shape"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert!(token_shapes.contains(&"anonymous-<uuid>"));
    assert!(token_shapes.contains(&"numeric"));

    // error message aggregation.
    let error_rows = v["by_error_message"].as_array().unwrap();
    assert_eq!(error_rows.len(), 1);
    assert_eq!(error_rows[0]["key"], "The filters should be facet filters");

    assert_eq!(v["session_ops"]["insights_calls"], 1);
}

/// THE critical constraint: a fetch landing at/near the live ~3,000-event
/// cap must be flagged as truncated — never silently presented as a
/// complete picture of the requested `--since` window.
#[tokio::test]
async fn events_sample_near_buffer_cap_warns_truncated() {
    let mock_server = MockServer::start().await;
    let events: Vec<serde_json::Value> = (0..2995)
        .map(|i| {
            serde_json::json!({
                "requestID": format!("r{i}"),
                "receivedAt": "2026-08-04T08:00:00.000Z",
                "status": 200,
                "errors": []
            })
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"events": events})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "sample", "--since", "30d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(v["fetched"], 2995);
    assert_eq!(v["truncated"], true);
    let warning = v["truncation_warning"]
        .as_str()
        .expect("expected a truncation warning");
    assert!(warning.to_lowercase().contains("silently dropped"));
    assert!(
        !v["truncated"].as_bool().unwrap() || v["fetched"].as_u64().unwrap() < 30 * 24 * 60 * 10000,
        "sanity: must never claim this is a complete 30-day window"
    );
}

#[tokio::test]
async fn events_sample_persist_writes_meta_and_jsonl_and_never_overwrites() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [
                {"requestID": "r1", "receivedAt": "2026-08-04T08:00:00.000Z", "status": 200, "errors": []}
            ]
        })))
        .mount(&mock_server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path = dir.path().to_str().unwrap();

    let run = || {
        Command::new(alx_bin())
            .args(["events", "sample", "--since", "10m", "--persist", dir_path])
            .env("ALGOLIA_APPLICATION_ID", "testapp")
            .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
            .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
            .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
            .output()
            .expect("failed to run alx binary")
    };

    let out1 = run();
    assert!(out1.status.success());
    let v1: Value = serde_json::from_str(&String::from_utf8_lossy(&out1.stdout)).unwrap();
    let meta1 = v1["persisted"]["meta_file"].as_str().unwrap().to_string();
    let events1 = v1["persisted"]["events_file"].as_str().unwrap().to_string();
    assert!(std::path::Path::new(&meta1).exists());
    assert!(std::path::Path::new(&events1).exists());

    let events_body = std::fs::read_to_string(&events1).unwrap();
    assert_eq!(events_body.lines().count(), 1);
    let parsed_line: Value = serde_json::from_str(events_body.lines().next().unwrap()).unwrap();
    assert_eq!(parsed_line["requestID"], "r1");

    // Second run against the SAME dir at plausibly the same timestamp
    // resolution must never clobber the first run's files.
    let out2 = run();
    assert!(out2.status.success());
    let v2: Value = serde_json::from_str(&String::from_utf8_lossy(&out2.stdout)).unwrap();
    let meta2 = v2["persisted"]["meta_file"].as_str().unwrap().to_string();

    // Either a distinct timestamp or a -2 suffix — either way, must not be
    // the identical path with silently-replaced content, and both files
    // must exist on disk simultaneously.
    if meta1 == meta2 {
        panic!("second persist run reused the exact same meta path: {meta1}");
    }
    assert!(std::path::Path::new(&meta1).exists());
    assert!(std::path::Path::new(&meta2).exists());
}

#[tokio::test]
async fn events_errors_groups_by_message_event_name_source_and_client() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [
                {
                    "requestID": "r1",
                    "receivedAt": "2026-08-04T08:00:00.000Z",
                    "status": 200,
                    "errors": [],
                    "event": {"eventName": "Product Viewed", "eventType": "view"}
                },
                {
                    "requestID": "r2",
                    "receivedAt": "2026-08-04T08:01:00.000Z",
                    "status": 422,
                    "errors": ["The filters should be facet filters"],
                    "headers": {"User-Agent": ["Mozilla/5.0"]},
                    "event": {
                        "eventName": "Filter Applied", "eventType": "click",
                        "algoliaSource": ["instantsearch-internal"],
                        "objectData": [{"filters": "review_rating>=4"}]
                    }
                },
                {
                    "requestID": "r3",
                    "receivedAt": "2026-08-04T08:02:00.000Z",
                    "status": 500,
                    "errors": [],
                    "event": {"eventName": "Conversion", "eventType": "conversion"}
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "errors", "--since", "10m"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(v["total_checked"], 3);
    assert_eq!(v["error_count"], 2, "the 200 event must be excluded");

    let groups = v["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2);

    let filter_group = groups
        .iter()
        .find(|g| g["event_name"] == "Filter Applied")
        .expect("expected the Filter Applied error group");
    assert_eq!(
        filter_group["error_message"],
        "The filters should be facet filters"
    );
    assert_eq!(filter_group["algolia_source"], "instantsearch-internal");
    assert_eq!(filter_group["client"], "browser");
    assert_eq!(filter_group["example_status"], 422);

    let conversion_group = groups
        .iter()
        .find(|g| g["event_name"] == "Conversion")
        .expect("expected the Conversion error group (status 500, no errors[] array)");
    assert!(conversion_group["error_message"]
        .as_str()
        .unwrap()
        .contains("HTTP 500"));

    assert_eq!(v["session_ops"]["insights_calls"], 1);
}

/// BUG-ALX-EVENTS-NULLCOLL regression, exact repro from the bug report:
/// `{"events":[{"requestID":"r1","status":200,"errors":null}]}` used to
/// fail the whole fetch with `invalid type: null, expected a sequence`
/// (exit 1) — `errors: null` is a PRESENT key with an explicit `null`
/// value, which `#[serde(default)]` alone does not rescue. Must now exit 0
/// with the event surfacing correctly and `errors` treated as empty.
#[tokio::test]
async fn events_sample_tolerates_null_errors_field_exact_bug_repro() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{"requestID": "r1", "status": 200, "errors": null}]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "sample", "--since", "10m"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected exit 0 for the exact bug-report repro payload, got exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["fetched"], 1);
    assert_eq!(v["skipped_count"], 0);
}

/// Same repro for `headers: null` and `objectIDs: null` — the other two
/// fields the bug report called out explicitly.
#[tokio::test]
async fn events_sample_tolerates_null_headers_and_object_ids() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{
                "requestID": "r1",
                "status": 200,
                "headers": null,
                "event": {"eventName": "Product Viewed", "objectIDs": null, "positions": null}
            }]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "sample", "--since", "10m"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected exit 0, got exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("valid JSON");
    assert_eq!(v["fetched"], 1);
    assert_eq!(v["skipped_count"], 0);
}

/// Per-event resilience end to end: one genuinely malformed event (not a
/// null-collection case — `status` holding an object where a number was
/// expected) mixed into an otherwise well-formed batch must be dropped and
/// counted, never abort the whole fetch.
#[tokio::test]
async fn events_sample_mixed_batch_skips_malformed_entry_and_reports_count() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [
                {"requestID": "good-1", "status": 200, "errors": []},
                {"requestID": "bad-1", "status": {"nested": "garbage"}},
                {"requestID": "good-2", "status": 200, "errors": []}
            ]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "sample", "--since", "10m"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "one malformed entry must never abort the whole fetch, got exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("valid JSON");
    assert_eq!(
        v["fetched"], 3,
        "fetched counts raw entries, including the skipped one"
    );
    assert_eq!(v["skipped_count"], 1);
}

/// Credential fallback: no ALGOLIA_INSIGHTS_API_KEY set, but
/// ALGOLIA_LOGS_API_KEY resolves — this is the entire reason `events`
/// exists without minting a new key (the logs ACL is empirically what the
/// live Insights API accepts).
#[tokio::test]
async fn events_falls_back_to_logs_api_key_when_no_insights_key_set() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .and(wiremock::matchers::header(
            "X-Algolia-API-Key",
            "logs-key-value",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"events": []})))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "sample", "--since", "10m"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env_remove("ALGOLIA_INSIGHTS_API_KEY")
        .env_remove("ALGOLIA_API_KEY")
        .env("ALGOLIA_LOGS_API_KEY", "logs-key-value")
        .env("ALX_INSIGHTS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", CLOSED_SEARCH_BASE_URL)
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit (logs-key fallback), stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["fetched"], 0);
}

#[tokio::test]
async fn events_missing_credentials_fails_cleanly() {
    let output = Command::new(alx_bin())
        .args(["events", "sample"])
        .env_remove("ALGOLIA_APPLICATION_ID")
        .env_remove("ALGOLIA_INSIGHTS_API_KEY")
        .env_remove("ALGOLIA_LOGS_API_KEY")
        .env_remove("ALGOLIA_API_KEY")
        .env_remove("ALGOLIA_ANALYTICS_API_KEY")
        .env_remove("ALGOLIA_USAGE_API_KEY")
        .env_remove("ALGOLIA_KEYS_API_KEY")
        .output()
        .expect("failed to run alx binary");

    assert!(
        !output.status.success(),
        "missing credentials must not exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON error envelope");
    assert!(v["error"]
        .as_str()
        .unwrap_or_default()
        .contains("ALGOLIA_APPLICATION_ID"));
}

#[tokio::test]
async fn events_safety_refusal_when_key_is_write_capable() {
    // D0.3: the over-privilege preflight must run before the first real
    // Insights call — pin that it actually fires for `events` the same way
    // it does for `logs`/`analytics`/`usage`.
    let search_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/keys/testkey"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": "testkey",
            "acl": ["search", "deleteIndex"]
        })))
        .mount(&search_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["events", "metrics"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_INSIGHTS_API_KEY", "testkey")
        .env("ALX_SEARCH_BASE_URL", search_server.uri())
        // Deliberately no ALX_INSIGHTS_BASE_URL — if the preflight refusal
        // didn't short-circuit before the real call, this would attempt a
        // real network request to insights.de.algolia.io and hang/fail
        // differently than exit 6.
        .output()
        .expect("failed to run alx binary");

    assert_eq!(
        output.status.code(),
        Some(6),
        "over-privileged key must refuse with exit 6, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
