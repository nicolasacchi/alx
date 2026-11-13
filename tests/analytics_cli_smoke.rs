//! Black-box integration tests for `alx analytics ...`. This package has no
//! library target (bin-only, see `Cargo.toml`) so an integration test in
//! `tests/` cannot `use` crate internals directly — instead these spawn the
//! actual compiled binary (`CARGO_BIN_EXE_alx`, cargo's sanctioned hook for
//! testing bin-only crates) against a local wiremock server, exercising the
//! full CLI -> AppContext -> command -> algolia -> http pipeline end to
//! end. Pure-function/HTTP-request-shape coverage lives inline in
//! `src/algolia/analytics.rs` / `src/commands/analytics.rs` per D12 ("inline
//! `#[cfg(test)]` for pure functions").

use serde_json::Value;
use std::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn alx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_alx")
}

#[tokio::test]
async fn analytics_top_searches_end_to_end_json() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "searches": [
                {"search": "aspirina", "count": 500, "nbHits": 12}
            ]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "top-searches", "--since", "7d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        // D0.3 over-privilege gate now runs before the first real
        // analytics call; redirect it to a guaranteed-closed loopback
        // port so it fails fast instead of attempting a real network call.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["index"], "Product");
    assert_eq!(v["region"], "de");
    assert_eq!(v["rows"][0]["search"], "aspirina");
    assert_eq!(v["rows"][0]["count"], 500);
    assert_eq!(v["session_ops"]["analytics_calls"], 1);
}

#[tokio::test]
async fn analytics_wrong_region_surfaces_suggestion_end_to_end() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"message": "Index not found"})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args([
            "analytics",
            "top-searches",
            "--since",
            "7d",
            "--region",
            "de",
        ])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        // D0.3 over-privilege gate now runs before the first real
        // analytics call; redirect it to a guaranteed-closed loopback
        // port so it fails fast instead of attempting a real network call.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a generic Api error (404) maps to exit code 1 (D5); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON error envelope");
    let suggestion = v["suggestion"]
        .as_str()
        .expect("expected a suggestion field in the error envelope");
    assert!(
        suggestion.contains("--region us"),
        "suggestion was: {suggestion}"
    );
}

#[tokio::test]
async fn analytics_no_results_pairs_list_with_overall_rate_end_to_end() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches/noResults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "searches": [
                {"search": "xyz123", "count": 42, "withFilterCount": 5}
            ]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/searches/noResultRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": 0.08,
            "count": 12500,
            "noResultCount": 1000,
            "dates": []
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "no-results", "--since", "7d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        // D0.3 over-privilege gate now runs before the first real
        // analytics call; redirect it to a guaranteed-closed loopback
        // port so it fails fast instead of attempting a real network call.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    // U-style instinct applied here: never show the no-results list without
    // the headline overall rate alongside it.
    assert_eq!(v["rows"][0]["search"], "xyz123");
    assert_eq!(v["overall_rate"]["rate"], 0.08);
    assert_eq!(v["overall_rate"]["count"], 12500);
    assert_eq!(v["session_ops"]["analytics_calls"], 2);
}

/// BUG-ALX-ANALYTICS-NULLCOLL, exact repro: `$ alx analytics top-searches
/// --since 30d --region us` — confirmed live 2026-08-04, a no-data region
/// returns HTTP 200 with `{"searches": null}` (a present key with an
/// explicit `null`, not an absent key), which `#[serde(default)]` alone
/// does not rescue. Before the fix this failed the whole command with
/// "failed to parse top-searches response: invalid type: null, expected a
/// sequence" (exit 1); must now exit 0 with zero rows.
#[tokio::test]
async fn analytics_top_searches_no_data_region_tolerates_null_searches() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"searches": null})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args([
            "analytics",
            "top-searches",
            "--since",
            "30d",
            "--region",
            "us",
        ])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "a null 'searches' field must exit 0, not fail the parse — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["rows"].as_array().unwrap().len(), 0);
}

/// Same exact repro for `alx analytics no-results --since 30d --region us`
/// — the second command the bug report called out.
#[tokio::test]
async fn analytics_no_results_no_data_region_tolerates_null_searches() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches/noResults"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"searches": null})),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/searches/noResultRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": null, "count": 0, "noResultCount": 0, "dates": null
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args([
            "analytics",
            "no-results",
            "--since",
            "30d",
            "--region",
            "us",
        ])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "a null 'searches'/'dates' field must exit 0, not fail the parse — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["rows"].as_array().unwrap().len(), 0);
    assert!(v["overall_rate"]["rate"].is_null());
}

#[tokio::test]
async fn analytics_scrape_signals_reports_all_four_keys_end_to_end() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "searches": [
                {"search": "scarpe da corsa", "count": 300, "nbHits": 40},
                {"search": "crema solare", "count": 210, "nbHits": 22},
                {"search": "vitamina c", "count": 180, "nbHits": 15}
            ]
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "scrape-signals", "--since", "7d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        // D0.3 over-privilege gate now runs before the first real
        // analytics call; redirect it to a guaranteed-closed loopback
        // port so it fails fast instead of attempting a real network call.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let signals = v["signals"].as_array().expect("signals array");
    assert_eq!(
        signals.len(),
        4,
        "A2: all four signals must be reported distinctly"
    );
    let names: Vec<&str> = signals
        .iter()
        .map(|s| s["signal"].as_str().unwrap())
        .collect();
    for expected in [
        "systematic_enumeration",
        "empty_query_high_volume_pagination",
        "non_served_language_or_test_strings",
        "flat_distribution",
    ] {
        assert!(
            names.contains(&expected),
            "missing signal {expected} in {names:?}"
        );
    }

    let lower = stdout.to_lowercase();
    assert!(
        !lower.contains("confirmed"),
        "A3: must not assert confirmed abuse"
    );
    assert!(
        !lower.contains("scraper detected"),
        "A3: must not assert a scraper as detected"
    );
}

#[tokio::test]
async fn analytics_clicks_end_to_end_json() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/clickThroughRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": 0.105,
            "trackedSearchCount": 120000,
            "clickCount": 12600,
            "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/averageClickPosition"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "average": 6.42,
            "clickCount": 12600,
            "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/positions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "positions": [
                {"position": [1, 1], "clickCount": 6000},
                {"position": [21, -1], "clickCount": 1100}
            ]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "updatedAt": "2026-08-04T06:00:00.000Z"
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "clicks", "--since", "7d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        // D0.3 over-privilege gate now runs before the first real
        // analytics call; redirect it to a guaranteed-closed loopback
        // port so it fails fast instead of attempting a real network call.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["index"], "Product");
    assert_eq!(v["region"], "de");
    assert_eq!(v["updated_at"], "2026-08-04T06:00:00.000Z");
    assert_eq!(v["click_through_rate"]["clickCount"], 12600);
    assert_eq!(v["average_click_position"]["average"], 6.42);
    assert_eq!(v["positions"][0]["clickCount"], 6000);
    assert_eq!(v["positions"][1]["position"][1], -1);
    // Four calls: clickThroughRate + averageClickPosition + positions + status.
    assert_eq!(v["session_ops"]["analytics_calls"], 4);
}

#[tokio::test]
async fn analytics_conversions_end_to_end_json() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/conversions/conversionRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": 0.08,
            "trackedSearchCount": 120000,
            "conversionCount": 9600,
            "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/conversions/addToCartRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": 0.075,
            "trackedSearchCount": 120000,
            "addToCartCount": 9000,
            "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/conversions/purchaseRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": 0.025,
            "trackedSearchCount": 120000,
            "purchaseCount": 3000,
            "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "updatedAt": "2026-08-04T06:00:00.000Z"
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args([
            "analytics",
            "conversions",
            "--since",
            "7d",
            "--region",
            "us",
        ])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(v["region"], "us");
    assert_eq!(v["conversion_rate"]["conversionCount"], 9600);
    assert_eq!(v["add_to_cart_rate"]["addToCartCount"], 9000);
    assert_eq!(v["purchase_rate"]["purchaseCount"], 3000);
    assert_eq!(v["updated_at"], "2026-08-04T06:00:00.000Z");
    assert_eq!(v["session_ops"]["analytics_calls"], 4);
}

#[tokio::test]
async fn analytics_revenue_end_to_end_json_never_assumes_eur_only() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/conversions/revenue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "currencies": {
                "EUR": {
                    "currency": "EUR",
                    "averageOrderValue": 38.58,
                    "revenue": 12345.6,
                    "transactionCount": 320
                },
                "USD": {
                    "currency": "USD",
                    "averageOrderValue": 51.2,
                    "revenue": 9820.5,
                    "transactionCount": 192
                }
            }
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "updatedAt": "2026-08-04T06:00:00.000Z"
        })))
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "revenue", "--since", "7d"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "expected success exit, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let currencies = v["currencies"].as_array().expect("currencies array");
    assert_eq!(currencies.len(), 2, "must render both EUR and USD rows");
    let codes: Vec<&str> = currencies
        .iter()
        .map(|c| c["currency"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"EUR"));
    assert!(codes.contains(&"USD"));
    assert_eq!(v["updated_at"], "2026-08-04T06:00:00.000Z");
    // Two calls: revenue + status.
    assert_eq!(v["session_ops"]["analytics_calls"], 2);
}

#[tokio::test]
async fn analytics_clicks_wrong_region_surfaces_suggestion_end_to_end() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/clickThroughRate"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"message": "Index not found"})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "clicks", "--since", "7d", "--region", "us"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a generic Api error (404) maps to exit code 1 (D5); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON error envelope");
    let suggestion = v["suggestion"]
        .as_str()
        .expect("expected a suggestion field in the error envelope");
    assert!(
        suggestion.contains("--region de"),
        "suggestion was: {suggestion}"
    );
}

#[tokio::test]
async fn analytics_clicks_no_data_region_returns_exit_0_with_null_updated_at() {
    // The bug this test exists to catch: Algolia's `/2/status` returns HTTP
    // 200 with `{"updatedAt": null}` (never an error) for a region/index
    // combination with no analytics data yet — confirmed live 2026-08-04
    // against `--region us`, which has none for this app. Before the fix,
    // `AnalyticsStatusResponse.updated_at: String` made this fail every
    // `clicks`/`conversions`/`revenue` call in that region with "failed to
    // parse status response: invalid type: null, expected a string" (exit
    // 1), even though the click/conversion/revenue endpoints themselves
    // returned perfectly valid (all-zero) data. This is a real black-box
    // run of the compiled binary — no direct access to `AnalyticsStatusResponse`
    // from this integration test (bin-only crate).
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/clickThroughRate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rate": null, "trackedSearchCount": 0, "clickCount": 0, "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/averageClickPosition"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "average": null, "clickCount": 0, "dates": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/clicks/positions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"positions": []})),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"updatedAt": null})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "clicks", "--since", "30d", "--region", "us"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "a no-data region must exit 0, not fail on the null status parse — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    // `updated_at` must serialize as JSON `null` and be PRESENT as a key —
    // never omitted — so a freshness-checking consumer can tell "no data"
    // apart from "field missing" (spec step 3).
    assert!(
        v.as_object().unwrap().contains_key("updated_at"),
        "updated_at key must be present even when the value is null: {v}"
    );
    assert!(
        v["updated_at"].is_null(),
        "updated_at should serialize as JSON null for a no-data region: {v}"
    );
    assert_eq!(v["click_through_rate"]["rate"], Value::Null);
    assert_eq!(v["click_through_rate"]["clickCount"], 0);
    assert_eq!(v["average_click_position"]["average"], Value::Null);
    assert_eq!(v["positions"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn analytics_conversions_no_data_region_returns_exit_0() {
    // Same class of bug as the `clicks` sibling test above, exercised
    // against `conversions` since it fans out through the same shared
    // `analytics::status` fetcher independently.
    let mock_server = MockServer::start().await;
    for p in [
        "/2/conversions/conversionRate",
        "/2/conversions/addToCartRate",
        "/2/conversions/purchaseRate",
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rate": null, "trackedSearchCount": 0, "conversionCount": 0,
                "addToCartCount": 0, "purchaseCount": 0, "dates": []
            })))
            .mount(&mock_server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"updatedAt": null})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args([
            "analytics",
            "conversions",
            "--since",
            "30d",
            "--region",
            "us",
        ])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "a no-data region must exit 0, not fail on the null status parse — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert!(v["updated_at"].is_null());
    assert!(v.as_object().unwrap().contains_key("updated_at"));
}

#[tokio::test]
async fn analytics_revenue_no_data_region_returns_exit_0() {
    // Same class of bug, exercised against `revenue`.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/conversions/revenue"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"currencies": {}})),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"updatedAt": null})),
        )
        .mount(&mock_server)
        .await;

    let output = Command::new(alx_bin())
        .args(["analytics", "revenue", "--since", "30d", "--region", "us"])
        .env("ALGOLIA_APPLICATION_ID", "testapp")
        .env("ALGOLIA_ANALYTICS_API_KEY", "testkey")
        .env("ALX_ANALYTICS_BASE_URL", mock_server.uri())
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to run alx binary");

    assert!(
        output.status.success(),
        "a no-data region must exit 0, not fail on the null status parse — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert!(v["updated_at"].is_null());
    assert!(v.as_object().unwrap().contains_key("updated_at"));
    assert_eq!(v["currencies"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn analytics_missing_credentials_fails_cleanly() {
    let output = Command::new(alx_bin())
        .args(["analytics", "top-searches"])
        .env_remove("ALGOLIA_APPLICATION_ID")
        .env_remove("ALGOLIA_ANALYTICS_API_KEY")
        .env_remove("ALGOLIA_API_KEY")
        .env_remove("ALGOLIA_LOGS_API_KEY")
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
