//! U1/U3 acceptance criteria: `alx usage summary`
//! must always surface both the requests and operations meters side by
//! side, and must expose the derived/approximate billed-requests figure as
//! a first-class labeled field. Runs the real compiled `alx` binary against
//! a `wiremock` server (`ALX_USAGE_BASE_URL` override) — no real network,
//! no real credentials.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spawn_alx(args: &[&str], base_url: &str) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    std::process::Command::new(bin)
        .args(args)
        .env_clear()
        .env("ALX_USAGE_BASE_URL", base_url)
        // D0.3 over-privilege gate now runs before the first real usage
        // call; redirect it to a guaranteed-closed loopback port so it
        // fails fast (network error, best-effort no-op) instead of
        // attempting a real DNS/network call to algolia.net.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to spawn the alx binary")
}

async fn run_alx_json(args: Vec<&'static str>, base_url: String) -> (i32, Value) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, &base_url))
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

fn stat_response(points: &[(i64, Value)]) -> Value {
    json!({
        "statistics": points
            .iter()
            .map(|(t, v)| json!({"t": t, "v": v}))
            .collect::<Vec<_>>()
    })
}

async fn mount_summary_mocks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(&[
            (1_690_000_000, json!(1000)),
            (1_690_086_400, json!(1200)),
        ])))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(&[
            (1_690_000_000, json!(2000)),
            (1_690_086_400, json!(2400.0)),
        ])))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/1/usage/querysuggestions_total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(&[
            (1_690_000_000, json!(100)),
            (1_690_086_400, json!(120)),
        ])))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(&[
            (1_690_000_000, json!(50000)),
            (1_690_086_400, json!(50500)),
        ])))
        .mount(server)
        .await;
}

#[tokio::test]
async fn u1_both_meters_in_summary_json() {
    let server = MockServer::start().await;
    mount_summary_mocks(&server).await;

    let (code, json) = run_alx_json(
        vec![
            "--app-id", "test-app", "--key", "test-key", "usage", "summary", "--since", "30d",
        ],
        server.uri(),
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");

    // U1: never a single collapsed "usage" number — requests AND
    // operations both present, every time, at the top level.
    assert!(
        json.get("requests").is_some(),
        "summary JSON must include a `requests` meter: {json}"
    );
    assert!(
        json.get("operations").is_some(),
        "summary JSON must include an `operations` meter: {json}"
    );
    assert_eq!(
        json["requests"]["statistic"],
        json!("total_search_requests")
    );
    assert_eq!(
        json["operations"]["statistic"],
        json!("total_search_operations")
    );
    assert_eq!(json["requests"]["value"], json!(2200.0));
    assert_eq!(json["operations"]["value"], json!(4400.0));
}

#[tokio::test]
async fn u3_derived_field_computed_and_labeled() {
    let server = MockServer::start().await;
    mount_summary_mocks(&server).await;

    let (code, json) = run_alx_json(
        vec![
            "--app-id", "test-app", "--key", "test-key", "usage", "summary", "--since", "30d",
        ],
        server.uri(),
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");

    let derived = &json["billed_search_requests_approx"];
    assert!(
        derived.is_object(),
        "expected a first-class billed_search_requests_approx object: {json}"
    );
    // requests total (1000+1200=2200) - querysuggestions total (100+120=220) = 1980
    assert_eq!(derived["value"], json!(1980.0));
    assert_eq!(derived["label"], json!("derived/approximate"));
    assert!(derived["formula"]
        .as_str()
        .unwrap()
        .contains("querysuggestions"));
}
