//! U1/U5 acceptance criteria: `alx usage meters` is a
//! dedicated subcommand (not an alias of `summary`) whose entire purpose is
//! the side-by-side requests-vs-operations daily series view. Runs the real
//! compiled `alx` binary against a `wiremock` server (`ALX_USAGE_BASE_URL`
//! override) — no real network, no real credentials.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spawn_alx(args: &[&str], base_url: Option<&str>) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).env_clear();
    if let Some(url) = base_url {
        cmd.env("ALX_USAGE_BASE_URL", url);
        // D0.3 over-privilege gate now runs before the first real usage
        // call; redirect it to a guaranteed-closed loopback port so it
        // fails fast instead of attempting a real network call.
        cmd.env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1");
    }
    cmd.output().expect("failed to spawn the alx binary")
}

async fn run_alx_json(args: Vec<&'static str>, base_url: String) -> (i32, Value) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, Some(&base_url)))
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

#[tokio::test]
async fn u1_both_meters_in_meters_json() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(&[
            (1_690_000_000, json!(10)),
            (1_690_086_400, json!(20)),
        ])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stat_response(&[
            (1_690_000_000, json!(15.5)),
            (1_690_086_400, json!(25)),
        ])))
        .mount(&server)
        .await;

    let (code, json) = run_alx_json(
        vec![
            "--app-id", "test-app", "--key", "test-key", "usage", "meters", "--since", "7d",
        ],
        server.uri(),
    )
    .await;

    assert_eq!(code, 0, "expected success, got json={json}");

    // U5: `meters` is not an alias of `summary` — it returns full daily
    // point series for each meter, not just totals.
    let requests_points = json["requests"]["points"]
        .as_array()
        .expect("requests.points must be an array");
    let operations_points = json["operations"]["points"]
        .as_array()
        .expect("operations.points must be an array");

    assert_eq!(requests_points.len(), 2);
    assert_eq!(operations_points.len(), 2);
    assert_eq!(
        json["requests"]["statistic"],
        json!("total_search_requests")
    );
    assert_eq!(
        json["operations"]["statistic"],
        json!("total_search_operations")
    );

    // Tolerant int/float parsing carried through end to end.
    assert_eq!(requests_points[0]["value"], json!(10.0));
    assert_eq!(operations_points[0]["value"], json!(15.5));
}

#[tokio::test]
async fn u5_meters_is_a_dedicated_subcommand_not_a_summary_alias() {
    let output = spawn_alx(&["usage", "meters", "--help"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "`usage meters --help` should exit 0: {stdout}"
    );
    let lower = stdout.to_lowercase();
    assert!(
        lower.contains("side by side") || lower.contains("side-by-side"),
        "`usage meters --help` should describe the side-by-side view: {stdout}"
    );
}
