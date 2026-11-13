//! U2 acceptance criteria (design decisions D0.2/D8): a
//! plan-gated 403 (or 402) from the Usage API must surface through the
//! command layer as the same `plan_gated` classification `doctor` uses
//! (`AppError::PlanGated`, exit code 5) — never a raw HTTP error dump.
//! Runs the real compiled `alx` binary against a `wiremock` server
//! returning a 403 with plan wording.

use serde_json::Value;
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
        // fails fast instead of attempting a real network call.
        .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
        .output()
        .expect("failed to spawn the alx binary")
}

async fn run_alx(args: Vec<&'static str>, base_url: String) -> (i32, Value) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, &base_url))
        .await
        .expect("spawn_blocking join failed");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let json: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected JSON error envelope on stdout (exit={code}): {e}\nstdout={stdout:?}\nstderr={stderr:?}")
    });
    (code, json)
}

#[tokio::test]
async fn u2_plan_gated_classification() {
    let server = MockServer::start().await;

    // A single `series` call keeps this deterministic (no concurrent-fetch
    // race the way `summary`/`meters` fan out four/two requests).
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "This API is not available for your plan.",
            "status": 403
        })))
        .mount(&server)
        .await;

    let (code, json) = run_alx(
        vec![
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
            "30d",
        ],
        server.uri(),
    )
    .await;

    // D5: PlanGated -> exit code 5, distinct from generic 403/auth (4) or
    // generic failure (1).
    assert_eq!(
        code, 5,
        "plan-gated 403 must map to exit code 5, got {code}: {json}"
    );

    let error_text = json["error"].as_str().unwrap_or_default();
    assert!(
        error_text.to_lowercase().contains("plan"),
        "error text should surface the plan-gated wording, not a raw dump: {json}"
    );
}

#[tokio::test]
async fn u2_plan_gated_402_also_classifies_correctly() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(402).set_body_json(serde_json::json!({
            "message": "Payment required",
            "status": 402
        })))
        .mount(&server)
        .await;

    let (code, json) = run_alx(
        vec![
            "--app-id",
            "test-app",
            "--key",
            "test-key",
            "usage",
            "series",
            "--statistic",
            "records",
            "--granularity",
            "daily",
            "--since",
            "30d",
        ],
        server.uri(),
    )
    .await;

    assert_eq!(
        code, 5,
        "402 must also classify as plan-gated (exit 5), got {code}: {json}"
    );
}
