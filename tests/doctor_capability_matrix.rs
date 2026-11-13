//! Black-box smoke test for `alx doctor` (design decision D8) — spawns the compiled binary against a `wiremock` server via the
//! `ALX_*_BASE_URL` env overrides. No real network, no real credentials.
//! Doctor deliberately never calls the over-privilege preflight (D8:
//! doctor's whole job is reporting on whatever key is configured, including
//! over-privileged ones — refusing to run would defeat its purpose), so
//! this is the one command whose black-box coverage needs no
//! `ALX_SEARCH_BASE_URL` override. `safety::preflight_privilege_check`
//! itself now takes an explicit `base_url` parameter (integrate-pass fix)
//! and every other real command wires it in — see
//! `tests/keys_input_validation.rs` for why `keys audit`'s own black-box
//! coverage still stops at its pre-network guard clauses.

use serde_json::{json, Value};
use std::os::unix::process::ExitStatusExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spawn_alx(args: &[&str], base_url: &str) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    std::process::Command::new(bin)
        .args(args)
        .env_clear()
        .env("ALGOLIA_APPLICATION_ID", "test-app")
        .env("ALGOLIA_API_KEY", "test-key")
        .env("ALX_LOGS_BASE_URLS", base_url)
        .env("ALX_USAGE_BASE_URL", base_url)
        .env("ALX_ANALYTICS_BASE_URL", base_url)
        .env("ALX_SEARCH_BASE_URL", base_url)
        .env("ALX_INSIGHTS_BASE_URL", base_url)
        .output()
        .expect("failed to spawn the alx binary")
}

async fn run_alx_json(args: &[&str], base_url: &str) -> (i32, Value) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let base_url = base_url.to_string();
    let output = tokio::task::spawn_blocking(move || {
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        spawn_alx(&args_ref, &base_url)
    })
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

#[tokio::test]
async fn doctor_smoke_reports_full_capability_matrix() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(402))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string("Insufficient ACL to access this resource."),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/keys/test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"value": "test-key", "acl": ["search"]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": []})))
        .mount(&server)
        .await;

    let (code, json) = run_alx_json(&["doctor"], &server.uri()).await;

    // D8: doctor exits 0 unless the app id itself is absent.
    assert_eq!(
        code, 0,
        "doctor should always exit 0 when app id is set: {json}"
    );

    let caps = json["capabilities"]
        .as_array()
        .expect("capabilities must be an array");
    assert_eq!(caps.len(), 5);

    let by = |name: &str| -> &Value {
        caps.iter()
            .find(|c| c["capability"] == name)
            .unwrap_or_else(|| panic!("missing capability row `{name}`: {json}"))
    };

    assert_eq!(by("logs")["reachable"], json!(true));
    assert_eq!(by("logs")["reason"], json!("ok"));

    assert_eq!(by("usage")["reachable"], json!(false));
    assert_eq!(by("usage")["reason"], json!("plan_gated"));

    assert_eq!(by("analytics")["reachable"], json!(true));
    assert_eq!(by("analytics")["reason"], json!("ok"));

    // keys: GET /1/keys 403s (non-admin, expected/informative per D8) but
    // the self-read fallback succeeds — still reachable/ok, single-key
    // scoped.
    let keys = by("keys");
    assert_eq!(keys["reachable"], json!(true));
    assert_eq!(keys["reason"], json!("ok"));
    assert!(keys["detail"]
        .as_str()
        .unwrap()
        .contains("single-key scoped"));

    assert_eq!(by("insights")["reachable"], json!(true));
    assert_eq!(by("insights")["reason"], json!("ok"));

    // D0.4 quota honesty: every completed call (including the 403) counts.
    let ops = &json["session_ops"];
    assert_eq!(ops["logs_calls"], json!(1));
    assert_eq!(ops["usage_calls"], json!(1));
    assert_eq!(ops["analytics_calls"], json!(1));
    assert_eq!(ops["keys_calls"], json!(2));
    assert_eq!(ops["insights_calls"], json!(1));
}

#[tokio::test]
async fn doctor_smoke_no_credentials_row_makes_no_http_call() {
    let server = MockServer::start().await;
    // Deliberately no mocks registered for any capability — if a
    // credential-less probe ever attempted an HTTP call, wiremock's
    // default "no matching mock" behavior would 500, which the assertions
    // below would catch via a non-`ok`/non-`no_credentials` reason.

    let bin = env!("CARGO_BIN_EXE_alx");
    let base_url = server.uri();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(bin)
            .arg("doctor")
            .env_clear()
            .env("ALGOLIA_APPLICATION_ID", "test-app")
            .env("ALX_LOGS_BASE_URLS", &base_url)
            .env("ALX_USAGE_BASE_URL", &base_url)
            .env("ALX_ANALYTICS_BASE_URL", &base_url)
            .env("ALX_SEARCH_BASE_URL", &base_url)
            .env("ALX_INSIGHTS_BASE_URL", &base_url)
            .output()
            .expect("failed to spawn the alx binary")
    })
    .await
    .expect("spawn_blocking join failed");

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("doctor stdout must be JSON");
    let caps = json["capabilities"].as_array().expect("capabilities array");
    assert_eq!(caps.len(), 5);
    for cap in caps {
        assert_eq!(
            cap["reason"],
            json!("no_credentials"),
            "capability={} full={json}",
            cap["capability"]
        );
        assert_eq!(cap["reachable"], json!(false));
    }

    let ops = &json["session_ops"];
    assert_eq!(ops["logs_calls"], json!(0));
    assert_eq!(ops["usage_calls"], json!(0));
    assert_eq!(ops["analytics_calls"], json!(0));
    assert_eq!(ops["keys_calls"], json!(0));
    assert_eq!(ops["insights_calls"], json!(0));
}

/// ADV-2 regression: an empty `ALX_LOGS_BASE_URLS` (e.g. an accidentally
/// exported empty env var — nothing prevents an operator/CI job from doing
/// this) used to panic `doctor` with an index-out-of-bounds at
/// `ctx.base_urls.logs(&app_id)[0]`, because `Some(vec![])` never falls
/// back to the 3-host default the way `None` does. `doctor` is explicitly
/// designed to run cleanly with any/no configuration (D8) — it must exit 0
/// here exactly as it does with no override at all, never crash.
#[tokio::test]
async fn doctor_empty_logs_base_urls_env_does_not_panic() {
    let output = tokio::task::spawn_blocking(|| {
        let bin = env!("CARGO_BIN_EXE_alx");
        std::process::Command::new(bin)
            .arg("doctor")
            .env_clear()
            .env("ALGOLIA_APPLICATION_ID", "test-app")
            .env("ALX_LOGS_BASE_URLS", "")
            .output()
            .expect("failed to spawn the alx binary")
    })
    .await
    .expect("spawn_blocking join failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.signal().is_none(),
        "doctor must not be killed by a signal (e.g. SIGABRT on panic=abort) on an empty \
         ALX_LOGS_BASE_URLS: status={:?} stderr={stderr}",
        output.status
    );
    assert!(
        !stderr.contains("panicked"),
        "doctor must not panic on an empty ALX_LOGS_BASE_URLS: stderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "doctor should still exit 0 (app id is set) — stderr={stderr}"
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("doctor stdout must be JSON");
    let caps = json["capabilities"].as_array().expect("capabilities array");
    assert_eq!(caps.len(), 5);
}

/// ADV-1 regression, end-to-end through the real binary: `probe_keys`
/// (D8) falls back from `list_keys` to the `/1/keys/{key}` self-read on
/// ANY error from the list call — including a genuine network failure, not
/// just the documented 403 — so pointing every base-URL override
/// (including the search host `get_self` hits) at a closed loopback port
/// drives `alx doctor`'s default (non-verbose) JSON output straight
/// through the vulnerable self-read path. The raw key must never appear
/// anywhere in stdout or stderr.
#[tokio::test]
async fn adv1_doctor_never_leaks_raw_key_on_self_read_network_failure() {
    let raw_key = "SUPERSECRETRAWKEYVALUE_ADV1_DOCTOR_E2E_1122334455";
    let output = tokio::task::spawn_blocking(move || {
        let bin = env!("CARGO_BIN_EXE_alx");
        std::process::Command::new(bin)
            .arg("doctor")
            .env_clear()
            .env("ALGOLIA_APPLICATION_ID", "test-app")
            .env("ALGOLIA_API_KEY", raw_key)
            .env("ALX_LOGS_BASE_URLS", "http://127.0.0.1:1")
            .env("ALX_USAGE_BASE_URL", "http://127.0.0.1:1")
            .env("ALX_ANALYTICS_BASE_URL", "http://127.0.0.1:1")
            .env("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")
            .env("ALX_INSIGHTS_BASE_URL", "http://127.0.0.1:1")
            .output()
            .expect("failed to spawn the alx binary")
    })
    .await
    .expect("spawn_blocking join failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(raw_key) && !stderr.contains(raw_key),
        "raw key leaked in doctor output: stdout={stdout} stderr={stderr}"
    );
    // Doctor still reports cleanly (network_error rows), it just must not
    // include the key value while doing so.
    let json: Value = serde_json::from_str(stdout.trim()).expect("doctor stdout must be JSON");
    let caps = json["capabilities"].as_array().expect("capabilities array");
    assert_eq!(caps.len(), 5);
}
