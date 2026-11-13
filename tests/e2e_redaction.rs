//! Redaction sweep (D0.2/D3): one test per command family, run with
//! `-v`/`--verbose` (the only sanctioned incidental-output channel,
//! `Presenter::progress`, stderr) against failing mocks, asserting a
//! distinctive raw key marker never appears anywhere in stdout+stderr
//! combined. `-v` matters specifically because `safety.rs`'s and
//! `commands/logs.rs`'s progress lines are the closest thing in this
//! codebase to a place a raw key could accidentally leak (ADV-1's actual
//! historical defect was exactly a progress/error-path leak, not a
//! response-body leak) — every other existing redaction-shaped test in the
//! suite (`adv1_*`, `k4_*`) runs non-verbose, so this file is the only place
//! the verbose path gets swept across every command family in one pass.
//!
//! No real network: every scenario points its surface's
//! `ALX_*_BASE_URL`/`ALX_LOGS_BASE_URLS` at a local `wiremock::MockServer`
//! returning a failing response (401/403), or at the guaranteed-closed
//! loopback port `http://127.0.0.1:1` for the over-privilege preflight's
//! search host (its network-error branch is itself a redaction-sensitive
//! path — see `safety::preflight_privilege_check`'s doc comment). Every
//! `Command` calls `.env_clear()` first.

use serde_json::json;
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

/// Asserts the marker never appears anywhere in stdout+stderr combined, and
/// (belt-and-suspenders) that the marker was actually distinctive enough to
/// be a meaningful check in the first place — a near-zero-risk sanity
/// assertion against a typo'd/empty marker silently making every assertion
/// here vacuously true.
fn assert_never_leaks(output: &std::process::Output, marker: &str) {
    assert!(marker.len() > 20, "marker not distinctive enough: {marker}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(marker) && !stderr.contains(marker),
        "raw key marker leaked — stdout={stdout:?} stderr={stderr:?}"
    );
}

// ---------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------

#[tokio::test]
async fn redaction_doctor_verbose_failing_mocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2/status"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    // /1/keys deliberately unmounted -> wiremock 404s -> list_keys fails ->
    // probe_keys falls back to /1/keys/{key}, which embeds the raw marker
    // as a path segment — exactly the shape ADV-1 originally leaked.
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;

    let marker = "REDACTION_DOCTOR_VERBOSE_RAW_KEY_MARKER_2026";
    let output = spawn_alx_async(
        sv(&["-v", "--app-id", "test-app", "--key", marker, "doctor"]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &server.uri()),
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", &server.uri()),
        ]),
    )
    .await;

    assert!(
        output.status.success(),
        "doctor reports failures, it doesn't fail on them: {:?}",
        output.status.code()
    );
    assert_never_leaks(&output, marker);
}

// ---------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------

#[tokio::test]
async fn redaction_logs_verbose_failing_mocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;

    let marker = "REDACTION_LOGS_VERBOSE_RAW_KEY_MARKER_2026";
    let output = spawn_alx_async(
        sv(&[
            "-v", "--app-id", "test-app", "--key", marker, "logs", "sample",
        ]),
        ev(&[
            ("ALX_LOGS_BASE_URLS", &server.uri()),
            // Own search host too, so the preflight self-check's own
            // (redaction-sensitive) network-error branch also fires.
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert!(
        !output.status.success(),
        "every host failing must fail the command"
    );
    assert_never_leaks(&output, marker);
}

// ---------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------

#[tokio::test]
async fn redaction_keys_verbose_failing_mocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    // /1/keys/{marker} deliberately unmounted -> 404 -> preflight
    // self-check skips silently (its own redaction-sensitive branch).

    let marker = "REDACTION_KEYS_VERBOSE_RAW_KEY_MARKER_2026";
    let output = spawn_alx_async(
        sv(&[
            "-v", "--app-id", "test-app", "--key", marker, "keys", "audit",
        ]),
        ev(&[("ALX_SEARCH_BASE_URL", &server.uri())]),
    )
    .await;

    assert!(!output.status.success());
    assert_never_leaks(&output, marker);
}

/// Extra: the specific ADV-1 shape — the self-read at `/1/keys/{key}`
/// itself fails at the transport layer (not just a 4xx), which is the one
/// call in this codebase whose *request URL* embeds the raw key value as a
/// path segment. Verbose mode's progress lines are exactly where that used
/// to leak.
#[tokio::test]
async fn redaction_keys_verbose_self_read_network_failure() {
    let marker = "REDACTION_KEYS_SELFREAD_NETFAIL_RAW_KEY_MARKER_2026";
    let output = spawn_alx_async(
        sv(&[
            "-v", "--app-id", "test-app", "--key", marker, "keys", "audit",
        ]),
        ev(&[("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1")]),
    )
    .await;

    assert!(!output.status.success());
    assert_never_leaks(&output, marker);
}

// ---------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------

#[tokio::test]
async fn redaction_usage_verbose_failing_mocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_operations"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/querysuggestions_total_search_requests"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/usage/records"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;

    let marker = "REDACTION_USAGE_VERBOSE_RAW_KEY_MARKER_2026";
    let output = spawn_alx_async(
        sv(&[
            "-v", "--app-id", "test-app", "--key", marker, "usage", "summary", "--since", "7d",
        ]),
        ev(&[
            ("ALX_USAGE_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert!(!output.status.success());
    assert_never_leaks(&output, marker);
}

// ---------------------------------------------------------------------
// analytics
// ---------------------------------------------------------------------

#[tokio::test]
async fn redaction_analytics_verbose_failing_mocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&server)
        .await;

    let marker = "REDACTION_ANALYTICS_VERBOSE_RAW_KEY_MARKER_2026";
    let output = spawn_alx_async(
        sv(&[
            "-v",
            "--app-id",
            "test-app",
            "--key",
            marker,
            "analytics",
            "top-searches",
            "--since",
            "7d",
        ]),
        ev(&[
            ("ALX_ANALYTICS_BASE_URL", &server.uri()),
            ("ALX_SEARCH_BASE_URL", "http://127.0.0.1:1"),
        ]),
    )
    .await;

    assert!(!output.status.success());
    assert_never_leaks(&output, marker);
}

// ---------------------------------------------------------------------
// Cross-cutting: the safety-refusal path itself (exit 6) is the one place
// a write-capable ACL list is printed alongside a key-adjacent decision —
// confirm verbose mode's extra progress output around it never leaks
// either, for both the refusal and the --i-know-bypassed proceed-with-
// warning branch (safety.rs line ~126, "proceeding with write-capable
// ACL(s) ... (--i-know)").
// ---------------------------------------------------------------------

#[tokio::test]
async fn redaction_safety_refusal_verbose_no_i_know() {
    let server = MockServer::start().await;
    let marker = "REDACTION_SAFETY_REFUSAL_VERBOSE_RAW_KEY_MARKER_2026";
    Mock::given(method("GET"))
        .and(path(format!("/1/keys/{marker}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": marker,
            "acl": ["search", "deleteIndex"],
        })))
        .mount(&server)
        .await;

    let output = spawn_alx_async(
        sv(&[
            "-v", "--app-id", "test-app", "--key", marker, "keys", "audit",
        ]),
        ev(&[("ALX_SEARCH_BASE_URL", &server.uri())]),
    )
    .await;

    assert_eq!(output.status.code(), Some(6));
    assert_never_leaks(&output, marker);
}

#[tokio::test]
async fn redaction_safety_i_know_proceed_with_warning_verbose() {
    let server = MockServer::start().await;
    let marker = "REDACTION_SAFETY_IKNOW_VERBOSE_RAW_KEY_MARKER_2026";
    Mock::given(method("GET"))
        .and(path(format!("/1/keys/{marker}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": marker,
            "acl": ["search", "deleteIndex"],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{"value": marker, "acl": ["search", "deleteIndex"]}]
        })))
        .mount(&server)
        .await;

    let output = spawn_alx_async(
        sv(&[
            "-v", "--i-know", "--app-id", "test-app", "--key", marker, "keys", "audit",
        ]),
        ev(&[("ALX_SEARCH_BASE_URL", &server.uri())]),
    )
    .await;

    assert!(output.status.success());
    assert_never_leaks(&output, marker);
}
