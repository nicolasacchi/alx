//! End-to-end exit-code matrix (design decision D5) — one canonical, passing
//! scenario per documented code, run against the real compiled binary
//! (`CARGO_BIN_EXE_alx`) via `std::process::Command`. Every scenario here is
//! independent of every other `tests/*.rs` file's own exit-code assertions;
//! this file exists so the whole D5 table can be read/verified in one place.
//!
//! No real network: every HTTP-touching scenario points its surface's
//! `ALX_*_BASE_URL`/`ALX_LOGS_BASE_URLS` override at either a local
//! `wiremock::MockServer` or the guaranteed-closed loopback port
//! `http://127.0.0.1:1`. Every `Command` calls `.env_clear()` first and adds
//! back only what the scenario needs.
//!
//! A note on the "invalid --since string" wording some specs use for the
//! generic exit-1 case: empirically, a *syntactically* malformed `--since`
//! value (e.g. `--since bogus`) is rejected by clap itself during argument
//! parsing (`SinceArg::from_str` returns `Err`, clap reports a usage error)
//! and exits with clap's own code 2 — confirmed below in
//! `exit_2_clap_rejects_syntactically_malformed_since_value`. The genuinely
//! *generic* (exit 1, `AppError::InvalidInput`) `--since`-shaped failure is a
//! `--since` value that parses fine syntactically but is semantically
//! invalid for the chosen `--granularity` (U4, D0.3) — that's what
//! `exit_1_generic_invalid_since_window_for_granularity` below exercises;
//! see that test's doc comment for the full reasoning.

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

fn parse_stdout(output: &std::process::Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON stdout (exit={:?}): {e}\nstdout={stdout:?}\nstderr={stderr:?}",
            output.status.code()
        )
    })
}

// ---------------------------------------------------------------------
// exit 0 — doctor with no credentials configured reports no_credentials
// rows for all five capabilities, never fails.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exit_0_doctor_no_credentials_reports_rows() {
    let output = spawn_alx_async(
        vec!["doctor".to_string()],
        vec![("ALGOLIA_APPLICATION_ID".to_string(), "test-app".to_string())],
    )
    .await;

    assert!(
        output.status.success(),
        "doctor must exit 0 with only an app id set: {:?}",
        output.status.code()
    );
    let json = parse_stdout(&output);
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
}

// ---------------------------------------------------------------------
// exit 1 — generic/unexpected. A --since value that parses fine as a
// SinceArg (so clap never rejects it — that's exit 2's domain) but is
// semantically invalid for the chosen --granularity (U4 pre-flight,
// D0.3): hourly supports at most 7 days, and "30d" is syntactically a
// perfectly valid SinceArg. algolia::usage::validate_granularity_window
// rejects this BEFORE any HTTP call with AppError::InvalidInput, which
// error.rs's default match arm maps to exit code 1.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exit_1_generic_invalid_since_window_for_granularity() {
    let server = MockServer::start().await;

    let output = spawn_alx_async(
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
            "hourly".to_string(),
            "--since".to_string(),
            "30d".to_string(),
        ],
        vec![("ALX_USAGE_BASE_URL".to_string(), server.uri())],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(1),
        "a semantically-invalid --since/--granularity pairing is AppError::InvalidInput (exit 1), stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Pre-flight (D0.3/U4): rejected before any HTTP call was ever made.
    let received = server
        .received_requests()
        .await
        .expect("wiremock request recording enabled");
    assert!(
        received.is_empty(),
        "expected zero HTTP requests before the pre-flight check rejects the window"
    );
}

// ---------------------------------------------------------------------
// exit 2 — clap's own usage-error class: an unrecognized flag, and (for
// completeness/traceability, see the file-level doc comment) a
// syntactically malformed --since string.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exit_2_clap_rejects_unknown_flag() {
    let output = spawn_alx_async(
        vec![
            "logs".to_string(),
            "sample".to_string(),
            "--this-flag-does-not-exist".to_string(),
        ],
        vec![],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap's own usage-error exit code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.to_lowercase().contains("unrecognized"),
        "expected clap's own unknown-flag wording: {stderr}"
    );
}

#[tokio::test]
async fn exit_2_clap_rejects_syntactically_malformed_since_value() {
    let output = spawn_alx_async(
        vec![
            "logs".to_string(),
            "sample".to_string(),
            "--since".to_string(),
            "bogus".to_string(),
        ],
        vec![],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(2),
        "a --since value SinceArg::from_str can't parse is clap's own value-validation error, not AppError::InvalidInput"
    );
}

// ---------------------------------------------------------------------
// exit 3 — network/timeout. `keys audit` against the search host pointed
// at a guaranteed-closed loopback port: the over-privilege preflight
// self-check swallows its own network error silently (D3/safety.rs), but
// the subsequent real `GET /1/keys` call propagates AppError::Network
// unmodified (its URL is `/1/keys` — no key value embedded, so no
// redaction interception applies), mapping to exit code 3.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exit_3_network_error_on_closed_port() {
    let output = spawn_alx_async(
        vec![
            "--app-id".to_string(),
            "test-app".to_string(),
            "--key".to_string(),
            "test-key".to_string(),
            "keys".to_string(),
            "audit".to_string(),
        ],
        vec![(
            "ALX_SEARCH_BASE_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        )],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(3),
        "a genuine transport-level failure must map to exit code 3, stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let json = parse_stdout(&output);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("network"),
        "expected network-error wording: {json}"
    );
}

/// BUG regression pin (same root cause as `tests/httpx_contract.rs`'s
/// `bug_logs_network_failure_on_all_hosts_should_exit_3_not_1` — tagged
/// there as `BUG ALX-LOGS-ERRCLASS`; reproduced independently here as part
/// of this file's complete D5 exit-code matrix walk): `logs sample` (and
/// `offsite`/`errors`, which share the same
/// `fetch_and_filter`/`fetch_logs_all_hosts` fetch layer) used to never
/// surface exit code 3 for a pure network failure, even when every one of
/// the (up to 3) per-host fetches failed with a genuine `AppError::Network`.
/// `fetch_logs_all_hosts` (src/algolia/logs.rs) tolerates per-host failures
/// by design (D7: "not fatal if >=1 host succeeds"), but when *every* host
/// failed it used to join the per-host error strings into one
/// `AppError::Other(...)` — discarding the fact that every underlying cause
/// was a network error. Fixed via `classify_all_hosts_error`, which
/// reclassifies a homogeneous all-Network failure back into
/// `AppError::Network` (exit 3).
/// `tests/logs_wiremock.rs::all_hosts_down_fails_the_command` still only
/// asserts `code != 0` for its (mixed/5xx) scenario — that's fine, since a
/// non-homogeneous failure set is documented to still collapse to the
/// generic exit code 1.
#[tokio::test]
async fn exit_3_network_logs_sample_closed_port_per_d5_contract() {
    let output = spawn_alx_async(
        vec![
            "--app-id".to_string(),
            "test-app".to_string(),
            "--key".to_string(),
            "test-key".to_string(),
            "logs".to_string(),
            "sample".to_string(),
        ],
        vec![
            (
                "ALX_LOGS_BASE_URLS".to_string(),
                "http://127.0.0.1:1".to_string(),
            ),
            (
                "ALX_SEARCH_BASE_URL".to_string(),
                "http://127.0.0.1:1".to_string(),
            ),
        ],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(3),
        "D5: exit code 3 = network/timeout, stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

// ---------------------------------------------------------------------
// exit 4 — auth: a 403 with a plain (non-plan-shaped) body classifies as
// MissingAcl (http::classify_forbidden) -> AppError::Auth.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exit_4_auth_403_plain_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string("Invalid Application-ID or API key"),
        )
        .mount(&server)
        .await;

    let output = spawn_alx_async(
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
            "30d".to_string(),
        ],
        vec![
            ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
            (
                "ALX_SEARCH_BASE_URL".to_string(),
                "http://127.0.0.1:1".to_string(),
            ),
        ],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(4),
        "a plain 403 body must classify as auth (exit 4), stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let json = parse_stdout(&output);
    assert!(json["error"]
        .as_str()
        .unwrap_or_default()
        .contains("authentication failed"));
}

// ---------------------------------------------------------------------
// exit 5 — plan-gated: a 403 whose body mentions plan wording classifies
// as PlanGated (http::classify_forbidden) -> AppError::PlanGated.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exit_5_plan_gated_403_with_plan_wording() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "This API is not available for your plan.",
            "status": 403
        })))
        .mount(&server)
        .await;

    let output = spawn_alx_async(
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
            "30d".to_string(),
        ],
        vec![
            ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
            (
                "ALX_SEARCH_BASE_URL".to_string(),
                "http://127.0.0.1:1".to_string(),
            ),
        ],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(5),
        "a plan-worded 403 must classify as plan-gated (exit 5), stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let json = parse_stdout(&output);
    assert!(json["error"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase()
        .contains("plan"));
}

// ---------------------------------------------------------------------
// exit 6 — safety refusal: the self-read at /1/keys/{key} reports a
// write-capable ACL (deleteIndex). Without --i-know this refuses (exit
// 6); with --i-know the same mocked data succeeds end to end (exit 0).
// ---------------------------------------------------------------------

async fn mount_self_read_with_write_acl(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/1/keys/test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": "test-key",
            "acl": ["search", "deleteIndex"],
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn exit_6_safety_refusal_write_capable_key_without_i_know() {
    let server = MockServer::start().await;
    mount_self_read_with_write_acl(&server).await;

    let output = spawn_alx_async(
        vec![
            "--app-id".to_string(),
            "test-app".to_string(),
            "--key".to_string(),
            "test-key".to_string(),
            "keys".to_string(),
            "audit".to_string(),
        ],
        vec![("ALX_SEARCH_BASE_URL".to_string(), server.uri())],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(6),
        "a write-capable key's self-check must refuse without --i-know, stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let json = parse_stdout(&output);
    assert!(json["error"]
        .as_str()
        .unwrap_or_default()
        .contains("refusing to proceed"));
    let suggestion = json["suggestion"].as_str().unwrap_or_default();
    assert!(suggestion.contains("--i-know"));
}

#[tokio::test]
async fn exit_0_i_know_bypasses_safety_refusal_and_succeeds() {
    let server = MockServer::start().await;
    mount_self_read_with_write_acl(&server).await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{"value": "test-key", "acl": ["search", "deleteIndex"]}]
        })))
        .mount(&server)
        .await;

    let output = spawn_alx_async(
        vec![
            "--app-id".to_string(),
            "test-app".to_string(),
            "--key".to_string(),
            "test-key".to_string(),
            "--i-know".to_string(),
            "keys".to_string(),
            "audit".to_string(),
        ],
        vec![("ALX_SEARCH_BASE_URL".to_string(), server.uri())],
    )
    .await;

    assert!(
        output.status.success(),
        "--i-know must bypass the safety refusal and succeed, stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout(&output);
    let keys = json["keys"].as_array().expect("keys array");
    assert_eq!(
        keys.len(),
        1,
        "expected the mocked audit data to flow through: {json}"
    );
    assert_eq!(json["scope"], json!("full"));
}
