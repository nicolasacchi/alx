//! Hostile/malformed-input coverage driven through the real HTTP wire
//! (`wiremock`) and the compiled `alx` binary (bin-only crate, no `[lib]`
//! target — see `Cargo.toml`; every integration test here spawns
//! `CARGO_BIN_EXE_alx` exactly like every sibling `tests/*.rs` file rather
//! than calling crate-internal functions directly).
//!
//! Scope (see the workflow brief): log-entry coercion extremes, the
//! origin-allow-list regex vector table, ASN classification extremes, and
//! Usage/Analytics/Keys response parsers under garbage input. Every test
//! asserts the process never panics and never crashes (`assert_never_
//! panicked`) — the specific `AppError`/exit-code classification is
//! asserted on top of that wherever a design decision pins one.

use serde_json::{json, Value};
use std::os::unix::process::ExitStatusExt;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------
// Shared helpers (duplicated per-file by repo convention — every sibling
// `tests/*.rs` file defines its own `spawn_alx`/`run_alx_json` rather than
// sharing a `tests/common` module; see design decision D12's test style note).
// ---------------------------------------------------------------------

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

async fn run_alx(args: Vec<String>, envs: Vec<(String, String)>) -> std::process::Output {
    tokio::task::spawn_blocking(move || spawn_alx(&args, &envs))
        .await
        .expect("spawn_blocking join failed")
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code_of(output: &std::process::Output) -> Option<i32> {
    output.status.code()
}

fn json_of(output: &std::process::Output) -> Value {
    let stdout = stdout_of(output);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON stdout (exit={:?}): {e}\nstdout={stdout:?}\nstderr={}",
            output.status.code(),
            stderr_of(output)
        )
    })
}

fn sv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Cross-cutting safety net for every hostile-input test in this file:
/// never a Rust panic (unwind, exit code 101) and never a hard crash
/// (killed by a signal — e.g. a stack-overflow abort). A clean `AppError`
/// (any other exit code) is always fine; this only rules out the two "the
/// process actually blew up" shapes.
fn assert_never_panicked(output: &std::process::Output, context: &str) {
    let stderr = stderr_of(output);
    assert!(
        !stderr.contains("panicked at"),
        "{context}: process panicked — stderr: {stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(101),
        "{context}: exit code 101 usually means an unwinding Rust panic — stderr: {stderr}"
    );
    assert!(
        output.status.signal().is_none(),
        "{context}: process was killed by signal {:?} (crash, e.g. stack overflow) — stderr: {stderr}",
        output.status.signal()
    );
}

/// D0.3's over-privilege self-check (`safety::preflight_privilege_check`)
/// runs before the first real call on every logs/usage/analytics/keys
/// command. Point it at a guaranteed-closed loopback port (immediate
/// connection-refused, no DNS, no real network) so it best-effort-skips
/// instead of either succeeding against our mock (and polluting
/// `received_requests()`/`keys_calls` assertions) or hanging.
fn closed_search_url() -> (String, String) {
    (
        "ALX_SEARCH_BASE_URL".to_string(),
        "http://127.0.0.1:1".to_string(),
    )
}

fn base_creds() -> Vec<String> {
    sv(&["--app-id", "test-app", "--key", "test-key"])
}

// ---------------------------------------------------------------------
// Experimental probe: how does `resp.json::<serde_json::Value>()` behave
// against a very deeply nested JSON body? `serde_json::Value`'s default
// deserializer is recursive with no depth limit — this is a known class of
// DoS input for any service parsing untrusted JSON. Not gated behind
// `#[ignore]` up front: run it and let the assertions describe whatever
// the real behavior turns out to be.
// ---------------------------------------------------------------------

fn nested_array_json(depth: usize) -> Vec<u8> {
    let mut body = String::with_capacity(depth * 2 + 16);
    body.push_str(r#"{"statistics":"#);
    for _ in 0..depth {
        body.push('[');
    }
    for _ in 0..depth {
        body.push(']');
    }
    body.push('}');
    body.into_bytes()
}

/// "Deeply nested garbage" — the extreme end of the hostile-input list.
/// `resp.json::<serde_json::Value>()` (used by every surface in
/// `http::get_json`) is a recursive descent parser; feeding it a
/// pathologically deep JSON body is a known DoS shape against naive JSON
/// consumers (unbounded stack growth -> a hard, uncatchable stack-overflow
/// abort, not a `Result::Err`). Empirically confirmed here: serde_json's
/// default (bounded) recursion limit already rejects this cleanly as a
/// decode error before any stack exhaustion, surfacing through `?` as
/// `AppError::Network` (exit code 3, D5) — never a crash, never a hang
/// (completes in well under a second at 100k levels).
#[tokio::test]
async fn hostile_deeply_nested_json_body_100k_levels_handled_cleanly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_bytes(nested_array_json(100_000)),
        )
        .mount(&server)
        .await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&[
            "usage",
            "series",
            "--statistic",
            "total_search_requests",
            "--granularity",
            "daily",
            "--since",
            "1d",
        ]));
        a
    };
    let envs = vec![
        ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
        closed_search_url(),
    ];

    let start = Instant::now();
    let output = run_alx(args, envs).await;
    let elapsed = start.elapsed();

    assert_never_panicked(&output, "100k-deep nested JSON body");
    assert!(
        elapsed < Duration::from_secs(60),
        "100k-deep nested JSON body took {elapsed:?} to fail — expected a fast, clean rejection"
    );
    assert_eq!(
        code_of(&output),
        Some(3),
        "expected AppError::Network (exit 3) from a JSON decode failure, got exit={:?} \
         stdout={} stderr={}",
        code_of(&output),
        stdout_of(&output),
        stderr_of(&output)
    );
}

/// A shallow-but-still-nonsense nested *value* inside an otherwise
/// well-shaped Usage API point — well under serde_json's own recursion
/// limit, so this actually reaches `parse_usage_response`'s field-level
/// logic rather than tripping the generic decode-failure path above. `v`
/// being a nested object rather than a number must be rejected as a clean
/// "missing/invalid 'v'" `AppError::Api` (`as_f64()` on an object returns
/// `None`), not accepted, not a crash.
#[tokio::test]
async fn hostile_usage_point_value_nested_object_rejected_cleanly() {
    let server = MockServer::start().await;

    let mut nested = json!("garbage");
    for _ in 0..20 {
        nested = json!({ "wrapped": nested });
    }
    let body = json!({ "statistics": [ { "t": 1_690_000_000, "v": nested } ] });

    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&[
            "usage",
            "series",
            "--statistic",
            "total_search_requests",
            "--granularity",
            "daily",
            "--since",
            "1d",
        ]));
        a
    };
    let envs = vec![
        ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
        closed_search_url(),
    ];

    let output = run_alx(args, envs).await;
    assert_never_panicked(&output, "20-deep nested 'v' value");
    assert_eq!(
        code_of(&output),
        Some(1),
        "expected AppError::Api (exit 1) for a nested-object 'v', got exit={:?} stdout={}",
        code_of(&output),
        stdout_of(&output)
    );
    let json = json_of(&output);
    let err = json
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        err.contains('v') && err.to_lowercase().contains("invalid"),
        "expected a clean 'missing/invalid v' style error, got: {json}"
    );
}

/// A genuinely deep nested `v` value (well past serde_json's own recursion
/// limit) never even reaches `parse_usage_response` — the generic
/// `resp.json::<Value>()` decode in `http::get_json` rejects it first, the
/// same clean `AppError::Network` (exit 3) as the whole-body case above.
/// Pinned separately so a future change to how deep the recursion limit
/// sits can't silently regress into a crash without a test noticing.
///
/// NOTE on how this fixture is built: an earlier draft built the nested
/// value as a `serde_json::Value` tree via the `json!` macro (mirroring the
/// shallow 20-level test above) and handed it to `set_body_json`, which
/// serializes it — `Serialize` for a deeply nested `Value` tree is
/// *itself* unbounded recursion with no depth guard (only
/// *deserialization* is depth-limited). At 5,000 levels that blew the
/// stack of the **test harness process itself** (SIGABRT) before `alx` was
/// even spawned — not a bug in `alx`'s production code path (which only
/// ever deserializes external JSON, never serializes an attacker-supplied
/// tree back out), but a real trap for hostile-input test fixtures. Built
/// as a raw byte string instead (same technique as `nested_array_json`) to
/// sidestep it entirely.
#[tokio::test]
async fn hostile_usage_point_value_pathologically_nested_object_hits_decode_limit_not_a_crash() {
    let server = MockServer::start().await;

    let depth = 5_000usize;
    let mut body = String::with_capacity(depth * 12 + 64);
    body.push_str(r#"{"statistics":[{"t":1690000000,"v":"#);
    for _ in 0..depth {
        body.push_str(r#"{"wrapped":"#);
    }
    body.push_str("\"garbage\"");
    for _ in 0..depth {
        body.push('}');
    }
    body.push_str("}]}");

    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_bytes(body.into_bytes()),
        )
        .mount(&server)
        .await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&[
            "usage",
            "series",
            "--statistic",
            "total_search_requests",
            "--granularity",
            "daily",
            "--since",
            "1d",
        ]));
        a
    };
    let envs = vec![
        ("ALX_USAGE_BASE_URL".to_string(), server.uri()),
        closed_search_url(),
    ];

    let output = run_alx(args, envs).await;
    assert_never_panicked(&output, "5000-deep nested 'v' value");
    assert_eq!(
        code_of(&output),
        Some(3),
        "expected AppError::Network (exit 3) from a decode-recursion-limit rejection, got \
         exit={:?} stdout={}",
        code_of(&output),
        stdout_of(&output)
    );
}

// =======================================================================
// Group A: log-entry coercion extremes (L5/L6, algolia::logs::coerce_entry
// and parse_headers). Driven through `alx logs sample|errors|offsite`
// against a single mocked `/1/logs` host — every field on the wire is a
// JSON string (L5), coerced explicitly; a field that fails to coerce drops
// the whole entry rather than panicking or failing the batch.
// =======================================================================

fn logs_envs(logs_uri: &str) -> Vec<(String, String)> {
    vec![
        ("ALX_LOGS_BASE_URLS".to_string(), logs_uri.to_string()),
        closed_search_url(),
    ]
}

/// A single well-formed log entry (every field a JSON string, per L5),
/// with every field overridable so hostile variants can be built by cloning
/// + mutating specific keys via `serde_json::Value::as_object_mut`.
fn valid_entry(sha1: &str, ip: &str) -> Value {
    json!({
        "timestamp": chrono_now_rfc3339(),
        "answer_code": "200",
        "query_body": "{}",
        "answer": "{}",
        "url": "/1/indexes/Product/query",
        "ip": ip,
        "query_headers": "User-Agent: curl/8.0\r\n",
        "sha1": sha1,
        "nb_api_calls": "1",
        "processing_time_ms": "10",
        "index": "Product",
    })
}

/// Minimal RFC3339 "now" without pulling `chrono` into this test binary's
/// dependency surface beyond what `serde_json`/`wiremock` already need —
/// `alx` itself links `chrono`, but `[dev-dependencies]` here only lists
/// `wiremock`/`assert_cmd`/`predicates`/`tempfile`, so this file sticks to
/// what those + `serde_json`/`tokio` (normal deps, available to every test
/// binary) provide. `std::time::SystemTime` -> a hand-rolled RFC3339
/// stamp is enough for entries the server-side `alx` binary only needs to
/// parse as "recent" (within the default 1h `--since` window).
fn chrono_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Days since epoch -> proleptic Gregorian civil date (Howard Hinnant's
    // well-known epoch<->civil algorithm), then format as RFC3339 UTC.
    let days = (now / 86400) as i64;
    let secs_of_day = now % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

async fn mount_logs_entries(server: &MockServer, entries: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "logs": entries })))
        .mount(server)
        .await;
}

/// Same shape as `mount_logs_entries`, but for a raw (non-JSON-macro-built)
/// body — used for the "non-array `logs` field" / "`logs` field absent"
/// variants where the body itself needs a specific top-level shape.
async fn mount_logs_raw_body(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// L5: hostile numeric-string values for `nb_api_calls` (u32) must drop
/// only the offending entry, never panic, never fail the whole batch — a
/// valid control entry mixed into the same response must still come
/// through. `total_entries` (the unfiltered, deduped fetch count) is the
/// signal: only the control entry should be counted.
#[tokio::test]
async fn hostile_log_numeric_extremes_dropped_not_panicking() {
    let server = MockServer::start().await;

    let mut entries = Vec::new();
    for (i, bad) in ["99999999999999999999", "-5", "", "NaN", "  ", "1_000"]
        .iter()
        .enumerate()
    {
        let mut e = valid_entry(&format!("bad-{i}"), "203.0.113.10");
        e["nb_api_calls"] = json!(bad);
        entries.push(e);
    }
    entries.push(valid_entry("control-entry", "203.0.113.11"));

    mount_logs_entries(&server, entries).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "nb_api_calls hostile numeric strings");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["total_entries"],
        json!(1),
        "expected only the control entry to survive coercion, got: {json}"
    );
}

/// L5: same treatment for `answer_code` (u16) and `processing_time_ms`
/// (u32) — both are required fields whose coercion failure must drop the
/// entry, never panic.
#[tokio::test]
async fn hostile_log_answer_code_and_processing_time_extremes_dropped() {
    let server = MockServer::start().await;

    let mut entries = Vec::new();
    for (i, bad) in ["99999999999999999999", "-1", "", "NaN"].iter().enumerate() {
        let mut e = valid_entry(&format!("bad-code-{i}"), "203.0.113.12");
        e["answer_code"] = json!(bad);
        entries.push(e);
    }
    for (i, bad) in ["99999999999999999999", "-1", "", "NaN"].iter().enumerate() {
        let mut e = valid_entry(&format!("bad-ptms-{i}"), "203.0.113.13");
        e["processing_time_ms"] = json!(bad);
        entries.push(e);
    }
    entries.push(valid_entry("control-entry-2", "203.0.113.14"));

    mount_logs_entries(&server, entries).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "answer_code/processing_time_ms hostile values");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["total_entries"],
        json!(1),
        "expected only the control entry to survive coercion, got: {json}"
    );
}

/// L5: `query_nb_hits` is the one OPTIONAL numeric field — a hostile value
/// must degrade to `None` (field omitted) WITHOUT dropping the whole
/// entry, unlike the required fields above. Verified indirectly: the
/// command must still succeed with the entry counted.
#[tokio::test]
async fn hostile_log_optional_query_nb_hits_garbage_does_not_drop_entry() {
    let server = MockServer::start().await;

    let mut e = valid_entry("optional-field-entry", "203.0.113.15");
    e["query_nb_hits"] = json!("not-a-number-at-all");
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "garbage query_nb_hits");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["total_entries"],
        json!(1),
        "an optional-field coercion failure must not drop the entry: {json}"
    );
}

/// L5: JSON `null` for required fields must behave exactly like the field
/// being absent (`Option<String>` -> `None` either way) — entry dropped,
/// no panic.
#[tokio::test]
async fn hostile_log_null_required_fields_dropped() {
    let server = MockServer::start().await;

    let fields = ["sha1", "ip", "timestamp", "answer_code", "nb_api_calls"];
    let mut entries = Vec::new();
    for f in fields {
        let mut e = valid_entry(&format!("null-{f}"), "203.0.113.16");
        e[f] = Value::Null;
        entries.push(e);
    }
    entries.push(valid_entry("control-entry-3", "203.0.113.17"));

    mount_logs_entries(&server, entries).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "null required fields");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["total_entries"],
        json!(1),
        "explicit JSON null on a required field must drop the entry, not panic: {json}"
    );
}

/// L5: a required field missing from the JSON object entirely (never even
/// serialized, as opposed to explicit `null`) must behave identically —
/// `serde`'s `Option<T>` treats an absent key exactly like `null`.
#[tokio::test]
async fn hostile_log_missing_required_fields_entirely_dropped() {
    let server = MockServer::start().await;

    let fields = ["sha1", "ip", "timestamp", "answer_code", "nb_api_calls"];
    let mut entries = Vec::new();
    for f in fields {
        let mut e = valid_entry(&format!("missing-{f}"), "203.0.113.18");
        e.as_object_mut().unwrap().remove(f);
        entries.push(e);
    }
    entries.push(valid_entry("control-entry-4", "203.0.113.19"));

    mount_logs_entries(&server, entries).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "missing required fields entirely");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["total_entries"],
        json!(1),
        "a required field missing entirely must drop the entry, not panic: {json}"
    );
}

/// The `logs` field absent from the response body entirely (`{}`) must be
/// treated as zero entries — success, not an error (`GetLogsResponse.logs`
/// has `#[serde(default)]`).
#[tokio::test]
async fn hostile_logs_field_absent_entirely_succeeds_with_zero_entries() {
    let server = MockServer::start().await;
    mount_logs_raw_body(&server, json!({})).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "logs field absent entirely");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["total_entries"], json!(0));
}

/// An explicit empty `logs` array must also succeed with zero entries.
#[tokio::test]
async fn hostile_logs_field_empty_array_succeeds_with_zero_entries() {
    let server = MockServer::start().await;
    mount_logs_raw_body(&server, json!({ "logs": [] })).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "logs field empty array");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["total_entries"], json!(0));
}

/// BUG-ALX-ANALYTICS-NULLCOLL/BUG-ALX-EVENTS-NULLCOLL sweep (task 3): an
/// explicit `"logs": null` (present key, `null` value — NOT the "field
/// absent entirely" case above, which is a different wire shape) must also
/// succeed with zero entries, exactly like the absent-key case — this is
/// the distinction `#[serde(default)]` alone gets wrong and
/// `null_as_default` fixes.
#[tokio::test]
async fn hostile_logs_field_explicit_null_succeeds_with_zero_entries() {
    let server = MockServer::start().await;
    mount_logs_raw_body(&server, json!({ "logs": null })).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "logs field explicit null");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["total_entries"], json!(0));
}

/// A `logs` field present but the WRONG TYPE (string/number/object instead
/// of an array) is a genuine deserialize failure — `#[serde(default)]`
/// only substitutes a default for an ABSENT key, not a present key with
/// the wrong shape. With a single logs host configured, this host's fetch
/// fails and (being the only host) the whole command fails cleanly — never
/// a panic, never a silent empty-success that hides the malformed
/// response.
#[tokio::test]
async fn hostile_logs_field_non_array_fails_cleanly_not_silently() {
    for bad_shape in [json!("not an array"), json!(42), json!({"oops": true})] {
        let server = MockServer::start().await;
        mount_logs_raw_body(&server, json!({ "logs": bad_shape })).await;

        let args = {
            let mut a = base_creds();
            a.extend(sv(&["logs", "sample"]));
            a
        };
        let output = run_alx(args, logs_envs(&server.uri())).await;

        assert_never_panicked(&output, &format!("logs field non-array shape {bad_shape}"));
        assert_ne!(
            code_of(&output),
            Some(0),
            "a non-array `logs` field must fail the command, not silently succeed: {bad_shape} \
             -> {output:?}"
        );
    }
}

/// A ~1MB single header line (e.g. an absurdly long User-Agent) must be
/// parsed without panicking and within a reasonable time budget — no
/// unbounded/quadratic blowup in `parse_headers`' line-by-line scan.
#[tokio::test]
async fn hostile_log_huge_1mb_query_header_line_handled_in_reasonable_time() {
    let server = MockServer::start().await;
    let huge_ua = "A".repeat(1_000_000);
    let mut e = valid_entry("huge-header-entry", "203.0.113.20");
    e["query_headers"] = json!(format!("User-Agent: {huge_ua}\r\n"));
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let start = Instant::now();
    let output = run_alx(args, logs_envs(&server.uri())).await;
    let elapsed = start.elapsed();

    assert_never_panicked(&output, "1MB query_headers line");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    assert!(
        elapsed < Duration::from_secs(60),
        "1MB header line took {elapsed:?} to process — expected well under 60s"
    );
    let json = json_of(&output);
    assert_eq!(json["total_entries"], json!(1));
}

/// A literal U+FFFD replacement character embedded in `query_headers`
/// (mojibake from upstream mangling, not a genuine encoding error — JSON
/// text itself must be valid Unicode) must be parsed through without
/// panicking; the header value round-trips containing the replacement
/// char.
#[tokio::test]
async fn hostile_log_replacement_char_in_headers_no_panic() {
    let server = MockServer::start().await;
    let mut e = valid_entry("replacement-char-entry", "203.0.113.21");
    e["query_headers"] = json!("User-Agent: Mozilla\u{FFFD}Test\r\n");
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "U+FFFD in query_headers");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["total_entries"], json!(1));
}

/// Genuinely invalid UTF-8 BYTES in the raw HTTP response body (as opposed
/// to a valid-Unicode replacement character above) make the body invalid
/// JSON text — this must fail the fetch cleanly (`AppError::Network` via
/// `resp.json()`'s decode failure), never panic, never silently succeed
/// with mangled data.
#[tokio::test]
async fn hostile_log_invalid_utf8_bytes_in_response_body_fails_cleanly() {
    let server = MockServer::start().await;
    let mut raw = br#"{"logs":[{"sha1":"x","ip":"203.0.113.22","timestamp":"2026-01-01T00:00:00Z","answer_code":"200","nb_api_calls":"1","processing_time_ms":"1","query_headers":"User-Agent: "#.to_vec();
    raw.extend_from_slice(&[0xFF, 0xFE, 0xC0, 0xAF]); // invalid UTF-8 sequences
    raw.extend_from_slice(br#"\r\n"}]}"#);

    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_bytes(raw),
        )
        .mount(&server)
        .await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "invalid UTF-8 bytes in response body");
    assert_ne!(
        code_of(&output),
        Some(0),
        "invalid UTF-8 response body must fail the command, not silently succeed: {output:?}"
    );
}

/// L6: duplicate `Referer` headers with different casing — `parse_headers`
/// matches case-insensitively and has no dedup guard, so each matching
/// line simply overwrites the previous value as the blob is scanned
/// top-to-bottom; the LAST matching line wins. Verified via `logs errors`
/// (which surfaces `referer` directly), with the winning value being our
/// own site so the result is unambiguous either way.
#[tokio::test]
async fn hostile_log_duplicate_referer_headers_different_casing_last_one_wins() {
    let server = MockServer::start().await;
    let mut e = valid_entry("dup-referer-entry", "203.0.113.23");
    e["answer_code"] = json!("403");
    e["query_headers"] =
        json!("Referer: https://evil.example/\r\nREFERER: https://1000farmacie.it/prodotto\r\n");
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "errors"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "duplicate Referer headers, different casing");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["error_count"], json!(1), "response: {json}");
    assert_eq!(
        json["errors"][0]["referer"],
        json!("https://1000farmacie.it/prodotto"),
        "expected the LAST matching header line (case-insensitive) to win: {json}"
    );
}

/// L6: a header line with no colon at all must be skipped (not parsed as
/// referer/UA, not crash `split_once(':')`'s `None` branch) — a real
/// Referer line elsewhere in the same blob must still parse correctly.
#[tokio::test]
async fn hostile_log_header_line_without_colon_is_skipped_not_fatal() {
    let server = MockServer::start().await;
    let mut e = valid_entry("no-colon-entry", "203.0.113.24");
    e["answer_code"] = json!("403");
    e["query_headers"] =
        json!("GARBAGE LINE WITH NO COLON AT ALL\r\nReferer: https://1000farmacie.it/\r\n");
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "errors"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "header line without a colon");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["error_count"], json!(1), "response: {json}");
    assert_eq!(
        json["errors"][0]["referer"],
        json!("https://1000farmacie.it/"),
        "a colon-less garbage line must not prevent parsing a real header later in the blob: {json}"
    );
}

/// L6/L3: same "garbage line doesn't break real header parsing" property
/// for the User-Agent line, observed indirectly via own-egress
/// classification (`logs sample`'s `own_egress_count`) since no command
/// exposes the parsed UA value directly in its JSON output.
#[tokio::test]
async fn hostile_log_header_line_without_colon_does_not_break_ua_parsing() {
    let server = MockServer::start().await;
    let mut e = valid_entry("no-colon-ua-entry", "203.0.113.25");
    e["query_headers"] =
        json!("not-a-header-line-at-all\r\nUser-Agent: Algolia for Rails (3.12.2)\r\n");
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "colon-less garbage line before a real UA header");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["own_egress_count"],
        json!(1),
        "the real User-Agent line after the garbage line must still be parsed and classified \
         as own-egress: {json}"
    );
}

/// L3/L6: duplicate User-Agent headers with different casing — same
/// "last one wins" semantics as Referer, observed via own-egress
/// classification. Two orderings: own-egress marker LAST (must classify as
/// own-egress) and own-egress marker FIRST, overwritten by a normal UA
/// (must NOT classify as own-egress).
#[tokio::test]
async fn hostile_log_duplicate_user_agent_headers_last_one_wins() {
    let server = MockServer::start().await;

    let mut own_egress_last = valid_entry("dup-ua-egress-last", "203.0.113.26");
    own_egress_last["query_headers"] =
        json!("User-Agent: Mozilla/5.0\r\nUSER-AGENT: Algolia for Rails (3.12.2)\r\n");

    let mut own_egress_first = valid_entry("dup-ua-egress-first", "203.0.113.27");
    own_egress_first["query_headers"] =
        json!("User-Agent: Algolia for Rails (3.12.2)\r\nUSER-AGENT: Mozilla/5.0\r\n");

    mount_logs_entries(&server, vec![own_egress_last, own_egress_first]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "sample"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "duplicate User-Agent headers, different casing");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["own_egress_count"],
        json!(1),
        "exactly one of the two entries (own-egress marker LAST) should classify as \
         own-egress, matching 'last header line wins': {json}"
    );
}

/// L6: old-Mac-style bare-`\r` line endings (no `\n` at all) — `parse_
/// headers` splits on `\n` only, so a blob with zero `\n` bytes is treated
/// as ONE single line. Documents the actual (not spec-mandated — D7/L6
/// only guarantees CRLF/LF handling) resulting behavior rather than
/// asserting an assumption: the whole blob is scanned as a single
/// "name: value" pair on the FIRST colon, so only the first header
/// (Referer, here) is recoverable and the value string retains the
/// embedded `\r` bytes (they're only stripped as a trailing suffix, not
/// mid-string) — never a panic either way.
#[tokio::test]
async fn hostile_log_cr_only_line_endings_documented_behavior() {
    let server = MockServer::start().await;
    let mut e = valid_entry("cr-only-entry", "203.0.113.28");
    e["answer_code"] = json!("403");
    e["query_headers"] = json!("Referer: https://1000farmacie.it/\rUser-Agent: curl/8.0\r");
    mount_logs_entries(&server, vec![e]).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "errors"]));
        a
    };
    let output = run_alx(args, logs_envs(&server.uri())).await;

    assert_never_panicked(&output, "CR-only (no LF) line endings");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["error_count"], json!(1), "response: {json}");
    // Documented current behavior: with no '\n' anywhere, the entire blob
    // is one "line"; parse_headers takes the value after the FIRST colon
    // and only strips a trailing '\r' (not an embedded one), so the
    // Referer value ends up containing the rest of the blob verbatim,
    // including the un-stripped embedded '\r' and the User-Agent text.
    let referer = json["errors"][0]["referer"]
        .as_str()
        .expect("referer should be present");
    assert!(
        referer.starts_with("https://1000farmacie.it/"),
        "referer={referer:?}"
    );
    assert!(
        referer.contains("User-Agent"),
        "with no LF to split on, the 'User-Agent' text should remain embedded in the single \
         parsed line's value rather than being recovered as its own header: referer={referer:?}"
    );
}

// =======================================================================
// Group B: origin allow-list regex vector table (L7,
// `ORIGIN_ALLOW_PATTERN` = `\Ahttps://([a-z0-9-]+\.)*1000farmacie\.(it|lol)
// (?:[/?#]|\z)`). `src/constants.rs`/`src/commands/logs.rs` already unit-
// test apex/subdomain/`.lol`-staging acceptance and the
// `1000farmacie.it.evil.com` lookalike rejection inline — this extends the
// vector table end-to-end through `alx logs offsite`'s
// `referer_is_own_site` field (the only place this regex's result is
// observable outside the crate, since it's a bin-only crate with no `[lib]`
// target to unit-test against directly). Every entry with a synthetic
// non-KEEP public IP so it lands in the `offsite` bucket regardless of the
// referer verdict, keeping the ASN dimension out of the way of the origin
// check being tested.
// =======================================================================

/// One vector: (label, referer value or None for "no Referer header",
/// expected `referer_is_own_site`). `expect_own_site: true` on a vector
/// whose referer is attacker/foreign-controlled would be the
/// security-relevant failure mode L7's anchor exists to prevent (accepting
/// a foreign origin as our own) — reported as a bug if ever observed here.
struct OriginVector {
    label: &'static str,
    referer: Option<&'static str>,
    expect_own_site: bool,
}

const ORIGIN_VECTORS: &[OriginVector] = &[
    OriginVector {
        label: "positive control: apex",
        referer: Some("https://1000farmacie.it/"),
        expect_own_site: true,
    },
    OriginVector {
        label: "positive control: subdomain",
        referer: Some("https://blog.1000farmacie.it/"),
        expect_own_site: true,
    },
    OriginVector {
        label: "userinfo trick: attacker host, our domain as userinfo",
        referer: Some("https://1000farmacie.it@evil.com/"),
        expect_own_site: false,
    },
    OriginVector {
        label: "non-standard port after our host",
        referer: Some("https://www.1000farmacie.it:8443/"),
        expect_own_site: false,
    },
    OriginVector {
        label: "uppercase scheme+host (case-sensitive regex)",
        referer: Some("HTTPS://WWW.1000FARMACIE.IT/"),
        expect_own_site: false,
    },
    OriginVector {
        label: "non-TLS http:// (intended rejection, https-only)",
        referer: Some("http://www.1000farmacie.it/"),
        expect_own_site: false,
    },
    OriginVector {
        label: "trailing-dot FQDN host",
        referer: Some("https://www.1000farmacie.it./"),
        expect_own_site: false,
    },
    OriginVector {
        label: "our domain embedded later in an attacker URL (anchor check)",
        referer: Some("https://evil.com/https://www.1000farmacie.it/"),
        expect_own_site: false,
    },
    OriginVector {
        label: "empty referer string",
        referer: Some(""),
        expect_own_site: false,
    },
    OriginVector {
        label: "no Referer header at all",
        referer: None,
        expect_own_site: false,
    },
    OriginVector {
        label: "garbage bytes / control characters",
        referer: Some("\u{1}\u{2}not-a-url-at-all\u{7f}"),
        expect_own_site: false,
    },
    OriginVector {
        label: "lookalike suffix domain (existing regression, re-verified end-to-end)",
        referer: Some("https://www.1000farmacie.it.evil.com/"),
        expect_own_site: false,
    },
];

#[tokio::test]
async fn hostile_origin_allowlist_vector_table_end_to_end() {
    let server = MockServer::start().await;

    let mut entries = Vec::new();
    for (idx, v) in ORIGIN_VECTORS.iter().enumerate() {
        let ip = format!("203.0.113.{}", 30u8 + idx as u8);
        let mut e = valid_entry(&format!("origin-{}", v.label), &ip);
        let headers = match v.referer {
            Some(r) => format!("Referer: {r}\r\nUser-Agent: curl/8.0\r\n"),
            None => "User-Agent: curl/8.0\r\n".to_string(),
        };
        e["query_headers"] = json!(headers);
        e["ip"] = json!(ip);
        entries.push((v, ip, e));
    }

    mount_logs_entries(&server, entries.iter().map(|(_, _, e)| e.clone()).collect()).await;

    // Map every vector's synthetic IP to a plain non-KEEP, non-crawler
    // ASN so it lands in the `offsite` bucket regardless of the referer
    // verdict — isolates the origin-regex check from ASN classification.
    let asn_map: String = entries
        .iter()
        .map(|(_, ip, _)| format!("{ip}=64500"))
        .collect::<Vec<_>>()
        .join(",");

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "offsite"]));
        a
    };
    let mut envs = logs_envs(&server.uri());
    envs.push(("ALX_ASN_STATIC_MAP".to_string(), asn_map));

    let output = run_alx(args, envs).await;
    assert_never_panicked(&output, "origin allow-list vector table");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    let offsite = json["offsite"]
        .as_array()
        .expect("offsite should be an array");

    for (v, ip, _) in &entries {
        let row = offsite
            .iter()
            .find(|g| g["ip"] == json!(ip))
            .unwrap_or_else(|| {
                panic!(
                    "vector {:?} (ip={ip}) missing from offsite bucket: {json}",
                    v.label
                )
            });
        assert_eq!(
            row["referer_is_own_site"],
            json!(v.expect_own_site),
            "vector {:?} (referer={:?}): expected referer_is_own_site={}, got {row}. \
             {}",
            v.label,
            v.referer,
            v.expect_own_site,
            if v.expect_own_site {
                ""
            } else {
                "A foreign/lookalike origin being accepted as our own site would be a \
                 security-relevant L7 regression."
            }
        );
    }
}

// =======================================================================
// Group C: ASN hostile inputs (D6). `asn::parse_cymru_asn`'s garbage-TXT-
// record handling ("", "not a number |", multi-record first-ASN-wins) is
// already exhaustively unit-tested inline in `src/asn.rs`
// (`parse_cymru_asn_takes_leading_field`) and isn't reachable from an
// integration test in a bin-only crate — not duplicated here. What IS
// reachable end-to-end: `ALX_ASN_STATIC_MAP` junk-value tolerance and the
// "never flagged offsite on missing/unresolvable ASN data" guarantee for
// IPv6, private, unspecified (0.0.0.0), and broadcast (255.255.255.255)
// addresses, all via `alx logs offsite`.
// =======================================================================

/// `ALX_ASN_STATIC_MAP` junk-value tolerance PLUS the "never flagged
/// offsite on unresolvable ASN" guarantee for IPv6 / private / unspecified
/// / broadcast addresses, in one `logs offsite` run. The static map is
/// used deliberately (rather than leaving it unset) so 255.255.255.255 —
/// which `asn::lookup`'s private/loopback/link-local/unspecified guard
/// does NOT cover — never triggers a real Team Cymru DNS round-trip (hard
/// rule: never hit the real network in tests). Every IP below is either
/// absent from the map (or maps to a malformed ASN) except one KEEP-ASN
/// control, so the "resolves to Unknown, never Offsite" claim is checked
/// against a working positive control in the same run.
#[tokio::test]
async fn hostile_asn_static_map_junk_values_and_never_offsite_on_unresolvable() {
    let server = MockServer::start().await;

    let cases: &[(&str, &str)] = &[
        ("203.0.113.40", "private-ipv4-unmapped"),
        ("0.0.0.0", "unspecified-unmapped"),
        ("255.255.255.255", "broadcast-unmapped"),
        ("203.0.113.41", "junk-asn-huge-number-in-map"),
        ("203.0.113.42", "junk-asn-not-a-number-in-map"),
        ("203.0.113.43", "keep-asn-control-must-be-keep"),
    ];
    // IPv6 has no map entry semantics at all — it never even reaches ASN
    // resolution (fails the `Ipv4Addr` parse before `resolve_many` is
    // called), tested as its own entry below.
    let ipv6_ip = "2001:db8::dead:beef";

    let mut entries: Vec<Value> = cases
        .iter()
        .map(|(ip, label)| {
            let mut e = valid_entry(&format!("asn-{label}"), ip);
            e["ip"] = json!(ip);
            e
        })
        .collect();
    let mut ipv6_entry = valid_entry("asn-ipv6-entry", ipv6_ip);
    ipv6_entry["ip"] = json!(ipv6_ip);
    entries.push(ipv6_entry);

    mount_logs_entries(&server, entries).await;

    // Junk map: malformed pairs interleaved with two deliberately-invalid
    // ASN values (overflow u32, non-numeric) for the two "junk-asn" IPs,
    // plus one genuine KEEP ASN (13335, Cloudflare/WARP) for the control
    // IP. 0.0.0.0/255.255.255.255/the private IP are deliberately absent
    // from the map (unmapped -> `AsnInfo::default()`, i.e. `Unknown`,
    // exactly like a real DNS miss per D6).
    let asn_map = "not-an-ip=1234,,\
203.0.113.41=99999999999999999999,\
203.0.113.42=notanumber,,\
203.0.113.43=13335"
        .to_string();

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "offsite"]));
        a
    };
    let mut envs = logs_envs(&server.uri());
    envs.push(("ALX_ASN_STATIC_MAP".to_string(), asn_map));

    let output = run_alx(args, envs).await;
    assert_never_panicked(&output, "ALX_ASN_STATIC_MAP junk values + unresolvable IPs");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);

    let offsite_ips: Vec<&str> = json["offsite"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["ip"].as_str())
        .collect();
    let unknown_ips: Vec<&str> = json["asn_unknown"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["ip"].as_str())
        .collect();
    let keep_ips: Vec<&str> = json["keep_benign"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["ip"].as_str())
        .collect();

    for ip in [
        "203.0.113.40",
        "0.0.0.0",
        "255.255.255.255",
        "203.0.113.41",
        "203.0.113.42",
        ipv6_ip,
    ] {
        assert!(
            !offsite_ips.contains(&ip),
            "{ip} must never land in the offsite/abuse bucket on unresolvable ASN data: {json}"
        );
        assert!(
            unknown_ips.contains(&ip),
            "{ip} should land in asn_unknown (missing/malformed ASN data): {json}"
        );
    }

    assert!(
        keep_ips.contains(&"203.0.113.43"),
        "the control IP mapped to a genuine KEEP ASN (13335) should land in keep_benign: {json}"
    );
    assert!(
        !offsite_ips.contains(&"203.0.113.43"),
        "the KEEP-mapped control IP must not appear in offsite: {json}"
    );
}

/// Private/loopback/link-local/unspecified IPv4 addresses through the REAL
/// (non-static-map) `asn::lookup` code path — `is_private()`/
/// `is_loopback()`/`is_link_local()`/`is_unspecified()` short-circuit
/// BEFORE any DNS round-trip (verified inline in `src/asn.rs`'s
/// `lookup_private_ip_never_touches_dns` unit test), so this is safe to
/// run with no `ALX_ASN_STATIC_MAP` at all — confirmed end-to-end here by
/// a tight wall-clock budget (a real hung/attempted DNS call would blow
/// well past this).
#[tokio::test]
async fn hostile_asn_private_and_unspecified_ips_no_static_map_stay_fast_and_unflagged() {
    let server = MockServer::start().await;

    let ips = [
        "10.1.2.3",
        "192.168.1.5",
        "172.16.0.9",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
    ];
    let entries: Vec<Value> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let mut e = valid_entry(&format!("private-ip-{i}"), ip);
            e["ip"] = json!(ip);
            e
        })
        .collect();
    mount_logs_entries(&server, entries).await;

    let args = {
        let mut a = base_creds();
        a.extend(sv(&["logs", "offsite"]));
        a
    };
    let start = Instant::now();
    let output = run_alx(args, logs_envs(&server.uri())).await;
    let elapsed = start.elapsed();

    assert_never_panicked(&output, "private/unspecified IPs, no static map");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "private/loopback/unspecified IPs should short-circuit before any DNS round-trip \
         (budget up to 10s) and complete fast — took {elapsed:?}"
    );

    let json = json_of(&output);
    let offsite_ips: Vec<&str> = json["offsite"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["ip"].as_str())
        .collect();
    for ip in ips {
        assert!(
            !offsite_ips.contains(&ip),
            "{ip} (private/loopback/unspecified) must never be flagged offsite on missing ASN \
             data: {json}"
        );
    }
}

// =======================================================================
// Group D: Usage API parser hostile inputs (`algolia::usage::
// parse_usage_response`), driven through `alx usage series --statistic
// total_search_requests`. Missing `statistics` array (object shape) and
// nested-`v`-value cases are already covered above near the "deeply nested
// garbage" probe — this group covers the rest of the vector list: strings/
// floats/negatives for `v`, missing `t`, missing `v`, and a 10k-point
// performance check.
// =======================================================================

fn usage_series_args() -> Vec<String> {
    let mut a = base_creds();
    a.extend(sv(&[
        "usage",
        "series",
        "--statistic",
        "total_search_requests",
        "--granularity",
        "daily",
        "--since",
        "1d",
    ]));
    a
}

fn usage_envs(usage_uri: &str) -> Vec<(String, String)> {
    vec![
        ("ALX_USAGE_BASE_URL".to_string(), usage_uri.to_string()),
        closed_search_url(),
    ]
}

async fn mount_usage_raw(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/1/usage/total_search_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// `v` arriving as a JSON STRING (not a number) — `as_f64()` on a
/// `Value::String` returns `None`, so this must be a clean
/// "missing/invalid 'v'" `AppError::Api`, not a silent numeric coercion.
#[tokio::test]
async fn hostile_usage_value_as_string_rejected_cleanly() {
    let server = MockServer::start().await;
    mount_usage_raw(
        &server,
        json!({ "statistics": [ { "t": 1_690_000_000, "v": "42500" } ] }),
    )
    .await;

    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_never_panicked(&output, "usage 'v' as a string");
    assert_eq!(
        code_of(&output),
        Some(1),
        "expected AppError::Api (exit 1): {output:?}"
    );
    let json = json_of(&output);
    let err = json["error"].as_str().unwrap_or_default();
    assert!(
        err.contains('v'),
        "expected the error to mention 'v': {json}"
    );
}

/// `v` as a negative number is semantically odd for a usage counter but is
/// a perfectly valid `f64` — must be accepted, not rejected, and must
/// round-trip the actual negative value (not silently clamped to zero).
#[tokio::test]
async fn hostile_usage_value_negative_accepted_not_clamped() {
    let server = MockServer::start().await;
    mount_usage_raw(
        &server,
        json!({ "statistics": [ { "t": 1_690_000_000, "v": -500 } ] }),
    )
    .await;

    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_never_panicked(&output, "usage 'v' negative");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["points"][0]["value"],
        json!(-500.0),
        "response: {json}"
    );
}

/// `v` as a float is the normal case per the Usage API reference, re-verified here as
/// a hostile-vector control (mixed float/negative/huge values in the same
/// series must all round-trip).
#[tokio::test]
async fn hostile_usage_value_float_and_huge_accepted() {
    let server = MockServer::start().await;
    mount_usage_raw(
        &server,
        json!({
            "statistics": [
                { "t": 1_690_000_000, "v": 38200.5 },
                { "t": 1_690_086_400, "v": 999999999999.9 }
            ]
        }),
    )
    .await;

    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_never_panicked(&output, "usage 'v' float/huge");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["points"][0]["value"], json!(38200.5));
    assert_eq!(json["points"][1]["value"], json!(999999999999.9));
}

/// A point missing the `t` key entirely must be a clean "missing/invalid
/// 't'" `AppError::Api`.
#[tokio::test]
async fn hostile_usage_missing_t_rejected_cleanly() {
    let server = MockServer::start().await;
    mount_usage_raw(&server, json!({ "statistics": [ { "v": 100 } ] })).await;

    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_never_panicked(&output, "usage point missing 't'");
    assert_eq!(
        code_of(&output),
        Some(1),
        "expected AppError::Api (exit 1): {output:?}"
    );
    let json = json_of(&output);
    let err = json["error"].as_str().unwrap_or_default();
    assert!(
        err.contains('t'),
        "expected the error to mention 't': {json}"
    );
}

/// A point missing the `v` key entirely must be a clean "missing/invalid
/// 'v'" `AppError::Api`.
#[tokio::test]
async fn hostile_usage_missing_v_rejected_cleanly() {
    let server = MockServer::start().await;
    mount_usage_raw(&server, json!({ "statistics": [ { "t": 1_690_000_000 } ] })).await;

    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_never_panicked(&output, "usage point missing 'v'");
    assert_eq!(
        code_of(&output),
        Some(1),
        "expected AppError::Api (exit 1): {output:?}"
    );
    let json = json_of(&output);
    let err = json["error"].as_str().unwrap_or_default();
    assert!(
        err.contains('v'),
        "expected the error to mention 'v': {json}"
    );
}

/// `statistics` present but as an OBJECT rather than an array — `as_array
/// ()` on an object returns `None`, and the `statistic`-keyed fallback also
/// isn't an array here, so this must be the clean "missing 'statistics'
/// array" `AppError::Api`.
#[tokio::test]
async fn hostile_usage_statistics_object_instead_of_array_rejected_cleanly() {
    let server = MockServer::start().await;
    mount_usage_raw(
        &server,
        json!({ "statistics": { "not": "an array", "nested": { "garbage": true } } }),
    )
    .await;

    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    assert_never_panicked(&output, "usage 'statistics' as an object");
    assert_eq!(
        code_of(&output),
        Some(1),
        "expected AppError::Api (exit 1): {output:?}"
    );
    let json = json_of(&output);
    let err = json["error"].as_str().unwrap_or_default();
    assert!(
        err.to_lowercase().contains("statistics"),
        "expected the error to mention the missing 'statistics' array: {json}"
    );
}

/// A 10,000-point series must complete in reasonable time and round-trip
/// every point correctly — no quadratic blowup in the point-by-point
/// parse/coerce loop.
#[tokio::test]
async fn hostile_usage_huge_10k_point_array_completes_quickly() {
    let server = MockServer::start().await;
    let points: Vec<Value> = (0..10_000)
        .map(|i| json!({ "t": 1_690_000_000 + i * 60, "v": i }))
        .collect();
    mount_usage_raw(&server, json!({ "statistics": points })).await;

    let start = Instant::now();
    let output = run_alx(usage_series_args(), usage_envs(&server.uri())).await;
    let elapsed = start.elapsed();

    assert_never_panicked(&output, "10k-point usage series");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    assert!(
        elapsed < Duration::from_secs(60),
        "10k-point usage series took {elapsed:?} — expected well under 60s"
    );
    let json = json_of(&output);
    assert_eq!(
        json["points"].as_array().unwrap().len(),
        10_000,
        "expected all 10k points to round-trip"
    );
    assert_eq!(json["points"][9999]["value"], json!(9999.0));
}

// =======================================================================
// Group E: Analytics parser hostile inputs (`algolia::analytics::
// top_searches`/`no_results`), driven through `alx analytics
// top-searches`.
// =======================================================================

async fn mount_analytics_searches_raw(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/2/searches"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

fn analytics_top_searches_args() -> Vec<String> {
    let mut a = base_creds();
    a.extend(sv(&["analytics", "top-searches", "--since", "1d"]));
    a
}

fn analytics_envs(analytics_uri: &str) -> Vec<(String, String)> {
    vec![
        (
            "ALX_ANALYTICS_BASE_URL".to_string(),
            analytics_uri.to_string(),
        ),
        closed_search_url(),
    ]
}

/// `searches` present but NOT an array (a raw string) — a genuine
/// deserialize failure, must fail cleanly, never panic, never silently
/// return zero rows as if it were legitimately empty.
#[tokio::test]
async fn hostile_analytics_searches_non_array_rejected_cleanly() {
    let server = MockServer::start().await;
    mount_analytics_searches_raw(&server, json!({ "searches": "not an array at all" })).await;

    let output = run_alx(analytics_top_searches_args(), analytics_envs(&server.uri())).await;
    assert_never_panicked(&output, "analytics 'searches' as a non-array");
    assert_ne!(
        code_of(&output),
        Some(0),
        "a non-array 'searches' field must fail the command, not silently succeed: {output:?}"
    );
}

/// `count` (required `u64`) arriving as a JSON string is a type mismatch —
/// must fail cleanly (the whole response fails to deserialize as
/// `TopSearchesResponse`), never panic.
#[tokio::test]
async fn hostile_analytics_count_as_string_rejected_cleanly() {
    let server = MockServer::start().await;
    mount_analytics_searches_raw(
        &server,
        json!({ "searches": [ { "search": "aspirina", "count": "500", "nbHits": 12 } ] }),
    )
    .await;

    let output = run_alx(analytics_top_searches_args(), analytics_envs(&server.uri())).await;
    assert_never_panicked(&output, "analytics 'count' as a string");
    assert_ne!(
        code_of(&output),
        Some(0),
        "a stringly-typed 'count' must fail the command cleanly, not silently succeed: {output:?}"
    );
}

/// `nbHits` is the one field with `#[serde(default)]` — omitting it
/// entirely must NOT fail the response, it must default to 0. Positive
/// control alongside the failure-mode tests above, so "missing field ->
/// error" isn't mistakenly assumed for every field.
#[tokio::test]
async fn hostile_analytics_missing_nb_hits_defaults_to_zero_not_an_error() {
    let server = MockServer::start().await;
    mount_analytics_searches_raw(
        &server,
        json!({ "searches": [ { "search": "aspirina", "count": 500 } ] }),
    )
    .await;

    let output = run_alx(analytics_top_searches_args(), analytics_envs(&server.uri())).await;
    assert_never_panicked(&output, "analytics missing 'nbHits'");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(json["rows"][0]["nbHits"], json!(0), "response: {json}");
}

/// A 10,000-row `top-searches` response must complete in reasonable time.
#[tokio::test]
async fn hostile_analytics_huge_10k_row_array_completes_quickly() {
    let server = MockServer::start().await;
    let rows: Vec<Value> = (0..10_000)
        .map(|i| json!({ "search": format!("query-{i}"), "count": i, "nbHits": i % 50 }))
        .collect();
    mount_analytics_searches_raw(&server, json!({ "searches": rows })).await;

    let start = Instant::now();
    let output = run_alx(analytics_top_searches_args(), analytics_envs(&server.uri())).await;
    let elapsed = start.elapsed();

    assert_never_panicked(&output, "10k-row analytics top-searches");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    assert!(
        elapsed < Duration::from_secs(60),
        "10k-row analytics response took {elapsed:?} — expected well under 60s"
    );
    let json = json_of(&output);
    assert_eq!(json["rows"].as_array().unwrap().len(), 10_000);
}

// =======================================================================
// Group F: Keys audit parser hostile inputs (`algolia::keys::
// parse_key_info`), driven through `alx keys audit`. `run_audit`'s
// over-privilege preflight (`safety::preflight_privilege_check`) and
// `list_keys` both hit `ctx.base_urls.search(app_id)` — the SAME mock
// server backs both `/1/keys/{key}` (self-check, must return a non-write
// ACL so the audit isn't refused) and `/1/keys` (the actual list, carrying
// the hostile key data), unlike the closed-port pattern used by every
// other group above.
// =======================================================================

async fn mount_keys(server: &MockServer, keys: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/1/keys/testkey"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "value": "testkey", "acl": ["search"] })),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
        .mount(server)
        .await;
}

fn keys_audit_args() -> Vec<String> {
    let mut a = base_creds();
    a.extend(sv(&["keys", "audit"]));
    a
}

fn keys_envs(search_uri: &str) -> Vec<(String, String)> {
    vec![("ALX_SEARCH_BASE_URL".to_string(), search_uri.to_string())]
}

/// `acl` present but NOT an array (a bare string) — `as_str_vec`'s
/// `.as_array()` returns `None` for a non-array `Value`, so this must
/// degrade to an empty ACL list, not panic and not propagate the string as
/// a single-element list.
#[tokio::test]
async fn hostile_keys_acl_non_array_degrades_to_empty_not_panicking() {
    let server = MockServer::start().await;
    mount_keys(
        &server,
        vec![json!({
            "value": "somekeyvalue1234567890",
            "acl": "search",
        })],
    )
    .await;

    let output = run_alx(keys_audit_args(), keys_envs(&server.uri())).await;
    assert_never_panicked(&output, "keys 'acl' as a non-array string");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["keys"][0]["acl"],
        json!([]),
        "a non-array 'acl' must degrade to an empty list, not panic or wrap the string: {json}"
    );
}

/// `validity` extremes: negative number (saturates to 0 via the tolerant
/// float-fallback cast, per `as_u64_tolerant`), an absurdly huge float
/// (saturates to `u64::MAX`), and a non-numeric string (rejected to
/// `None`) — none of these may panic, and the resulting values are pinned
/// so a future change to the coercion logic can't silently regress into a
/// wraparound or a crash.
#[tokio::test]
async fn hostile_keys_validity_extreme_values_never_panic() {
    let server = MockServer::start().await;
    mount_keys(
        &server,
        vec![
            json!({ "value": "key-neg-validity", "acl": ["search"], "validity": -100 }),
            json!({ "value": "key-huge-validity", "acl": ["search"], "validity": 1e30 }),
            json!({ "value": "key-string-garbage-validity", "acl": ["search"], "validity": "not-a-number" }),
            json!({ "value": "key-string-numeric-validity", "acl": ["search"], "validity": "12345" }),
        ],
    )
    .await;

    let output = run_alx(keys_audit_args(), keys_envs(&server.uri())).await;
    assert_never_panicked(&output, "keys 'validity' extremes");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    let keys = json["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 4);
    assert_eq!(
        keys[0]["validity"],
        json!(0),
        "negative validity should saturate to 0 via the tolerant float cast: {json}"
    );
    assert_eq!(
        keys[1]["validity"],
        json!(u64::MAX),
        "an absurdly huge validity should saturate to u64::MAX, not wrap or crash: {json}"
    );
    assert_eq!(
        keys[2]["validity"],
        Value::Null,
        "non-numeric string validity should degrade to null (None), not a panic: {json}"
    );
    assert_eq!(
        keys[3]["validity"],
        json!(12345),
        "a numeric-string validity should still parse correctly: {json}"
    );
}

/// `referers` containing embedded `null` elements alongside real strings —
/// `as_str_vec`'s `filter_map(|e| e.as_str()...)` silently drops any
/// non-string element (including `null`) rather than panicking or
/// propagating a `null` placeholder into the output array.
#[tokio::test]
async fn hostile_keys_referers_with_embedded_nulls_are_dropped_not_panicking() {
    let server = MockServer::start().await;
    mount_keys(
        &server,
        vec![json!({
            "value": "key-null-referers",
            "acl": ["search"],
            "referers": ["https://www.1000farmacie.it/*", null, "https://blog.1000farmacie.it/*", null],
        })],
    )
    .await;

    let output = run_alx(keys_audit_args(), keys_envs(&server.uri())).await;
    assert_never_panicked(&output, "keys 'referers' with embedded nulls");
    assert_eq!(code_of(&output), Some(0), "expected success: {output:?}");
    let json = json_of(&output);
    assert_eq!(
        json["keys"][0]["referers"],
        json!([
            "https://www.1000farmacie.it/*",
            "https://blog.1000farmacie.it/*"
        ]),
        "embedded nulls in 'referers' should be silently dropped, not turned into null entries \
         or a panic: {json}"
    );
}
