//! `alx logs sample|offsite|errors` acceptance criteria (L1-L4) plus D7's
//! multi-host fan-out/merge/dedupe and no-clobber persistence. Runs the real compiled `alx` binary against one or more
//! `wiremock` servers via the `ALX_LOGS_BASE_URLS` override wired into
//! `AppContext`/`BaseUrls` — no real network, no real credentials (a
//! dummy `--app-id`/`--key` pair is passed on the command line, which
//! outranks every env var per D3's resolution order, so no
//! `ALGOLIA_*_API_KEY` needs to exist at all).
//!
//! Test entries all use RFC1918-private IPs so `logs offsite`'s ASN
//! resolution (`asn::lookup`) short-circuits before any DNS round-trip —
//! see `asn.rs`'s own `is_private()` guard (D6).

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

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

async fn run_alx_json(args: Vec<String>, envs: Vec<(String, String)>) -> (i32, Value) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, &envs))
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

fn base_args(sub: &[&str]) -> Vec<String> {
    let mut a = sv(&["--app-id", "test-app", "--key", "test-key"]);
    a.extend(sv(sub));
    a
}

fn base_urls_env(uri: String) -> Vec<(String, String)> {
    vec![
        ("ALX_LOGS_BASE_URLS".to_string(), uri),
        // D0.3 over-privilege gate (safety::preflight_privilege_check) now
        // runs before the first real logs call. Point it at a guaranteed-
        // closed loopback port (immediate connection-refused, no DNS, no
        // real network) rather than the logs mock server itself — the
        // safety self-check hits `/1/keys/{key}` with no query string,
        // which would otherwise land in `server.received_requests()` and
        // break assertions (e.g. `l2_type_all_param`) that iterate every
        // recorded request on that server.
        (
            "ALX_SEARCH_BASE_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        ),
    ]
}

/// Builds a synthetic raw `Log` object exactly as the wire format returns
/// it (L5: every field a JSON string, even the numeric ones).
fn log_entry(
    sha1: &str,
    ip: &str,
    timestamp: &str,
    answer_code: &str,
    user_agent: &str,
    referer: Option<&str>,
) -> Value {
    let mut headers = String::new();
    if let Some(r) = referer {
        headers.push_str(&format!("Referer: {r}\r\n"));
    }
    headers.push_str(&format!("User-Agent: {user_agent}\r\n"));
    json!({
        "timestamp": timestamp,
        "method": "GET",
        "answer_code": answer_code,
        "query_body": "{}",
        "answer": "{}",
        "url": "/1/indexes/Product/query",
        "ip": ip,
        "query_headers": headers,
        "sha1": sha1,
        "nb_api_calls": "1",
        "processing_time_ms": "12",
        "index": "Product",
    })
}

async fn mount_logs(server: &MockServer, entries: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "logs": entries })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------
// L1 / L2: request-shape assertions
// ---------------------------------------------------------------------

#[tokio::test]
async fn l1_no_index_name_param() {
    let server = MockServer::start().await;
    mount_logs(&server, vec![]).await;

    let (code, json) =
        run_alx_json(base_args(&["logs", "sample"]), base_urls_env(server.uri())).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled by default");
    assert!(
        !requests.is_empty(),
        "expected at least one /1/logs request"
    );
    for req in &requests {
        let query = req.url.query().unwrap_or("");
        assert!(
            !query.contains("indexName"),
            "query string leaked indexName: {query}"
        );
    }
}

#[tokio::test]
async fn l2_type_all_param() {
    let server = MockServer::start().await;
    mount_logs(&server, vec![]).await;

    let (code, json) =
        run_alx_json(base_args(&["logs", "sample"]), base_urls_env(server.uri())).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    let requests = server.received_requests().await.unwrap();
    assert!(!requests.is_empty());
    for req in &requests {
        let query = req.url.query().unwrap_or("");
        assert!(query.contains("type=all"), "expected type=all: {query}");
        assert!(query.contains("offset=0"), "expected offset=0: {query}");
        assert!(
            query.contains("length=1000"),
            "expected length=1000: {query}"
        );
    }
}

// ---------------------------------------------------------------------
// Additional acceptance criterion: "offset + length pagination
// cannot page beyond 1,000 total entries" — the fetch layer has no paging
// loop at all (a single GET per host, always offset=0&length=1000), so
// this is satisfied by construction; this test names and pins that
// invariant explicitly (D12) rather than leaving it implicit in l1/l2's
// param-content assertions, so a future change that adds pagination can't
// silently violate the cap without a named test failing.
// ---------------------------------------------------------------------

#[tokio::test]
async fn pagination_never_exceeds_1000_cap_single_request_per_host() {
    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;
    mount_logs(&server_a, vec![]).await;
    mount_logs(&server_b, vec![]).await;

    let base_urls = format!("{},{}", server_a.uri(), server_b.uri());
    let (code, json) = run_alx_json(base_args(&["logs", "sample"]), base_urls_env(base_urls)).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    for server in [&server_a, &server_b] {
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one /1/logs request per host (no pagination loop): {requests:?}"
        );
        let query = requests[0].url.query().unwrap_or("");
        assert!(
            query.contains("length=1000"),
            "length must be exactly 1000, never more: {query}"
        );
        assert!(
            query.contains("offset=0"),
            "a single fetch must always start at offset=0: {query}"
        );
    }
}

// ---------------------------------------------------------------------
// L3: own-egress excluded from offsite totals, but still counted
// ---------------------------------------------------------------------

#[tokio::test]
async fn l3_own_egress_excluded_but_counted() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts_own = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let ts_other = (now - chrono::Duration::minutes(3)).to_rfc3339();

    mount_logs(
        &server,
        vec![
            log_entry(
                "sha-own",
                "10.10.10.10",
                &ts_own,
                "200",
                "Algolia for Rails (3.12.2)",
                None,
            ),
            log_entry(
                "sha-other",
                "10.10.10.20",
                &ts_other,
                "200",
                "Mozilla/5.0 Test",
                Some("https://evil.example/"),
            ),
        ],
    )
    .await;

    let (code, json) =
        run_alx_json(base_args(&["logs", "offsite"]), base_urls_env(server.uri())).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    assert_eq!(json["total_entries"], json!(2));
    assert_eq!(json["own_egress"]["count"], json!(1));

    let offsite_ips: Vec<String> = json["offsite"]
        .as_array()
        .expect("offsite should be an array")
        .iter()
        .map(|g| g["ip"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !offsite_ips.contains(&"10.10.10.10".to_string()),
        "own-egress IP must not appear in the offsite bucket: {json}"
    );
}

// ---------------------------------------------------------------------
// L8/§2.3: KEEP-list ASN routing, driven end-to-end through the real
// `logs offsite` command (not just `asn::classify` at the pure-function
// level) via the `ALX_ASN_STATIC_MAP` test seam (asn.rs) — the acceptance
// wording is "feeding a synthetic log entry with ip
// resolving to a KEEP ASN ... must not appear in the offsite/abuse
// flagged output, only in a separate known-benign datacenter bucket".
// ---------------------------------------------------------------------

#[tokio::test]
async fn l8_keep_asn_ip_routes_to_keep_benign_not_offsite() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts = (now - chrono::Duration::minutes(5)).to_rfc3339();

    // AS62044 (Zscaler CH) is on the KEEP list (D6/constants.rs) — a
    // non-bot UA on this ASN must land in `keep_benign`, never `offsite`.
    mount_logs(
        &server,
        vec![log_entry(
            "sha-keep",
            "203.0.113.99",
            &ts,
            "200",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            None,
        )],
    )
    .await;

    let mut envs = base_urls_env(server.uri());
    envs.push((
        "ALX_ASN_STATIC_MAP".to_string(),
        "203.0.113.99=62044".to_string(),
    ));

    let (code, json) = run_alx_json(base_args(&["logs", "offsite"]), envs).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    assert_eq!(json["total_entries"], json!(1));
    assert_eq!(
        json["keep_benign"]["count"],
        json!(1),
        "KEEP-ASN entry must land in keep_benign: {json}"
    );
    assert_eq!(
        json["offsite"]
            .as_array()
            .expect("offsite should be an array")
            .len(),
        0,
        "KEEP-ASN entry must NOT appear in the offsite/abuse bucket: {json}"
    );
    let keep_ips: Vec<String> = json["keep_benign"]["groups"]
        .as_array()
        .expect("keep_benign.groups should be an array")
        .iter()
        .map(|g| g["ip"].as_str().unwrap().to_string())
        .collect();
    assert!(
        keep_ips.contains(&"203.0.113.99".to_string()),
        "expected the KEEP-ASN IP inside keep_benign.groups: {json}"
    );
}

// ---------------------------------------------------------------------
// L4: real sample window (first -> last, elapsed minutes)
// ---------------------------------------------------------------------

#[tokio::test]
async fn l4_sample_window_reported() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let first = now - chrono::Duration::minutes(20);
    let middle = now - chrono::Duration::minutes(10);
    let last = now - chrono::Duration::minutes(2);

    mount_logs(
        &server,
        vec![
            log_entry(
                "sha-1",
                "203.0.113.10",
                &first.to_rfc3339(),
                "200",
                "Mozilla/5.0",
                None,
            ),
            log_entry(
                "sha-2",
                "203.0.113.11",
                &middle.to_rfc3339(),
                "200",
                "Mozilla/5.0",
                None,
            ),
            log_entry(
                "sha-3",
                "203.0.113.12",
                &last.to_rfc3339(),
                "200",
                "Mozilla/5.0",
                None,
            ),
        ],
    )
    .await;

    let (code, json) =
        run_alx_json(base_args(&["logs", "sample"]), base_urls_env(server.uri())).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    assert_eq!(json["window"]["elapsed_minutes"], json!(18));
    assert!(json["window"]["first"].is_string());
    assert!(json["window"]["last"].is_string());
    let note = json["window"]["note"].as_str().unwrap().to_lowercase();
    assert!(
        note.contains("sampling interval"),
        "L4 framing missing from note: {note}"
    );
    assert_eq!(json["total_entries"], json!(3));
}

// ---------------------------------------------------------------------
// D7: multi-host fan-out, merge + dedupe, per-host failure tolerance
// ---------------------------------------------------------------------

#[tokio::test]
async fn multi_host_merge_dedupe() {
    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;

    let now = chrono::Utc::now();
    let ts_shared = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let ts_a_only = (now - chrono::Duration::minutes(4)).to_rfc3339();
    let ts_b_only = (now - chrono::Duration::minutes(3)).to_rfc3339();

    let shared = log_entry(
        "sha-shared",
        "203.0.113.50",
        &ts_shared,
        "200",
        "Mozilla/5.0",
        None,
    );
    let a_only = log_entry(
        "sha-a",
        "203.0.113.51",
        &ts_a_only,
        "200",
        "Mozilla/5.0",
        None,
    );
    let b_only = log_entry(
        "sha-b",
        "203.0.113.52",
        &ts_b_only,
        "200",
        "Mozilla/5.0",
        None,
    );

    mount_logs(&server_a, vec![shared.clone(), a_only]).await;
    mount_logs(&server_b, vec![shared, b_only]).await;

    let base_urls = format!("{},{}", server_a.uri(), server_b.uri());
    let (code, json) = run_alx_json(base_args(&["logs", "sample"]), base_urls_env(base_urls)).await;
    assert_eq!(code, 0, "expected success, got json={json}");

    // 3 unique entries: the identical (sha1, timestamp, ip) triple served
    // by both hosts must collapse into one.
    assert_eq!(json["total_entries"], json!(3));
    assert_eq!(json["hosts"].as_array().unwrap().len(), 2);
    for h in json["hosts"].as_array().unwrap() {
        assert!(h["error"].is_null(), "both hosts should succeed: {json}");
        assert_eq!(h["fetched"], json!(2));
    }
}

#[tokio::test]
async fn one_host_down_still_succeeds() {
    let server_up = MockServer::start().await;
    let server_down = MockServer::start().await; // no mock mounted: any request 404s

    let now = chrono::Utc::now();
    let ts = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let entry = log_entry("sha-up", "203.0.113.60", &ts, "200", "Mozilla/5.0", None);
    mount_logs(&server_up, vec![entry]).await;

    let base_urls = format!("{},{}", server_up.uri(), server_down.uri());
    let (code, json) = run_alx_json(base_args(&["logs", "sample"]), base_urls_env(base_urls)).await;
    assert_eq!(
        code, 0,
        "one live host out of two should be enough to succeed: {json}"
    );
    assert_eq!(json["total_entries"], json!(1));

    let hosts = json["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);
    let failed = hosts
        .iter()
        .find(|h| h["error"].is_string())
        .expect("the down host should report a per-host error");
    assert!(!failed["error"].as_str().unwrap().is_empty());
    let ok_host = hosts
        .iter()
        .find(|h| h["error"].is_null())
        .expect("the live host should have succeeded");
    assert_eq!(ok_host["fetched"], json!(1));
}

#[tokio::test]
async fn all_hosts_down_fails_the_command() {
    let server_down_a = MockServer::start().await;
    let server_down_b = MockServer::start().await;

    let base_urls = format!("{},{}", server_down_a.uri(), server_down_b.uri());
    let (code, _json) =
        run_alx_json(base_args(&["logs", "sample"]), base_urls_env(base_urls)).await;
    assert_ne!(code, 0, "every host failing must fail the command");
}

// ---------------------------------------------------------------------
// D7: --persist naming + never-clobber
// ---------------------------------------------------------------------

#[tokio::test]
async fn persist_no_clobber() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let entry = log_entry(
        "sha-persist",
        "203.0.113.70",
        &ts,
        "200",
        "Mozilla/5.0",
        None,
    );
    mount_logs(&server, vec![entry]).await;

    let dir = std::env::temp_dir().join(format!(
        "alx-test-persist-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dir_str = dir.to_string_lossy().to_string();
    let base_url = server.uri();

    let mut args1 = base_args(&["logs", "sample", "--persist"]);
    args1.push(dir_str.clone());
    let (code1, json1) = run_alx_json(args1, base_urls_env(base_url.clone())).await;
    assert_eq!(code1, 0, "first run should succeed: {json1}");
    let meta1 = json1["persisted"]["meta_file"]
        .as_str()
        .expect("first run should report a persisted.meta_file")
        .to_string();
    let host_files1 = json1["persisted"]["host_files"]
        .as_array()
        .expect("first run should list host_files");
    assert!(!host_files1.is_empty(), "expected >=1 host jsonl: {json1}");

    let mut args2 = base_args(&["logs", "sample", "--persist"]);
    args2.push(dir_str.clone());
    let (code2, json2) = run_alx_json(args2, base_urls_env(base_url)).await;
    assert_eq!(code2, 0, "second run should succeed: {json2}");
    let meta2 = json2["persisted"]["meta_file"]
        .as_str()
        .expect("second run should report a persisted.meta_file")
        .to_string();

    assert_ne!(
        meta1, meta2,
        "second run must not clobber the first run's meta file"
    );
    assert!(std::path::Path::new(&meta1).exists());
    assert!(std::path::Path::new(&meta2).exists());

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// logs errors: type=all surfaces non-200 (referer-rejected etc.) entries
// ---------------------------------------------------------------------

#[tokio::test]
async fn errors_filters_non_200_answer_code() {
    let server = MockServer::start().await;
    let now = chrono::Utc::now();
    let ts_ok = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let ts_bad = (now - chrono::Duration::minutes(4)).to_rfc3339();

    mount_logs(
        &server,
        vec![
            log_entry("sha-ok", "203.0.113.80", &ts_ok, "200", "Mozilla/5.0", None),
            log_entry(
                "sha-bad",
                "203.0.113.81",
                &ts_bad,
                "403",
                "Mozilla/5.0",
                Some("https://someone-else.example/"),
            ),
        ],
    )
    .await;

    let (code, json) =
        run_alx_json(base_args(&["logs", "errors"]), base_urls_env(server.uri())).await;
    assert_eq!(code, 0, "expected success, got json={json}");
    assert_eq!(json["total_checked"], json!(2));
    assert_eq!(json["error_count"], json!(1));
    let errors = json["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["answer_code"], json!(403));
    assert_eq!(errors[0]["ip"], json!("203.0.113.81"));
}

// ---------------------------------------------------------------------
// D4: quota-honesty envelope present on every logs response
// ---------------------------------------------------------------------

#[tokio::test]
async fn session_ops_present_in_every_response() {
    let server = MockServer::start().await;
    mount_logs(&server, vec![]).await;

    let (code, json) =
        run_alx_json(base_args(&["logs", "sample"]), base_urls_env(server.uri())).await;
    assert_eq!(code, 0, "expected success, got json={json}");
    assert!(
        json["session_ops"].is_object(),
        "missing session_ops: {json}"
    );
    assert!(json["session_ops"]["logs_calls"].as_u64().unwrap() >= 1);
}
