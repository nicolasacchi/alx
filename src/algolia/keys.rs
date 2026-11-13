//! Keys API (D10) — read-only audit. No PUT/POST/DELETE anywhere in this
//! module, ever (K3) — `keys audit` cannot mutate by construction.
//!
//! Host: `{application-id}.algolia.net` (same host as the Search API —
//! `AppContext::base_urls::search`), per Algolia's API keys reference.
//! `GET /1/keys`
//! requires the `admin` ACL; `GET /1/keys/{key}` may always be called with
//! the key itself (self-read), returning `description: "<redacted>"` for
//! non-admin callers (Algolia docs, "Admin-Only Access Control").

use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::{self, Surface};
use serde::Serialize;
use serde_json::Value;

/// Typed, tolerant projection of Algolia's `GetApiKeyResponse` (D10: acl,
/// validity, maxQueriesPerIPPerHour, maxHitsPerQuery, indexes, referers,
/// description, createdAt — every field tolerates missing/null input).
///
/// ADV-4: `Debug` is hand-written below (not derived) so `value` is
/// redacted through `safety::mask_key` in `{:?}` output too — `#[serde(
/// skip_serializing)]` only keeps `value` out of *serialized* (JSON)
/// output; `Debug` is a wholly separate trait it does nothing to. Without
/// this, any future `eprintln!("{:?}", key)`, `dbg!(key)`, or a panicking
/// `.unwrap()`/`.expect()` on a value containing this struct would dump
/// the raw key to stderr via its Debug-formatted panic message, bypassing
/// `mask_key` entirely.
#[derive(Clone, Serialize)]
pub struct KeyInfo {
    /// The raw key value, when the API response includes one. Never
    /// serialized (D0.2/K4) — callers MUST go through `safety::mask_key`
    /// before this reaches any output path. Kept in-memory only for
    /// `keys audit`'s `--server-side-key` prefix matching.
    #[serde(skip_serializing)]
    pub value: Option<String>,
    pub acl: Vec<String>,
    /// `None`/empty per Algolia semantics both mean "no restriction — every
    /// index in the app" (Algolia's `indexes` field docs).
    pub indexes: Option<Vec<String>>,
    pub referers: Option<Vec<String>>,
    pub description: Option<String>,
    pub max_queries_per_ip_per_hour: Option<u64>,
    pub max_hits_per_query: Option<u64>,
    pub validity: Option<u64>,
    /// RFC3339 when `createdAt` arrives as a ms-epoch number (the
    /// documented, but UNVERIFIED, wire type); passed
    /// through verbatim if it's already a string.
    pub created_at: Option<String>,
}

impl std::fmt::Debug for KeyInfo {
    /// ADV-4: redacts `value` through `safety::mask_key` instead of the
    /// raw string a derived `Debug` would print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyInfo")
            .field("value", &self.value.as_deref().map(crate::safety::mask_key))
            .field("acl", &self.acl)
            .field("indexes", &self.indexes)
            .field("referers", &self.referers)
            .field("description", &self.description)
            .field(
                "max_queries_per_ip_per_hour",
                &self.max_queries_per_ip_per_hour,
            )
            .field("max_hits_per_query", &self.max_hits_per_query)
            .field("validity", &self.validity)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Result of the list-then-self-read fallback (D10: "on 403 for list, fall
/// back to self-read and mark the audit single-key-scoped").
#[derive(Debug, Clone)]
pub struct KeysFetchResult {
    pub keys: Vec<KeyInfo>,
    pub single_key_scoped: bool,
}

fn as_str_vec(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|e| e.as_str().map(str::to_string))
            .collect()
    })
}

fn as_str_opt(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn as_u64_tolerant(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// `createdAt`'s wire type is UNVERIFIED ("ms since epoch" per gem
/// comments, not confirmed against live behavior).
/// Tolerate a ms-epoch number (converted to RFC3339), a pre-formatted
/// string (passed through), or a missing/null/unparseable value (`None`,
/// never a panic).
fn coerce_created_at(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => {
            let ms = n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?;
            chrono::DateTime::from_timestamp_millis(ms).map(|dt| dt.to_rfc3339())
        }
        _ => None,
    }
}

/// Pure coercion from a raw `GetApiKeyResponse` JSON value into `KeyInfo`.
/// Every field tolerates a missing key, an explicit `null`, or (for the
/// numeric fields) a stringly-typed number — never panics, never errors.
pub fn parse_key_info(v: &Value) -> KeyInfo {
    KeyInfo {
        value: as_str_opt(v.get("value")),
        acl: as_str_vec(v.get("acl")).unwrap_or_default(),
        indexes: as_str_vec(v.get("indexes")),
        referers: as_str_vec(v.get("referers")),
        description: as_str_opt(v.get("description")),
        max_queries_per_ip_per_hour: as_u64_tolerant(v.get("maxQueriesPerIPPerHour")),
        max_hits_per_query: as_u64_tolerant(v.get("maxHitsPerQuery")),
        validity: as_u64_tolerant(v.get("validity")),
        created_at: coerce_created_at(v.get("createdAt")),
    }
}

/// Percent-encode a single path segment (RFC 3986 unreserved set kept
/// literal; everything else escaped). No `url`/`urlencoding` crate is
/// available (D2) — key values are opaque strings that may contain `/`,
/// `+`, `=` and must not be misread as path separators when placed in
/// `/1/keys/{key}`.
fn percent_encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `GET /1/keys` — lists every key the provided credential can enumerate.
/// Requires the `admin` ACL; non-admin keys 403 (see `audit_fetch` for the
/// D10 fallback that handles this).
pub async fn list_keys(ctx: &AppContext, app_id: &str, key: &str) -> AppResult<Vec<KeyInfo>> {
    let url = format!("{}/1/keys", ctx.base_urls.search(app_id));
    let body = http::get_json(&ctx.client, &url, app_id, key, Surface::Keys, &ctx.ops).await?;
    let keys = body
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(parse_key_info).collect())
        .unwrap_or_default();
    Ok(keys)
}

/// `GET /1/keys/{target_key}` — any ACL may fetch its own key (description
/// redacted); fetching a *different* key requires `admin` (403 otherwise).
///
/// ADV-1 fix: `target_key` (the raw key value) is embedded verbatim in
/// `url`'s path segment. If `.send()` fails at the network layer (DNS
/// failure, connect error, timeout, ...) — not a 4xx/5xx response, a true
/// transport failure — `reqwest::Error`'s `Display` unconditionally embeds
/// the full request URL, so the raw key would otherwise flow unredacted
/// into `AppError::Network`'s message and from there into `alx doctor`'s
/// default (non-verbose) JSON output and `alx keys audit`'s error envelope.
/// `redact_self_read_network_error` intercepts exactly that one variant
/// before it can propagate any further and replaces it with a key-free
/// message; every other error variant (whose message comes from the
/// server's response body, not our request URL) passes through unchanged.
pub async fn get_key(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
    target_key: &str,
) -> AppResult<KeyInfo> {
    let url = format!(
        "{}/1/keys/{}",
        ctx.base_urls.search(app_id),
        percent_encode_path_segment(target_key)
    );
    let body = http::get_json(&ctx.client, &url, app_id, key, Surface::Keys, &ctx.ops)
        .await
        .map_err(redact_self_read_network_error)?;
    Ok(parse_key_info(&body))
}

/// See `get_key`'s doc comment (ADV-1). A network-layer failure on the
/// `/1/keys/{key}` self-read is the only call in this module whose request
/// URL can embed the raw key value — this is the single choke point that
/// redacts it before the error is ever formatted anywhere.
fn redact_self_read_network_error(e: AppError) -> AppError {
    match e {
        AppError::Network(_) => AppError::Other(
            "network error contacting the keys self-read endpoint (details redacted — the \
             request URL for this endpoint embeds the key value)"
                .to_string(),
        ),
        other => other,
    }
}

/// `GET /1/keys/{key}` self-read — any ACL can read its own definition.
/// This is the D10 fallback target when `list_keys` 403s.
pub async fn get_self(ctx: &AppContext, app_id: &str, key: &str) -> AppResult<KeyInfo> {
    get_key(ctx, app_id, key, key).await
}

/// The list-then-self-read fallback flow (D10): try `list_keys`; on a
/// **403** specifically (the documented shape for a non-admin key per
/// Algolia's API keys reference — 401 means the credential itself is bad, not "not admin",
/// and is left to propagate rather than wasting a second call), fall back
/// to `get_self` and mark the result single-key-scoped. Any other error
/// (network, plan-gated, ...) propagates unchanged.
pub async fn audit_fetch(ctx: &AppContext, app_id: &str, key: &str) -> AppResult<KeysFetchResult> {
    match list_keys(ctx, app_id, key).await {
        Ok(keys) => Ok(KeysFetchResult {
            keys,
            single_key_scoped: false,
        }),
        Err(AppError::Auth { status: 403, .. }) => {
            let self_key = get_self(ctx, app_id, key).await?;
            Ok(KeysFetchResult {
                keys: vec![self_key],
                single_key_scoped: true,
            })
        }
        Err(e) => Err(e),
    }
}

/// Serializes environment-variable mutations across every test in the
/// crate. `cargo test` compiles all `#[cfg(test)]` modules (across every
/// source file) into one test binary and runs them on multiple threads by
/// default; `std::env::set_var`/`remove_var` are documented as not
/// thread-safe against a concurrent env read on another thread. Any test —
/// in this file or a sibling command module's test block — that needs to
/// redirect `BaseUrls::from_env()` (or a credential env var) at a mock
/// server/synthetic value MUST hold this lock for the full
/// set→read→clear window. `pub(crate)` and declared outside `mod tests` so
/// `commands::doctor`'s test module can share the same lock instead of
/// racing against it with an independent per-module mutex.
#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::BaseUrls;
    use crate::http::SessionOps;
    use crate::output::Presenter;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// ADV-4 regression: `KeyInfo`'s hand-written `Debug` must redact
    /// `value` the same way `mask_key` does everywhere else — a derived
    /// `Debug` would print it verbatim, which `#[serde(skip_serializing)]`
    /// (a JSON-serialization-only guarantee) does nothing to prevent.
    #[test]
    fn adv4_key_info_debug_never_contains_raw_value() {
        let raw_key = "SUPERSECRETRAWKEYVALUE_ADV4_DEBUG_5544332211";
        let k = parse_key_info(&json!({"value": raw_key, "acl": ["search"]}));
        let debug_str = format!("{k:?}");
        assert!(
            !debug_str.contains(raw_key),
            "raw key leaked in KeyInfo's Debug output: {debug_str}"
        );
        assert!(
            debug_str.contains(&crate::safety::mask_key(raw_key)),
            "expected the masked form in Debug output: {debug_str}"
        );
    }

    #[test]
    fn parse_key_info_tolerates_missing_fields() {
        let v = json!({"acl": ["search"]});
        let k = parse_key_info(&v);
        assert_eq!(k.acl, vec!["search".to_string()]);
        assert_eq!(k.indexes, None);
        assert_eq!(k.referers, None);
        assert_eq!(k.description, None);
        assert_eq!(k.max_queries_per_ip_per_hour, None);
        assert_eq!(k.max_hits_per_query, None);
        assert_eq!(k.validity, None);
        assert_eq!(k.created_at, None);
    }

    #[test]
    fn parse_key_info_tolerates_null_fields() {
        let v = json!({
            "acl": null,
            "indexes": null,
            "referers": null,
            "description": null,
            "maxQueriesPerIPPerHour": null,
            "maxHitsPerQuery": null,
            "validity": null,
            "createdAt": null,
        });
        let k = parse_key_info(&v);
        assert!(k.acl.is_empty());
        assert_eq!(k.indexes, None);
        assert_eq!(k.referers, None);
        assert_eq!(k.max_queries_per_ip_per_hour, None);
        assert_eq!(k.created_at, None);
    }

    #[test]
    fn parse_key_info_reads_full_shape() {
        let v = json!({
            "value": "abcd1234",
            "acl": ["search", "browse"],
            "indexes": ["Product"],
            "referers": ["https://www.1000farmacie.it/*"],
            "description": "Frontend search key",
            "maxQueriesPerIPPerHour": 1000,
            "maxHitsPerQuery": 20,
            "validity": 0,
            "createdAt": 1700000000000i64,
        });
        let k = parse_key_info(&v);
        assert_eq!(k.value.as_deref(), Some("abcd1234"));
        assert_eq!(k.acl, vec!["search".to_string(), "browse".to_string()]);
        assert_eq!(k.indexes, Some(vec!["Product".to_string()]));
        assert_eq!(k.max_queries_per_ip_per_hour, Some(1000));
        assert_eq!(k.max_hits_per_query, Some(20));
        assert!(k.created_at.unwrap().starts_with("2023-11-14"));
    }

    #[test]
    fn coerce_created_at_accepts_stringly_typed_numbers() {
        // Defensive: some Algolia numeric fields arrive as JSON strings
        // elsewhere in the API surface (L5) — tolerate it here too.
        let v = json!({"maxQueriesPerIPPerHour": "1000"});
        let k = parse_key_info(&v);
        assert_eq!(k.max_queries_per_ip_per_hour, Some(1000));
    }

    #[test]
    fn percent_encode_path_segment_leaves_safe_chars_alone() {
        assert_eq!(
            percent_encode_path_segment("abcDEF123-_.~"),
            "abcDEF123-_.~"
        );
    }

    #[test]
    fn percent_encode_path_segment_escapes_special_chars() {
        assert_eq!(percent_encode_path_segment("a/b+c="), "a%2Fb%2Bc%3D");
    }

    /// Point `BaseUrls::search` at a mock server for the duration this
    /// helper runs, via the hidden `ALX_SEARCH_BASE_URL` override — the
    /// only way to redirect `AppContext::base_urls` without a live network
    /// call (the struct's fields are private outside `context.rs`).
    /// Mutex-guarded so parallel test threads never race on the env var.
    fn base_urls_for(mock_uri: &str) -> BaseUrls {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        std::env::set_var("ALX_SEARCH_BASE_URL", mock_uri);
        let b = BaseUrls::from_env();
        std::env::remove_var("ALX_SEARCH_BASE_URL");
        b
    }

    fn test_ctx(mock_uri: &str) -> AppContext {
        AppContext {
            client: reqwest::Client::new(),
            presenter: Presenter::new(false, false, false, false, None),
            app_id: Some("testapp".to_string()),
            key_override: Some("testkey".to_string()),
            i_know: false,
            ops: SessionOps::new(),
            base_urls: base_urls_for(mock_uri),
        }
    }

    #[tokio::test]
    async fn list_keys_sends_canonical_auth_headers() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .and(wiremock::matchers::header(
                "X-Algolia-Application-Id",
                "testapp",
            ))
            .and(wiremock::matchers::header("X-Algolia-API-Key", "testkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let keys = list_keys(&ctx, "testapp", "testkey").await.unwrap();
        assert!(keys.is_empty());
        assert_eq!(ctx.ops.snapshot().keys_calls, 1);
    }

    /// Coverage gap closed: every other `audit_fetch` test drives the 403
    /// self-read fallback or an error-propagation branch — this is the only
    /// one that exercises the plain `Ok(keys) => ...` success branch (D10's
    /// happy path: `GET /1/keys` succeeds outright, no fallback needed).
    #[tokio::test]
    async fn audit_fetch_success_path_returns_full_list_not_single_key_scoped() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [
                    {
                        "value": "keyone",
                        "acl": ["search", "browse"],
                        "indexes": ["Product", "Category"],
                    },
                    {
                        "value": "keytwo",
                        "acl": ["search"],
                        "description": "frontend browser key",
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let result = audit_fetch(&ctx, "testapp", "testkey").await.unwrap();

        assert!(
            !result.single_key_scoped,
            "a successful list_keys must NOT mark the audit single-key-scoped"
        );
        assert_eq!(result.keys.len(), 2);
        assert_eq!(result.keys[0].acl, vec!["search", "browse"]);
        assert_eq!(
            result.keys[1].description.as_deref(),
            Some("frontend browser key")
        );
        // Only the one successful list call — no self-read fallback fired.
        assert_eq!(ctx.ops.snapshot().keys_calls, 1);
    }

    #[tokio::test]
    async fn keys_403_falls_back_to_self_read() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "message": "Insufficient ACL to access this resource.",
                "status": 403
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/1/keys/testkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": "testkey",
                "acl": ["search"],
                "createdAt": 1700000000000i64,
                "description": "<redacted>",
                "indexes": ["Product"],
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let result = audit_fetch(&ctx, "testapp", "testkey").await.unwrap();

        assert!(result.single_key_scoped);
        assert_eq!(result.keys.len(), 1);
        assert_eq!(result.keys[0].acl, vec!["search".to_string()]);
        assert_eq!(result.keys[0].description.as_deref(), Some("<redacted>"));
        // Both the forbidden list call and the self-read fallback consume
        // operations quota (D0.4) — both must be counted.
        assert_eq!(ctx.ops.snapshot().keys_calls, 2);
    }

    #[tokio::test]
    async fn audit_fetch_propagates_401_without_self_read_fallback() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "message": "Invalid API key",
                "status": 401
            })))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let err = audit_fetch(&ctx, "testapp", "testkey").await.unwrap_err();
        assert!(matches!(err, AppError::Auth { status: 401, .. }));
        // No self-read attempted for a bad-credential (401) failure.
        assert_eq!(ctx.ops.snapshot().keys_calls, 1);
    }

    #[tokio::test]
    async fn audit_fetch_propagates_plan_gated_without_fallback() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .respond_with(ResponseTemplate::new(402))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(&mock_server.uri());
        let err = audit_fetch(&ctx, "testapp", "testkey").await.unwrap_err();
        assert!(matches!(err, AppError::PlanGated { .. }));
    }

    /// ADV-1 regression: a genuine network-layer failure (not an HTTP
    /// error response) on the `/1/keys/{key}` self-read must never surface
    /// the raw key value — `reqwest::Error`'s `Display` embeds the full
    /// request URL, and that URL contains `target_key` verbatim. Point
    /// `get_self` at a closed loopback port (connection refused, no real
    /// network) with a distinctive raw key and assert it never appears in
    /// the resulting error's `.to_string()`.
    #[tokio::test]
    async fn adv1_get_self_network_failure_never_leaks_raw_key() {
        let raw_key = "SUPERSECRETRAWKEYVALUE_ADV1_DIRECT_1234567890";
        let ctx = test_ctx("http://127.0.0.1:1");

        let err = get_self(&ctx, "testapp", raw_key).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains(raw_key),
            "raw key leaked into get_self's network-error message: {msg}"
        );
        assert!(
            matches!(err, AppError::Other(_)),
            "expected the network error to be redacted into AppError::Other, got: {err:?}"
        );
    }

    /// ADV-1 regression, full `audit_fetch` fallback sequence: `GET
    /// /1/keys` 403s (non-admin key, the documented D10 shape), so
    /// `audit_fetch` falls back to the `/1/keys/{key}` self-read — which
    /// this test forces to fail at the network layer via a request timeout
    /// (the mock delays its response far longer than the test client's
    /// configured timeout) rather than tearing the mock server down
    /// between the two calls: dropping a live `MockServer` frees its OS
    /// port immediately, and under `cargo test`'s default parallelism
    /// another concurrently running test's `MockServer` can — and, when
    /// first written this way, reproducibly did — rebind that exact port
    /// before this test's second request went out, silently routing it to
    /// a *different* test's mocks instead of failing. A deterministic
    /// client-side timeout against a still-live, still-owned server has no
    /// such race. The raw key must never appear in the propagated error.
    #[tokio::test]
    async fn adv1_audit_fetch_self_read_network_failure_never_leaks_raw_key() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "message": "Insufficient ACL to access this resource.",
                "status": 403
            })))
            .mount(&mock_server)
            .await;

        let raw_key = "SUPERSECRETRAWKEYVALUE_ADV1_AUDIT_FALLBACK_9876543210";
        // The self-read path is `/1/keys/{raw_key}` — delay it well past
        // the test client's timeout so `.send()` fails with a genuine
        // `reqwest::Error` (Elapsed), not a routed response.
        Mock::given(method("GET"))
            .and(path(format!("/1/keys/{raw_key}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(15))
                    .set_body_json(json!({"value": raw_key, "acl": ["search"]})),
            )
            .mount(&mock_server)
            .await;

        let short_timeout_client = reqwest::Client::builder()
            // Applies to BOTH calls: the immediate 403 on /1/keys must
            // finish well inside it even on a heavily loaded machine
            // (150ms flaked there), while the 15s-delayed self-read must
            // still time out.
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let mut ctx = test_ctx(&mock_server.uri());
        ctx.client = short_timeout_client;

        let err = audit_fetch(&ctx, "testapp", raw_key).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, AppError::Other(_)),
            "expected the self-read timeout to be redacted into AppError::Other, got: {err:?}"
        );
        assert!(
            !msg.contains(raw_key),
            "raw key leaked into audit_fetch's self-read fallback error: {msg}"
        );
    }
}
