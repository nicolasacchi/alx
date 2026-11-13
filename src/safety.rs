//! Over-privilege gate (D3 / spec §0.3) and key redaction. Centralizes the
//! ONLY place a key value is ever formatted for display.
//!
//! `preflight_privilege_check` takes `base_url` as an explicit parameter
//! (the search host, e.g. `ctx.base_urls.search(app_id)`) rather than
//! hardcoding `https://{app_id}.algolia.net` — this is what lets
//! `ALX_SEARCH_BASE_URL` redirect the self-check at a wiremock server in
//! tests, so every command that wires this gate in stays free of real
//! network calls under test (integrate-pass fix: the logs/usage/analytics
//! builders independently hit this exact wall — see the logs builder's
//! reported deviation).
#![allow(dead_code)]

use crate::error::AppResult;
use crate::output::Presenter;
use std::collections::HashSet;

/// ACLs that, if present on the configured key, trigger a safety refusal
/// unless `--i-know` is passed.
const WRITE_ACLS: [&str; 5] = [
    "addObject",
    "deleteObject",
    "deleteIndex",
    "editSettings",
    "settings",
];

/// Mask a key value for display: first 4 chars, an ellipsis, and the total
/// length in parens — e.g. `"abcd…(32)"`. Never more than 4 leading chars,
/// and never the raw key. A key value must never appear in any output, log,
/// error, debug, or verbose path outside this function's output.
pub fn mask_key(key: &str) -> String {
    let visible: String = key.chars().take(4).collect();
    format!("{visible}…({})", key.chars().count())
}

/// Returns the subset of `acls` that intersect the write-capable set.
/// Pure logic, split out from the async network call so it's independently
/// unit-testable.
pub fn intersect_write_acls(acls: &[String]) -> Vec<String> {
    let write_set: HashSet<&str> = WRITE_ACLS.iter().copied().collect();
    acls.iter()
        .filter(|a| write_set.contains(a.as_str()))
        .cloned()
        .collect()
}

/// Best-effort self-inspect: `GET /1/keys/{key}` using the key itself
/// (non-admin keys can read their own definition). If the ACL set
/// intersects the write-capable set and `--i-know` was not passed, returns
/// `Err(AppError::SafetyRefusal)`. On 403/404/network failure, proceeds
/// without blocking (best-effort — noted in verbose mode only), per D3.
///
/// `base_url` is the search host to probe (callers pass
/// `ctx.base_urls.search(app_id)`, which defaults to
/// `https://{app_id}.algolia.net` and honors the `ALX_SEARCH_BASE_URL` test
/// override) — this function never derives the host itself.
pub async fn preflight_privilege_check(
    client: &reqwest::Client,
    base_url: &str,
    app_id: &str,
    key: &str,
    i_know: bool,
    presenter: &Presenter,
) -> AppResult<()> {
    let url = format!("{base_url}/1/keys/{key}");

    let resp = match client
        .get(&url)
        .header("X-Algolia-Application-Id", app_id)
        .header("X-Algolia-API-Key", key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_e) => {
            // ADV-1: never format the underlying `reqwest::Error` here.
            // `url` embeds the raw key as a path segment (`/1/keys/{key}`),
            // and `reqwest::Error`'s `Display`/`Debug` unconditionally
            // includes the request URL on a transport-layer failure (DNS,
            // connect, timeout) — interpolating `{e}` would leak the key
            // into this progress line (D0.2/D3 "never print key material,
            // anywhere, including verbose/debug/error paths").
            presenter.progress(
                "over-privilege self-check skipped (network error contacting the keys \
                 self-read endpoint)",
            );
            return Ok(());
        }
    };

    if !resp.status().is_success() {
        presenter.progress(&format!(
            "over-privilege self-check skipped (HTTP {})",
            resp.status()
        ));
        return Ok(());
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            presenter.progress(&format!(
                "over-privilege self-check skipped (unparseable response: {e})"
            ));
            return Ok(());
        }
    };

    let acls: Vec<String> = body
        .get("acl")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let offending = intersect_write_acls(&acls);
    if !offending.is_empty() && !i_know {
        return Err(crate::error::AppError::SafetyRefusal { acls: offending });
    }

    if !offending.is_empty() {
        presenter.progress(&format!(
            "proceeding with write-capable ACL(s) {offending:?} (--i-know)"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Presenter;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The one `preflight_privilege_check` branch e2e_exit_codes.rs's
    /// SafetyRefusal/`--i-know` tests and e2e_redaction.rs's 404
    /// (non-2xx-skip) test don't reach: a 200 response whose body isn't
    /// valid JSON at all — must best-effort skip (`Ok(())`), never fail
    /// the command over an unparseable self-check response.
    #[tokio::test]
    async fn unparseable_response_body_skips_the_check_instead_of_failing() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/keys/test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all {{{"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let presenter = Presenter::new(false, false, false, false, None);
        let result = preflight_privilege_check(
            &client,
            &mock_server.uri(),
            "testapp",
            "test-key",
            false,
            &presenter,
        )
        .await;

        assert!(
            result.is_ok(),
            "an unparseable 200 body must skip, not fail: {result:?}"
        );
    }

    /// Companion positive case in the same suite: a well-formed 200 body
    /// with an ACL that carries none of the write-capable ACLs must also
    /// succeed silently (the "safe key" happy path — distinct from both
    /// the skip branches above and the SafetyRefusal branch pinned in
    /// tests/e2e_exit_codes.rs).
    #[tokio::test]
    async fn safe_acl_proceeds_without_refusal() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/keys/test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "test-key",
                "acl": ["search", "browse"]
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let presenter = Presenter::new(false, false, false, false, None);
        let result = preflight_privilege_check(
            &client,
            &mock_server.uri(),
            "testapp",
            "test-key",
            false,
            &presenter,
        )
        .await;

        assert!(result.is_ok());
    }

    #[test]
    fn mask_key_never_exceeds_four_leading_chars() {
        assert_eq!(mask_key("abcdefgh12345678"), "abcd…(16)");
        assert_eq!(mask_key("ab"), "ab…(2)");
        assert_eq!(mask_key(""), "…(0)");
    }

    #[test]
    fn mask_key_reports_correct_length() {
        let key = "0123456789abcdef0123456789abcdef";
        let masked = mask_key(key);
        assert!(masked.ends_with(&format!("({})", key.len())));
        assert!(!masked.contains(&key[4..]));
    }

    #[test]
    fn intersect_write_acls_detects_dangerous_acls() {
        let acls = vec!["search".to_string(), "deleteIndex".to_string()];
        assert_eq!(intersect_write_acls(&acls), vec!["deleteIndex"]);
    }

    #[test]
    fn intersect_write_acls_empty_for_safe_key() {
        let acls = vec![
            "search".to_string(),
            "browse".to_string(),
            "logs".to_string(),
        ];
        assert!(intersect_write_acls(&acls).is_empty());
    }

    #[test]
    fn intersect_write_acls_detects_all_five() {
        let acls: Vec<String> = [
            "addObject",
            "deleteObject",
            "deleteIndex",
            "editSettings",
            "settings",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let got = intersect_write_acls(&acls);
        assert_eq!(got.len(), 5);
    }
}
