//! `alx keys audit` (D10) — read-only ACL/restriction audit. No mutation
//! code paths whatsoever (K3): this module contains no PUT/POST/DELETE.

use crate::algolia::keys::{self, KeyInfo};
use crate::cli::KeysAuditArgs;
use crate::constants::FRONTEND_INDEXES;
use crate::context::AppContext;
use crate::display;
use crate::error::{AppError, AppResult};
use crate::http::Surface;
use crate::output::SessionOpsSnapshot;
use crate::safety;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Advisory,
    Warning,
    Hard,
}

#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyAuditEntry {
    /// D0.2/K4: the raw key value never appears anywhere in this struct or
    /// its serialized form — only the masked identifier (`safety::mask_key`).
    pub masked_value: String,
    pub acl: Vec<String>,
    pub validity: Option<u64>,
    pub max_queries_per_ip_per_hour: Option<u64>,
    pub max_hits_per_query: Option<u64>,
    pub indexes: Option<Vec<String>>,
    pub referers: Option<Vec<String>>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    Full,
    SingleKeyScoped,
}

#[derive(Debug, Serialize)]
pub struct KeysAuditResponse {
    pub scope: AuditScope,
    pub scope_detail: String,
    pub keys: Vec<KeyAuditEntry>,
    pub session_ops: SessionOpsSnapshot,
}

/// A key counts as "browser-scoped" if it carries a referer restriction, or
/// its description mentions browser/frontend/public usage — Algolia's key
/// metadata has no explicit "used in the browser" field, so this is a
/// heuristic (D10 K1), not a certainty.
fn is_browser_scoped(key: &KeyInfo) -> bool {
    let has_referers = key.referers.as_ref().is_some_and(|r| !r.is_empty());
    let desc_signals_browser = key
        .description
        .as_deref()
        .map(|d| {
            let lower = d.to_lowercase();
            lower.contains("browser") || lower.contains("frontend") || lower.contains("public")
        })
        .unwrap_or(false);
    has_referers || desc_signals_browser
}

/// K1: a browser-scoped key restricted to a subset of `FRONTEND_INDEXES` is
/// missing sources the frontend actually queries — those requests 403
/// (verified set: `Product`, `QuerySuggestions`, `Category`, `Brand`).
/// A browser-scoped key with NO `indexes` restriction is
/// the opposite problem — it can reach every index in the app, not just the
/// frontend four — flagged as a lower-severity advisory instead.
fn k1_check(key: &KeyInfo) -> Option<Warning> {
    if !is_browser_scoped(key) {
        return None;
    }

    match &key.indexes {
        Some(idx) if !idx.is_empty() => {
            let present: HashSet<&str> = idx.iter().map(String::as_str).collect();
            let missing: Vec<&str> = FRONTEND_INDEXES
                .iter()
                .copied()
                .filter(|f| !present.contains(f))
                .collect();
            if missing.is_empty() {
                None
            } else {
                Some(Warning {
                    code: "K1",
                    severity: Severity::Warning,
                    message: format!(
                        "browser-scoped key is restricted to indexes {idx:?} but the frontend also queries {missing:?} — requests to those indices will 403"
                    ),
                })
            }
        }
        _ => Some(Warning {
            code: "K1",
            severity: Severity::Advisory,
            message: format!(
                "browser-scoped key has no `indexes` restriction — it can query every index in the app, not just the frontend set {FRONTEND_INDEXES:?}; consider restricting it"
            ),
        }),
    }
}

/// Match a `--server-side-key`/`ALX_SERVER_SIDE_KEYS` entry against a key.
/// Entries may be a raw-value prefix (matched in-memory only — never
/// printed, per D0.2/K4), a `mask_key`-style masked prefix, or a
/// description substring.
fn matches_server_side_list(key: &KeyInfo, list: &[String]) -> bool {
    list.iter().any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        if let Some(v) = &key.value {
            if v.starts_with(entry) {
                return true;
            }
        }
        let masked = safety::mask_key(key.value.as_deref().unwrap_or(""));
        if masked.starts_with(entry) {
            return true;
        }
        key.description
            .as_deref()
            .map(|d| d.to_lowercase().contains(&entry.to_lowercase()))
            .unwrap_or(false)
    })
}

/// K2: a key carrying `maxQueriesPerIPPerHour` that is *also* used
/// server-side is a NAT hazard: server-side callers typically egress
/// through only a handful of NAT IPs, so a browser-sized per-IP cap would
/// 403 all of them at once, with no deploy and no rollback signal (a
/// dashboard toggle only). Algolia's key metadata has no
/// "also used server-side" field, so this needs operator input
/// (`--server-side-key`/`ALX_SERVER_SIDE_KEYS`); absent that, fall back to
/// a lower-severity advisory for any browser-restricted, rate-limited key.
fn k2_check(key: &KeyInfo, server_side_list: &[String]) -> Option<Warning> {
    let has_rate_limit = key.max_queries_per_ip_per_hour.is_some_and(|v| v > 0);
    if !has_rate_limit {
        return None;
    }

    if !server_side_list.is_empty() {
        if matches_server_side_list(key, server_side_list) {
            return Some(Warning {
                code: "K2",
                severity: Severity::Hard,
                message: "this key is on the configured server-side-usage list AND carries \
maxQueriesPerIPPerHour — RecommendService NAT hazard: a browser-sized per-IP cap will 403 all \
server-side calls egressing through the app's 2-3 NAT IPs, site-wide, with no deploy and no \
rollback signal (a dashboard toggle only)."
                    .to_string(),
            });
        }
        return None;
    }

    if is_browser_scoped(key) {
        return Some(Warning {
            code: "K2",
            severity: Severity::Advisory,
            message: "this key has a browser restriction (referers) AND carries \
maxQueriesPerIPPerHour > 0 — confirm it isn't also used server-side (e.g. \
Algolia::RecommendService); pass --server-side-key to make this a hard warning if it is."
                .to_string(),
        });
    }

    None
}

/// Build the redacted, warning-annotated report row for one key. K4: the
/// raw key value never leaves this function — only `mask_key`'s output is
/// stored on the returned `KeyAuditEntry`.
fn build_entry(key: &KeyInfo, server_side_list: &[String]) -> KeyAuditEntry {
    let mut warnings = Vec::new();
    if let Some(w) = k1_check(key) {
        warnings.push(w);
    }
    if let Some(w) = k2_check(key, server_side_list) {
        warnings.push(w);
    }

    KeyAuditEntry {
        masked_value: safety::mask_key(key.value.as_deref().unwrap_or("")),
        acl: key.acl.clone(),
        validity: key.validity,
        max_queries_per_ip_per_hour: key.max_queries_per_ip_per_hour,
        max_hits_per_query: key.max_hits_per_query,
        indexes: key.indexes.clone(),
        referers: key.referers.clone(),
        description: key.description.clone(),
        created_at: key.created_at.clone(),
        warnings,
    }
}

fn collect_server_side_list(args: &KeysAuditArgs) -> Vec<String> {
    let mut list = args.server_side_key.clone();
    if let Ok(env_list) = std::env::var("ALX_SERVER_SIDE_KEYS") {
        list.extend(
            env_list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        );
    }
    list
}

pub async fn run_audit(ctx: &AppContext, args: &KeysAuditArgs) -> AppResult<()> {
    let app_id = ctx.resolve_app_id().ok_or_else(|| {
        AppError::InvalidInput(
            "ALGOLIA_APPLICATION_ID is not set (and --app-id was not passed)".to_string(),
        )
    })?;
    let key = ctx.resolve_key(Surface::Keys).ok_or_else(|| {
        AppError::InvalidInput(
            "no key configured for `keys audit` — set ALGOLIA_KEYS_API_KEY, the generic \
ALGOLIA_API_KEY, or pass --key"
                .to_string(),
        )
    })?;

    // D0.3/K4: refuse to audit with an over-privileged credential unless
    // --i-know. Best-effort — never blocks on network failure (safety.rs
    // handles that by proceeding silently).
    safety::preflight_privilege_check(
        &ctx.client,
        &ctx.base_urls.search(&app_id),
        &app_id,
        &key,
        ctx.i_know,
        &ctx.presenter,
    )
    .await?;

    let server_side_list = collect_server_side_list(args);

    let fetch = keys::audit_fetch(ctx, &app_id, &key).await?;

    let entries: Vec<KeyAuditEntry> = fetch
        .keys
        .iter()
        .map(|k| build_entry(k, &server_side_list))
        .collect();

    let (scope, scope_detail) = if fetch.single_key_scoped {
        (
            AuditScope::SingleKeyScoped,
            "GET /1/keys was forbidden (non-admin key) — audit falls back to the authenticating \
key's own definition only."
                .to_string(),
        )
    } else {
        (AuditScope::Full, format!("listed {} key(s)", entries.len()))
    };

    let response = KeysAuditResponse {
        scope,
        scope_detail,
        keys: entries,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_human)
}

fn render_human(r: &KeysAuditResponse) -> String {
    let mut out = String::new();
    out.push_str(&display::heading("alx keys audit"));
    out.push('\n');
    out.push_str(&display::kv_line(
        "scope",
        format!("{:?} — {}", r.scope, r.scope_detail),
    ));
    out.push('\n');
    for entry in &r.keys {
        out.push_str(&format!("  key {}\n", entry.masked_value));
        out.push_str(&format!("    acl: {:?}\n", entry.acl));
        if let Some(idx) = &entry.indexes {
            out.push_str(&format!("    indexes: {idx:?}\n"));
        }
        for w in &entry.warnings {
            out.push_str(&format!(
                "    [{:?}/{}] {}\n",
                w.severity, w.code, w.message
            ));
        }
    }
    out.push_str(&crate::output::format_session_ops_line(&r.session_ops));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key(overrides: impl FnOnce(&mut KeyInfo)) -> KeyInfo {
        let mut k = KeyInfo {
            value: Some("abcdefgh12345678abcdefgh12345678".to_string()),
            acl: vec!["search".to_string()],
            indexes: None,
            referers: None,
            description: None,
            max_queries_per_ip_per_hour: None,
            max_hits_per_query: None,
            validity: None,
            created_at: None,
        };
        overrides(&mut k);
        k
    }

    // -------------------------------------------------------------------
    // `render_human` (--human path): never called by any subprocess test
    // in practice — every `alx` invocation spawned via `std::process::
    // Command` has no controlling TTY on stdin, so `agent::detect`'s TTY
    // check unconditionally forces JSON regardless of `--human`. The only
    // way to exercise this function at all is a direct, in-process call.
    // -------------------------------------------------------------------

    #[test]
    fn render_human_never_prints_a_raw_key_value_only_the_masked_form() {
        let raw_key = "supersecretRAWKEYVALUE0000000000";
        let masked = crate::safety::mask_key(raw_key);
        let response = KeysAuditResponse {
            scope: AuditScope::Full,
            scope_detail: "listed via GET /1/keys".to_string(),
            keys: vec![KeyAuditEntry {
                masked_value: masked.clone(),
                acl: vec!["search".to_string(), "browse".to_string()],
                validity: Some(0),
                max_queries_per_ip_per_hour: Some(1000),
                max_hits_per_query: None,
                indexes: Some(vec!["Product".to_string()]),
                referers: Some(vec!["https://www.1000farmacie.it/*".to_string()]),
                description: Some("frontend browser key".to_string()),
                created_at: Some("2026-01-01T00:00:00Z".to_string()),
                warnings: vec![Warning {
                    code: "K1",
                    severity: Severity::Warning,
                    message: "missing frontend index QuerySuggestions".to_string(),
                }],
            }],
            session_ops: SessionOpsSnapshot {
                logs_calls: 0,
                usage_calls: 0,
                analytics_calls: 0,
                keys_calls: 1,
                insights_calls: 0,
            },
        };

        let rendered = render_human(&response);

        assert!(!rendered.contains(raw_key), "raw key leaked: {rendered}");
        assert!(rendered.contains(&masked));
        assert!(rendered.contains("search"));
        assert!(rendered.contains("Product"));
        assert!(rendered.contains("K1"));
        assert!(rendered.contains("missing frontend index QuerySuggestions"));
    }

    #[test]
    fn k1_missing_indexes_warning() {
        let key = sample_key(|k| {
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
            k.indexes = Some(vec!["Product".to_string()]);
        });
        let warning = k1_check(&key).expect("expected K1 warning");
        assert_eq!(warning.code, "K1");
        assert_eq!(warning.severity, Severity::Warning);
        assert!(warning.message.contains("QuerySuggestions"));
        assert!(warning.message.contains("Category"));
        assert!(warning.message.contains("Brand"));
    }

    #[test]
    fn k1_no_warning_when_not_browser_scoped() {
        let key = sample_key(|k| {
            k.indexes = Some(vec!["Product".to_string()]);
        });
        assert!(k1_check(&key).is_none());
    }

    #[test]
    fn k1_no_warning_when_all_frontend_indexes_present() {
        let key = sample_key(|k| {
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
            k.indexes = Some(vec![
                "Product".to_string(),
                "QuerySuggestions".to_string(),
                "Category".to_string(),
                "Brand".to_string(),
            ]);
        });
        assert!(k1_check(&key).is_none());
    }

    #[test]
    fn k1_advisory_for_unrestricted_browser_key() {
        let key = sample_key(|k| {
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
        });
        let warning = k1_check(&key).expect("expected advisory warning");
        assert_eq!(warning.severity, Severity::Advisory);
    }

    #[test]
    fn k1_description_signal_also_counts_as_browser_scoped() {
        let key = sample_key(|k| {
            k.description = Some("Public frontend search key".to_string());
            k.indexes = Some(vec!["Product".to_string()]);
        });
        assert!(k1_check(&key).is_some());
    }

    #[test]
    fn k2_nat_hazard_hard_warning() {
        let key = sample_key(|k| {
            k.value = Some("serversidekeyvalue1234567890abc".to_string());
            k.max_queries_per_ip_per_hour = Some(1000);
        });
        let list = vec!["serversidekeyvalue".to_string()];
        let warning = k2_check(&key, &list).expect("expected hard warning");
        assert_eq!(warning.severity, Severity::Hard);
        assert!(warning.message.contains("RecommendService"));
    }

    #[test]
    fn k2_default_advisory() {
        let key = sample_key(|k| {
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
            k.max_queries_per_ip_per_hour = Some(1000);
        });
        let warning = k2_check(&key, &[]).expect("expected advisory warning");
        assert_eq!(warning.severity, Severity::Advisory);
    }

    #[test]
    fn k2_no_warning_without_rate_limit() {
        let key = sample_key(|k| {
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
        });
        assert!(k2_check(&key, &[]).is_none());
    }

    #[test]
    fn k2_no_warning_when_rate_limit_is_zero() {
        let key = sample_key(|k| {
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
            k.max_queries_per_ip_per_hour = Some(0);
        });
        assert!(k2_check(&key, &[]).is_none());
    }

    #[test]
    fn k2_no_warning_when_list_given_but_key_not_matched() {
        let key = sample_key(|k| {
            k.max_queries_per_ip_per_hour = Some(1000);
        });
        let list = vec!["someotherkeyprefix".to_string()];
        assert!(k2_check(&key, &list).is_none());
    }

    #[test]
    fn k4_output_never_contains_key() {
        let raw_key = "SUPERSECRETKEYVALUE1234567890ABCDEF";
        let key = sample_key(|k| {
            k.value = Some(raw_key.to_string());
            k.referers = Some(vec!["https://www.1000farmacie.it/*".to_string()]);
            k.max_queries_per_ip_per_hour = Some(500);
            k.indexes = Some(vec!["Product".to_string()]);
        });
        let entry = build_entry(&key, &[]);
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(!serialized.contains(raw_key));
        assert!(serialized.contains(&entry.masked_value));
    }

    #[test]
    fn k4_output_never_contains_key_even_when_matched_by_server_side_list() {
        // The --server-side-key match path reads key.value internally;
        // confirm that never leaks into the serialized warning text either.
        let raw_key = "serversidekeyvalue1234567890abc";
        let key = sample_key(|k| {
            k.value = Some(raw_key.to_string());
            k.max_queries_per_ip_per_hour = Some(1000);
        });
        let list = vec!["serversidekeyvalue".to_string()];
        let entry = build_entry(&key, &list);
        assert!(!entry.warnings.is_empty());
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(!serialized.contains(raw_key));
    }

    #[test]
    fn collect_server_side_list_merges_flag_and_env() {
        // Shares the crate-wide env-var test mutex with algolia::keys and
        // commands::doctor's test modules — see its doc comment for why a
        // per-module mutex isn't sufficient (`cargo test` runs every
        // `#[cfg(test)]` module in one multi-threaded binary).
        let _guard = crate::algolia::keys::TEST_ENV_MUTEX.lock().unwrap();
        let args = KeysAuditArgs {
            server_side_key: vec!["fromflag".to_string()],
        };
        std::env::set_var("ALX_SERVER_SIDE_KEYS", "fromenv1, fromenv2");
        let list = collect_server_side_list(&args);
        std::env::remove_var("ALX_SERVER_SIDE_KEYS");
        assert!(list.contains(&"fromflag".to_string()));
        assert!(list.contains(&"fromenv1".to_string()));
        assert!(list.contains(&"fromenv2".to_string()));
    }
}
