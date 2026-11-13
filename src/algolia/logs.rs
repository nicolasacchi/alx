//! Logs API fetch layer (D7). GET `/1/logs?offset=0&length=1000&type=all`
//! against each of the per-server hosts concurrently — `indexName` is
//! NEVER sent (L1), log type is always `all` (L2).

use super::serde_util::null_as_default;
use crate::asn::join_all;
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::{self, Surface};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Wire envelope: `GET /1/logs` returns `{"logs": [...]}`.
#[derive(Debug, Deserialize)]
struct GetLogsResponse {
    // BUG-ALX-ANALYTICS-NULLCOLL/BUG-ALX-EVENTS-NULLCOLL sweep (task 3):
    // no live evidence of `"logs": null` from this API specifically, but
    // the exact same bug class has now been confirmed live on THREE
    // separate Algolia API families in this codebase (Insights `/1/events`,
    // `/1/metrics`; Search Analytics `/2/searches*`) — defensive fix at
    // zero marginal cost via the shared helper, per the "fix everything
    // fragile, not just the one bug" discipline. Existing
    // `hostile_logs_field_non_array_fails_cleanly_not_silently` (tests/
    // hostile_wire.rs) still pins that a genuinely WRONG-shaped `logs`
    // field (string/number/object) is a hard error — only the null case
    // changes behavior.
    #[serde(default, deserialize_with = "null_as_default")]
    logs: Vec<RawLogEntry>,
}

/// Every field deserializes as `String` (L5) — the Algolia Logs API
/// returns every field, including the numeric/temporal ones, typed String
/// on the wire (confirmed against the `algolia` gem 3.12.2, `log.rb`
/// `types_mapping`). Typing these as `String` here — not `u32`/`u16`/a
/// `chrono` type — is what makes deserialization succeed at all; coercion
/// into `LogEntry` happens explicitly in `coerce_entry`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawLogEntry {
    pub timestamp: Option<String>,
    pub answer_code: Option<String>,
    pub query_body: Option<String>,
    pub answer: Option<String>,
    pub url: Option<String>,
    pub ip: Option<String>,
    pub query_headers: Option<String>,
    pub sha1: Option<String>,
    pub nb_api_calls: Option<String>,
    pub processing_time_ms: Option<String>,
    pub index: Option<String>,
    pub query_nb_hits: Option<String>,
}

/// Coerced, typed shape downstream commands (`logs sample`/`offsite`/
/// `errors`) consume. `referer`/`user_agent` are parsed out of
/// `query_headers` once at coercion time (L6) so every downstream consumer
/// shares one parse instead of re-parsing the raw blob.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub answer_code: u16,
    pub nb_api_calls: u32,
    pub processing_time_ms: u32,
    pub query_nb_hits: Option<u32>,
    pub url: String,
    pub query_body: String,
    pub answer: String,
    pub query_headers: String,
    pub sha1: String,
    pub ip: String,
    pub index: Option<String>,
    /// Which per-server host this entry was fetched from.
    pub host: String,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

/// Per-host fetch bookkeeping (L4): counts plus the raw, `--since`-
/// unfiltered first/last timestamp span for that host's fetched buffer —
/// i.e. how much wall-clock time the host's up-to-1,000-entry ring buffer
/// currently holds. That span, not a `--since`-narrowed one, is the number
/// that tells an operator how often they must sample to never miss a
/// window (L4).
#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub host: String,
    pub fetched: usize,
    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FetchAllResult {
    /// Merged across all hosts, deduped on `(sha1, timestamp, ip)`.
    pub entries: Vec<LogEntry>,
    pub hosts: Vec<HostResult>,
}

/// Parses `query_headers` (L6): a CRLF- or LF-delimited raw text blob —
/// NOT a hash/map (`query_headers[:referer]`-style access is never valid
/// here). Referer/User-Agent are matched case-insensitively and the
/// trailing `\r` a CRLF blob leaves on every line is stripped before the
/// value is returned.
pub fn parse_headers(raw: &str) -> (Option<String>, Option<String>) {
    let mut referer = None;
    let mut user_agent = None;
    for line in raw.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("referer") {
            referer = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("user-agent") {
            user_agent = Some(value.to_string());
        }
    }
    (referer, user_agent)
}

/// Explicit String -> typed coercion (L5). Per the Logs API reference every field
/// except `index`/`query_nb_hits` is required on the wire; an entry that's
/// missing or fails to parse one of those required fields is dropped
/// rather than panicking or failing the whole batch — one malformed entry
/// must never take down the sample.
fn coerce_entry(raw: RawLogEntry, host: &str) -> Option<LogEntry> {
    let timestamp = DateTime::parse_from_rfc3339(raw.timestamp.as_deref()?.trim())
        .ok()?
        .with_timezone(&Utc);
    let answer_code: u16 = raw.answer_code.as_deref()?.trim().parse().ok()?;
    let nb_api_calls: u32 = raw.nb_api_calls.as_deref()?.trim().parse().ok()?;
    let processing_time_ms: u32 = raw.processing_time_ms.as_deref()?.trim().parse().ok()?;
    let query_nb_hits = raw
        .query_nb_hits
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok());
    let ip = raw.ip?;
    let sha1 = raw.sha1?;
    let query_headers = raw.query_headers.unwrap_or_default();
    let (referer, user_agent) = parse_headers(&query_headers);

    Some(LogEntry {
        timestamp,
        answer_code,
        nb_api_calls,
        processing_time_ms,
        query_nb_hits,
        url: raw.url.unwrap_or_default(),
        query_body: raw.query_body.unwrap_or_default(),
        answer: raw.answer.unwrap_or_default(),
        query_headers,
        sha1,
        ip,
        index: raw.index,
        host: host.to_string(),
        referer,
        user_agent,
    })
}

/// GET `/1/logs?offset=0&length=1000&type=all` against a single per-server
/// host. `indexName` is NEVER a query param here (L1) — index filtering,
/// if ever needed, happens client-side against the coerced `LogEntry.
/// index` field. `type=all` (L2) is what makes non-2xx / referer-rejected
/// calls show up at all (`logs errors` depends on this).
pub async fn fetch_logs_from_host(
    ctx: &AppContext,
    host: &str,
    app_id: &str,
    key: &str,
) -> AppResult<Vec<RawLogEntry>> {
    let url = format!("{host}/1/logs?offset=0&length=1000&type=all");
    let value = http::get_json(&ctx.client, &url, app_id, key, Surface::Logs, &ctx.ops).await?;
    let parsed: GetLogsResponse = serde_json::from_value(value)
        .map_err(|e| AppError::Other(format!("failed to parse logs response from {host}: {e}")))?;
    Ok(parsed.logs)
}

/// Fan out across every base in `ctx.base_urls.logs(app_id)` concurrently,
/// merge + dedupe on `(sha1, timestamp, ip)`. Per-host failures are
/// reported per-host (`HostResult.error`), not fatal if at least one host
/// succeeds — only when every host fails does this return `Err`.
pub async fn fetch_logs_all_hosts(
    ctx: &AppContext,
    app_id: &str,
    key: &str,
) -> AppResult<FetchAllResult> {
    let hosts = ctx.base_urls.logs(app_id);

    let futures: Vec<_> = hosts
        .iter()
        .map(|host| fetch_logs_from_host(ctx, host, app_id, key))
        .collect();
    let results = join_all(futures).await;

    let mut host_results = Vec::with_capacity(hosts.len());
    let mut merged: Vec<LogEntry> = Vec::new();
    let mut any_ok = false;
    // Retained alongside `host_results` (which only keeps the *stringified*
    // error) so an all-hosts-failed aggregate can still classify by the
    // shared underlying `AppError` kind (see `classify_all_hosts_error`).
    let mut host_errors: Vec<AppError> = Vec::new();

    for (host, result) in hosts.iter().zip(results) {
        match result {
            Ok(raw_entries) => {
                any_ok = true;
                let mut coerced: Vec<LogEntry> = raw_entries
                    .into_iter()
                    .filter_map(|r| coerce_entry(r, host))
                    .collect();
                let first_ts = coerced.iter().map(|e| e.timestamp).min();
                let last_ts = coerced.iter().map(|e| e.timestamp).max();
                host_results.push(HostResult {
                    host: host.clone(),
                    fetched: coerced.len(),
                    first_ts,
                    last_ts,
                    error: None,
                });
                merged.append(&mut coerced);
            }
            Err(e) => {
                host_results.push(HostResult {
                    host: host.clone(),
                    fetched: 0,
                    first_ts: None,
                    last_ts: None,
                    error: Some(e.to_string()),
                });
                host_errors.push(e);
            }
        }
    }

    if !any_ok {
        let detail = host_results
            .iter()
            .filter_map(|h| h.error.as_deref().map(|e| format!("{}: {e}", h.host)))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(classify_all_hosts_error(
            host_errors,
            detail,
            host_results.len(),
        ));
    }

    let mut seen = HashSet::new();
    merged.retain(|e| seen.insert((e.sha1.clone(), e.timestamp, e.ip.clone())));

    Ok(FetchAllResult {
        entries: merged,
        hosts: host_results,
    })
}

/// Coarse classification used only to decide whether every per-host error
/// shares the same D5 exit-code class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrClass {
    Network,
    Auth,
    PlanGated,
    Other,
}

fn classify(e: &AppError) -> ErrClass {
    match e {
        AppError::Network(_) => ErrClass::Network,
        AppError::Auth { .. } => ErrClass::Auth,
        AppError::PlanGated { .. } => ErrClass::PlanGated,
        _ => ErrClass::Other,
    }
}

/// BUG-ALX-LOGS-ERRCLASS fix: when *every* logs host fails,
/// `fetch_logs_all_hosts` used to unconditionally collapse the per-host
/// errors into a generic `AppError::Other` (exit 1) — discarding the fact
/// that, say, all three hosts failed with the exact same transport-level
/// `AppError::Network` (should be exit 3, D5) or the exact same 401
/// `AppError::Auth` (should be exit 4). This reclassifies: if every per-host
/// error is the *same* D5-significant kind (`Network`/`Auth`/`PlanGated`),
/// propagate that kind — for `Auth`/`PlanGated` the free-text `message`
/// field is replaced with the full per-host `detail` join so no per-host
/// information is lost; `Network` has no such field (it wraps
/// `reqwest::Error`, which has no public constructor to re-message), so the
/// first host's own error is returned as-is — still accurate and
/// credential-free, since `/1/logs` never embeds a key in the URL (D0.2).
/// A *mixed* set of failure kinds (or an all-`Api`/generic set, e.g. all
/// three hosts returning 500) has no single correct D5 code, so it still
/// collapses to `AppError::Other` with the full `detail` — unchanged from
/// the pre-fix behavior for that case.
fn classify_all_hosts_error(errors: Vec<AppError>, detail: String, host_count: usize) -> AppError {
    let generic = || AppError::Other(format!("all {host_count} logs hosts failed: {detail}"));

    let Some(first_class) = errors.first().map(classify) else {
        return generic();
    };
    let homogeneous = errors.iter().all(|e| classify(e) == first_class);
    if !homogeneous {
        return generic();
    }

    match first_class {
        ErrClass::Network => errors
            .into_iter()
            .next()
            .expect("non-empty checked via first_class above"),
        ErrClass::Auth => {
            let (status, suggestion) = match &errors[0] {
                AppError::Auth {
                    status, suggestion, ..
                } => (*status, suggestion.clone()),
                _ => unreachable!("classified as Auth above"),
            };
            AppError::Auth {
                status,
                message: detail,
                suggestion,
            }
        }
        ErrClass::PlanGated => {
            let capability = match &errors[0] {
                AppError::PlanGated { capability, .. } => capability.clone(),
                _ => unreachable!("classified as PlanGated above"),
            };
            AppError::PlanGated {
                capability,
                message: detail,
            }
        }
        ErrClass::Other => generic(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(
        timestamp: &str,
        answer_code: &str,
        nb_api_calls: &str,
        processing_time_ms: &str,
    ) -> RawLogEntry {
        RawLogEntry {
            timestamp: Some(timestamp.to_string()),
            answer_code: Some(answer_code.to_string()),
            query_body: Some("{}".to_string()),
            answer: Some("{}".to_string()),
            url: Some("/1/indexes/Product/query".to_string()),
            ip: Some("203.0.113.5".to_string()),
            query_headers: Some(String::new()),
            sha1: Some("abc123".to_string()),
            nb_api_calls: Some(nb_api_calls.to_string()),
            processing_time_ms: Some(processing_time_ms.to_string()),
            index: Some("Product".to_string()),
            query_nb_hits: None,
        }
    }

    /// L5: numeric/temporal fields arrive as JSON strings on the wire —
    /// coercion must not panic and must produce correctly-typed values.
    #[test]
    fn l5_string_coercion() {
        let entry = raw("2026-07-24T14:30:00Z", "200", "5", "42");
        let coerced = coerce_entry(entry, "host-1").expect("should coerce");
        assert_eq!(coerced.answer_code, 200);
        assert_eq!(coerced.nb_api_calls, 5);
        assert_eq!(coerced.processing_time_ms, 42);
        assert_eq!(
            coerced.timestamp,
            DateTime::parse_from_rfc3339("2026-07-24T14:30:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn l5_malformed_entry_is_dropped_not_panicking() {
        let mut entry = raw("2026-07-24T14:30:00Z", "200", "5", "42");
        entry.nb_api_calls = Some("not-a-number".to_string());
        assert!(coerce_entry(entry, "host-1").is_none());

        let mut entry = raw("2026-07-24T14:30:00Z", "200", "5", "42");
        entry.timestamp = Some("not-a-timestamp".to_string());
        assert!(coerce_entry(entry, "host-1").is_none());
    }

    #[test]
    fn l5_query_nb_hits_optional_coerces_when_present() {
        let mut entry = raw("2026-07-24T14:30:00Z", "200", "5", "42");
        entry.query_nb_hits = Some("1500".to_string());
        let coerced = coerce_entry(entry, "host-1").unwrap();
        assert_eq!(coerced.query_nb_hits, Some(1500));

        let entry = raw("2026-07-24T14:30:00Z", "200", "5", "42");
        let coerced = coerce_entry(entry, "host-1").unwrap();
        assert_eq!(coerced.query_nb_hits, None);
    }

    /// L6: CRLF line endings must not leak a trailing `\r` into the parsed
    /// User-Agent/Referer, and headers must be parsed as raw text, never
    /// as a hash/map.
    #[test]
    fn l6_crlf_stripped() {
        let blob = "Referer: https://1000farmacie.it/cerca\r\nUser-Agent: Mozilla/5.0 Test\r\nX-Other: value\r\n";
        let (referer, user_agent) = parse_headers(blob);
        assert_eq!(referer.as_deref(), Some("https://1000farmacie.it/cerca"));
        let ua = user_agent.expect("user agent present");
        assert_eq!(ua, "Mozilla/5.0 Test");
        assert!(!ua.ends_with('\r'), "trailing CR leaked into UA: {ua:?}");
    }

    #[test]
    fn l6_headers_matched_case_insensitively() {
        let blob = "referer: https://1000farmacie.it/\nUSER-AGENT: curl/8.0\n";
        let (referer, user_agent) = parse_headers(blob);
        assert_eq!(referer.as_deref(), Some("https://1000farmacie.it/"));
        assert_eq!(user_agent.as_deref(), Some("curl/8.0"));
    }

    #[test]
    fn l6_lf_only_blob_also_strips_nothing_extra() {
        let blob = "User-Agent: plain-lf-agent\n";
        let (_, user_agent) = parse_headers(blob);
        assert_eq!(user_agent.as_deref(), Some("plain-lf-agent"));
    }

    #[test]
    fn l6_missing_headers_are_none() {
        let (referer, user_agent) = parse_headers("X-Something: value\r\n");
        assert_eq!(referer, None);
        assert_eq!(user_agent, None);
    }

    // -------------------------------------------------------------------
    // BUG-ALX-LOGS-ERRCLASS regression: `classify_all_hosts_error` directly.
    // The subprocess-level regression pins live in
    // tests/httpx_contract.rs::bug_logs_{auth,network}_failure_on_all_hosts_*
    // and tests/e2e_exit_codes.rs::exit_3_network_logs_sample_closed_port_*;
    // these unit tests pin the classification helper itself, including the
    // mixed-kind and empty-input edges the subprocess tests can't cheaply
    // reach.
    // -------------------------------------------------------------------

    fn auth_err(status: u16, message: &str) -> AppError {
        AppError::Auth {
            status,
            message: message.to_string(),
            suggestion: Some("confirm the key used for `logs` carries the required ACL".into()),
        }
    }

    fn plan_gated_err(message: &str) -> AppError {
        AppError::PlanGated {
            capability: "logs".to_string(),
            message: message.to_string(),
        }
    }

    // reqwest::Error has no public constructor; mirror error.rs's own test
    // trick — a malformed URL fails at `.send()` as a "builder" error
    // without touching the network, so this stays offline-safe.
    async fn network_err() -> AppError {
        reqwest::Client::new()
            .get("not a valid url")
            .send()
            .await
            .unwrap_err()
            .into()
    }

    #[test]
    fn classify_all_hosts_error_homogeneous_auth_preserves_status_and_joins_detail() {
        let errors = vec![
            auth_err(401, "host-1 says no"),
            auth_err(401, "host-2 says no"),
            auth_err(401, "host-3 says no"),
        ];
        let err = classify_all_hosts_error(errors, "host-1: no; host-2: no; host-3: no".into(), 3);
        assert_eq!(
            err.exit_code(),
            4,
            "homogeneous Auth failure must map to D5 exit 4"
        );
        match err {
            AppError::Auth {
                status, message, ..
            } => {
                assert_eq!(status, 401);
                assert_eq!(message, "host-1: no; host-2: no; host-3: no");
            }
            other => panic!("expected AppError::Auth, got {other:?}"),
        }
    }

    #[test]
    fn classify_all_hosts_error_homogeneous_plan_gated_preserves_capability() {
        let errors = vec![
            plan_gated_err("not on your plan (host 1)"),
            plan_gated_err("not on your plan (host 2)"),
        ];
        let err = classify_all_hosts_error(errors, "joined detail".into(), 2);
        match err {
            AppError::PlanGated {
                capability,
                message,
            } => {
                assert_eq!(capability, "logs");
                assert_eq!(message, "joined detail");
            }
            other => panic!("expected AppError::PlanGated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_all_hosts_error_homogeneous_network_preserves_network_kind() {
        let errors = vec![
            network_err().await,
            network_err().await,
            network_err().await,
        ];
        let err = classify_all_hosts_error(errors, "joined detail".into(), 3);
        assert!(
            matches!(err, AppError::Network(_)),
            "expected AppError::Network, got {err:?}"
        );
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn classify_all_hosts_error_mixed_kinds_falls_back_to_other() {
        let errors = vec![auth_err(401, "auth fail"), plan_gated_err("plan fail")];
        let err = classify_all_hosts_error(errors, "auth fail; plan fail".into(), 2);
        assert_eq!(
            err.exit_code(),
            1,
            "mixed-kind failure has no single D5 code, must stay generic exit 1"
        );
        match err {
            AppError::Other(message) => {
                assert!(message.contains("all 2 logs hosts failed"));
                assert!(message.contains("auth fail; plan fail"));
            }
            other => panic!("expected AppError::Other for a mixed-kind failure, got {other:?}"),
        }
    }

    #[test]
    fn classify_all_hosts_error_all_generic_kind_falls_back_to_other() {
        // All-500s-style failures classify as `Api`/`Other`-family errors,
        // which have no D5-significant exit code of their own — stays
        // generic even though every host failed identically.
        let errors = vec![
            AppError::Api {
                status: 500,
                message: "boom".into(),
                suggestion: None,
            },
            AppError::Api {
                status: 500,
                message: "boom".into(),
                suggestion: None,
            },
        ];
        let err = classify_all_hosts_error(errors, "host-1: boom; host-2: boom".into(), 2);
        assert!(matches!(err, AppError::Other(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn classify_all_hosts_error_empty_input_falls_back_to_other() {
        let err = classify_all_hosts_error(Vec::new(), "no hosts configured".into(), 0);
        match err {
            AppError::Other(message) => assert!(message.contains("no hosts configured")),
            other => panic!("expected AppError::Other for empty input, got {other:?}"),
        }
    }
}
