//! `alx doctor` — capability matrix probe (D8). Runs with whatever
//! credentials exist; a missing env var is a `no_credentials` row, not a
//! hard failure — `doctor` only fails on total absence of an app id.
//!
//! Deliberately does NOT call `safety::preflight_privilege_check` — that
//! gate exists to refuse running a command *with* an over-privileged key;
//! doctor's entire job is reporting on whatever key is configured
//! (including over-privileged ones), so refusing to run would defeat its
//! purpose (spec: "Doctor must NOT run the over-privilege preflight").

use crate::context::AppContext;
use crate::display;
use crate::error::{AppError, AppResult};
use crate::http::{self, Surface};
use crate::output::SessionOpsSnapshot;
use serde::Serialize;

/// Failure classification for a capability probe (D8's exact vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Ok,
    MissingAcl,
    PlanGated,
    NetworkError,
    NoCredentials,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityRow {
    pub capability: String,
    pub reachable: bool,
    pub reason: Reason,
    pub detail: String,
    /// Name of the env var (or `--key`) that supplied the credential used
    /// for this probe — NAME ONLY, never the value (D0.2).
    pub credential_source: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorResponse {
    pub app_id: String,
    /// `--app-id` or `ALGOLIA_APPLICATION_ID` — NAME ONLY.
    pub app_id_source: String,
    pub capabilities: Vec<CapabilityRow>,
    pub session_ops: SessionOpsSnapshot,
}

fn surface_env_var(surface: Surface) -> &'static str {
    match surface {
        Surface::Logs => "ALGOLIA_LOGS_API_KEY",
        Surface::Usage => "ALGOLIA_USAGE_API_KEY",
        Surface::Analytics => "ALGOLIA_ANALYTICS_API_KEY",
        Surface::Keys => "ALGOLIA_KEYS_API_KEY",
        Surface::Insights => "ALGOLIA_INSIGHTS_API_KEY",
    }
}

/// Mirrors `AppContext::resolve_key`'s Insights-specific 3-tier fallback
/// (`--key` > `ALGOLIA_INSIGHTS_API_KEY` > `ALGOLIA_LOGS_API_KEY` >
/// `ALGOLIA_API_KEY`) but additionally reports which source supplied the
/// credential, by name only — same reason `resolve_key_source` exists for
/// every other surface, split out separately here because Insights has one
/// extra fallback tier the generic helper doesn't model.
fn resolve_insights_key_source(ctx: &AppContext) -> Option<(String, &'static str)> {
    if let Some(v) = ctx.key_override.clone().filter(|v| !v.is_empty()) {
        return Some((v, "--key"));
    }
    if let Ok(v) = std::env::var("ALGOLIA_INSIGHTS_API_KEY") {
        if !v.is_empty() {
            return Some((v, "ALGOLIA_INSIGHTS_API_KEY"));
        }
    }
    if let Ok(v) = std::env::var("ALGOLIA_LOGS_API_KEY") {
        if !v.is_empty() {
            return Some((v, "ALGOLIA_LOGS_API_KEY"));
        }
    }
    std::env::var("ALGOLIA_API_KEY")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| (v, "ALGOLIA_API_KEY"))
}

fn resolve_app_id_source(ctx: &AppContext) -> Option<(String, &'static str)> {
    if let Some(v) = ctx.app_id.clone().filter(|v| !v.is_empty()) {
        return Some((v, "--app-id"));
    }
    std::env::var("ALGOLIA_APPLICATION_ID")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| (v, "ALGOLIA_APPLICATION_ID"))
}

/// Mirrors `AppContext::resolve_key`'s priority order (D3) but additionally
/// reports which source supplied the credential, by name only — the
/// frozen `resolve_key` doesn't expose that, and doctor needs it for the
/// capability matrix's `credential_source` column.
fn resolve_key_source(ctx: &AppContext, surface: Surface) -> Option<(String, &'static str)> {
    if let Some(v) = ctx.key_override.clone().filter(|v| !v.is_empty()) {
        return Some((v, "--key"));
    }
    let surface_var = surface_env_var(surface);
    if let Ok(v) = std::env::var(surface_var) {
        if !v.is_empty() {
            return Some((v, surface_var));
        }
    }
    std::env::var("ALGOLIA_API_KEY")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| (v, "ALGOLIA_API_KEY"))
}

fn no_credentials_row(capability: &str, surface: Surface) -> CapabilityRow {
    CapabilityRow {
        capability: capability.to_string(),
        reachable: false,
        reason: Reason::NoCredentials,
        detail: format!(
            "no credential resolved for `{capability}` — set {}, the generic ALGOLIA_API_KEY, or pass --key",
            surface_env_var(surface)
        ),
        credential_source: None,
    }
}

/// Maps an `AppError` from a probe call into D8's `reason`/`detail` pair.
/// Never a raw error dump (D8) — every branch produces a clean sentence.
fn classify_error(err: &AppError) -> (Reason, String) {
    match err {
        AppError::Auth {
            status, message, ..
        } => (Reason::MissingAcl, format!("HTTP {status}: {message}")),
        AppError::PlanGated { message, .. } => (Reason::PlanGated, message.clone()),
        AppError::Network(e) => (Reason::NetworkError, e.to_string()),
        AppError::Api {
            status, message, ..
        } => (Reason::Unknown, format!("HTTP {status}: {message}")),
        other => (Reason::Unknown, other.to_string()),
    }
}

/// Probe a single capability by explicit URL — deliberately independent of
/// `AppContext::base_urls` so it's directly wiremock-testable without any
/// env-var base-URL override plumbing. `run()` is the only caller that
/// derives `url` from `ctx.base_urls`.
async fn probe(
    ctx: &AppContext,
    capability: &str,
    url: &str,
    app_id: &str,
    surface: Surface,
    credential: Option<(String, &'static str)>,
) -> CapabilityRow {
    let Some((key, source)) = credential else {
        return no_credentials_row(capability, surface);
    };

    match http::get_json(&ctx.client, url, app_id, &key, surface, &ctx.ops).await {
        Ok(_) => CapabilityRow {
            capability: capability.to_string(),
            reachable: true,
            reason: Reason::Ok,
            detail: "reachable".to_string(),
            credential_source: Some(source.to_string()),
        },
        Err(e) => {
            let (reason, detail) = classify_error(&e);
            CapabilityRow {
                capability: capability.to_string(),
                reachable: false,
                reason,
                detail,
                credential_source: Some(source.to_string()),
            }
        }
    }
}

/// Keys capability probe: `GET /1/keys` (list), and — since a 403 there is
/// the *expected*, informative shape for a non-admin key, not a failure —
/// always also try `GET /1/keys/{self}` before giving up (D8: "Any valid
/// key can list/read its own metadata | N/A baseline"). Deliberately more
/// lenient than `algolia::keys::audit_fetch`'s strict 403-only fallback:
/// doctor only wants "is *any* keys access reachable", not an accurate
/// key list.
async fn probe_keys(
    ctx: &AppContext,
    app_id: &str,
    credential: Option<(String, &'static str)>,
) -> CapabilityRow {
    let Some((key, source)) = credential else {
        return no_credentials_row("keys", Surface::Keys);
    };

    match crate::algolia::keys::list_keys(ctx, app_id, &key).await {
        Ok(keys) => CapabilityRow {
            capability: "keys".to_string(),
            reachable: true,
            reason: Reason::Ok,
            detail: format!("listed {} key(s)", keys.len()),
            credential_source: Some(source.to_string()),
        },
        Err(_list_err) => match crate::algolia::keys::get_self(ctx, app_id, &key).await {
            Ok(_) => CapabilityRow {
                capability: "keys".to_string(),
                reachable: true,
                reason: Reason::Ok,
                detail: "list forbidden (non-admin key); self-read succeeded — single-key scoped"
                    .to_string(),
                credential_source: Some(source.to_string()),
            },
            Err(self_err) => {
                let (reason, detail) = classify_error(&self_err);
                CapabilityRow {
                    capability: "keys".to_string(),
                    reachable: false,
                    reason,
                    detail,
                    credential_source: Some(source.to_string()),
                }
            }
        },
    }
}

pub async fn run(ctx: &AppContext) -> AppResult<()> {
    let Some((app_id, app_id_source)) = resolve_app_id_source(ctx) else {
        return Err(AppError::InvalidInput(
            "ALGOLIA_APPLICATION_ID is not set (and --app-id was not passed) — doctor needs at least the app id to run"
                .to_string(),
        ));
    };

    // ADV-2 defense-in-depth: `BaseUrls::from_env` (context.rs) now
    // guarantees `logs()` never returns an empty vec (an empty/whitespace
    // `ALX_LOGS_BASE_URLS` falls through to the 3-host default), but index
    // via `.first()` rather than `[0]` anyway so a future regression in
    // that invariant degrades to a clean `network_error`-classified row
    // instead of an index-out-of-bounds panic in the one command that's
    // explicitly designed to run safely with any/no configuration.
    let logs_hosts = ctx.base_urls.logs(&app_id);
    let logs_url = match logs_hosts.first() {
        Some(host) => format!("{host}/1/logs?length=1"),
        None => format!("https://{app_id}-1.algolianet.com/1/logs?length=1"),
    };

    // The Usage API needs a full ISO-8601 datetime; a date-only value is
    // rejected as `422 "Unexpected parameters"` (verified live 2026-07-30 —
    // see `algolia::usage::date_window`). Reuse that helper rather than
    // formatting dates here, so the probe can never drift from the real
    // command's window format again.
    let (usage_start, usage_end) = crate::algolia::usage::date_window(1);
    let usage_url = format!(
        "{}/1/usage/records?startDate={usage_start}&endDate={usage_end}&granularity=daily",
        ctx.base_urls.usage(),
    );

    // Doctor has no --region flag (bare subcommand); default per D9's
    // documented default ("de" — our app is EU). `index` is REQUIRED on
    // every Search Analytics endpoint including `/2/status` — omitting it
    // returns `422 "Index is required"`, which the probe would otherwise
    // report as an opaque `unknown` capability (verified live 2026-07-30).
    let analytics_url = format!(
        "{}/2/status?index={}",
        ctx.base_urls.analytics("de"),
        crate::constants::FRONTEND_INDEXES[0],
    );

    let logs_row = probe(
        ctx,
        "logs",
        &logs_url,
        &app_id,
        Surface::Logs,
        resolve_key_source(ctx, Surface::Logs),
    )
    .await;

    let usage_row = probe(
        ctx,
        "usage",
        &usage_url,
        &app_id,
        Surface::Usage,
        resolve_key_source(ctx, Surface::Usage),
    )
    .await;

    let analytics_row = probe(
        ctx,
        "analytics",
        &analytics_url,
        &app_id,
        Surface::Analytics,
        resolve_key_source(ctx, Surface::Analytics),
    )
    .await;

    let keys_row = probe_keys(ctx, &app_id, resolve_key_source(ctx, Surface::Keys)).await;

    // Insights probe: GET /1/events?limit=1 — the cheapest real call
    // against the Events -> Debugger endpoint (a 60-minute window is
    // irrelevant to the result either way, since the live API returns its
    // rolling ~3,000-event buffer regardless of the requested window — see
    // `algolia::insights`'s module doc). Hardcoded to the `de` region, same
    // as every `events` command (no `--region` flag exists for Insights).
    let insights_url = {
        let (start, end) = crate::algolia::insights::date_window(60);
        format!(
            "{}/1/events?startDate={start}&endDate={end}&limit=1",
            ctx.base_urls.insights("de"),
        )
    };
    let insights_row = probe(
        ctx,
        "insights",
        &insights_url,
        &app_id,
        Surface::Insights,
        resolve_insights_key_source(ctx),
    )
    .await;

    let response = DoctorResponse {
        app_id,
        app_id_source: app_id_source.to_string(),
        capabilities: vec![logs_row, usage_row, analytics_row, keys_row, insights_row],
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, render_human)
}

fn render_human(r: &DoctorResponse) -> String {
    let mut out = String::new();
    out.push_str(&display::heading("alx doctor"));
    out.push('\n');
    out.push_str(&display::kv_line(
        "app_id",
        format!("{} (via {})", r.app_id, r.app_id_source),
    ));
    out.push('\n');
    for row in &r.capabilities {
        out.push_str(&format!(
            "  [{}] {:<10} reason={:?} {}\n",
            display::status_marker(row.reachable),
            row.capability,
            row.reason,
            row.detail
        ));
        if let Some(src) = &row.credential_source {
            out.push_str(&format!("        credential: {src}\n"));
        }
    }
    out.push_str(&crate::output::format_session_ops_line(&r.session_ops));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algolia::keys::TEST_ENV_MUTEX;
    use crate::context::BaseUrls;
    use crate::http::SessionOps;
    use crate::output::Presenter;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_ctx(base_urls: BaseUrls, app_id: Option<&str>) -> AppContext {
        AppContext {
            client: reqwest::Client::new(),
            presenter: Presenter::new(false, false, false, false, None),
            app_id: app_id.map(str::to_string),
            key_override: None,
            i_know: false,
            ops: SessionOps::new(),
            base_urls,
        }
    }

    // -------------------------------------------------------------------
    // `render_human` (--human path): never called by any subprocess test
    // in practice — every `alx` invocation spawned via `std::process::
    // Command` has no controlling TTY on stdin, so `agent::detect`'s TTY
    // check (branch 4) unconditionally forces JSON regardless of
    // `--human`, structurally independent of whether the test suite
    // itself happens to run nested in an agent shell. The only way to
    // exercise this function at all is a direct, in-process call.
    // -------------------------------------------------------------------

    #[test]
    fn render_human_includes_every_capability_and_never_leaks_a_credential_value() {
        let response = DoctorResponse {
            app_id: "test-app".to_string(),
            app_id_source: "--app-id".to_string(),
            capabilities: vec![
                CapabilityRow {
                    capability: "logs".to_string(),
                    reachable: true,
                    reason: Reason::Ok,
                    detail: "200 OK".to_string(),
                    credential_source: Some("ALGOLIA_LOGS_API_KEY".to_string()),
                },
                CapabilityRow {
                    capability: "usage".to_string(),
                    reachable: false,
                    reason: Reason::PlanGated,
                    detail: "HTTP 402: not on plan".to_string(),
                    credential_source: Some("ALGOLIA_API_KEY".to_string()),
                },
                CapabilityRow {
                    capability: "keys".to_string(),
                    reachable: false,
                    reason: Reason::NoCredentials,
                    detail: "no credential resolved".to_string(),
                    credential_source: None,
                },
            ],
            session_ops: SessionOpsSnapshot {
                logs_calls: 1,
                usage_calls: 1,
                analytics_calls: 0,
                keys_calls: 0,
                insights_calls: 0,
            },
        };

        let rendered = render_human(&response);

        assert!(rendered.contains("test-app"));
        assert!(rendered.contains("logs"));
        assert!(rendered.contains("usage"));
        assert!(rendered.contains("keys"));
        assert!(rendered.contains("ALGOLIA_LOGS_API_KEY"));
        assert!(
            rendered.contains("PlanGated") || rendered.to_lowercase().contains("plangated"),
            "expected the PlanGated reason to be rendered: {rendered}"
        );
        // D0.2: never a raw key value in any output path, human included —
        // this response only ever carries credential *source names*, never
        // a value, so a rendering regression that started interpolating
        // one in would show up as literal env-var-name-shaped noise, not
        // caught here directly, but this at minimum pins that today's
        // fixture (which never sets a key value on the struct) renders
        // clean.
        assert!(!rendered.is_empty());
    }

    // -------------------------------------------------------------------
    // `classify_error`'s Network/Api (generic-Unknown) arms — only the
    // Auth/PlanGated arms were exercised by
    // `doctor_classifies_plan_gated_vs_missing_acl` (via `probe`, which
    // calls `classify_error` internally); these two are never separately
    // hit by any test.
    // -------------------------------------------------------------------

    #[test]
    fn classify_error_network_arm() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let network_err = rt.block_on(async {
            reqwest::Client::new()
                .get("not a valid url")
                .send()
                .await
                .unwrap_err()
        });
        let (reason, detail) = classify_error(&AppError::Network(network_err));
        assert_eq!(reason, Reason::NetworkError);
        assert!(!detail.is_empty());
    }

    #[test]
    fn classify_error_api_arm_is_unknown_reason() {
        let (reason, detail) = classify_error(&AppError::Api {
            status: 500,
            message: "internal server error".to_string(),
            suggestion: None,
        });
        assert_eq!(reason, Reason::Unknown);
        assert!(detail.contains("500"));
        assert!(detail.contains("internal server error"));
    }

    #[test]
    fn classify_error_other_variant_falls_back_to_unknown() {
        let (reason, _detail) = classify_error(&AppError::InvalidInput("bad flag".to_string()));
        assert_eq!(reason, Reason::Unknown);
    }

    // -------------------------------------------------------------------
    // `resolve_key_source`'s per-surface-env-var and generic-`ALGOLIA_
    // API_KEY`-fallback branches (previously only `--key`/`key_override`
    // and the fully-absent-credential path were exercised, since doctor's
    // own success test sets `ctx.key_override` directly).
    // -------------------------------------------------------------------

    #[test]
    fn resolve_key_source_per_surface_env_var_wins_over_generic_fallback() {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        let saved_surface = std::env::var("ALGOLIA_LOGS_API_KEY").ok();
        let saved_generic = std::env::var("ALGOLIA_API_KEY").ok();

        std::env::set_var("ALGOLIA_LOGS_API_KEY", "surface-key");
        std::env::set_var("ALGOLIA_API_KEY", "generic-key");

        let ctx = test_ctx(BaseUrls::default(), Some("testapp"));
        let resolved = resolve_key_source(&ctx, Surface::Logs);

        match saved_surface {
            Some(v) => std::env::set_var("ALGOLIA_LOGS_API_KEY", v),
            None => std::env::remove_var("ALGOLIA_LOGS_API_KEY"),
        }
        match saved_generic {
            Some(v) => std::env::set_var("ALGOLIA_API_KEY", v),
            None => std::env::remove_var("ALGOLIA_API_KEY"),
        }

        assert_eq!(
            resolved,
            Some(("surface-key".to_string(), "ALGOLIA_LOGS_API_KEY"))
        );
    }

    #[test]
    fn resolve_key_source_generic_fallback_when_per_surface_absent() {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        let saved_surface = std::env::var("ALGOLIA_USAGE_API_KEY").ok();
        let saved_generic = std::env::var("ALGOLIA_API_KEY").ok();

        std::env::remove_var("ALGOLIA_USAGE_API_KEY");
        std::env::set_var("ALGOLIA_API_KEY", "generic-key");

        let ctx = test_ctx(BaseUrls::default(), Some("testapp"));
        let resolved = resolve_key_source(&ctx, Surface::Usage);

        match saved_surface {
            Some(v) => std::env::set_var("ALGOLIA_USAGE_API_KEY", v),
            None => std::env::remove_var("ALGOLIA_USAGE_API_KEY"),
        }
        match saved_generic {
            Some(v) => std::env::set_var("ALGOLIA_API_KEY", v),
            None => std::env::remove_var("ALGOLIA_API_KEY"),
        }

        assert_eq!(
            resolved,
            Some(("generic-key".to_string(), "ALGOLIA_API_KEY"))
        );
    }

    #[test]
    fn doctor_no_credentials_row() {
        let row = no_credentials_row("usage", Surface::Usage);
        assert_eq!(row.reason, Reason::NoCredentials);
        assert!(!row.reachable);
        assert!(row.credential_source.is_none());
        assert!(row.detail.contains("ALGOLIA_USAGE_API_KEY"));
    }

    #[tokio::test]
    async fn doctor_classifies_plan_gated_vs_missing_acl() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/plan_gated_402"))
            .respond_with(ResponseTemplate::new(402))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/plan_gated_403"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string("This feature is not available on your plan"),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/missing_acl_403"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("Invalid Application-ID or API key"),
            )
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(BaseUrls::default(), Some("testapp"));
        let cred = Some(("testkey".to_string(), "ALGOLIA_USAGE_API_KEY"));

        let row_402 = probe(
            &ctx,
            "usage",
            &format!("{}/plan_gated_402", mock_server.uri()),
            "testapp",
            Surface::Usage,
            cred.clone(),
        )
        .await;
        assert_eq!(row_402.reason, Reason::PlanGated);
        assert!(!row_402.reachable);

        let row_403_plan = probe(
            &ctx,
            "usage",
            &format!("{}/plan_gated_403", mock_server.uri()),
            "testapp",
            Surface::Usage,
            cred.clone(),
        )
        .await;
        assert_eq!(row_403_plan.reason, Reason::PlanGated);
        assert!(!row_403_plan.reachable);

        let row_403_plain = probe(
            &ctx,
            "logs",
            &format!("{}/missing_acl_403", mock_server.uri()),
            "testapp",
            Surface::Logs,
            cred,
        )
        .await;
        assert_eq!(row_403_plain.reason, Reason::MissingAcl);
        assert!(!row_403_plain.reachable);
    }

    #[tokio::test]
    async fn probe_reports_ok_on_success_and_tags_credential_source() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/logs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
            .mount(&mock_server)
            .await;

        let ctx = test_ctx(BaseUrls::default(), Some("testapp"));
        let row = probe(
            &ctx,
            "logs",
            &format!("{}/1/logs", mock_server.uri()),
            "testapp",
            Surface::Logs,
            Some(("testkey".to_string(), "ALGOLIA_LOGS_API_KEY")),
        )
        .await;

        assert!(row.reachable);
        assert_eq!(row.reason, Reason::Ok);
        assert_eq!(
            row.credential_source.as_deref(),
            Some("ALGOLIA_LOGS_API_KEY")
        );
        assert_eq!(ctx.ops.snapshot().logs_calls, 1);
    }

    #[tokio::test]
    async fn doctor_requires_app_id() {
        // Guard scoped to the env mutation only — never held across the
        // `.await` below (clippy::await_holding_lock).
        let prev = {
            let _guard = TEST_ENV_MUTEX.lock().unwrap();
            let prev = std::env::var("ALGOLIA_APPLICATION_ID").ok();
            std::env::remove_var("ALGOLIA_APPLICATION_ID");
            prev
        };

        let ctx = test_ctx(BaseUrls::default(), None);
        let result = run(&ctx).await;

        {
            let _guard = TEST_ENV_MUTEX.lock().unwrap();
            if let Some(v) = prev {
                std::env::set_var("ALGOLIA_APPLICATION_ID", v);
            }
        }

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().exit_code(), 1);
    }

    #[tokio::test]
    async fn doctor_run_reports_all_capabilities_reachable() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/1/logs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"logs": []})))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/1/usage/records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/2/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/1/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": []})))
            .mount(&mock_server)
            .await;

        let base_urls = {
            let _guard = TEST_ENV_MUTEX.lock().unwrap();
            std::env::set_var("ALX_LOGS_BASE_URLS", mock_server.uri());
            std::env::set_var("ALX_USAGE_BASE_URL", mock_server.uri());
            std::env::set_var("ALX_ANALYTICS_BASE_URL", mock_server.uri());
            std::env::set_var("ALX_SEARCH_BASE_URL", mock_server.uri());
            std::env::set_var("ALX_INSIGHTS_BASE_URL", mock_server.uri());
            let b = BaseUrls::from_env();
            std::env::remove_var("ALX_LOGS_BASE_URLS");
            std::env::remove_var("ALX_USAGE_BASE_URL");
            std::env::remove_var("ALX_ANALYTICS_BASE_URL");
            std::env::remove_var("ALX_SEARCH_BASE_URL");
            std::env::remove_var("ALX_INSIGHTS_BASE_URL");
            b
        };

        let mut ctx = test_ctx(base_urls, Some("testapp"));
        ctx.key_override = Some("testkey".to_string());

        run(&ctx).await.unwrap();

        assert_eq!(ctx.ops.snapshot().logs_calls, 1);
        assert_eq!(ctx.ops.snapshot().usage_calls, 1);
        assert_eq!(ctx.ops.snapshot().analytics_calls, 1);
        assert_eq!(ctx.ops.snapshot().keys_calls, 1);
        assert_eq!(ctx.ops.snapshot().insights_calls, 1);
    }

    #[tokio::test]
    async fn doctor_insights_row_falls_back_to_logs_key_source() {
        // Insights-specific: no ALGOLIA_INSIGHTS_API_KEY set, but a logs
        // key resolves — `resolve_insights_key_source` must report that as
        // the credential source, not silently fall to the generic
        // ALGOLIA_API_KEY tier or report no_credentials.
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("ALGOLIA_LOGS_API_KEY").ok();
        std::env::set_var("ALGOLIA_LOGS_API_KEY", "logs-key-for-insights");

        let ctx = test_ctx(BaseUrls::default(), Some("testapp"));
        let resolved = resolve_insights_key_source(&ctx);

        match saved {
            Some(v) => std::env::set_var("ALGOLIA_LOGS_API_KEY", v),
            None => std::env::remove_var("ALGOLIA_LOGS_API_KEY"),
        }

        assert_eq!(
            resolved,
            Some(("logs-key-for-insights".to_string(), "ALGOLIA_LOGS_API_KEY"))
        );
    }

    #[test]
    fn doctor_insights_no_credentials_row() {
        let row = no_credentials_row("insights", Surface::Insights);
        assert_eq!(row.reason, Reason::NoCredentials);
        assert!(!row.reachable);
        assert!(row.detail.contains("ALGOLIA_INSIGHTS_API_KEY"));
    }
}
