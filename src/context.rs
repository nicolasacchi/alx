//! `AppContext` is the one shared-state struct, built once in `main()` and
//! passed by `&` into every command's `run()`. Commands never construct
//! their own HTTP client, re-derive output mode, or read env vars for
//! credentials directly — everything flows from `ctx`.

use crate::agent;
use crate::cli::Cli;
use crate::http::{self, SessionOps, Surface};
use crate::output::Presenter;

pub struct AppContext {
    pub client: reqwest::Client,
    pub presenter: Presenter,
    pub app_id: Option<String>,
    pub key_override: Option<String>,
    pub i_know: bool,
    pub ops: SessionOps,
    pub base_urls: BaseUrls,
}

impl AppContext {
    pub fn new(cli: &Cli) -> Self {
        let agent_info = agent::detect(cli.agent, cli.json);
        let client = http::build_client(cli.timeout).expect("failed to build HTTP client");
        let presenter = Presenter::new(
            cli.human,
            cli.json,
            agent_info.is_agent,
            cli.verbose,
            cli.jq.clone(),
        );

        AppContext {
            client,
            presenter,
            app_id: cli.app_id.clone(),
            key_override: cli.key.clone(),
            i_know: cli.i_know,
            ops: SessionOps::new(),
            base_urls: BaseUrls::from_env(),
        }
    }

    /// Resolves `ALGOLIA_APPLICATION_ID`, or `--app-id` (which wins). `None`
    /// if neither is set — callers decide whether that's fatal (`doctor`
    /// tolerates it; every other command should error with a clear message).
    pub fn resolve_app_id(&self) -> Option<String> {
        self.app_id
            .clone()
            .filter(|v| !v.is_empty())
            .or_else(|| std::env::var("ALGOLIA_APPLICATION_ID").ok())
            .filter(|v| !v.is_empty())
    }

    /// Credentials resolver (D3, exact order): `--key` wins over
    /// everything, then the per-surface env var, then the generic
    /// `ALGOLIA_API_KEY` fallback. NEVER reads `ALGOLIA_WRITE_API_KEY` or
    /// `ALGOLIA_SEARCH_API_KEY` implicitly.
    pub fn resolve_key(&self, surface: Surface) -> Option<String> {
        if let Some(k) = self.key_override.clone().filter(|v| !v.is_empty()) {
            return Some(k);
        }

        let surface_var = match surface {
            Surface::Logs => "ALGOLIA_LOGS_API_KEY",
            Surface::Usage => "ALGOLIA_USAGE_API_KEY",
            Surface::Analytics => "ALGOLIA_ANALYTICS_API_KEY",
            Surface::Keys => "ALGOLIA_KEYS_API_KEY",
            Surface::Insights => "ALGOLIA_INSIGHTS_API_KEY",
        };
        if let Ok(v) = std::env::var(surface_var) {
            if !v.is_empty() {
                return Some(v);
            }
        }

        // Insights-specific extra fallback: measured 2026-08-04, the
        // **logs** ACL is empirically what the Insights API accepts
        // (ALGOLIA_LOGS_API_KEY -> 200, ALGOLIA_ANALYTICS_API_KEY/
        // ALGOLIA_USAGE_API_KEY -> 401) — deliberate, so no new key needs
        // minting if a logs key is already configured. Order: --key >
        // ALGOLIA_INSIGHTS_API_KEY > ALGOLIA_LOGS_API_KEY > ALGOLIA_API_KEY.
        if surface == Surface::Insights {
            if let Ok(v) = std::env::var("ALGOLIA_LOGS_API_KEY") {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }

        std::env::var("ALGOLIA_API_KEY")
            .ok()
            .filter(|v| !v.is_empty())
    }
}

/// Per-surface base URLs, with hidden env overrides so wiremock-based tests
/// can point at a local mock server instead of the real Algolia hosts.
#[derive(Debug, Clone, Default)]
pub struct BaseUrls {
    logs_override: Option<Vec<String>>,
    search_override: Option<String>,
    usage_override: Option<String>,
    analytics_override: Option<String>,
    insights_override: Option<String>,
}

impl BaseUrls {
    pub fn from_env() -> Self {
        BaseUrls {
            // ADV-2 fix: an empty/whitespace-only `ALX_LOGS_BASE_URLS`
            // (e.g. an accidentally-exported empty env var) must fall
            // through to the 3-host default, exactly like the var being
            // unset — `Some(vec![])` must never be observable here, since
            // `logs()`'s `unwrap_or_else` only substitutes the default for
            // `None`, and `doctor::run` indexes `logs(&app_id)[0]`
            // unconditionally.
            logs_override: std::env::var("ALX_LOGS_BASE_URLS").ok().and_then(|v| {
                let hosts: Vec<String> = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if hosts.is_empty() {
                    None
                } else {
                    Some(hosts)
                }
            }),
            search_override: std::env::var("ALX_SEARCH_BASE_URL").ok(),
            usage_override: std::env::var("ALX_USAGE_BASE_URL").ok(),
            analytics_override: std::env::var("ALX_ANALYTICS_BASE_URL").ok(),
            insights_override: std::env::var("ALX_INSIGHTS_BASE_URL").ok(),
        }
    }

    /// The three per-server write hosts logs sampling fans out against
    /// concurrently (D7). Default: `https://{app}-1.algolianet.com`,
    /// `-2`, `-3`.
    pub fn logs(&self, app_id: &str) -> Vec<String> {
        self.logs_override.clone().unwrap_or_else(|| {
            (1..=3)
                .map(|n| format!("https://{app_id}-{n}.algolianet.com"))
                .collect()
        })
    }

    /// Default: `https://{app}.algolia.net`.
    pub fn search(&self, app_id: &str) -> String {
        self.search_override
            .clone()
            .unwrap_or_else(|| format!("https://{app_id}.algolia.net"))
    }

    /// Default: `https://usage.algolia.com`.
    pub fn usage(&self) -> String {
        self.usage_override
            .clone()
            .unwrap_or_else(|| "https://usage.algolia.com".to_string())
    }

    /// Default: `https://analytics.{region}.algolia.com`.
    pub fn analytics(&self, region: &str) -> String {
        self.analytics_override
            .clone()
            .unwrap_or_else(|| format!("https://analytics.{region}.algolia.com"))
    }

    /// Default: `https://insights.{region}.algolia.io` — NOTE the `.io`
    /// TLD (every other surface here is `.com`/`.net`). Verified live
    /// 2026-08-04: `insights.de.algolia.io` -> 200, `insights.us.algolia.io`
    /// -> 401 (an AUTH failure, not the empty-region 200 the analytics API's
    /// `us` region returns — a different failure class; see
    /// `algolia::insights`).
    pub fn insights(&self, region: &str) -> String {
        self.insights_override
            .clone()
            .unwrap_or_else(|| format!("https://insights.{region}.algolia.io"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algolia::keys::TEST_ENV_MUTEX;
    use crate::http::SessionOps;
    use crate::output::Presenter;

    fn test_ctx(app_id: Option<&str>, key_override: Option<&str>) -> AppContext {
        AppContext {
            client: reqwest::Client::new(),
            presenter: Presenter::new(false, false, false, false, None),
            app_id: app_id.map(str::to_string),
            key_override: key_override.map(str::to_string),
            i_know: false,
            ops: SessionOps::new(),
            base_urls: BaseUrls::default(),
        }
    }

    /// All env vars any `resolve_*` test below might touch, saved/restored
    /// as a group so tests never leak state into siblings running in
    /// parallel on other threads within the same process (env vars are
    /// process-global) — held under `TEST_ENV_MUTEX` for the entire
    /// set-up/exercise/tear-down window.
    const CRED_ENV_VARS: [&str; 7] = [
        "ALGOLIA_APPLICATION_ID",
        "ALGOLIA_API_KEY",
        "ALGOLIA_LOGS_API_KEY",
        "ALGOLIA_USAGE_API_KEY",
        "ALGOLIA_ANALYTICS_API_KEY",
        "ALGOLIA_KEYS_API_KEY",
        "ALGOLIA_INSIGHTS_API_KEY",
    ];

    /// Runs `body` with exactly the given `(var, value)` pairs set and every
    /// other `CRED_ENV_VARS` entry cleared, then restores every var to its
    /// pre-test value — never leaves modified global state behind even if
    /// `body` panics (via `catch_unwind` + resume).
    fn with_cred_env<R>(set: &[(&str, &str)], body: impl FnOnce() -> R) -> R {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        let saved: Vec<(&str, Option<String>)> = CRED_ENV_VARS
            .iter()
            .map(|v| (*v, std::env::var(v).ok()))
            .collect();

        for var in CRED_ENV_VARS {
            std::env::remove_var(var);
        }
        for (var, val) in set {
            std::env::set_var(var, val);
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));

        for (var, val) in saved {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }

        match result {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    // -------------------------------------------------------------------
    // D3 credential precedence, pinned directly against `resolve_app_id`/
    // `resolve_key` (previously only exercised piecemeal and indirectly
    // through scattered subprocess env-var setups elsewhere, none of which
    // asserted on precedence itself).
    // -------------------------------------------------------------------

    #[test]
    fn resolve_app_id_prefers_flag_over_env() {
        with_cred_env(&[("ALGOLIA_APPLICATION_ID", "env-app")], || {
            let ctx = test_ctx(Some("flag-app"), None);
            assert_eq!(ctx.resolve_app_id().as_deref(), Some("flag-app"));
        });
    }

    #[test]
    fn resolve_app_id_falls_back_to_env_when_flag_absent() {
        with_cred_env(&[("ALGOLIA_APPLICATION_ID", "env-app")], || {
            let ctx = test_ctx(None, None);
            assert_eq!(ctx.resolve_app_id().as_deref(), Some("env-app"));
        });
    }

    #[test]
    fn resolve_app_id_none_when_neither_set() {
        with_cred_env(&[], || {
            let ctx = test_ctx(None, None);
            assert_eq!(ctx.resolve_app_id(), None);
        });
    }

    #[test]
    fn resolve_app_id_empty_flag_falls_through_to_env() {
        with_cred_env(&[("ALGOLIA_APPLICATION_ID", "env-app")], || {
            let ctx = test_ctx(Some(""), None);
            assert_eq!(
                ctx.resolve_app_id().as_deref(),
                Some("env-app"),
                "an empty --app-id must not shadow a real env value"
            );
        });
    }

    #[test]
    fn resolve_key_flag_wins_over_every_env_var() {
        with_cred_env(
            &[
                ("ALGOLIA_LOGS_API_KEY", "surface-key"),
                ("ALGOLIA_API_KEY", "generic-key"),
            ],
            || {
                let ctx = test_ctx(None, Some("flag-key"));
                assert_eq!(ctx.resolve_key(Surface::Logs).as_deref(), Some("flag-key"));
            },
        );
    }

    #[test]
    fn resolve_key_per_surface_env_wins_over_generic_fallback() {
        with_cred_env(
            &[
                ("ALGOLIA_LOGS_API_KEY", "surface-key"),
                ("ALGOLIA_API_KEY", "generic-key"),
            ],
            || {
                let ctx = test_ctx(None, None);
                assert_eq!(
                    ctx.resolve_key(Surface::Logs).as_deref(),
                    Some("surface-key"),
                    "the per-surface var must win when both it and the generic fallback are set"
                );
            },
        );
    }

    #[test]
    fn resolve_key_generic_fallback_used_when_per_surface_absent() {
        with_cred_env(&[("ALGOLIA_API_KEY", "generic-key")], || {
            let ctx = test_ctx(None, None);
            assert_eq!(
                ctx.resolve_key(Surface::Logs).as_deref(),
                Some("generic-key")
            );
        });
    }

    #[test]
    fn resolve_key_none_when_nothing_set() {
        with_cred_env(&[], || {
            let ctx = test_ctx(None, None);
            assert_eq!(ctx.resolve_key(Surface::Logs), None);
        });
    }

    #[test]
    fn resolve_key_never_reads_write_or_search_key_env_vars() {
        // D3: "NEVER read ALGOLIA_WRITE_API_KEY or ALGOLIA_SEARCH_API_KEY
        // implicitly" — these aren't in CRED_ENV_VARS at all, so setting
        // them via a raw std::env call (outside the helper's managed set)
        // and asserting resolution still comes back None pins that they're
        // truly never consulted.
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        for var in CRED_ENV_VARS {
            std::env::remove_var(var);
        }
        std::env::set_var("ALGOLIA_WRITE_API_KEY", "should-never-be-read");
        std::env::set_var("ALGOLIA_SEARCH_API_KEY", "should-never-be-read-either");

        let ctx = test_ctx(None, None);
        let resolved = ctx.resolve_key(Surface::Logs);

        std::env::remove_var("ALGOLIA_WRITE_API_KEY");
        std::env::remove_var("ALGOLIA_SEARCH_API_KEY");

        assert_eq!(resolved, None);
    }

    #[test]
    fn resolve_key_each_surface_reads_its_own_per_surface_var_only() {
        with_cred_env(
            &[
                ("ALGOLIA_LOGS_API_KEY", "logs-key"),
                ("ALGOLIA_USAGE_API_KEY", "usage-key"),
                ("ALGOLIA_ANALYTICS_API_KEY", "analytics-key"),
                ("ALGOLIA_KEYS_API_KEY", "keys-key"),
                ("ALGOLIA_INSIGHTS_API_KEY", "insights-key"),
            ],
            || {
                let ctx = test_ctx(None, None);
                assert_eq!(ctx.resolve_key(Surface::Logs).as_deref(), Some("logs-key"));
                assert_eq!(
                    ctx.resolve_key(Surface::Usage).as_deref(),
                    Some("usage-key")
                );
                assert_eq!(
                    ctx.resolve_key(Surface::Analytics).as_deref(),
                    Some("analytics-key")
                );
                assert_eq!(ctx.resolve_key(Surface::Keys).as_deref(), Some("keys-key"));
                assert_eq!(
                    ctx.resolve_key(Surface::Insights).as_deref(),
                    Some("insights-key")
                );
            },
        );
    }

    // -------------------------------------------------------------------
    // Insights' extra fallback tier: --key > ALGOLIA_INSIGHTS_API_KEY >
    // ALGOLIA_LOGS_API_KEY > ALGOLIA_API_KEY. No other surface has a
    // second per-surface fallback like this — pinned separately from the
    // generic precedence tests above.
    // -------------------------------------------------------------------

    #[test]
    fn resolve_key_insights_prefers_its_own_var_over_logs_fallback() {
        with_cred_env(
            &[
                ("ALGOLIA_INSIGHTS_API_KEY", "insights-key"),
                ("ALGOLIA_LOGS_API_KEY", "logs-key"),
            ],
            || {
                let ctx = test_ctx(None, None);
                assert_eq!(
                    ctx.resolve_key(Surface::Insights).as_deref(),
                    Some("insights-key")
                );
            },
        );
    }

    #[test]
    fn resolve_key_insights_falls_back_to_logs_key_before_generic() {
        with_cred_env(
            &[
                ("ALGOLIA_LOGS_API_KEY", "logs-key"),
                ("ALGOLIA_API_KEY", "generic-key"),
            ],
            || {
                let ctx = test_ctx(None, None);
                assert_eq!(
                    ctx.resolve_key(Surface::Insights).as_deref(),
                    Some("logs-key"),
                    "insights must fall back to the logs key before the generic ALGOLIA_API_KEY"
                );
            },
        );
    }

    #[test]
    fn resolve_key_insights_falls_back_to_generic_when_no_insights_or_logs_key() {
        with_cred_env(&[("ALGOLIA_API_KEY", "generic-key")], || {
            let ctx = test_ctx(None, None);
            assert_eq!(
                ctx.resolve_key(Surface::Insights).as_deref(),
                Some("generic-key")
            );
        });
    }

    #[test]
    fn resolve_key_insights_none_when_nothing_set() {
        with_cred_env(&[], || {
            let ctx = test_ctx(None, None);
            assert_eq!(ctx.resolve_key(Surface::Insights), None);
        });
    }

    #[test]
    fn base_urls_default_logs_are_three_per_server_hosts() {
        let b = BaseUrls::default();
        let urls = b.logs("APPID123");
        assert_eq!(
            urls,
            vec![
                "https://APPID123-1.algolianet.com",
                "https://APPID123-2.algolianet.com",
                "https://APPID123-3.algolianet.com",
            ]
        );
    }

    #[test]
    fn base_urls_default_search_usage_analytics() {
        let b = BaseUrls::default();
        assert_eq!(b.search("APPID123"), "https://APPID123.algolia.net");
        assert_eq!(b.usage(), "https://usage.algolia.com");
        assert_eq!(b.analytics("de"), "https://analytics.de.algolia.com");
        assert_eq!(b.analytics("us"), "https://analytics.us.algolia.com");
    }

    #[test]
    fn base_urls_default_insights_uses_dot_io_tld() {
        let b = BaseUrls::default();
        assert_eq!(b.insights("de"), "https://insights.de.algolia.io");
        assert_eq!(b.insights("us"), "https://insights.us.algolia.io");
    }
}
