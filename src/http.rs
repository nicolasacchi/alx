//! Centralized HTTP layer. THE ONLY HTTP METHOD EXPOSED IS GET (D11) — there
//! is no generic request builder taking a method, and no `.post(`/`.put(`/
//! `.delete(`/`Method::POST` anywhere in this file or its callers outside
//! tests.

use crate::error::{AppError, AppResult};
use crate::output::SessionOpsSnapshot;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const USER_AGENT: &str = concat!("alx/", env!("CARGO_PKG_VERSION"));

pub fn build_client(timeout_secs: u64) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
}

/// Which capability surface a request belongs to, for quota-honesty
/// counting (D0.4 / D4) and credential resolution (D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Logs,
    Usage,
    Analytics,
    Keys,
    Insights,
}

impl Surface {
    pub fn as_str(&self) -> &'static str {
        match self {
            Surface::Logs => "logs",
            Surface::Usage => "usage",
            Surface::Analytics => "analytics",
            Surface::Keys => "keys",
            Surface::Insights => "insights",
        }
    }
}

/// Per-session call counters, one per surface, incremented by `get_json`
/// after every completed (non-network-error) request. Quota honesty (D0.4):
/// every `logs`/`usage`/`analytics`/`keys` call consumes operations quota
/// and does not itself appear in the logs — the session must self-report.
#[derive(Debug, Default)]
pub struct SessionOps {
    logs: AtomicU32,
    usage: AtomicU32,
    analytics: AtomicU32,
    keys: AtomicU32,
    insights: AtomicU32,
}

impl SessionOps {
    pub fn new() -> Self {
        Self::default()
    }

    fn counter(&self, surface: Surface) -> &AtomicU32 {
        match surface {
            Surface::Logs => &self.logs,
            Surface::Usage => &self.usage,
            Surface::Analytics => &self.analytics,
            Surface::Keys => &self.keys,
            Surface::Insights => &self.insights,
        }
    }

    pub fn increment(&self, surface: Surface) {
        self.counter(surface).fetch_add(1, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> SessionOpsSnapshot {
        SessionOpsSnapshot {
            logs_calls: self.logs.load(Ordering::SeqCst),
            usage_calls: self.usage.load(Ordering::SeqCst),
            analytics_calls: self.analytics.load(Ordering::SeqCst),
            keys_calls: self.keys.load(Ordering::SeqCst),
            insights_calls: self.insights.load(Ordering::SeqCst),
        }
    }
}

/// Distinguishes a 401/402/403 caused by a missing ACL from one caused by
/// the plan tier not including the capability at all (D8). Fingerprint
/// (D8/D0.2): status 402, or a 403 whose body mentions plan/feature/"not
/// available" wording, classifies as plan-gated. Everything else 401/403 is
/// treated as a missing-ACL / bad-credential auth failure. Never a raw
/// error dump either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forbidden {
    MissingAcl,
    PlanGated,
}

pub fn classify_forbidden(status: u16, body: &str) -> Forbidden {
    if status == 402 {
        return Forbidden::PlanGated;
    }
    let lower = body.to_lowercase();
    if status == 403
        && (lower.contains("plan") || lower.contains("feature") || lower.contains("not available"))
    {
        return Forbidden::PlanGated;
    }
    Forbidden::MissingAcl
}

const MAX_RETRIES: u32 = 3;
const BACKOFF_BASE_MS: u64 = 1000;

/// Fire a GET request against `url` with the canonical Algolia auth headers
/// (D0.1, mixed-case), retry 429 with exponential backoff (1s/2s/4s, max 3
/// attempts), classify 401/402/403 into `AppError::Auth` vs
/// `AppError::PlanGated` via `classify_forbidden`, and increment the
/// per-surface session counter on every completed request.
pub async fn get_json(
    client: &reqwest::Client,
    url: &str,
    app_id: &str,
    api_key: &str,
    surface: Surface,
    ops: &SessionOps,
) -> AppResult<serde_json::Value> {
    let mut attempt: u32 = 0;

    loop {
        let resp = client
            .get(url)
            .header("X-Algolia-Application-Id", app_id)
            .header("X-Algolia-API-Key", api_key)
            .send()
            .await?;

        let status = resp.status();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < MAX_RETRIES {
            attempt += 1;
            let backoff_ms = BACKOFF_BASE_MS * 2u64.pow(attempt - 1);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            continue;
        }

        ops.increment(surface);

        if status.is_success() {
            let value = resp.json::<serde_json::Value>().await?;
            return Ok(value);
        }

        let status_u16 = status.as_u16();
        let body = resp.text().await.unwrap_or_default();

        if status_u16 == 401 || status_u16 == 402 || status_u16 == 403 {
            return match classify_forbidden(status_u16, &body) {
                Forbidden::PlanGated => Err(AppError::PlanGated {
                    capability: surface.as_str().to_string(),
                    message: body,
                }),
                Forbidden::MissingAcl => Err(AppError::Auth {
                    status: status_u16,
                    message: body,
                    suggestion: Some(format!(
                        "confirm the key used for `{}` carries the required ACL",
                        surface.as_str()
                    )),
                }),
            };
        }

        return Err(AppError::Api {
            status: status_u16,
            message: body,
            suggestion: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// D12 gap: the 429-retry branch itself is exercised end-to-end by
    /// `tests/httpx_contract.rs` (retry count, final exit code), but
    /// nothing previously asserted on `session_ops`'s specific increment
    /// semantics under retry — does it increment once per HTTP *attempt*
    /// (would read 3 after 2 retried 429s + 1 success) or once per
    /// *completed* request (would read 1)? `get_json`'s `ops.increment
    /// (surface)` call sits AFTER the 429-retry `continue`, so only the
    /// terminal, non-retried response increments it — this pins that
    /// directly against the real function, in-process.
    #[tokio::test]
    async fn retry_429_then_success_increments_session_ops_exactly_once() {
        let server = MockServer::start().await;
        // First 2 matching requests get a 429 (triggering the retry loop's
        // backoff+continue); the 3rd falls through to this unlimited 200
        // mock once the capped mock above goes out of scope.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let client = build_client(5).expect("client build");
        let ops = SessionOps::new();
        let url = format!("{}/1/test", server.uri());

        let result = get_json(&client, &url, "app", "key", Surface::Usage, &ops).await;

        assert!(result.is_ok(), "expected eventual success: {result:?}");
        assert_eq!(
            ops.snapshot().usage_calls,
            1,
            "session_ops must increment once per COMPLETED request, not once per attempt \
             (2 retried 429s + 1 success = 3 attempts, exactly 1 completion)"
        );

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            3,
            "expected exactly 2 retried 429 attempts + 1 successful final request: {requests:?}"
        );
    }

    #[test]
    fn classify_forbidden_402_is_always_plan_gated() {
        assert_eq!(classify_forbidden(402, ""), Forbidden::PlanGated);
        assert_eq!(classify_forbidden(402, "anything"), Forbidden::PlanGated);
    }

    #[test]
    fn classify_forbidden_403_with_plan_wording_is_plan_gated() {
        assert_eq!(
            classify_forbidden(403, "This feature is not available on your plan"),
            Forbidden::PlanGated
        );
        assert_eq!(
            classify_forbidden(403, "Upgrade your plan to use Usage API"),
            Forbidden::PlanGated
        );
        assert_eq!(
            classify_forbidden(403, "Feature not enabled for this application"),
            Forbidden::PlanGated
        );
    }

    #[test]
    fn classify_forbidden_403_without_plan_wording_is_missing_acl() {
        assert_eq!(
            classify_forbidden(403, "Invalid Application-ID or API key"),
            Forbidden::MissingAcl
        );
        assert_eq!(
            classify_forbidden(401, "Invalid API key"),
            Forbidden::MissingAcl
        );
    }

    #[test]
    fn session_ops_snapshot_starts_at_zero() {
        let ops = SessionOps::new();
        let snap = ops.snapshot();
        assert_eq!(snap.logs_calls, 0);
        assert_eq!(snap.usage_calls, 0);
        assert_eq!(snap.analytics_calls, 0);
        assert_eq!(snap.keys_calls, 0);
        assert_eq!(snap.insights_calls, 0);
    }

    #[test]
    fn session_ops_increments_correct_counter() {
        let ops = SessionOps::new();
        ops.increment(Surface::Logs);
        ops.increment(Surface::Logs);
        ops.increment(Surface::Usage);
        ops.increment(Surface::Analytics);
        ops.increment(Surface::Keys);
        ops.increment(Surface::Insights);
        let snap = ops.snapshot();
        assert_eq!(snap.logs_calls, 2);
        assert_eq!(snap.usage_calls, 1);
        assert_eq!(snap.analytics_calls, 1);
        assert_eq!(snap.keys_calls, 1);
        assert_eq!(snap.insights_calls, 1);
    }

    #[test]
    fn user_agent_embeds_crate_version() {
        assert!(USER_AGENT.starts_with("alx/"));
        assert_eq!(USER_AGENT, format!("alx/{}", env!("CARGO_PKG_VERSION")));
    }
}
