use thiserror::Error;

/// Application error type. Every variant that can plausibly be self-corrected
/// carries an optional `suggestion` surfaced identically in both output modes
/// (JSON gets a `"suggestion"` key, human gets a dimmed `hint:` line).
#[derive(Error, Debug)]
pub enum AppError {
    /// ADV-1/ADV-4 caution for future call sites: `reqwest::Error`'s
    /// `Display`/`Debug` unconditionally embeds the full request URL on a
    /// transport-layer failure. The one place in this codebase where that
    /// URL could embed a raw key value (`/1/keys/{key}` self-read, in
    /// `algolia::keys::get_key`/`get_self`) intercepts the error *before*
    /// it becomes this variant and substitutes a key-free `Other` message
    /// instead (see `algolia::keys::redact_self_read_network_error`) — any
    /// new call site that builds a URL containing a key value must do the
    /// same rather than let it reach `Network` (or anywhere `{e}`/`{e:?}`
    /// gets formatted) unredacted.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("authentication failed (HTTP {status}): {message}")]
    Auth {
        status: u16,
        message: String,
        suggestion: Option<String>,
    },

    #[error("plan does not include this capability ({capability}): {message}")]
    PlanGated { capability: String, message: String },

    #[error(
        "refusing to proceed: the configured key carries write-capable ACL(s) {acls:?} — pass --i-know to override"
    )]
    SafetyRefusal { acls: Vec<String> },

    #[error("algolia API error (HTTP {status}): {message}")]
    Api {
        status: u16,
        message: String,
        suggestion: Option<String>,
    },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("jq failed: {0}")]
    JqFailed(String),

    #[error("{0}")]
    Other(String),
}

impl AppError {
    pub fn suggestion(&self) -> Option<&str> {
        match self {
            AppError::Auth { suggestion, .. } => suggestion.as_deref(),
            AppError::Api { suggestion, .. } => suggestion.as_deref(),
            AppError::PlanGated { .. } => {
                Some("this Algolia plan tier does not include this capability; upgrade or use a different key")
            }
            AppError::SafetyRefusal { .. } => {
                Some("re-run with --i-know once you've confirmed this key's privileges are expected")
            }
            AppError::JqFailed(_) => Some("install jq or drop --jq"),
            _ => None,
        }
    }

    /// Exit code mapping (D5). `main()` is the single place this is consumed.
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::Network(_) => 3,
            AppError::Auth { .. } => 4,
            AppError::PlanGated { .. } => 5,
            AppError::SafetyRefusal { .. } => 6,
            _ => 1,
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_d5() {
        assert_eq!(AppError::Network(make_reqwest_error()).exit_code(), 3);
        assert_eq!(
            AppError::Auth {
                status: 401,
                message: "bad key".into(),
                suggestion: None
            }
            .exit_code(),
            4
        );
        assert_eq!(
            AppError::PlanGated {
                capability: "usage".into(),
                message: "not on plan".into()
            }
            .exit_code(),
            5
        );
        assert_eq!(
            AppError::SafetyRefusal {
                acls: vec!["deleteIndex".into()]
            }
            .exit_code(),
            6
        );
        assert_eq!(AppError::Other("x".into()).exit_code(), 1);
        assert_eq!(AppError::InvalidInput("x".into()).exit_code(), 1);
        assert_eq!(AppError::JqFailed("x".into()).exit_code(), 1);
    }

    #[test]
    fn suggestions_present_where_expected() {
        let e = AppError::JqFailed("no jq on PATH".into());
        assert_eq!(e.suggestion(), Some("install jq or drop --jq"));

        let e = AppError::SafetyRefusal {
            acls: vec!["editSettings".into()],
        };
        assert!(e.suggestion().unwrap().contains("--i-know"));
    }

    // reqwest::Error has no public constructor. A malformed URL fails at
    // `.send()` as a "builder" error without ever touching the network, so
    // this stays fast, deterministic, and offline-safe.
    fn make_reqwest_error() -> reqwest::Error {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            reqwest::Client::new()
                .get("not a valid url")
                .send()
                .await
                .unwrap_err()
        })
    }
}
