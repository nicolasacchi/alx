//! Typed Algolia API layer — one module per capability surface. Each module
//! owns its own request/response shapes; the shared HTTP primitives
//! (`http::get_json`, credential/base-url resolution via `AppContext`) are
//! reused from `crate::http`/`crate::context`. Command builders fill these
//! in; `commands/*.rs` is the dispatch boundary that calls into them.

pub mod analytics;
pub mod insights;
pub mod keys;
pub mod logs;
pub(crate) mod serde_util;
pub mod usage;
