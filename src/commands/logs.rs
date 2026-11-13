//! `alx logs sample|offsite|errors` (D7). Highest-urgency command per the
//! build order — the 7-day retention window means every day without a
//! persisted sample loses evidence permanently.

use crate::algolia::logs::{self as logs_api, LogEntry};
use crate::asn::{self, AsnClass, AsnInfo};
use crate::cli::{LogsErrorsArgs, LogsOffsiteArgs, LogsSampleArgs, SinceArg};
use crate::constants::ORIGIN_ALLOW_PATTERN;
use crate::context::AppContext;
use crate::error::{AppError, AppResult};
use crate::http::Surface;
use crate::output::SessionOpsSnapshot;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as IoWrite;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------
// Response envelopes (D4: one Serialize struct per command, single source
// of truth for both JSON and human rendering).
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SampleResponse {
    pub since: String,
    pub window: WindowSummary,
    pub total_entries: usize,
    pub filtered_count: usize,
    pub own_egress_count: usize,
    pub hosts: Vec<HostWindowSummary>,
    pub persisted: Option<PersistSummary>,
    pub session_ops: SessionOpsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowSummary {
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    pub elapsed_minutes: Option<i64>,
    /// L4: framed explicitly as the required sampling interval, not just a
    /// stat — an operator reading this should walk away knowing how often
    /// to run `logs sample --persist` to never miss a window.
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostWindowSummary {
    pub host: String,
    pub fetched: usize,
    pub kept_in_window: usize,
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PersistSummary {
    pub dir: String,
    pub meta_file: String,
    pub host_files: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PersistMeta {
    generated_at: DateTime<Utc>,
    since: String,
    window_start: Option<DateTime<Utc>>,
    window_end: Option<DateTime<Utc>>,
    elapsed_minutes: Option<i64>,
    hosts: Vec<HostWindowSummary>,
    merged_total: usize,
    own_egress_count: usize,
}

#[derive(Debug, Serialize)]
pub struct OffsiteResponse {
    pub since: String,
    pub total_entries: usize,
    pub offsite: Vec<GroupedEntry>,
    pub own_egress: BucketSummary,
    pub keep_benign: BucketSummary,
    pub crawler: BucketSummary,
    pub private_relay_probable: BucketSummary,
    pub asn_unknown: BucketSummary,
    pub session_ops: SessionOpsSnapshot,
}

#[derive(Debug, Serialize)]
pub struct BucketSummary {
    pub count: usize,
    pub groups: Vec<GroupedEntry>,
}

#[derive(Debug, Serialize)]
pub struct GroupedEntry {
    pub ip: String,
    pub referer: Option<String>,
    pub count: usize,
    pub asn: Option<u32>,
    /// L7: whether `referer` matches the anchored `1000farmacie.(it|lol)`
    /// allow-list — a hint that this row, despite landing in a
    /// non-KEEP/non-crawler bucket, still carries a referer consistent
    /// with a real page load on our own site.
    pub referer_is_own_site: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorsResponse {
    pub since: String,
    pub total_checked: usize,
    pub error_count: usize,
    pub errors: Vec<ErrorEntry>,
    pub session_ops: SessionOpsSnapshot,
}

#[derive(Debug, Serialize)]
pub struct ErrorEntry {
    pub timestamp: DateTime<Utc>,
    pub answer_code: u16,
    pub ip: String,
    pub url: String,
    pub index: Option<String>,
    pub host: String,
    pub referer: Option<String>,
}

// ---------------------------------------------------------------------
// Shared fetch + credential resolution
// ---------------------------------------------------------------------

/// Resolves credentials, fetches across every logs host, and applies the
/// client-side `--since` filter (D7). Returns both the raw fetch result
/// (for `sample`'s unfiltered buffer-window reporting, L4) and the
/// filtered entries (what `sample --persist`/`offsite`/`errors` actually
/// operate on).
///
/// Runs `safety::preflight_privilege_check` (spec §0.3) before the first
/// real logs call — resolved as this builder's reported deviation (option
/// a): `safety::preflight_privilege_check` now takes an explicit
/// `base_url` parameter (`ctx.base_urls.search(app_id)`) instead of
/// hardcoding the host, so `ALX_SEARCH_BASE_URL` redirects the self-check
/// at a mock server in tests exactly like every other `BaseUrls`-backed
/// call.
async fn fetch_and_filter(
    ctx: &AppContext,
    since: &SinceArg,
) -> AppResult<(logs_api::FetchAllResult, Vec<LogEntry>)> {
    let app_id = ctx.resolve_app_id().ok_or_else(|| {
        AppError::InvalidInput(
            "missing Algolia Application ID: set ALGOLIA_APPLICATION_ID or pass --app-id"
                .to_string(),
        )
    })?;
    let key = ctx.resolve_key(Surface::Logs).ok_or_else(|| {
        AppError::InvalidInput(
            "missing logs API key: set ALGOLIA_LOGS_API_KEY (or ALGOLIA_API_KEY, or --key)"
                .to_string(),
        )
    })?;

    ctx.presenter.progress(&format!(
        "fetching logs for app {app_id} with key {}",
        crate::safety::mask_key(&key)
    ));

    crate::safety::preflight_privilege_check(
        &ctx.client,
        &ctx.base_urls.search(&app_id),
        &app_id,
        &key,
        ctx.i_know,
        &ctx.presenter,
    )
    .await?;

    let fetch_result = logs_api::fetch_logs_all_hosts(ctx, &app_id, &key).await?;

    let cutoff = Utc::now() - since.as_chrono_duration();
    let filtered: Vec<LogEntry> = fetch_result
        .entries
        .iter()
        .filter(|e| e.timestamp >= cutoff)
        .cloned()
        .collect();

    Ok((fetch_result, filtered))
}

fn elapsed_minutes(first: Option<DateTime<Utc>>, last: Option<DateTime<Utc>>) -> Option<i64> {
    match (first, last) {
        (Some(a), Some(b)) => Some((b - a).num_minutes()),
        _ => None,
    }
}

/// UA-only own-egress check (L3), reusing `asn::classify`'s marker match
/// with a default (unresolved) `AsnInfo` — classification checks the UA
/// marker before ever looking at ASN, so this is free of any DNS work.
fn is_own_egress(entry: &LogEntry) -> bool {
    let ua = entry.user_agent.as_deref().unwrap_or("");
    asn::classify(AsnInfo::default(), ua) == AsnClass::OwnEgress
}

// ---------------------------------------------------------------------
// logs sample
// ---------------------------------------------------------------------

pub async fn run_sample(ctx: &AppContext, args: &LogsSampleArgs) -> AppResult<()> {
    let (fetch_result, filtered) = fetch_and_filter(ctx, &args.since).await?;

    // Unfiltered (whole-buffer) window (L4) — this is the number that
    // answers "how often must I sample to never miss a window", which a
    // `--since`-narrowed view can't answer honestly.
    let merged_first = fetch_result.entries.iter().map(|e| e.timestamp).min();
    let merged_last = fetch_result.entries.iter().map(|e| e.timestamp).max();
    let elapsed = elapsed_minutes(merged_first, merged_last);

    let own_egress_count = filtered.iter().filter(|e| is_own_egress(e)).count();

    let hosts: Vec<HostWindowSummary> = fetch_result
        .hosts
        .iter()
        .map(|h| {
            let kept_in_window = filtered.iter().filter(|e| e.host == h.host).count();
            HostWindowSummary {
                host: h.host.clone(),
                fetched: h.fetched,
                kept_in_window,
                first: h.first_ts,
                last: h.last_ts,
                error: h.error.clone(),
            }
        })
        .collect();

    let persisted = match &args.persist {
        Some(dir) => Some(persist_sample(
            dir,
            PersistInput {
                filtered: &filtered,
                since: &args.since,
                window_start: merged_first,
                window_end: merged_last,
                elapsed_minutes: elapsed,
                hosts: &hosts,
                own_egress_count,
            },
        )?),
        None => None,
    };

    let response = SampleResponse {
        since: args.since.to_string(),
        window: WindowSummary {
            first: merged_first,
            last: merged_last,
            elapsed_minutes: elapsed,
            note: "elapsed = your required sampling interval: this many minutes of traffic \
                   filled the fetched buffer (up to 1,000 entries per host, 7-day retention) \
                   — sample at least this often or you will lose evidence."
                .to_string(),
        },
        total_entries: fetch_result.entries.len(),
        filtered_count: filtered.len(),
        own_egress_count,
        hosts,
        persisted,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, format_sample_human)
}

/// Bundled to keep `persist_sample` under clippy's argument-count limit.
struct PersistInput<'a> {
    filtered: &'a [LogEntry],
    since: &'a SinceArg,
    window_start: Option<DateTime<Utc>>,
    window_end: Option<DateTime<Utc>>,
    elapsed_minutes: Option<i64>,
    hosts: &'a [HostWindowSummary],
    own_egress_count: usize,
}

/// `--persist DIR` (D7): one JSONL file per host that contributed at least
/// one entry to the `--since` window (`alx-logs-<ts>-<host>.jsonl`), plus
/// a single `alx-logs-<ts>-meta.json` describing the window/counts. Never
/// overwrites — collisions get `-2`, `-3`, ... suffixes applied uniformly
/// across the whole run's files.
///
/// ADV-3 fix: the "does this collide" check and the write used to be two
/// separate steps (`.exists()` probe, then `std::fs::write`, which
/// truncates-or-creates) — a classic TOCTOU race where two overlapping
/// invocations against the same `DIR` within the same
/// `%Y%m%dT%H%M%SZ`-resolution second could both observe "no collision" for
/// the identical unsuffixed candidate and then have the second write
/// silently clobber the first. `claim_persist_paths` closes that window by
/// making the collision check *be* the atomic create: every path is opened
/// with `create_new(true)` (`O_CREAT|O_EXCL` on Unix), which the kernel
/// guarantees only one concurrent opener can win for a given path — a loser
/// gets `AlreadyExists` and the whole candidate suffix is abandoned in
/// favor of the next one, exactly like the old pre-check loop did, except
/// the "does it collide" answer now comes from the OS itself instead of a
/// stale `.exists()` snapshot.
fn persist_sample(dir: &str, input: PersistInput) -> AppResult<PersistSummary> {
    let dir_path = Path::new(dir);
    std::fs::create_dir_all(dir_path)?;

    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let mut per_host: std::collections::BTreeMap<String, Vec<&LogEntry>> =
        std::collections::BTreeMap::new();
    for e in input.filtered {
        per_host.entry(e.host.clone()).or_default().push(e);
    }
    let host_names: Vec<String> = per_host.keys().cloned().collect();

    let (meta_path, mut meta_file, host_file_handles) =
        claim_persist_paths(dir_path, &ts, &host_names)?;

    let mut host_files = Vec::with_capacity(host_file_handles.len());
    for (host, path, mut file) in host_file_handles {
        let mut body = String::new();
        if let Some(entries) = per_host.get(&host) {
            for e in entries {
                let line = serde_json::to_string(e).map_err(|err| {
                    AppError::Other(format!("failed to serialize log entry: {err}"))
                })?;
                body.push_str(&line);
                body.push('\n');
            }
        }
        IoWrite::write_all(&mut file, body.as_bytes())?;
        host_files.push(path.display().to_string());
    }

    let meta = PersistMeta {
        generated_at: Utc::now(),
        since: input.since.to_string(),
        window_start: input.window_start,
        window_end: input.window_end,
        elapsed_minutes: input.elapsed_minutes,
        hosts: input.hosts.to_vec(),
        merged_total: input.filtered.len(),
        own_egress_count: input.own_egress_count,
    };
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| AppError::Other(format!("failed to serialize persist meta: {e}")))?;
    IoWrite::write_all(&mut meta_file, meta_json.as_bytes())?;

    Ok(PersistSummary {
        dir: dir.to_string(),
        meta_file: meta_path.display().to_string(),
        host_files,
    })
}

/// One claimed `(host, path, open-file-handle)` triple.
type ClaimedHostFile = (String, PathBuf, std::fs::File);
/// `claim_persist_paths`'s return shape: the meta path/handle, plus every
/// claimed host file.
type ClaimedPersistPaths = (PathBuf, std::fs::File, Vec<ClaimedHostFile>);

/// Atomically claims the first unused `-N` suffix (starting unsuffixed) by
/// exclusively creating every target path (meta + every host jsonl) for
/// that suffix — never a separate exists-check followed by a write (ADV-3).
/// On any `AlreadyExists` for a path under the current suffix, the paths
/// already claimed under that same attempt are removed (best-effort) and
/// the next suffix is tried, so a losing run never leaves a half-claimed
/// suffix behind for the winner to trip over.
fn claim_persist_paths(dir: &Path, ts: &str, hosts: &[String]) -> AppResult<ClaimedPersistPaths> {
    let mut n: u32 = 1;
    loop {
        let suffix = if n == 1 {
            String::new()
        } else {
            format!("-{n}")
        };
        let meta_path = dir.join(format!("alx-logs-{ts}{suffix}-meta.json"));

        let meta_file = match create_new_exclusive(&meta_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                n += 1;
                continue;
            }
            Err(e) => return Err(AppError::Io(e)),
        };

        let mut claimed: Vec<ClaimedHostFile> = Vec::with_capacity(hosts.len());
        let mut collided = false;
        for h in hosts {
            let path = dir.join(format!("alx-logs-{ts}{suffix}-{}.jsonl", host_slug(h)));
            match create_new_exclusive(&path) {
                Ok(f) => claimed.push((h.clone(), path, f)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    collided = true;
                    break;
                }
                Err(e) => return Err(AppError::Io(e)),
            }
        }

        if collided {
            // This suffix is partially occupied by something outside our
            // control (a prior crashed run, manual tampering, ...) — undo
            // what we just claimed under it and move on rather than risk
            // writing into a directory another process still owns.
            drop(meta_file);
            let _ = std::fs::remove_file(&meta_path);
            for (_, path, file) in claimed {
                drop(file);
                let _ = std::fs::remove_file(&path);
            }
            n += 1;
            continue;
        }

        return Ok((meta_path, meta_file, claimed));
    }
}

/// `O_CREAT|O_EXCL`-equivalent exclusive create: fails atomically with
/// `AlreadyExists` if the path already exists, rather than truncating it
/// (`std::fs::write`'s behavior) or requiring a separate `.exists()` probe
/// that can go stale between the check and the write.
fn create_new_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn host_slug(host: &str) -> String {
    let stripped = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    stripped
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn format_sample_human(r: &SampleResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "alx logs sample — since {}", r.since);
    let _ = writeln!(
        out,
        "buffer window (unfiltered): {} -> {} ({})",
        fmt_ts(r.window.first),
        fmt_ts(r.window.last),
        fmt_minutes(r.window.elapsed_minutes)
    );
    let _ = writeln!(out, "  {}", r.window.note);
    let _ = writeln!(
        out,
        "total fetched (unfiltered, deduped): {}",
        r.total_entries
    );
    let _ = writeln!(out, "kept within --since window: {}", r.filtered_count);
    let _ = writeln!(
        out,
        "own-egress (excluded from offsite totals): {}",
        r.own_egress_count
    );
    let _ = writeln!(out, "hosts:");
    for h in &r.hosts {
        if let Some(err) = &h.error {
            let _ = writeln!(out, "  {} — FAILED: {err}", h.host);
        } else {
            let _ = writeln!(
                out,
                "  {} — fetched {} ({} -> {}), kept {}",
                h.host,
                h.fetched,
                fmt_ts(h.first),
                fmt_ts(h.last),
                h.kept_in_window
            );
        }
    }
    if let Some(p) = &r.persisted {
        let _ = writeln!(out, "persisted to {}", p.dir);
        let _ = writeln!(out, "  meta: {}", p.meta_file);
        for f in &p.host_files {
            let _ = writeln!(out, "  host file: {f}");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        crate::output::format_session_ops_line(&r.session_ops)
    );
    out
}

fn fmt_ts(ts: Option<DateTime<Utc>>) -> String {
    ts.map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "-".to_string())
}

fn fmt_minutes(m: Option<i64>) -> String {
    m.map(|m| format!("{m} min"))
        .unwrap_or_else(|| "n/a".to_string())
}

// ---------------------------------------------------------------------
// logs offsite
// ---------------------------------------------------------------------

struct Classified<'a> {
    entry: &'a LogEntry,
    asn: AsnInfo,
}

fn origin_allow_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(ORIGIN_ALLOW_PATTERN).expect("static origin allow regex"))
}

/// L7: whether `referer` matches the anchored own-site allow-list.
fn referer_matches_own_site(referer: &Option<String>) -> bool {
    referer
        .as_deref()
        .map(|r| origin_allow_re().is_match(r))
        .unwrap_or(false)
}

/// D7: group by `(ip, referer)`, sorted by call count desc (ties broken by
/// IP for stable output).
fn group_by_ip_referer(items: &[Classified]) -> Vec<GroupedEntry> {
    let mut groups: HashMap<(String, Option<String>), (usize, Option<u32>)> = HashMap::new();
    for c in items {
        let key = (c.entry.ip.clone(), c.entry.referer.clone());
        let slot = groups.entry(key).or_insert((0, c.asn.asn));
        slot.0 += 1;
    }
    let mut out: Vec<GroupedEntry> = groups
        .into_iter()
        .map(|((ip, referer), (count, asn))| {
            let referer_is_own_site = referer_matches_own_site(&referer);
            GroupedEntry {
                ip,
                referer,
                count,
                asn,
                referer_is_own_site,
            }
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
    out
}

pub async fn run_offsite(ctx: &AppContext, args: &LogsOffsiteArgs) -> AppResult<()> {
    let (_fetch_result, filtered) = fetch_and_filter(ctx, &args.since).await?;

    let ipv4s: Vec<Ipv4Addr> = filtered
        .iter()
        .filter_map(|e| e.ip.parse::<Ipv4Addr>().ok())
        .collect();
    let asn_map = asn::resolve_many(&ipv4s).await;

    let mut offsite = Vec::new();
    let mut own_egress = Vec::new();
    let mut keep_benign = Vec::new();
    let mut crawler = Vec::new();
    let mut private_relay = Vec::new();
    let mut asn_unknown = Vec::new();

    for entry in &filtered {
        let asn_info = entry
            .ip
            .parse::<Ipv4Addr>()
            .ok()
            .and_then(|ip| asn_map.get(&ip).copied())
            .unwrap_or_default();
        let ua = entry.user_agent.as_deref().unwrap_or("");
        let classified = Classified {
            entry,
            asn: asn_info,
        };
        match asn::classify(asn_info, ua) {
            AsnClass::OwnEgress => own_egress.push(classified),
            AsnClass::Keep => keep_benign.push(classified),
            AsnClass::Crawler => crawler.push(classified),
            AsnClass::PrivateRelayProbable => private_relay.push(classified),
            AsnClass::Unknown => asn_unknown.push(classified),
            AsnClass::Offsite => offsite.push(classified),
        }
    }

    let response = OffsiteResponse {
        since: args.since.to_string(),
        total_entries: filtered.len(),
        offsite: group_by_ip_referer(&offsite),
        own_egress: BucketSummary {
            count: own_egress.len(),
            groups: group_by_ip_referer(&own_egress),
        },
        keep_benign: BucketSummary {
            count: keep_benign.len(),
            groups: group_by_ip_referer(&keep_benign),
        },
        crawler: BucketSummary {
            count: crawler.len(),
            groups: group_by_ip_referer(&crawler),
        },
        private_relay_probable: BucketSummary {
            count: private_relay.len(),
            groups: group_by_ip_referer(&private_relay),
        },
        asn_unknown: BucketSummary {
            count: asn_unknown.len(),
            groups: group_by_ip_referer(&asn_unknown),
        },
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, format_offsite_human)
}

fn format_offsite_human(r: &OffsiteResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "alx logs offsite — since {}", r.since);
    let _ = writeln!(out, "total entries in window: {}", r.total_entries);
    let _ = writeln!(out);
    let _ = writeln!(out, "offsite (candidate abuse) — {} rows", r.offsite.len());
    for g in r.offsite.iter().take(20) {
        let _ = writeln!(
            out,
            "  {:>6}x  ip={}  asn={}  referer={}{}",
            g.count,
            g.ip,
            g.asn
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".to_string()),
            g.referer.as_deref().unwrap_or("-"),
            if g.referer_is_own_site {
                "  [own-site referer]"
            } else {
                ""
            }
        );
    }
    let _ = writeln!(out);
    for (label, bucket) in [
        ("own_egress", &r.own_egress),
        ("keep_benign", &r.keep_benign),
        ("crawler", &r.crawler),
        ("private_relay_probable", &r.private_relay_probable),
        ("asn_unknown", &r.asn_unknown),
    ] {
        let _ = writeln!(out, "{label}: {}", bucket.count);
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        crate::output::format_session_ops_line(&r.session_ops)
    );
    out
}

// ---------------------------------------------------------------------
// logs errors
// ---------------------------------------------------------------------

pub async fn run_errors(ctx: &AppContext, args: &LogsErrorsArgs) -> AppResult<()> {
    let (_fetch_result, filtered) = fetch_and_filter(ctx, &args.since).await?;

    // L2: this only surfaces referer-allow-list rejections and other
    // non-2xx calls because the fetch layer always requests type=all.
    let errors: Vec<ErrorEntry> = filtered
        .iter()
        .filter(|e| e.answer_code != 200)
        .map(|e| ErrorEntry {
            timestamp: e.timestamp,
            answer_code: e.answer_code,
            ip: e.ip.clone(),
            url: e.url.clone(),
            index: e.index.clone(),
            host: e.host.clone(),
            referer: e.referer.clone(),
        })
        .collect();

    let response = ErrorsResponse {
        since: args.since.to_string(),
        total_checked: filtered.len(),
        error_count: errors.len(),
        errors,
        session_ops: ctx.ops.snapshot(),
    };

    ctx.presenter.success(&response, format_errors_human)
}

fn format_errors_human(r: &ErrorsResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "alx logs errors — since {}", r.since);
    let _ = writeln!(
        out,
        "checked {} entries, {} non-200",
        r.total_checked, r.error_count
    );
    for e in r.errors.iter().take(50) {
        let _ = writeln!(
            out,
            "  {}  {}  ip={}  url={}",
            e.timestamp.to_rfc3339(),
            e.answer_code,
            e.ip,
            e.url
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        crate::output::format_session_ops_line(&r.session_ops)
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ip: &str, referer: Option<&str>, ua: &str, minutes_ago: i64) -> LogEntry {
        LogEntry {
            timestamp: Utc::now() - chrono::Duration::minutes(minutes_ago),
            answer_code: 200,
            nb_api_calls: 1,
            processing_time_ms: 10,
            query_nb_hits: None,
            url: "/1/indexes/Product/query".to_string(),
            query_body: "{}".to_string(),
            answer: "{}".to_string(),
            query_headers: String::new(),
            sha1: format!("{ip}-{minutes_ago}"),
            ip: ip.to_string(),
            index: Some("Product".to_string()),
            host: "host-1".to_string(),
            referer: referer.map(|r| r.to_string()),
            user_agent: Some(ua.to_string()),
        }
    }

    // -------------------------------------------------------------------
    // `format_sample_human`/`format_offsite_human`/`format_errors_human`
    // (--human path): never called by any subprocess test in practice —
    // every `alx` invocation spawned via `std::process::Command` has no
    // controlling TTY on stdin, so `agent::detect`'s TTY check
    // unconditionally forces JSON regardless of `--human`. The only way
    // to exercise these functions at all is a direct, in-process call.
    // -------------------------------------------------------------------

    fn sample_session_ops() -> SessionOpsSnapshot {
        SessionOpsSnapshot {
            logs_calls: 3,
            usage_calls: 0,
            analytics_calls: 0,
            keys_calls: 0,
            insights_calls: 0,
        }
    }

    #[test]
    fn format_sample_human_renders_window_and_every_host() {
        let response = SampleResponse {
            since: "1h".to_string(),
            window: WindowSummary {
                first: Some(Utc::now() - chrono::Duration::minutes(76)),
                last: Some(Utc::now()),
                elapsed_minutes: Some(76),
                note: "sample at least every 76 minutes to avoid gaps".to_string(),
            },
            total_entries: 250,
            filtered_count: 40,
            own_egress_count: 5,
            hosts: vec![
                HostWindowSummary {
                    host: "app-1.algolianet.com".to_string(),
                    fetched: 125,
                    kept_in_window: 20,
                    first: Some(Utc::now()),
                    last: Some(Utc::now()),
                    error: None,
                },
                HostWindowSummary {
                    host: "app-2.algolianet.com".to_string(),
                    fetched: 0,
                    kept_in_window: 0,
                    first: None,
                    last: None,
                    error: Some("HTTP 500".to_string()),
                },
            ],
            persisted: Some(PersistSummary {
                dir: "./algolia-logs".to_string(),
                meta_file: "alx-logs-20260724T000000Z-meta.json".to_string(),
                host_files: vec!["alx-logs-20260724T000000Z-app-1.jsonl".to_string()],
            }),
            session_ops: sample_session_ops(),
        };

        let rendered = format_sample_human(&response);

        assert!(rendered.contains("app-1.algolianet.com"));
        assert!(rendered.contains("app-2.algolianet.com"));
        assert!(rendered.contains("HTTP 500"));
        assert!(rendered.contains("76 minutes"));
        assert!(rendered.contains("algolia-logs"));
    }

    #[test]
    fn format_offsite_human_renders_every_bucket() {
        let group = GroupedEntry {
            ip: "203.0.113.9".to_string(),
            referer: Some("https://evil.example/".to_string()),
            count: 12,
            asn: Some(64512),
            referer_is_own_site: false,
        };
        let empty_bucket = || BucketSummary {
            count: 0,
            groups: vec![],
        };
        let response = OffsiteResponse {
            since: "6h".to_string(),
            total_entries: 100,
            offsite: vec![group],
            own_egress: empty_bucket(),
            keep_benign: empty_bucket(),
            crawler: empty_bucket(),
            private_relay_probable: empty_bucket(),
            asn_unknown: empty_bucket(),
            session_ops: sample_session_ops(),
        };

        let rendered = format_offsite_human(&response);

        assert!(rendered.contains("203.0.113.9"));
        assert!(rendered.contains("evil.example"));
        assert!(rendered.contains("64512"));
    }

    #[test]
    fn format_errors_human_renders_every_error_entry() {
        let response = ErrorsResponse {
            since: "24h".to_string(),
            total_checked: 500,
            error_count: 1,
            errors: vec![ErrorEntry {
                timestamp: Utc::now(),
                answer_code: 403,
                ip: "203.0.113.9".to_string(),
                url: "/1/indexes/Product/query".to_string(),
                index: Some("Product".to_string()),
                host: "app-1.algolianet.com".to_string(),
                referer: Some("https://1000farmacie.it/cerca".to_string()),
            }],
            session_ops: sample_session_ops(),
        };

        let rendered = format_errors_human(&response);

        assert!(rendered.contains("403"));
        assert!(rendered.contains("203.0.113.9"));
        assert!(rendered.contains("/1/indexes/Product/query"));
        assert!(rendered.contains("500")); // total_checked
    }

    #[test]
    fn elapsed_minutes_none_when_missing_either_bound() {
        assert_eq!(elapsed_minutes(None, None), None);
        assert_eq!(elapsed_minutes(Some(Utc::now()), None), None);
    }

    #[test]
    fn elapsed_minutes_computes_span() {
        let first = Utc::now() - chrono::Duration::minutes(15);
        let last = Utc::now();
        assert_eq!(elapsed_minutes(Some(first), Some(last)), Some(15));
    }

    #[test]
    fn is_own_egress_matches_marker_only() {
        let e = entry("203.0.113.1", None, "Algolia for Rails (3.12.2)", 1);
        assert!(is_own_egress(&e));
        let e = entry("203.0.113.1", None, "Mozilla/5.0", 1);
        assert!(!is_own_egress(&e));
    }

    #[test]
    fn l7_referer_matches_own_site_accepts_apex_subdomains_and_lol() {
        assert!(referer_matches_own_site(&Some(
            "https://1000farmacie.it/".to_string()
        )));
        assert!(referer_matches_own_site(&Some(
            "https://www.1000farmacie.it/cerca".to_string()
        )));
        assert!(referer_matches_own_site(&Some(
            "https://blog.1000farmacie.it/".to_string()
        )));
        assert!(referer_matches_own_site(&Some(
            "https://staging.1000farmacie.lol/".to_string()
        )));
    }

    #[test]
    fn l7_referer_matches_own_site_rejects_lookalike_domain() {
        assert!(!referer_matches_own_site(&Some(
            "https://www.1000farmacie.it.evil.com/".to_string()
        )));
        assert!(!referer_matches_own_site(&None));
    }

    #[test]
    fn group_by_ip_referer_sorts_by_count_desc() {
        let a = entry("203.0.113.1", Some("https://evil.example/"), "curl", 1);
        let b1 = entry("203.0.113.2", Some("https://evil.example/"), "curl", 2);
        let b2 = entry("203.0.113.2", Some("https://evil.example/"), "curl", 3);
        let b3 = entry("203.0.113.2", Some("https://evil.example/"), "curl", 4);
        let items: Vec<Classified> = vec![&a, &b1, &b2, &b3]
            .into_iter()
            .map(|entry| Classified {
                entry,
                asn: AsnInfo { asn: Some(64445) },
            })
            .collect();
        let grouped = group_by_ip_referer(&items);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].ip, "203.0.113.2");
        assert_eq!(grouped[0].count, 3);
        assert_eq!(grouped[1].ip, "203.0.113.1");
        assert_eq!(grouped[1].count, 1);
        assert!(!grouped[0].referer_is_own_site);
    }

    #[test]
    fn group_by_ip_referer_flags_own_site_referer() {
        let a = entry(
            "203.0.113.5",
            Some("https://1000farmacie.it/prodotto"),
            "x",
            1,
        );
        let items = vec![Classified {
            entry: &a,
            asn: AsnInfo::default(),
        }];
        let grouped = group_by_ip_referer(&items);
        assert_eq!(grouped.len(), 1);
        assert!(grouped[0].referer_is_own_site);
    }

    #[test]
    fn host_slug_strips_scheme_and_sanitizes() {
        assert_eq!(
            host_slug("https://APPID123-1.algolianet.com"),
            "APPID123-1.algolianet.com"
        );
        assert_eq!(host_slug("http://127.0.0.1:8080"), "127.0.0.1_8080");
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "alx-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn claim_persist_paths_never_clobbers_sequential_runs() {
        let dir = unique_temp_dir("persist-paths-sequential");
        std::fs::create_dir_all(&dir).unwrap();

        let hosts = vec!["host-a".to_string()];
        let ts = "20260724T120000Z";

        let (meta1, meta_file1, host_files1) = claim_persist_paths(&dir, ts, &hosts).unwrap();
        drop(meta_file1);
        drop(host_files1);

        let (meta2, meta_file2, host_files2) = claim_persist_paths(&dir, ts, &hosts).unwrap();
        drop(meta_file2);
        drop(host_files2);

        assert_ne!(
            meta1, meta2,
            "second run must not reuse the first run's meta path"
        );
        assert!(meta2.to_string_lossy().contains("-2-meta.json"));
        assert!(meta1.exists());
        assert!(meta2.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADV-3 regression: the old implementation checked `.exists()` for a
    /// candidate path and only *then* wrote to it — a classic TOCTOU race
    /// where two concurrent `--persist` invocations against the same `DIR`
    /// and the same second-resolution timestamp could both observe "no
    /// collision" for the identical unsuffixed candidate and the second
    /// write would silently clobber the first (no error, no suffix, no
    /// warning — exactly the failure mode `--persist` exists to prevent,
    /// per the 7-day-retention design rationale). Two real OS
    /// threads race `claim_persist_paths` against the *same* `dir`/`ts`
    /// (synchronized with a barrier so both reach the claim at essentially
    /// the same instant) — the fix must guarantee both runs land on
    /// distinct, uncorrupted files rather than one silently overwriting the
    /// other.
    #[test]
    fn claim_persist_paths_concurrent_runs_never_clobber_each_other() {
        let dir = unique_temp_dir("persist-paths-concurrent");
        std::fs::create_dir_all(&dir).unwrap();

        let hosts = vec!["host-a".to_string()];
        let ts = "20260724T130000Z";
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let run = |marker: &'static str,
                   dir: PathBuf,
                   hosts: Vec<String>,
                   barrier: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                let (meta_path, mut meta_file, host_files) =
                    claim_persist_paths(&dir, ts, &hosts).unwrap();
                // Simulate real work between claiming the path and writing
                // the body — this is exactly the window the old
                // check-then-write design left open to a second racer.
                std::thread::yield_now();
                IoWrite::write_all(&mut meta_file, marker.as_bytes()).unwrap();
                for (_, host_path, mut f) in host_files {
                    IoWrite::write_all(&mut f, marker.as_bytes()).unwrap();
                    drop(f);
                    let _ = host_path;
                }
                meta_path
            })
        };

        let t1 = run("run-A", dir.clone(), hosts.clone(), barrier.clone());
        let t2 = run("run-B", dir.clone(), hosts.clone(), barrier);

        let meta1 = t1.join().unwrap();
        let meta2 = t2.join().unwrap();

        assert_ne!(
            meta1, meta2,
            "two concurrent runs must never be assigned the same meta path"
        );

        let content1 = std::fs::read_to_string(&meta1).unwrap();
        let content2 = std::fs::read_to_string(&meta2).unwrap();
        assert_ne!(
            content1, content2,
            "each run's file must retain only its own writer's content — a clobber would make \
             these equal or corrupt one of them"
        );
        let mut markers = [content1.as_str(), content2.as_str()];
        markers.sort_unstable();
        assert_eq!(
            markers,
            ["run-A", "run-B"],
            "both runs' evidence must survive under distinct filenames, uncorrupted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
