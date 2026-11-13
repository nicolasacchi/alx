//! IP -> ASN classification (D6). Resolution is Team Cymru origin DNS: for
//! an IPv4 address `a.b.c.d`, reverse the octets and query the TXT record
//! at `d.c.b.a.origin.asn.cymru.com`, which replies with
//! `"AS# | prefix | CC | registry | date"` — we only need the leading
//! `AS#` field. Private/loopback/link-local/unspecified addresses and any
//! lookup failure/timeout degrade to `AsnInfo { asn: None }` (`Unknown`),
//! never flagged as datacenter on missing data (D6). IPv6 is out of scope
//! for v0.1 (D13) — callers simply never pass an `Ipv6Addr` in here.
//!
//! `classify()` is the pure decision function and its semantics are fixed
//! by D6 — this file only adds the DNS lookup machinery around it.

use crate::constants::{
    CRAWLER_UA_PATTERN, IOS_UA_PATTERN, KEEP_ASNS, OWN_EGRESS_UA_MARKER, PRIVATE_RELAY_ASNS,
};
use hickory_resolver::config::{ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnClass {
    /// KEEP-list ASN with a non-crawler UA — real user, never flag as abuse.
    Keep,
    /// Known crawler UA (Googlebot, GPTBot, ...) — sampled, not hard-excluded.
    Crawler,
    /// iOS UA behind an Akamai/Fastly/Cloudflare-class ASN — iCloud Private
    /// Relay heuristic, not a datacenter-scraper flag.
    PrivateRelayProbable,
    /// `algoliasearch-rails` own server-side egress.
    OwnEgress,
    /// Not KEEP, not a recognized crawler/relay pattern — candidate for the
    /// offsite/abuse bucket.
    Offsite,
    /// ASN lookup failed/timed out or entry is IPv6 — never flagged as
    /// datacenter on missing data.
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AsnInfo {
    pub asn: Option<u32>,
}

fn crawler_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(CRAWLER_UA_PATTERN).expect("static crawler UA regex"))
}

fn ios_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(IOS_UA_PATTERN).expect("static iOS UA regex"))
}

/// Pure classification: KEEP list > own-egress > crawler > private-relay >
/// offsite > unknown. `user_agent` is the raw UA string extracted from
/// `query_headers` (already CRLF-stripped by the caller).
pub fn classify(info: AsnInfo, user_agent: &str) -> AsnClass {
    if user_agent.contains(OWN_EGRESS_UA_MARKER) {
        return AsnClass::OwnEgress;
    }

    let Some(asn) = info.asn else {
        return AsnClass::Unknown;
    };

    let is_crawler_ua = crawler_re().is_match(user_agent);

    if KEEP_ASNS.contains(&asn) {
        // AS15169 (Google) is gated: Googlebot/Storebot is the crawler
        // bucket, not KEEP-benign real-user traffic.
        if asn == 15169 && is_crawler_ua {
            return AsnClass::Crawler;
        }
        return AsnClass::Keep;
    }

    if is_crawler_ua {
        return AsnClass::Crawler;
    }

    if PRIVATE_RELAY_ASNS.contains(&asn) && ios_re().is_match(user_agent) {
        return AsnClass::PrivateRelayProbable;
    }

    AsnClass::Offsite
}

// ---------------------------------------------------------------------
// Team Cymru origin-DNS lookup (D6)
// ---------------------------------------------------------------------

/// At most this many origin-DNS lookups in flight at once.
const MAX_CONCURRENT_LOOKUPS: usize = 8;
/// Best-effort total wall-clock budget for a batch of lookups (`resolve_many`).
/// Whatever hasn't resolved by the time the budget is exhausted is simply
/// left out of the returned map — callers treat a cache miss as `Unknown`.
const LOOKUP_BUDGET: Duration = Duration::from_secs(10);

fn resolver() -> &'static TokioResolver {
    static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        // Google public DNS (same upstream the 0.24 default used), not the system resolver.
        Resolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .expect("hickory resolver config")
    })
}

/// Parses a Team Cymru origin-ASN TXT record body: `"AS# | prefix | CC |
/// registry | date"`. Multi-origin prefixes can report several
/// space-separated ASNs in the first field (e.g. `"1234 5678"`) — the
/// first one is used.
fn parse_cymru_asn(record: &str) -> Option<u32> {
    let first_field = record.split('|').next()?.trim();
    first_field.split_whitespace().next()?.parse().ok()
}

/// Single-IP Team Cymru origin-DNS lookup (D6). Private/loopback/
/// link-local/unspecified addresses never leave the process (no DNS
/// round-trip is even attempted, since Team Cymru has no origin data for
/// non-public space); any query failure or unparseable response degrades
/// to `AsnInfo { asn: None }`.
pub async fn lookup(ip: Ipv4Addr) -> AsnInfo {
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        return AsnInfo { asn: None };
    }

    let octets = ip.octets();
    let query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );

    let asn = match resolver().txt_lookup(query).await {
        Ok(txt) => txt.answers().iter().find_map(|answer| {
            let RData::TXT(record) = &answer.data else {
                return None;
            };
            let joined: String = record
                .txt_data
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk))
                .collect::<Vec<_>>()
                .concat();
            parse_cymru_asn(&joined)
        }),
        Err(_) => None,
    };

    AsnInfo { asn }
}

/// L8/§2.3 test seam (mirrors `ALX_SEARCH_BASE_URL` et al. in
/// `context.rs`): when `ALX_ASN_STATIC_MAP` is set, `resolve_many` answers
/// entirely from this map instead of touching Team Cymru DNS at all — lets
/// a `logs offsite` integration test drive the full command end-to-end
/// (wiremock for the logs fetch + this override for ASN resolution) with a
/// synthetic KEEP/crawler/offsite ASN, closing the gap where L8's KEEP-list
/// routing was previously only verified at `asn::classify`'s pure-function
/// level, never through the actual `logs offsite` command output. Format:
/// comma-separated `ip=asn` pairs, e.g. `"203.0.113.5=62044,203.0.113.6=9009"`.
/// An IP queried but absent from the map still resolves to
/// `AsnInfo::default()` (`Unknown`) — the same "missing = unknown, never
/// datacenter" semantics a real lookup miss has (D6). Never read in
/// production use (the env var is never set outside tests).
fn static_asn_override() -> Option<HashMap<Ipv4Addr, u32>> {
    let raw = std::env::var("ALX_ASN_STATIC_MAP").ok()?;
    let mut map = HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((ip_s, asn_s)) = pair.split_once('=') else {
            continue;
        };
        if let (Ok(ip), Ok(asn)) = (ip_s.trim().parse::<Ipv4Addr>(), asn_s.trim().parse::<u32>()) {
            map.insert(ip, asn);
        }
    }
    Some(map)
}

/// Resolves ASN for many IPv4 addresses with a per-run cache (repeated IPs
/// are looked up once), bounded concurrency (<=8 in-flight, D6), and a
/// ~10s total lookup budget shared across the whole batch — whatever
/// hasn't resolved by the time the budget runs out is simply absent from
/// the returned map, and callers treat a miss the same as `AsnInfo::
/// default()` (`Unknown`), never as "datacenter".
pub async fn resolve_many(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, AsnInfo> {
    if let Some(overrides) = static_asn_override() {
        return ips
            .iter()
            .map(|&ip| {
                (
                    ip,
                    AsnInfo {
                        asn: overrides.get(&ip).copied(),
                    },
                )
            })
            .collect();
    }

    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for &ip in ips {
        if seen.insert(ip) {
            unique.push(ip);
        }
    }

    let deadline = Instant::now() + LOOKUP_BUDGET;
    let mut resolved = HashMap::with_capacity(unique.len());

    for chunk in unique.chunks(MAX_CONCURRENT_LOOKUPS) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        let futures: Vec<_> = chunk
            .iter()
            .map(|&ip| async move { (ip, lookup(ip).await) })
            .collect();

        if let Ok(pairs) = tokio::time::timeout(remaining, join_all(futures)).await {
            for (ip, info) in pairs {
                resolved.insert(ip, info);
            }
        }
    }

    resolved
}

/// Minimal `join_all` (deliberately hand-rolled — D2 freezes `Cargo.toml`
/// and the `futures` crate isn't a declared dependency). Polls every
/// future concurrently on the *current* task, preserving input order;
/// nothing is spawned onto another task/thread, so this works fine with
/// borrowed (non-`'static`) captures, which `resolve_many`'s per-IP
/// futures and `algolia::logs`'s per-host fetch futures both rely on.
struct JoinAll<F: Future> {
    slots: Vec<Option<Pin<Box<F>>>>,
    done: Vec<Option<F::Output>>,
}

// `JoinAll` only ever pins its *elements* (each already boxed behind its
// own `Pin<Box<F>>`, which is `Unpin` unconditionally since `Box<T>` is
// always `Unpin` regardless of `T`); the outer struct itself never needs
// address stability, so it's sound to opt it out of `!Unpin` regardless of
// whether `F::Output` happens to be `Unpin`.
impl<F: Future> Unpin for JoinAll<F> {}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut all_ready = true;
        for (slot, done) in this.slots.iter_mut().zip(this.done.iter_mut()) {
            if done.is_some() {
                continue;
            }
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(v) => {
                        *done = Some(v);
                        *slot = None;
                    }
                    Poll::Pending => all_ready = false,
                }
            }
        }
        if all_ready {
            Poll::Ready(this.done.iter_mut().map(|d| d.take().unwrap()).collect())
        } else {
            Poll::Pending
        }
    }
}

pub(crate) async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    let len = futures.len();
    JoinAll {
        slots: futures.into_iter().map(|f| Some(Box::pin(f))).collect(),
        done: (0..len).map(|_| None).collect(),
    }
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(asn: u32) -> AsnInfo {
        AsnInfo { asn: Some(asn) }
    }

    #[test]
    fn keep_asn_non_bot_ua_is_keep() {
        assert_eq!(
            classify(info(62044), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            AsnClass::Keep
        );
        assert_eq!(
            classify(info(13335), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)"),
            AsnClass::Keep
        );
        assert_eq!(
            classify(info(16509), "Mozilla/5.0 (X11; Linux x86_64)"),
            AsnClass::Keep
        );
    }

    #[test]
    fn as15169_crawler_ua_is_crawler_not_keep() {
        assert_eq!(
            classify(info(15169), "Mozilla/5.0 (compatible; Googlebot/2.1)"),
            AsnClass::Crawler
        );
        assert_eq!(
            classify(info(15169), "Mozilla/5.0 (compatible; Storebot-Google/1.0)"),
            AsnClass::Crawler
        );
    }

    #[test]
    fn as15169_non_bot_ua_is_keep() {
        assert_eq!(
            classify(info(15169), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            AsnClass::Keep
        );
    }

    #[test]
    fn non_keep_crawler_ua_is_crawler() {
        assert_eq!(
            classify(info(132203), "Mozilla/5.0 (compatible; GPTBot/1.0)"),
            AsnClass::Crawler
        );
        assert_eq!(
            classify(info(9009), "Mozilla/5.0 (compatible; bingbot/2.0)"),
            AsnClass::Crawler
        );
    }

    #[test]
    fn ios_behind_relay_asn_is_private_relay_probable() {
        // Akamai
        assert_eq!(
            classify(
                info(20940),
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
            ),
            AsnClass::PrivateRelayProbable
        );
        // Fastly
        assert_eq!(
            classify(info(54113), "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)"),
            AsnClass::PrivateRelayProbable
        );
    }

    #[test]
    fn non_ios_ua_behind_relay_asn_is_offsite() {
        assert_eq!(
            classify(info(20940), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            AsnClass::Offsite
        );
    }

    #[test]
    fn own_egress_marker_wins_over_everything() {
        assert_eq!(
            classify(info(9009), "Algolia for Rails (3.12.2)"),
            AsnClass::OwnEgress
        );
        // Even a KEEP ASN should still report own-egress if the UA marker matches.
        assert_eq!(
            classify(info(62044), "Algolia for Rails (3.12.2)"),
            AsnClass::OwnEgress
        );
    }

    #[test]
    fn unresolved_asn_is_unknown_never_datacenter() {
        assert_eq!(
            classify(AsnInfo { asn: None }, "Mozilla/5.0"),
            AsnClass::Unknown
        );
    }

    #[test]
    fn plain_scraper_asn_non_bot_ua_is_offsite() {
        assert_eq!(
            classify(info(132203), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            AsnClass::Offsite
        );
    }

    /// L8: the whole classification pipeline is drivable purely from a
    /// synthetic `AsnInfo` — no DNS involved. Exercises the full KEEP /
    /// crawler / private-relay / offsite / unknown decision tree in one
    /// pass so it's clear the pure function alone (not `lookup()`) is what
    /// backs `logs offsite`'s bucketing.
    #[test]
    fn l8_classification_via_synthetic_asn() {
        let cases = [
            (info(62044), "curl/8.0", AsnClass::Keep),
            (info(15169), "Googlebot/2.1", AsnClass::Crawler),
            (
                info(54113),
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
                AsnClass::PrivateRelayProbable,
            ),
            (info(64445), "curl/8.0", AsnClass::Offsite),
            (AsnInfo { asn: None }, "curl/8.0", AsnClass::Unknown),
            (
                info(64445),
                "Algolia for Rails (3.12.2)",
                AsnClass::OwnEgress,
            ),
        ];
        for (info, ua, expected) in cases {
            assert_eq!(classify(info, ua), expected, "ua={ua:?} info={info:?}");
        }
    }

    #[tokio::test]
    async fn lookup_private_ip_never_touches_dns() {
        // is_private()/is_loopback()/is_link_local() short-circuit before
        // any network I/O, so this is safe to run offline.
        for ip in [
            "10.1.2.3",
            "192.168.1.5",
            "172.16.0.9",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            let info = lookup(ip.parse().unwrap()).await;
            assert_eq!(info.asn, None, "expected Unknown for private/local {ip}");
        }
    }

    #[test]
    fn parse_cymru_asn_takes_leading_field() {
        assert_eq!(
            parse_cymru_asn("15169 | 8.8.8.0/24 | US | arin | 1992-12-01"),
            Some(15169)
        );
        assert_eq!(parse_cymru_asn("  62044 | ... "), Some(62044));
        assert_eq!(parse_cymru_asn("not a cymru record"), None);
        // Multi-origin: first ASN wins.
        assert_eq!(
            parse_cymru_asn("1234 5678 | 1.2.3.0/24 | US | arin | date"),
            Some(1234)
        );
    }

    #[tokio::test]
    async fn resolve_many_dedupes_and_skips_private_without_dns() {
        let ips: Vec<Ipv4Addr> = vec![
            "10.1.2.3".parse().unwrap(),
            "10.1.2.3".parse().unwrap(), // duplicate
            "192.168.0.1".parse().unwrap(),
        ];
        let resolved = resolve_many(&ips).await;
        assert_eq!(resolved.len(), 2);
        for ip in &ips {
            assert_eq!(resolved.get(ip).unwrap().asn, None);
        }
    }

    #[tokio::test]
    async fn join_all_preserves_order_and_concurrency() {
        async fn ready(n: i32) -> i32 {
            n
        }
        let futures = vec![ready(1), ready(2), ready(3)];
        let results = join_all(futures).await;
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn static_asn_override_parses_ip_equals_asn_pairs() {
        let _guard = crate::algolia::keys::TEST_ENV_MUTEX.lock().unwrap();
        std::env::set_var(
            "ALX_ASN_STATIC_MAP",
            " 203.0.113.5=62044, 203.0.113.6=9009 ,,malformed,203.0.113.7=notanumber",
        );
        let map = static_asn_override().expect("env var was set");
        std::env::remove_var("ALX_ASN_STATIC_MAP");

        assert_eq!(map.get(&"203.0.113.5".parse().unwrap()), Some(&62044));
        assert_eq!(map.get(&"203.0.113.6".parse().unwrap()), Some(&9009));
        assert_eq!(map.get(&"203.0.113.7".parse().unwrap()), None);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn static_asn_override_none_when_env_unset() {
        let _guard = crate::algolia::keys::TEST_ENV_MUTEX.lock().unwrap();
        std::env::remove_var("ALX_ASN_STATIC_MAP");
        assert!(static_asn_override().is_none());
    }

    /// L8/§2.3 test-seam regression: `resolve_many` under the override must
    /// answer a KEEP-listed ASN for the mapped IP (so `logs offsite`
    /// integration tests can drive the real KEEP-list routing end-to-end,
    /// see `tests/logs_wiremock.rs::l8_keep_asn_ip_routes_to_keep_benign_not_offsite`)
    /// and `Unknown` (never a guessed/default ASN) for any IP absent from
    /// the map — the same "missing = unknown" contract a real DNS miss has.
    ///
    /// Plain (non-`tokio::test`) sync test, mirroring `error.rs`'s
    /// `make_reqwest_error` pattern: the env-var guard must be held for the
    /// full set→read→clear window (shared `TEST_ENV_MUTEX` convention), but
    /// holding a `std::sync::MutexGuard` across a real `.await` point
    /// inside an `async fn` trips `clippy::await_holding_lock` — driving
    /// the future through a manually built current-thread runtime's
    /// `block_on` from synchronous test code sidesteps that without
    /// weakening the mutex's guarantee (the override path never actually
    /// yields anyway).
    #[test]
    fn resolve_many_uses_static_override_when_set() {
        let _guard = crate::algolia::keys::TEST_ENV_MUTEX.lock().unwrap();
        std::env::set_var("ALX_ASN_STATIC_MAP", "203.0.113.9=62044");

        let ips: Vec<Ipv4Addr> = vec![
            "203.0.113.9".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
        ];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolved = rt.block_on(resolve_many(&ips));

        std::env::remove_var("ALX_ASN_STATIC_MAP");

        assert_eq!(resolved.get(&ips[0]).unwrap().asn, Some(62044));
        assert_eq!(resolved.get(&ips[1]).unwrap().asn, None);
    }
}
