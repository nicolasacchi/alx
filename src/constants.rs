//! Fleet-wide constants shared across command modules. Single source of
//! truth — command builders must reference these, never re-hardcode them.

/// The four Algolia indexes the frontend actually queries (autocomplete +
/// search). A browser-scoped key restricted to a subset of these will 403 on
/// the missing sources. Source: the website's own code — `Product`,
/// `Category` and `Brand` are the indexes its models sync to Algolia;
/// `QuerySuggestions` is Algolia-generated and hardcoded in the client-side
/// autocomplete plugin.
pub const FRONTEND_INDEXES: [&str; 4] = ["Product", "QuerySuggestions", "Category", "Brand"];

/// Datacenter-ASN carve-outs — real users / known-benign infrastructure,
/// never flag as scraper/offsite abuse. AS15169 (Google) is
/// additionally gated on a non-crawler User-Agent (Googlebot/Storebot are a
/// separate crawler bucket, not KEEP) — see `asn::classify`.
pub const KEEP_ASNS: [u32; 6] = [
    62044, // Zscaler CH (corporate proxy) — real users
    53813, // Zscaler (additional range) — same cohort as AS62044
    22616, // Zscaler (additional range) — same cohort as AS53813
    13335, // Cloudflare / Cloudflare WARP — consumer VPN carrying real shoppers
    16509, // Amazon AWS — CloudFront / hosted monitoring egress
    15169, // Google — real shoppers via Google infra (Googlebot/Storebot excluded, see asn.rs)
];

/// ASNs behind which iOS Private Relay (Akamai/Fastly/Cloudflare) egresses
/// real iPhone/iPad users. Combined with an iOS User-Agent signature this is
/// a `PrivateRelayProbable` classification, not a datacenter-scraper flag.
pub const PRIVATE_RELAY_ASNS: [u32; 4] = [
    20940, // Akamai
    16625, // Akamai
    35994, // Akamai
    54113, // Fastly
];

/// Origin allow-list — anchored, matches apex + all subdomains + the `.lol`
/// staging host, and rejects lookalike domains like
/// `1000farmacie.it.evil.com` (design decision D7 / acceptance criterion
/// L7). Rust `regex` supports `\A`/`\z` anchors natively.
pub const ORIGIN_ALLOW_PATTERN: &str =
    r"\Ahttps://([a-z0-9-]+\.)*1000farmacie\.(it|lol)(?:[/?#]|\z)";

/// User-Agent marker `algoliasearch-rails` stamps on every server-side
/// egress call. Entries matching this are `own_egress`, excluded from
/// offsite totals but still counted and reported separately (L3).
pub const OWN_EGRESS_UA_MARKER: &str = "Algolia for Rails";

/// Crawler User-Agent signatures — gates AS15169 (Google) between real
/// shoppers (KEEP) and the crawler population (sampled, not hard-excluded).
pub const CRAWLER_UA_PATTERN: &str =
    r"(Googlebot|Storebot-Google|bingbot|GPTBot|OAI-SearchBot|ClaudeBot|PerplexityBot)";

/// iOS signature used for the Private Relay heuristic.
pub const IOS_UA_PATTERN: &str = r"(iPhone|iPad|iOS)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_indexes_matches_verified_set() {
        assert_eq!(
            FRONTEND_INDEXES,
            ["Product", "QuerySuggestions", "Category", "Brand"]
        );
    }

    #[test]
    fn keep_asns_matches_d6_exactly() {
        let mut got = KEEP_ASNS;
        got.sort_unstable();
        let mut want = [62044u32, 53813, 22616, 13335, 16509, 15169];
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn l7_origin_allowlist_accepts_apex_subdomains_and_lol_staging() {
        let re = regex::Regex::new(ORIGIN_ALLOW_PATTERN).unwrap();
        assert!(re.is_match("https://1000farmacie.it/"));
        assert!(re.is_match("https://www.1000farmacie.it/cerca"));
        assert!(re.is_match("https://blog.1000farmacie.it/"));
        assert!(re.is_match("https://staging.1000farmacie.lol/"));
    }

    #[test]
    fn l7_origin_allowlist_rejects_lookalike_domain() {
        let re = regex::Regex::new(ORIGIN_ALLOW_PATTERN).unwrap();
        assert!(!re.is_match("https://www.1000farmacie.it.evil.com/"));
    }

    #[test]
    fn crawler_and_ios_patterns_compile_and_match() {
        let crawler = regex::Regex::new(CRAWLER_UA_PATTERN).unwrap();
        assert!(crawler.is_match("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(crawler.is_match("Mozilla/5.0 (compatible; GPTBot/1.0)"));
        assert!(!crawler.is_match("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));

        let ios = regex::Regex::new(IOS_UA_PATTERN).unwrap();
        assert!(ios.is_match("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"));
        assert!(!ios.is_match("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
    }
}
