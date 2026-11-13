//! Hostile-input coverage for `alx`'s pure CLI argument parsing — no
//! network, no wiremock, no credentials needed. `alx` is a bin-only crate
//! (no `[lib]` target — see `Cargo.toml`), so this spawns the real compiled
//! binary (`CARGO_BIN_EXE_alx`) exactly like every sibling `tests/*.rs`
//! file, rather than calling `SinceArg::from_str` directly.
//!
//! `--since` (`cli::SinceArg::from_str`) is parsed by clap *before*
//! `AppContext` is ever built — an invalid value never reaches the network
//! layer at all, it fails as a clap usage error (exit code 2, design
//! decision D5). `src/cli.rs` already unit-tests `SinceArg::from_str` in isolation
//! (`since_arg_rejects_garbage`); this file extends that with the full
//! hostile vector list from the test brief, driven end-to-end through the
//! real binary (closing the "instrumentation blind spot" the coverage audit
//! flagged for every subprocess-based test in this suite) and adds vectors
//! the inline unit test doesn't cover (`999999d`, `1.5h`, whitespace-only).

use std::os::unix::process::ExitStatusExt;

fn spawn_alx(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    std::process::Command::new(bin)
        .args(args)
        .env_clear()
        .output()
        .expect("failed to spawn the alx binary")
}

/// Cross-cutting safety net for every hostile-input test in this suite:
/// never a Rust panic (unwind, exit code 101) and never a hard crash
/// (killed by a signal — e.g. a stack overflow abort). A clean `AppError`
/// (any other exit code) or a clap usage error (exit code 2) are both fine;
/// this only rules out the two "the process actually blew up" shapes.
fn assert_never_panicked(output: &std::process::Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "{context}: process panicked — stderr: {stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(101),
        "{context}: exit code 101 usually means an unwinding Rust panic — stderr: {stderr}"
    );
    assert!(
        output.status.signal().is_none(),
        "{context}: process was killed by signal {:?} (crash, e.g. stack overflow) — stderr: {stderr}",
        output.status.signal()
    );
}

/// `--since` values clap must reject as a usage error (exit code 2, D5) —
/// `alx` never even reaches `AppContext`/network for these.
const REJECTED_SINCE_VECTORS: &[&str] = &[
    "0h",   // zero is rejected ("must be positive")
    "1x",   // unit 'x' is not m|h|d
    "",     // empty string, too short to parse
    "-1h",  // negative number rejected ("must be positive")
    "1.5h", // fractional number, not a valid i64
    " ",    // whitespace-only trims to empty
    "   ",  // whitespace-only (wider)
    "h",    // unit with no number at all
    "5",    // number with no unit at all (len ok, but split gives unit '5', num_part empty)
    "5hh",  // trailing garbage after a valid-looking prefix
    "-0h",  // "-0" parses to 0, still <=0 -> rejected
    "1e3h", // scientific notation is not a valid i64
    "+h",   // sign with no digits
];

#[test]
fn since_hostile_vectors_rejected_as_clap_usage_errors() {
    for value in REJECTED_SINCE_VECTORS {
        let output = spawn_alx(&["logs", "sample", "--since", value]);
        assert_never_panicked(&output, &format!("--since {value:?}"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "--since {value:?} should be rejected as a clap usage error (exit 2, D5); got \
             exit={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.is_empty(),
            "expected a non-empty clap error message on stderr for --since {value:?}"
        );
    }
}

/// The one `\t1h` case above (leading tab, otherwise valid) deserves its own
/// pinned assertion — `SinceArg::from_str` trims the *whole* string before
/// parsing, so a tab in front of an otherwise-valid `1h` value is actually
/// ACCEPTED, not rejected. Documented as a separate positive-control test
/// rather than folded into `REJECTED_SINCE_VECTORS` (which would be wrong).
#[test]
fn since_leading_tab_is_trimmed_and_accepted() {
    let output = spawn_alx(&["logs", "sample", "--since", "\t1h"]);
    assert_never_panicked(&output, "--since \\t1h");
    assert_ne!(
        output.status.code(),
        Some(2),
        "a leading tab should be trimmed by SinceArg::from_str, not rejected as a clap usage \
         error — exit={:?}",
        output.status.code()
    );
}

/// `999999d` has no upper bound anywhere in `SinceArg::from_str` (only the
/// Usage API's granularity pre-flight — a different code path — rejects
/// overly wide windows). It must parse successfully and let the command
/// proceed to credential resolution, failing there instead (exit code 1,
/// `AppError::InvalidInput`, missing `ALGOLIA_APPLICATION_ID`) — never a
/// clap usage error (2) and never a panic.
#[test]
fn since_huge_999999d_accepted_by_parser_fails_later_on_missing_credentials() {
    let output = spawn_alx(&["logs", "sample", "--since", "999999d"]);
    assert_never_panicked(&output, "--since 999999d");
    assert_eq!(
        output.status.code(),
        Some(1),
        "999999d should parse fine and fail downstream on missing credentials (exit 1), not as \
         a clap usage error — exit={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Every numeric `--since` value that IS accepted must round-trip through
/// every subcommand that takes `--since` (`logs sample|offsite|errors`,
/// `usage summary|meters`, `analytics top-searches|no-results|scrape-signals`)
/// without a parser-level rejection — confirms the hostile-vector coverage
/// above isn't accidentally specific to `logs sample`.
#[test]
fn since_valid_value_accepted_across_every_subcommand_taking_since() {
    let subcommands: &[&[&str]] = &[
        &["logs", "sample"],
        &["logs", "offsite"],
        &["logs", "errors"],
        &["usage", "summary"],
        &["usage", "meters"],
        &["analytics", "top-searches"],
        &["analytics", "no-results"],
        &["analytics", "scrape-signals"],
    ];
    for sub in subcommands {
        let mut args: Vec<&str> = sub.to_vec();
        args.push("--since");
        args.push("2h");
        let output = spawn_alx(&args);
        assert_never_panicked(&output, &format!("{sub:?} --since 2h"));
        assert_ne!(
            output.status.code(),
            Some(2),
            "{sub:?} --since 2h should not be a clap usage error — exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// `usage series --granularity` (a separate `ValueEnum`, not `SinceArg`) has
/// its own hostile-input surface: an unrecognized value must be a clap
/// usage error, never silently coerced to a default.
#[test]
fn usage_series_granularity_hostile_value_rejected() {
    for value in ["HOURLY", "daily ", "weekly", "", "0", "hourly;rm -rf"] {
        let output = spawn_alx(&[
            "usage",
            "series",
            "--statistic",
            "total_search_requests",
            "--granularity",
            value,
            "--since",
            "1d",
        ]);
        assert_never_panicked(&output, &format!("--granularity {value:?}"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "--granularity {value:?} should be a clap usage error (exit 2); got {:?}",
            output.status.code()
        );
    }
}

/// `analytics ... --region` (another `ValueEnum`) — same hostile-input
/// shape check.
#[test]
fn analytics_region_hostile_value_rejected() {
    for value in ["DE", "eu", "de-central", "'; DROP TABLE", ""] {
        let output = spawn_alx(&[
            "analytics",
            "top-searches",
            "--since",
            "1d",
            "--region",
            value,
        ]);
        assert_never_panicked(&output, &format!("--region {value:?}"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "--region {value:?} should be a clap usage error (exit 2); got {:?}",
            output.status.code()
        );
    }
}

/// Negative/garbage `--limit` on analytics subcommands must not panic —
/// clap's `u32` value parser rejects a negative number or non-numeric
/// garbage as a usage error before any command logic runs.
#[test]
fn analytics_limit_hostile_values_rejected_or_handled_cleanly() {
    for value in ["-1", "not-a-number", "99999999999999999999", ""] {
        let output = spawn_alx(&[
            "analytics",
            "top-searches",
            "--since",
            "1d",
            "--limit",
            value,
        ]);
        assert_never_panicked(&output, &format!("--limit {value:?}"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "--limit {value:?} should be a clap usage error (exit 2) — u32 parsing must reject \
             negatives/garbage/overflow cleanly; got {:?}",
            output.status.code()
        );
    }
}
