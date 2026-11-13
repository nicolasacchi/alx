//! Black-box smoke test for `alx keys audit`'s *pre-network* credential
//! guard clauses. `run_audit` calls `safety::preflight_privilege_check`
//! before making any keys-API call; that function now takes an explicit
//! `base_url` parameter (`ctx.base_urls.search(app_id)`, redirectable via
//! `ALX_SEARCH_BASE_URL` — integrate-pass fix, see `src/safety.rs`), so a
//! full end-to-end black-box test is possible in principle. These two
//! tests still exercise only the `--app-id`/key resolution that returns
//! *before* any network call is ever made, keeping this file network-free
//! by construction rather than by env-var setup. Full coverage of the
//! audit logic itself (K1/K2/K4, the list-then-self-read fallback) lives as
//! inline `#[cfg(test)]` tests in `src/commands/keys.rs` and
//! `src/algolia/keys.rs`, which call the testable units directly rather
//! than through `run_audit`.

use std::process::Command;

fn spawn_alx(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    let mut cmd = Command::new(bin);
    cmd.args(args).env_clear();
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn the alx binary")
}

#[test]
fn keys_smoke_requires_app_id() {
    let output = spawn_alx(&["keys", "audit"], &[]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALGOLIA_APPLICATION_ID"), "stdout={stdout}");
}

#[test]
fn keys_smoke_requires_a_key() {
    let output = spawn_alx(
        &["keys", "audit"],
        &[("ALGOLIA_APPLICATION_ID", "test-app")],
    );

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("keys audit"), "stdout={stdout}");
}
