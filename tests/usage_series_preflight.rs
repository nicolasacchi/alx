//! U4 acceptance criteria (design decision D0.3): `alx
//! usage series` must reject an invalid granularity/window combination
//! BEFORE making any HTTP call. These run the real compiled `alx` binary
//! (`env!("CARGO_BIN_EXE_alx")`) against a `wiremock` server pointed at via
//! `ALX_USAGE_BASE_URL` and assert the mock received ZERO requests — this
//! is a stronger check than asserting the error message alone, since a
//! naive implementation could still fire the HTTP call and only reject the
//! response afterward.
//!
//! `std::process::Command` (not `tokio::process`) is used because the
//! `tokio` dependency in Cargo.toml only enables the `macros`/
//! `rt-multi-thread` features — no `process` feature — so the blocking
//! call is off-loaded onto tokio's blocking pool via `spawn_blocking`
//! rather than run directly on an async worker thread.

use wiremock::MockServer;

fn spawn_alx(args: &[&str], base_url: &str) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_alx");
    std::process::Command::new(bin)
        .args(args)
        .env_clear()
        .env("ALX_USAGE_BASE_URL", base_url)
        .output()
        .expect("failed to spawn the alx binary")
}

async fn run_alx(args: Vec<&'static str>, base_url: String) -> (i32, String) {
    let output = tokio::task::spawn_blocking(move || spawn_alx(&args, &base_url))
        .await
        .expect("spawn_blocking join failed");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (code, stdout)
}

#[tokio::test]
async fn u4_preflight_hourly_beyond_7d_no_http_call() {
    let server = MockServer::start().await;

    let (code, stdout) = run_alx(
        vec![
            "--app-id",
            "test-app",
            "--key",
            "test-key",
            "usage",
            "series",
            "--statistic",
            "total_search_requests",
            "--granularity",
            "hourly",
            "--since",
            "30d",
        ],
        server.uri(),
    )
    .await;

    assert_eq!(
        code, 1,
        "expected exit code 1 (InvalidInput) for hourly beyond 7d, stdout={stdout}"
    );
    assert!(
        stdout.contains('7'),
        "pre-flight error should name the 7-day hourly limit: {stdout}"
    );

    let received = server
        .received_requests()
        .await
        .expect("wiremock request recording should be enabled");
    assert!(
        received.is_empty(),
        "expected ZERO HTTP requests before the pre-flight check rejects the window, got: {received:?}"
    );
}

#[tokio::test]
async fn u4_preflight_daily_beyond_365d() {
    let server = MockServer::start().await;

    let (code, stdout) = run_alx(
        vec![
            "--app-id",
            "test-app",
            "--key",
            "test-key",
            "usage",
            "series",
            "--statistic",
            "total_search_requests",
            "--granularity",
            "daily",
            "--since",
            "400d",
        ],
        server.uri(),
    )
    .await;

    assert_eq!(
        code, 1,
        "expected exit code 1 (InvalidInput) for daily beyond 365d, stdout={stdout}"
    );
    assert!(
        stdout.contains("365"),
        "pre-flight error should name the 365-day daily limit: {stdout}"
    );

    let received = server
        .received_requests()
        .await
        .expect("wiremock request recording should be enabled");
    assert!(
        received.is_empty(),
        "expected ZERO HTTP requests before the pre-flight check rejects the window, got: {received:?}"
    );
}
