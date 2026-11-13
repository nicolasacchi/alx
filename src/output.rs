//! Presenter (D4): JSON is the DEFAULT output mode. `--human` opts into
//! colored rendering; `--json` is an explicit no-op-if-already-json flag;
//! agent detection (agent.rs) forces JSON regardless of `--human`. `--jq`
//! pipes the final JSON payload through the system `jq` binary and takes
//! precedence over both rendering modes. ALL incidental output must go
//! through `Presenter::progress()` — no raw `eprintln!`/`println!` anywhere
//! else in the codebase.

use crate::error::{AppError, AppResult};
use colored::Colorize;
use serde::Serialize;
use std::io::{IsTerminal, Write};
use std::process::Stdio;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

/// Embedded in every command response envelope (D4 quota-honesty
/// requirement) — the running count of Algolia operations-quota-consuming
/// calls made this session, broken out per surface.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SessionOpsSnapshot {
    pub logs_calls: u32,
    pub usage_calls: u32,
    pub analytics_calls: u32,
    pub keys_calls: u32,
    pub insights_calls: u32,
}

/// One human-readable closing line every command's human renderer should
/// append, so quota honesty (D0.4) is visible outside JSON mode too.
pub fn format_session_ops_line(ops: &SessionOpsSnapshot) -> String {
    format!(
        "session ops — logs: {}, usage: {}, analytics: {}, keys: {}, insights: {}",
        ops.logs_calls, ops.usage_calls, ops.analytics_calls, ops.keys_calls, ops.insights_calls
    )
}

#[derive(Debug)]
pub struct Presenter {
    pub output_mode: OutputMode,
    pub verbose: bool,
    pub jq: Option<String>,
}

impl Presenter {
    /// `json_flag` is the explicit `--json` flag (a no-op given JSON is
    /// already the default; kept only so `--json` is harmless to pass).
    /// `human_flag` is `--human`. `is_agent` (from agent.rs) always wins to
    /// JSON, overriding even an explicit `--human`.
    pub fn new(
        human_flag: bool,
        json_flag: bool,
        is_agent: bool,
        verbose: bool,
        jq: Option<String>,
    ) -> Self {
        let output_mode = if is_agent {
            OutputMode::Json
        } else if human_flag && !json_flag {
            OutputMode::Human
        } else {
            OutputMode::Json
        };

        let colors_enabled = output_mode == OutputMode::Human
            && std::env::var("NO_COLOR").is_err()
            && std::io::stdout().is_terminal();

        if !colors_enabled {
            colored::control::set_override(false);
        }

        Presenter {
            output_mode,
            verbose,
            jq,
        }
    }

    /// Universal success output call. `value` is the single source of truth
    /// — `human_format` renders the *same* struct, never a re-derived shape.
    /// When `--jq` is set, the serialized JSON is piped through the system
    /// `jq` binary instead of either renderer.
    pub fn success<T: Serialize>(
        &self,
        value: &T,
        human_format: impl FnOnce(&T) -> String,
    ) -> AppResult<()> {
        if let Some(expr) = &self.jq {
            let json_value = serde_json::to_value(value)
                .map_err(|e| AppError::JqFailed(format!("serialization failed: {e}")))?;
            let piped = run_jq(&json_value, expr)?;
            println!("{piped}");
            return Ok(());
        }

        match self.output_mode {
            OutputMode::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(value).unwrap_or_else(|e| format!(
                        "{{\"error\": \"serialization failed: {e}\"}}"
                    ))
                );
            }
            OutputMode::Human => {
                println!("{}", human_format(value));
            }
        }
        Ok(())
    }

    /// Errors print to stdout in JSON mode (JSON output is meant to be the
    /// sole piped payload), stderr in human mode.
    pub fn error(&self, err: &AppError) {
        match self.output_mode {
            OutputMode::Json => {
                let mut obj = serde_json::json!({ "error": err.to_string() });
                if let Some(suggestion) = err.suggestion() {
                    obj["suggestion"] = serde_json::Value::String(suggestion.to_string());
                }
                println!("{}", serde_json::to_string_pretty(&obj).unwrap());
            }
            OutputMode::Human => {
                eprintln!("{} {}", "error:".red().bold(), err);
                if let Some(suggestion) = err.suggestion() {
                    eprintln!("  {} {}", "hint:".yellow(), suggestion);
                }
            }
        }
    }

    /// Verbose-gated, always stderr. The only sanctioned channel for
    /// incidental/progress output anywhere in the codebase.
    pub fn progress(&self, msg: &str) {
        if self.verbose {
            eprintln!("{} {}", "...".dimmed(), msg);
        }
    }

    /// Kept as documented `Presenter` API (the shared CLI convention's
    /// `is_json()`) even though no command currently branches on it
    /// directly — every command instead routes through `success()`, which
    /// already dispatches on `output_mode` internally. Exercised by this
    /// module's own tests.
    #[allow(dead_code)]
    pub fn is_json(&self) -> bool {
        self.output_mode == OutputMode::Json
    }
}

fn run_jq(value: &serde_json::Value, expr: &str) -> AppResult<String> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| AppError::JqFailed(format!("serialization failed: {e}")))?;

    let mut child = std::process::Command::new("jq")
        .arg(expr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::JqFailed("jq not found on PATH".to_string())
            } else {
                AppError::JqFailed(e.to_string())
            }
        })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| AppError::JqFailed("failed to open jq stdin".to_string()))?;
        // A write failure here (typically a broken pipe) just means jq
        // already exited without reading our input — e.g. a syntax error
        // in `expr` fails at jq's program-compile step, before it ever
        // touches stdin. Swallowing it and falling through to
        // `wait_with_output()` below lets the real exit status/stderr
        // (jq's own, more specific error message) win, instead of a
        // generic "Broken pipe" IO error masking it. This also removes a
        // timing race that made the same scenario nondeterministic: which
        // error surfaced depended on whether the write syscall completed
        // before jq's exit was observed.
        let _ = stdin.write_all(json_str.as_bytes());
    }

    let output = child
        .wait_with_output()
        .map_err(|e| AppError::JqFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::JqFailed(format!(
            "jq exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_mode_is_json() {
        let p = Presenter::new(false, false, false, false, None);
        assert_eq!(p.output_mode, OutputMode::Json);
        assert!(p.is_json());
    }

    #[test]
    fn human_flag_switches_to_human() {
        let p = Presenter::new(true, false, false, false, None);
        assert_eq!(p.output_mode, OutputMode::Human);
    }

    #[test]
    fn agent_forces_json_even_with_human_flag() {
        let p = Presenter::new(true, false, true, false, None);
        assert_eq!(p.output_mode, OutputMode::Json);
    }

    #[test]
    fn explicit_json_flag_wins_over_human() {
        let p = Presenter::new(true, true, false, false, None);
        assert_eq!(p.output_mode, OutputMode::Json);
    }

    #[test]
    fn session_ops_line_formats_all_four_surfaces() {
        let ops = SessionOpsSnapshot {
            logs_calls: 3,
            usage_calls: 1,
            analytics_calls: 0,
            keys_calls: 2,
            insights_calls: 4,
        };
        let line = format_session_ops_line(&ops);
        assert!(line.contains("logs: 3"));
        assert!(line.contains("usage: 1"));
        assert!(line.contains("analytics: 0"));
        assert!(line.contains("keys: 2"));
        assert!(line.contains("insights: 4"));
    }

    #[test]
    fn jq_passthrough_filters_field() {
        let p = Presenter::new(false, false, false, false, Some(".n".to_string()));
        // Just verify run_jq directly since success() prints to stdout.
        let value = serde_json::json!({"n": 42});
        let out = run_jq(&value, ".n").unwrap();
        assert_eq!(out, "42");
        let _ = p; // presenter construction itself must not panic with --jq set
    }

    #[test]
    fn jq_syntax_error_in_expression_yields_jqfailed_with_stderr() {
        // Exercises the REAL `run_jq`'s "jq exited non-zero" branch
        // (previously only a parallel `run_jq_with_binary` test helper
        // covered an equivalent shape, never the actual production
        // function) — an unbalanced `.[` is a jq syntax error, guaranteed
        // non-zero exit, no real data needed. jq fails this one at its
        // program-compile step, before ever reading stdin — exercising
        // exactly the "child exits before we finish writing" race that
        // `run_jq`'s write_all-failure-swallowing fix now handles
        // deterministically (previously nondeterministic: whether the
        // write syscall completed before jq's exit was observed decided
        // which of two different error messages surfaced).
        let value = serde_json::json!({"n": 1});
        let err = run_jq(&value, ".[").unwrap_err();
        match err {
            AppError::JqFailed(msg) => {
                assert!(
                    msg.contains("jq exited with"),
                    "expected the non-zero-exit message shape: {msg}"
                );
            }
            other => panic!("expected JqFailed, got {other:?}"),
        }
    }

    #[test]
    fn success_jq_branch_prints_filtered_json_to_stdout() {
        // Exercises the `--jq` branch INSIDE `Presenter::success()` itself
        // (serialize -> run_jq -> println), not just the standalone
        // `run_jq` helper — `success()` prints directly so this only
        // pins "does not error", the actual stdout content is asserted
        // end-to-end by tests/e2e_cli.rs::jq_end_to_end_session_ops.
        let p = Presenter::new(false, false, false, false, Some(".n".to_string()));
        #[derive(Serialize)]
        struct Payload {
            n: u32,
        }
        let result = p.success(&Payload { n: 7 }, |_| "unused human render".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn jq_missing_binary_produces_clean_error() {
        let value = serde_json::json!({"n": 1});
        let err = run_jq_with_binary(&value, ".n", "definitely-not-a-real-binary-xyz").unwrap_err();
        match err {
            AppError::JqFailed(msg) => assert!(!msg.is_empty()),
            other => panic!("expected JqFailed, got {other:?}"),
        }
    }

    // Test-only variant of run_jq that allows swapping the binary name, so
    // the "jq not on PATH" path is exercised without mutating $PATH.
    fn run_jq_with_binary(
        value: &serde_json::Value,
        expr: &str,
        binary: &str,
    ) -> AppResult<String> {
        let json_str = serde_json::to_string(value).unwrap();
        let mut child = std::process::Command::new(binary)
            .arg(expr)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    AppError::JqFailed(format!("{binary} not found on PATH"))
                } else {
                    AppError::JqFailed(e.to_string())
                }
            })?;
        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(json_str.as_bytes()).unwrap();
        }
        let output = child
            .wait_with_output()
            .map_err(|e| AppError::JqFailed(e.to_string()))?;
        if !output.status.success() {
            return Err(AppError::JqFailed("non-zero exit".to_string()));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_string())
    }
}
