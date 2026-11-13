//! LLM-agent auto-detection, lifted verbatim from algosearch (a shared
//! convention across these CLIs, not DocSearch-specific).
//! Layered by confidence, first match wins; every branch records
//! `detected_by` for debugging. `AppContext::new` only folds `is_agent`
//! into `Presenter::new` today — `detected_by` isn't surfaced by any
//! command response yet, so it's kept for future doctor/debug surfacing
//! and is exercised directly by this module's own tests.

use std::io::IsTerminal;

#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub is_agent: bool,
    #[allow(dead_code)]
    pub detected_by: Option<String>,
}

pub fn detect(force_agent: bool, json_explicit: bool) -> AgentInfo {
    // 1. Explicit --agent flag
    if force_agent {
        return AgentInfo {
            is_agent: true,
            detected_by: Some("--agent flag".to_string()),
        };
    }

    // 2. Known LLM agent environment variables
    let env_checks = [
        ("CLAUDE_CODE", None),
        ("CURSOR_SESSION", None),
        ("CODEX", None),
        ("CONTINUE_SESSION", None),
        ("AIDER_SESSION", None),
        ("LLM_AGENT", Some("1")),
    ];

    for (var, expected_val) in &env_checks {
        if let Ok(val) = std::env::var(var) {
            if expected_val.is_none() || expected_val == &Some(val.as_str()) {
                return AgentInfo {
                    is_agent: true,
                    detected_by: Some(format!("env {var}")),
                };
            }
        }
    }

    // CI=true combined with no TTY
    if std::env::var("CI").is_ok_and(|v| v == "true") && !std::io::stdin().is_terminal() {
        return AgentInfo {
            is_agent: true,
            detected_by: Some("CI=true + no TTY".to_string()),
        };
    }

    // 3. Parent process tree check
    if let Some(detected_by) = check_parent_processes() {
        return AgentInfo {
            is_agent: true,
            detected_by: Some(detected_by),
        };
    }

    // 4. TTY check: stdin not a terminal and --json not explicitly passed
    if !std::io::stdin().is_terminal() && !json_explicit {
        return AgentInfo {
            is_agent: true,
            detected_by: Some("no TTY on stdin".to_string()),
        };
    }

    AgentInfo {
        is_agent: false,
        detected_by: None,
    }
}

fn check_parent_processes() -> Option<String> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let known_agents = ["claude", "cursor", "codex", "aider", "continue"];
    let mut sys = System::new();

    let mut current_pid = Pid::from_u32(std::process::id());

    // Walk up to 10 levels of parent processes. Refresh ONLY the pid being
    // inspected (name + parent come from /proc/<pid>/stat): refreshing every
    // process scans all of /proc including per-thread files, which cost
    // seconds on a busy host and made every invocation (and the subprocess
    // contract tests' timing assertions) slow.
    for _ in 0..10 {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[current_pid]),
            false,
            ProcessRefreshKind::nothing(),
        );
        let process = sys.process(current_pid)?;
        let name = process.name().to_string_lossy().to_lowercase();

        for agent in &known_agents {
            if name.contains(agent) {
                return Some(format!("parent process: {name}"));
            }
        }

        current_pid = process.parent()?;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algolia::keys::TEST_ENV_MUTEX;

    #[test]
    fn test_force_agent_flag() {
        let info = detect(true, false);
        assert!(info.is_agent);
        assert_eq!(info.detected_by.as_deref(), Some("--agent flag"));
    }

    /// Every env var `detect()`'s step 2 checks, so a test targeting one
    /// can clear the rest first — these branches were previously entirely
    /// untested; this codebase's own dev/CI environment (the one these
    /// tests run in) may itself already have some of these set by an
    /// ambient coding-agent session, so every test below explicitly
    /// clears the full set before setting only the one var under test,
    /// and restores every prior value afterward, under `TEST_ENV_MUTEX`
    /// for the whole window.
    const AGENT_ENV_VARS: [&str; 6] = [
        "CLAUDE_CODE",
        "CURSOR_SESSION",
        "CODEX",
        "CONTINUE_SESSION",
        "AIDER_SESSION",
        "LLM_AGENT",
    ];

    fn with_agent_env<R>(set: &[(&str, &str)], body: impl FnOnce() -> R) -> R {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        let mut all_vars: Vec<&str> = AGENT_ENV_VARS.to_vec();
        all_vars.push("CI");
        let saved: Vec<(&str, Option<String>)> = all_vars
            .iter()
            .map(|v| (*v, std::env::var(v).ok()))
            .collect();

        for var in &all_vars {
            std::env::remove_var(var);
        }
        for (var, val) in set {
            std::env::set_var(var, val);
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));

        for (var, val) in saved {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }

        match result {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn env_var_claude_code_presence_alone_triggers_agent_mode() {
        with_agent_env(&[("CLAUDE_CODE", "anything")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("env CLAUDE_CODE"));
        });
    }

    #[test]
    fn env_var_cursor_session_presence_alone_triggers_agent_mode() {
        with_agent_env(&[("CURSOR_SESSION", "1")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("env CURSOR_SESSION"));
        });
    }

    #[test]
    fn env_var_codex_presence_alone_triggers_agent_mode() {
        with_agent_env(&[("CODEX", "1")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("env CODEX"));
        });
    }

    #[test]
    fn env_var_continue_session_presence_alone_triggers_agent_mode() {
        with_agent_env(&[("CONTINUE_SESSION", "1")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("env CONTINUE_SESSION"));
        });
    }

    #[test]
    fn env_var_aider_session_presence_alone_triggers_agent_mode() {
        with_agent_env(&[("AIDER_SESSION", "1")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("env AIDER_SESSION"));
        });
    }

    /// `LLM_AGENT` is the one var in the table with an `expected_val`
    /// (`Some("1")`) rather than `None` — presence isn't enough, the value
    /// must match exactly.
    #[test]
    fn env_var_llm_agent_requires_exact_value_match() {
        with_agent_env(&[("LLM_AGENT", "1")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("env LLM_AGENT"));
        });

        // A present-but-wrong-value LLM_AGENT must NOT match on its own —
        // falls through to whatever the next layer decides (still
        // asserted true here since step 3/4 downstream in this sandboxed
        // test process are themselves environment-dependent, but
        // `detected_by` must not claim the LLM_AGENT env match).
        with_agent_env(&[("LLM_AGENT", "0")], || {
            let info = detect(false, false);
            assert_ne!(info.detected_by.as_deref(), Some("env LLM_AGENT"));
        });
    }

    #[test]
    fn ci_true_with_no_tty_triggers_agent_mode() {
        // No agent env var set, but CI=true — combined with this test
        // process's stdin never being a real TTY (spawned by `cargo
        // test`), this must fire before the parent-process walk is ever
        // reached.
        with_agent_env(&[("CI", "true")], || {
            let info = detect(false, false);
            assert!(info.is_agent);
            assert_eq!(info.detected_by.as_deref(), Some("CI=true + no TTY"));
        });
    }
}
