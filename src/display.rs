//! Minimal shared human-format helpers. Command-specific rendering lives in
//! each command module's own closure passed to `Presenter::success` — this
//! file holds only the small pieces reused across more than one command.

use colored::Colorize;

/// A single `label: value` line, label dimmed, for simple key/value human
/// output blocks.
pub fn kv_line(label: &str, value: impl std::fmt::Display) -> String {
    format!("{} {}", format!("{label}:").dimmed(), value)
}

/// Section heading used at the top of a command's human-mode output.
pub fn heading(title: &str) -> String {
    title.bold().to_string()
}

/// Renders `ok`/`!!`/`--` status markers consistently across commands
/// (doctor's capability matrix, keys audit warnings, etc.).
pub fn status_marker(ok: bool) -> colored::ColoredString {
    if ok {
        "OK".green()
    } else {
        "!!".red()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_line_includes_label_and_value() {
        let line = kv_line("app_id", "ABC123");
        assert!(line.contains("app_id"));
        assert!(line.contains("ABC123"));
    }

    #[test]
    fn heading_returns_title_text() {
        assert_eq!(heading("alx doctor"), "alx doctor");
    }
}
