#![allow(dead_code)]

use std::fs::OpenOptions;
use std::io::Write;

use chrono::Utc;
use nix::unistd::Uid;

use crate::config::Config;
use crate::grants::Grant;

/// Write an audit log entry for a successful command run.
/// Called as root, before execvp. Failures are logged to stderr but don't
/// prevent the command from running.
pub fn log_run(
    config: &Config,
    real_uid: Uid,
    cmd: &[String],
    cmd_hash: &str,
    grant: &Grant,
) {
    let entry = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": "run",
        "real_uid": real_uid.as_raw(),
        "command": cmd,
        "cmd_hash": cmd_hash,
        "grant_id": grant.id,
        "grant_type": grant.request.grant_type,
        "agent_id": config.agent_id,
        "decided_by": grant.decided_by,
        "target": config.effective_target(),
        "cwd": std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
    });

    write_entry(config, &entry);
}

/// Write an audit log entry for a denied grant.
pub fn log_denied(
    config: &Config,
    real_uid: Uid,
    cmd: &[String],
    cmd_hash: &str,
    grant_id: &str,
    decided_by: &str,
) {
    let entry = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": "denied",
        "real_uid": real_uid.as_raw(),
        "command": cmd,
        "cmd_hash": cmd_hash,
        "grant_id": grant_id,
        "agent_id": config.agent_id,
        "decided_by": decided_by,
        "target": config.effective_target(),
    });

    write_entry(config, &entry);
}

/// Write an audit log entry for a timeout.
pub fn log_timeout(
    config: &Config,
    real_uid: Uid,
    cmd: &[String],
    cmd_hash: &str,
    grant_id: &str,
    secs: u64,
) {
    let entry = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": "timeout",
        "real_uid": real_uid.as_raw(),
        "command": cmd,
        "cmd_hash": cmd_hash,
        "grant_id": grant_id,
        "agent_id": config.agent_id,
        "target": config.effective_target(),
        "timeout_secs": secs,
    });

    write_entry(config, &entry);
}

/// Write an audit log entry for an error.
pub fn log_error(
    config: &Config,
    real_uid: Uid,
    cmd: &[String],
    message: &str,
) {
    let entry = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": "error",
        "real_uid": real_uid.as_raw(),
        "command": cmd,
        "agent_id": config.agent_id,
        "target": config.effective_target(),
        "message": message,
    });

    write_entry(config, &entry);
}

fn write_entry(config: &Config, entry: &serde_json::Value) {
    let log_path = config.effective_audit_log();

    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut file| {
            writeln!(file, "{entry}")
        });

    if let Err(e) = result {
        eprintln!(
            "{}",
            serde_json::json!({"warning": "audit_log_failed", "path": log_path.display().to_string(), "error": e.to_string()})
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config(dir: &std::path::Path) -> Config {
        Config {
            server_url: "https://test.example.com".into(),
            agent_id: "test-agent".into(),
            key_path: PathBuf::from("/dev/null"),
            target: Some("test-target".into()),
            audit_log: Some(dir.join("audit.log")),
            poll: crate::config::PollConfig::default(),
            tls: crate::config::TlsConfig::default(),
        }
    }

    #[test]
    fn test_write_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let entry = serde_json::json!({"event": "test", "ts": "2026-01-01T00:00:00Z"});
        write_entry(&config, &entry);

        let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(content.contains("\"event\":\"test\""));
    }

    #[test]
    fn test_append_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        write_entry(&config, &serde_json::json!({"n": 1}));
        write_entry(&config, &serde_json::json!({"n": 2}));

        let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
