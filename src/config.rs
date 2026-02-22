use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    pub server_url: String,
    pub agent_id: String,
    pub key_path: PathBuf,
    pub target: Option<String>,
    pub audit_log: Option<PathBuf>,

    #[serde(default)]
    pub poll: PollConfig,

    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Deserialize)]
pub struct PollConfig {
    #[serde(default = "default_poll_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_poll_timeout")]
    pub timeout_secs: u64,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_poll_interval(),
            timeout_secs: default_poll_timeout(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
pub struct TlsConfig {
    pub ca_bundle: Option<PathBuf>,
}

fn default_poll_interval() -> u64 {
    2
}

fn default_poll_timeout() -> u64 {
    300
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Err(Error::ConfigNotFound(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read {}: {e}", path.display())))?;

        let config: Config = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse {}: {e}", path.display())))?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.server_url.is_empty() {
            return Err(Error::Config("server_url is required".into()));
        }
        if self.agent_id.is_empty() {
            return Err(Error::Config("agent_id is required".into()));
        }
        if !self.key_path.exists() {
            return Err(Error::Config(format!(
                "Key file not found: {}",
                self.key_path.display()
            )));
        }
        Ok(())
    }

    pub fn effective_target(&self) -> String {
        self.target
            .clone()
            .unwrap_or_else(|| hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_else(|_| "unknown".into()))
    }

    pub fn effective_audit_log(&self) -> PathBuf {
        self.audit_log
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/log/apes/audit.log"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("agent.key");
        std::fs::write(&key_path, "dummy-key").unwrap();

        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
server_url = "https://id.example.com"
agent_id = "test-uuid"
key_path = "{}"
target = "my-server"
"#,
            key_path.display()
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.server_url, "https://id.example.com");
        assert_eq!(config.agent_id, "test-uuid");
        assert_eq!(config.poll.interval_secs, 2);
        assert_eq!(config.poll.timeout_secs, 300);
        assert_eq!(config.effective_target(), "my-server");
    }

    #[test]
    fn test_missing_config_file() {
        let result = Config::load(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_defaults() {
        let poll = PollConfig::default();
        assert_eq!(poll.interval_secs, 2);
        assert_eq!(poll.timeout_secs, 300);
    }
}
