use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AgentConfig {
    pub name: String,
    pub public_key: String,
    pub server_url: String,
}

/// Raw deserialization target that can detect legacy format.
#[derive(Debug, Deserialize)]
struct RawConfig {
    // Legacy fields — presence triggers LegacyConfig error
    agent_id: Option<String>,
    key_path: Option<PathBuf>,
    server_url: Option<String>,

    // Current fields
    target: Option<String>,
    audit_log: Option<PathBuf>,

    #[serde(default)]
    poll: PollConfig,

    #[serde(default)]
    tls: TlsConfig,

    #[serde(default)]
    agents: Vec<AgentConfig>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Config {
    pub target: Option<String>,
    pub audit_log: Option<PathBuf>,
    pub poll: PollConfig,
    pub tls: TlsConfig,
    pub agents: Vec<AgentConfig>,
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

        let raw: RawConfig = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse {}: {e}", path.display())))?;

        // Detect legacy single-agent format
        if raw.agent_id.is_some() || raw.key_path.is_some() || (raw.server_url.is_some() && raw.agents.is_empty()) {
            return Err(Error::LegacyConfig);
        }

        let config = Config {
            target: raw.target,
            audit_log: raw.audit_log,
            poll: raw.poll,
            tls: raw.tls,
            agents: raw.agents,
        };

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.agents.is_empty() {
            return Err(Error::Config("No agents configured. Add at least one [[agents]] entry.".into()));
        }
        for agent in &self.agents {
            if agent.name.is_empty() {
                return Err(Error::Config("Agent name is required".into()));
            }
            if agent.public_key.is_empty() {
                return Err(Error::Config(format!("Agent '{}': public_key is required", agent.name)));
            }
            if agent.server_url.is_empty() {
                return Err(Error::Config(format!("Agent '{}': server_url is required", agent.name)));
            }
        }
        Ok(())
    }

    pub fn find_agent_by_public_key(&self, public_key: &str) -> Option<&AgentConfig> {
        self.agents.iter().find(|a| a.public_key == public_key)
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

        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
target = "my-server"

[poll]
interval_secs = 5
timeout_secs = 120

[[agents]]
name = "web-deploy"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"
server_url = "https://id.example.com"

[[agents]]
name = "system-admin"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther"
server_url = "https://id.example.com"
"#
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.agents.len(), 2);
        assert_eq!(config.agents[0].name, "web-deploy");
        assert_eq!(config.agents[1].name, "system-admin");
        assert_eq!(config.poll.interval_secs, 5);
        assert_eq!(config.poll.timeout_secs, 120);
        assert_eq!(config.effective_target(), "my-server");
    }

    #[test]
    fn test_find_agent_by_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
[[agents]]
name = "deploy"
public_key = "ssh-ed25519 AAAA"
server_url = "https://id.example.com"

[[agents]]
name = "admin"
public_key = "ssh-ed25519 BBBB"
server_url = "https://id2.example.com"
"#
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();

        let agent = config.find_agent_by_public_key("ssh-ed25519 BBBB");
        assert!(agent.is_some());
        assert_eq!(agent.unwrap().name, "admin");
        assert_eq!(agent.unwrap().server_url, "https://id2.example.com");

        assert!(config.find_agent_by_public_key("ssh-ed25519 CCCC").is_none());
    }

    #[test]
    fn test_legacy_config_detected() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
server_url = "https://id.example.com"
agent_id = "test-uuid"
key_path = "/dev/null"
"#
        )
        .unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::LegacyConfig));
    }

    #[test]
    fn test_empty_agents_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "target = \"test\"\n").unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
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
