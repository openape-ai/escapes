use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    /// Trusted issuer URLs (REQUIRED, non-empty)
    pub allowed_issuers: Vec<String>,

    /// Allowed approver identifiers (REQUIRED, non-empty)
    pub allowed_approvers: Vec<String>,

    /// Allowed JWT audiences (default: ["apes"])
    #[serde(default = "default_allowed_audiences")]
    pub allowed_audiences: Vec<String>,
}

fn default_allowed_audiences() -> Vec<String> {
    vec!["apes".to_string()]
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
pub struct TlsConfig {
    pub ca_bundle: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    /// Hostname for target_host verification (default: system hostname)
    #[serde(default)]
    pub host: Option<String>,

    /// Default user to run as (default: "root")
    #[serde(default = "default_run_as")]
    pub run_as: String,

    /// Audit log path
    #[serde(default = "default_audit_log")]
    pub audit_log: PathBuf,

    /// Security configuration
    pub security: SecurityConfig,

    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,
}

fn default_run_as() -> String {
    "root".to_string()
}

fn default_audit_log() -> PathBuf {
    PathBuf::from("/var/log/apes/audit.log")
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
        if self.security.allowed_issuers.is_empty() {
            return Err(Error::Config(
                "[security] allowed_issuers must not be empty".into(),
            ));
        }
        if self.security.allowed_approvers.is_empty() {
            return Err(Error::Config(
                "[security] allowed_approvers must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// Returns the configured host or the system hostname.
    pub fn effective_host(&self) -> String {
        self.host.clone().unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into())
        })
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
host = "macmini"
run_as = "root"

[security]
allowed_issuers = ["https://id.openape.at"]
allowed_approvers = ["phofmann@delta-mind.at"]
allowed_audiences = ["apes"]
"#
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.effective_host(), "macmini");
        assert_eq!(config.run_as, "root");
        assert_eq!(
            config.security.allowed_issuers,
            vec!["https://id.openape.at"]
        );
        assert_eq!(
            config.security.allowed_approvers,
            vec!["phofmann@delta-mind.at"]
        );
        assert_eq!(config.security.allowed_audiences, vec!["apes"]);
    }

    #[test]
    fn test_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
[security]
allowed_issuers = ["https://id.openape.at"]
allowed_approvers = ["admin@example.com"]
"#
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.run_as, "root");
        assert_eq!(config.audit_log, PathBuf::from("/var/log/apes/audit.log"));
        assert_eq!(config.security.allowed_audiences, vec!["apes"]);
        assert!(config.host.is_none());
        // effective_host should return system hostname when not configured
        assert!(!config.effective_host().is_empty());
    }

    #[test]
    fn test_empty_issuers_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
[security]
allowed_issuers = []
allowed_approvers = ["admin@example.com"]
"#
        )
        .unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("allowed_issuers"),
            "error should mention allowed_issuers: {msg}"
        );
    }

    #[test]
    fn test_empty_approvers_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
[security]
allowed_issuers = ["https://id.openape.at"]
allowed_approvers = []
"#
        )
        .unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("allowed_approvers"),
            "error should mention allowed_approvers: {msg}"
        );
    }

    #[test]
    fn test_missing_config_file() {
        let result = Config::load(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ConfigNotFound(_)));
    }

    #[test]
    fn test_missing_security_section_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "host = \"test\"\n").unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
audit_log = "/custom/audit.log"

[security]
allowed_issuers = ["https://id.openape.at"]
allowed_approvers = ["admin@example.com"]
"#
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.audit_log, PathBuf::from("/custom/audit.log"));
    }

    #[test]
    fn test_tls_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
[security]
allowed_issuers = ["https://id.openape.at"]
allowed_approvers = ["admin@example.com"]

[tls]
ca_bundle = "/etc/ssl/custom-ca.pem"
"#
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(
            config.tls.ca_bundle.as_deref(),
            Some(Path::new("/etc/ssl/custom-ca.pem"))
        );
    }
}
