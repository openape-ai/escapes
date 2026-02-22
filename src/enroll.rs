use std::fs;
use std::os::unix::fs::PermissionsExt;

use ssh_key::{Algorithm, PrivateKey};
use uuid::Uuid;

use crate::error::Error;

const CONFIG_DIR: &str = "/etc/apes";

/// Run the enroll subcommand.
pub fn run(server_url: &str, agent_name: Option<String>) -> Result<(), Error> {
    let name = agent_name.unwrap_or_else(|| {
        hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "apes-agent".into())
    });

    let agent_id = Uuid::new_v4().to_string();

    // Ensure config directory exists
    fs::create_dir_all(CONFIG_DIR)
        .map_err(|e| Error::Config(format!("Failed to create {CONFIG_DIR}: {e}")))?;

    fs::set_permissions(CONFIG_DIR, fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::Config(format!("Failed to set permissions on {CONFIG_DIR}: {e}")))?;

    // Generate Ed25519 keypair
    let key_path = format!("{CONFIG_DIR}/agent.key");
    let private_key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
        .map_err(|e| Error::Config(format!("Failed to generate keypair: {e}")))?;

    let private_pem = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| Error::Config(format!("Failed to encode private key: {e}")))?;

    fs::write(&key_path, private_pem.as_bytes())
        .map_err(|e| Error::Config(format!("Failed to write key: {e}")))?;

    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::Config(format!("Failed to set key permissions: {e}")))?;

    // Get public key
    let public_key = private_key.public_key().to_openssh()
        .map_err(|e| Error::Config(format!("Failed to export public key: {e}")))?;

    // Write config with agent_id already set
    let config_content = format!(
        r#"server_url = "{server_url}"
agent_id = "{agent_id}"
key_path = "{key_path}"
# target = "{name}"  # Uncomment to override hostname
# audit_log = "/var/log/apes/audit.log"

[poll]
interval_secs = 2
timeout_secs = 300
"#
    );

    let config_file = format!("{CONFIG_DIR}/config.toml");
    fs::write(&config_file, &config_content)
        .map_err(|e| Error::Config(format!("Failed to write config: {e}")))?;

    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::Config(format!("Failed to set config permissions: {e}")))?;

    // Build enrollment URL for admin (includes agent_id)
    let encoded_name = name.replace(' ', "%20");
    let encoded_key = public_key.replace(' ', "%20");
    let enroll_url = format!(
        "{server_url}/enroll?name={encoded_name}&key={encoded_key}&id={agent_id}"
    );

    eprintln!();
    eprintln!("  Agent enrolled locally.");
    eprintln!();
    eprintln!("  Agent ID:    {agent_id}");
    eprintln!("  Agent Name:  {name}");
    eprintln!("  Config:      {config_file}");
    eprintln!("  Key:         {key_path}");
    eprintln!("  Public Key:  {public_key}");
    eprintln!();
    eprintln!("  Share this URL with your admin to complete enrollment:");
    eprintln!("  {enroll_url}");
    eprintln!();
    eprintln!("  The agent is ready to use once the admin approves.");
    eprintln!();

    Ok(())
}
