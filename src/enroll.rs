use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ssh_key::{Algorithm, PrivateKey};

use crate::error::Error;
use crate::exec;

const CONFIG_DIR: &str = "/etc/apes";
const CONFIG_FILE: &str = "/etc/apes/config.toml";

/// Run the enroll subcommand.
///
/// Flow:
/// 1. Drop privileges to real user (key operations as user)
/// 2. Generate or load key from key_path
/// 3. Derive public key and agent_id
/// 4. Re-elevate to root to modify global config
/// 5. Append [[agents]] block to config
/// 6. Drop back to real user
/// 7. Print enrollment URL
pub fn run(server_url: &str, agent_email: &str, agent_name: &str, key_path: &Path, existing: bool) -> Result<(), Error> {
    // 1. Drop privileges — key operations happen as real user
    let _real_uid = exec::drop_privileges()?;

    // 2. Generate or load key
    let public_key = if key_path.exists() {
        let private_key = PrivateKey::read_openssh_file(key_path)
            .map_err(|e| Error::Config(format!("Failed to read key {}: {e}", key_path.display())))?;
        let public_key = private_key
            .public_key()
            .to_openssh()
            .map_err(|e| Error::Config(format!("Failed to export public key: {e}")))?;
        eprintln!("  Using existing key: {}", key_path.display());
        public_key
    } else {
        // Generate new Ed25519 keypair
        let private_key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
            .map_err(|e| Error::Config(format!("Failed to generate keypair: {e}")))?;

        let private_pem = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| Error::Config(format!("Failed to encode private key: {e}")))?;

        // Ensure parent directory exists (as user)
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("Failed to create key directory {}: {e}", parent.display())))?;
        }

        fs::write(key_path, private_pem.as_bytes())
            .map_err(|e| Error::Config(format!("Failed to write key: {e}")))?;

        fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Config(format!("Failed to set key permissions: {e}")))?;

        let public_key = private_key
            .public_key()
            .to_openssh()
            .map_err(|e| Error::Config(format!("Failed to export public key: {e}")))?;

        eprintln!("  Generated new key: {}", key_path.display());
        public_key
    };

    // 3. Re-elevate to root to modify global config
    exec::elevate()?;

    // Ensure config directory exists
    fs::create_dir_all(CONFIG_DIR)
        .map_err(|e| Error::Config(format!("Failed to create {CONFIG_DIR}: {e}")))?;

    fs::set_permissions(CONFIG_DIR, fs::Permissions::from_mode(0o755))
        .map_err(|e| Error::Config(format!("Failed to set permissions on {CONFIG_DIR}: {e}")))?;

    // 4a. Duplicate guard — reject if this email is already in the config
    if Path::new(CONFIG_FILE).exists() {
        let existing_content = fs::read_to_string(CONFIG_FILE)
            .map_err(|e| Error::Config(format!("Failed to read {CONFIG_FILE}: {e}")))?;
        if existing_content.contains(agent_email) {
            return Err(Error::Config(format!(
                "Agent with email {agent_email} already enrolled in {CONFIG_FILE}. Use `apes update --email {agent_email} --server <new-url>` to change the server URL.",
            )));
        }
    }

    // 4b. Append [[agents]] block to config (or create config if it doesn't exist)
    let agent_block = format!(
        r#"
[[agents]]
name = "{agent_name}"
email = "{agent_email}"
public_key = "{public_key}"
server_url = "{server_url}"
"#
    );

    if Path::new(CONFIG_FILE).exists() {
        // Append to existing config
        let existing = fs::read_to_string(CONFIG_FILE)
            .map_err(|e| Error::Config(format!("Failed to read {CONFIG_FILE}: {e}")))?;
        let new_content = format!("{existing}{agent_block}");
        fs::write(CONFIG_FILE, &new_content)
            .map_err(|e| Error::Config(format!("Failed to write {CONFIG_FILE}: {e}")))?;
    } else {
        // Create new config with defaults + first agent
        let config_content = format!(
            r#"# target = "{hostname}"
# audit_log = "/var/log/apes/audit.log"

[poll]
interval_secs = 2
timeout_secs = 300
{agent_block}"#,
            hostname = hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
        );
        fs::write(CONFIG_FILE, &config_content)
            .map_err(|e| Error::Config(format!("Failed to write {CONFIG_FILE}: {e}")))?;
    }

    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o644))
        .map_err(|e| Error::Config(format!("Failed to set config permissions: {e}")))?;

    // 5. Drop back to real user
    let _ = exec::drop_privileges()?;

    // 6. Print enrollment info
    eprintln!();
    eprintln!("  Agent enrolled locally.");
    eprintln!();
    eprintln!("  Agent Name:  {agent_name}");
    eprintln!("  Agent Email: {agent_email}");
    eprintln!("  Config:      {CONFIG_FILE}");
    eprintln!("  Key:         {}", key_path.display());
    eprintln!("  Public Key:  {public_key}");

    if existing {
        eprintln!();
        eprintln!("  Agent added to local config (server-side enrollment skipped).");
    } else {
        let encoded_email = agent_email.replace(' ', "%20");
        let encoded_name = agent_name.replace(' ', "%20");
        let encoded_key = public_key.replace(' ', "%20");
        let enroll_url = format!(
            "{server_url}/enroll?email={encoded_email}&name={encoded_name}&key={encoded_key}"
        );

        eprintln!();
        eprintln!("  Share this URL with your admin to complete enrollment:");
        eprintln!("  {enroll_url}");
        eprintln!();
        eprintln!("  The agent is ready to use once the admin approves.");
    }
    eprintln!();

    Ok(())
}
