use std::fs;
use std::os::unix::fs::PermissionsExt;

use toml_edit::DocumentMut;

use crate::auth;
use crate::config::Config;
use crate::crypto;
use crate::error::Error;
use crate::exec;

const CONFIG_FILE: &str = "/etc/apes/config.toml";

/// Run the remove subcommand.
///
/// Removes an agent from the local config (identified by email).
/// If `remote` is true, also deletes the agent on the IdP server via challenge-response auth.
pub fn run(email: &str, remote: bool) -> Result<(), Error> {
    // 1. Elevate to root to read/modify global config
    exec::elevate()?;

    // 2. Read and parse config
    let content = fs::read_to_string(CONFIG_FILE)
        .map_err(|e| Error::Config(format!("Failed to read {CONFIG_FILE}: {e}")))?;

    let config = Config::load(std::path::Path::new(CONFIG_FILE))?;

    let agent = config.find_agent_by_email(email)
        .ok_or_else(|| Error::Config(format!(
            "No agent with email {email} found in {CONFIG_FILE}."
        )))?;

    // 3. Remote deletion (if requested)
    if remote {
        let server_url = agent.server_url.clone();

        // Drop privileges to read user's key
        let _real_uid = exec::drop_privileges()?;

        // We need a key to authenticate — find it from CLI context or config
        // For remote deletion, we need the user to have access to the key.
        // We'll look for the key in the standard location.
        let key_path = std::path::Path::new("/etc/apes/agent.key");
        if !key_path.exists() {
            return Err(Error::Config(
                "Cannot authenticate for remote deletion: /etc/apes/agent.key not found. \
                 Use --remote false to only remove from local config.".into()
            ));
        }

        let (signing_key, _public_key) = crypto::load_key_and_derive_public(key_path)?;

        // Re-elevate for config modification
        exec::elevate()?;

        // Authenticate and delete on server
        let token = auth::authenticate(&server_url, email, &signing_key)?;

        let delete_url = format!("{server_url}/api/my-agent");
        let resp = ureq::delete(&delete_url)
            .set("Authorization", &format!("Bearer {token}"))
            .call();

        match resp {
            Ok(_) => eprintln!("  Agent deleted on server."),
            Err(e) => eprintln!("  Warning: remote deletion failed: {e}"),
        }
    }

    // 4. Remove from local config
    let mut doc = content.parse::<DocumentMut>()
        .map_err(|e| Error::Config(format!("Failed to parse {CONFIG_FILE}: {e}")))?;

    let agents = doc.get_mut("agents")
        .and_then(|v| v.as_array_of_tables_mut())
        .ok_or_else(|| Error::Config(format!("No [[agents]] entries found in {CONFIG_FILE}")))?;

    let mut index_to_remove = None;
    for (i, agent) in agents.iter().enumerate() {
        if let Some(e) = agent.get("email").and_then(|v| v.as_str()) {
            if e == email {
                index_to_remove = Some(i);
                break;
            }
        }
    }

    match index_to_remove {
        Some(i) => { agents.remove(i); }
        None => {
            return Err(Error::Config(format!(
                "No agent with email {email} found in {CONFIG_FILE}."
            )));
        }
    }

    // 5. Write config back
    fs::write(CONFIG_FILE, doc.to_string())
        .map_err(|e| Error::Config(format!("Failed to write {CONFIG_FILE}: {e}")))?;

    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o644))
        .map_err(|e| Error::Config(format!("Failed to set config permissions: {e}")))?;

    // 6. Drop back to real user
    let _ = exec::drop_privileges()?;

    eprintln!();
    eprintln!("  Removed agent: {email}");
    eprintln!("  Config: {CONFIG_FILE}");
    eprintln!();

    Ok(())
}
