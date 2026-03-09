use std::fs;
use std::os::unix::fs::PermissionsExt;

use toml_edit::DocumentMut;

use crate::error::Error;
use crate::exec;

const CONFIG_FILE: &str = "/etc/apes/config.toml";

/// Run the update subcommand.
///
/// Updates the server_url for an existing agent identified by its email.
pub fn run(server_url: &str, email: &str) -> Result<(), Error> {
    // 1. Elevate to root to modify global config
    exec::elevate()?;

    // 2. Read config
    let content = fs::read_to_string(CONFIG_FILE)
        .map_err(|e| Error::Config(format!("Failed to read {CONFIG_FILE}: {e}")))?;

    let mut doc = content.parse::<DocumentMut>()
        .map_err(|e| Error::Config(format!("Failed to parse {CONFIG_FILE}: {e}")))?;

    // 3. Find the [[agents]] entry with matching email
    let agents = doc.get_mut("agents")
        .and_then(|v| v.as_array_of_tables_mut())
        .ok_or_else(|| Error::Config(format!("No [[agents]] entries found in {CONFIG_FILE}")))?;

    let mut found = false;
    for agent in agents.iter_mut() {
        if let Some(e) = agent.get("email").and_then(|v| v.as_str()) {
            if e == email {
                agent["server_url"] = toml_edit::value(server_url);
                found = true;
                break;
            }
        }
    }

    if !found {
        return Err(Error::Config(format!(
            "No agent with email {email} found in {CONFIG_FILE}. Use `apes enroll` first."
        )));
    }

    // 4. Write config back
    fs::write(CONFIG_FILE, doc.to_string())
        .map_err(|e| Error::Config(format!("Failed to write {CONFIG_FILE}: {e}")))?;

    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o644))
        .map_err(|e| Error::Config(format!("Failed to set config permissions: {e}")))?;

    // 5. Drop back to real user
    let _ = exec::drop_privileges()?;

    eprintln!();
    eprintln!("  Updated server_url to: {server_url}");
    eprintln!("  Agent: {email}");
    eprintln!("  Config: {CONFIG_FILE}");
    eprintln!();

    Ok(())
}
