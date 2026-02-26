use std::path::Path;

use base64::Engine;
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Digest, Sha256};
use ssh_key::PrivateKey;

use crate::error::Error;

/// Sign a challenge with a pre-loaded signing key.
/// Returns the signature as base64 (matching the server's expected format).
pub fn sign_challenge(signing_key: &SigningKey, challenge: &str) -> String {
    let signature = signing_key.sign(challenge.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
}

/// Load a private key and derive the public key in OpenSSH format.
/// Must be called as the real user (after privilege drop) since the key is user-owned.
pub fn load_key_and_derive_public(key_path: &Path) -> Result<(SigningKey, String), Error> {
    let ssh_key = PrivateKey::read_openssh_file(key_path)
        .map_err(|e| Error::Auth(format!("Failed to read key {}: {e}", key_path.display())))?;

    let ed25519_keypair = ssh_key
        .key_data()
        .ed25519()
        .ok_or(Error::WrongKeyType)?;

    let secret_bytes: &[u8; 32] = ed25519_keypair.private.as_ref();
    let signing_key = SigningKey::from_bytes(secret_bytes);

    let public_key = ssh_key
        .public_key()
        .to_openssh()
        .map_err(|e| Error::Auth(format!("Failed to export public key: {e}")))?;

    Ok((signing_key, public_key))
}

/// Derive agent_id from a public key string: sha256(public_key) as hex.
pub fn derive_agent_id(public_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of a command and its arguments.
/// Format: hash of space-joined command parts.
pub fn cmd_hash(cmd: &[String]) -> String {
    let input = cmd.join(" ");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_hash_deterministic() {
        let cmd = vec!["rm".to_string(), "-rf".to_string(), "/tmp/test".to_string()];
        let hash1 = cmd_hash(&cmd);
        let hash2 = cmd_hash(&cmd);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_cmd_hash_differs_for_different_commands() {
        let cmd1 = vec!["ls".to_string()];
        let cmd2 = vec!["pwd".to_string()];
        assert_ne!(cmd_hash(&cmd1), cmd_hash(&cmd2));
    }

    #[test]
    fn test_derive_agent_id_deterministic() {
        let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest";
        let id1 = derive_agent_id(pubkey);
        let id2 = derive_agent_id(pubkey);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_derive_agent_id_differs_for_different_keys() {
        let id1 = derive_agent_id("ssh-ed25519 AAAA");
        let id2 = derive_agent_id("ssh-ed25519 BBBB");
        assert_ne!(id1, id2);
    }
}
