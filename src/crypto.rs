use std::path::Path;

use base64::Engine;
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Digest, Sha256};
use ssh_key::PrivateKey;

use crate::error::Error;

/// Load an Ed25519 signing key from an OpenSSH private key file.
/// Must be called while still root (key file is 0600 root-owned).
pub fn load_signing_key(key_path: &Path) -> Result<SigningKey, Error> {
    let ssh_key = PrivateKey::read_openssh_file(key_path)
        .map_err(|e| Error::Auth(format!("Failed to read key {}: {e}", key_path.display())))?;

    let ed25519_keypair = ssh_key
        .key_data()
        .ed25519()
        .ok_or(Error::WrongKeyType)?;

    let secret_bytes: &[u8; 32] = ed25519_keypair.private.as_ref();
    Ok(SigningKey::from_bytes(secret_bytes))
}

/// Sign a challenge with a pre-loaded signing key.
/// Returns the signature as base64 (matching the server's expected format).
pub fn sign_challenge(signing_key: &SigningKey, challenge: &str) -> String {
    let signature = signing_key.sign(challenge.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
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
}
