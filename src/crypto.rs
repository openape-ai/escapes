use sha2::{Digest, Sha256};

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
