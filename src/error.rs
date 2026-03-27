use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Config error: {0}")]
    Config(String),

    #[error("Config file not found: {0}")]
    ConfigNotFound(PathBuf),

    #[error("JWT verification failed: {0}")]
    Jwt(String),

    #[error("cmd_hash mismatch: expected {expected}, got {got}")]
    CmdHashMismatch { expected: String, got: String },

    #[error("Exec failed: {0}")]
    Exec(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Privilege error: {0}")]
    Privilege(String),

    #[error("Update error: {0}")]
    Update(String),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) | Error::ConfigNotFound(_) => 1,
            Error::Jwt(_) | Error::CmdHashMismatch { .. } => 5,
            Error::Exec(_) | Error::Privilege(_) => 126,
            Error::Http(_) | Error::Io(_) | Error::Json(_) | Error::Update(_) => 1,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Error::Config(msg) => {
                serde_json::json!({"error": "config", "message": msg})
            }
            Error::ConfigNotFound(path) => {
                serde_json::json!({"error": "config", "message": format!("Config file not found: {}", path.display())})
            }
            Error::Jwt(msg) => {
                serde_json::json!({"error": "jwt", "message": msg})
            }
            Error::CmdHashMismatch { expected, got } => {
                serde_json::json!({"error": "cmd_hash_mismatch", "expected": expected, "got": got})
            }
            Error::Exec(msg) => {
                serde_json::json!({"error": "exec", "message": msg})
            }
            _ => {
                serde_json::json!({"error": "internal", "message": self.to_string()})
            }
        }
    }
}
