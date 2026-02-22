use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::Error;

#[derive(Debug, Serialize)]
struct CreateGrantRequest {
    requester: String,
    target: String,
    grant_type: String,
    command: Vec<String>,
    cmd_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Grant {
    pub id: String,
    pub status: String,
    pub request: GrantRequest,
    pub decided_by: Option<String>,
    pub created_at: Option<serde_json::Value>,
    pub decided_at: Option<serde_json::Value>,
    pub expires_at: Option<serde_json::Value>,
    pub used_at: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GrantRequest {
    pub requester: String,
    pub target: String,
    pub grant_type: String,
    pub cmd_hash: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    #[serde(rename = "authzJWT")]
    pub authz_jwt: String,
    pub grant: Grant,
}

/// Create a new grant request.
pub fn create_grant(
    config: &Config,
    agent_token: &str,
    target: &str,
    command: &[String],
    cmd_hash: &str,
    reason: Option<&str>,
) -> Result<Grant, Error> {
    let url = format!("{}/api/grants", config.server_url);
    let body = CreateGrantRequest {
        requester: String::new(), // server overrides with agent identity
        target: target.to_string(),
        grant_type: "once".to_string(),
        command: command.to_vec(),
        cmd_hash: cmd_hash.to_string(),
        reason: reason.map(|r| r.to_string()),
    };

    let grant: Grant = ureq::post(&url)
        .set("Authorization", &format!("Bearer {agent_token}"))
        .send_json(&body)
        .map_err(|e| Error::Http(format!("Failed to create grant: {e}")))?
        .into_json()
        .map_err(|e| Error::Http(format!("Failed to parse grant response: {e}")))?;

    Ok(grant)
}

/// Poll for grant approval until approved, denied, or timeout.
pub fn poll_grant(
    config: &Config,
    agent_token: &str,
    grant_id: &str,
    timeout_secs: u64,
    interval_secs: u64,
) -> Result<Grant, Error> {
    let url = format!("{}/api/grants/{}", config.server_url, grant_id);
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let interval = Duration::from_secs(interval_secs);

    loop {
        if start.elapsed() >= timeout {
            return Err(Error::Timeout {
                grant_id: grant_id.to_string(),
                secs: timeout_secs,
            });
        }

        let grant: Grant = ureq::get(&url)
            .set("Authorization", &format!("Bearer {agent_token}"))
            .call()
            .map_err(|e| Error::Http(format!("Failed to poll grant: {e}")))?
            .into_json()
            .map_err(|e| Error::Http(format!("Failed to parse grant poll response: {e}")))?;

        match grant.status.as_str() {
            "approved" => return Ok(grant),
            "denied" | "revoked" => {
                return Err(Error::Denied {
                    grant_id: grant_id.to_string(),
                    decided_by: grant.decided_by.unwrap_or_else(|| "unknown".into()),
                });
            }
            "pending" => {
                thread::sleep(interval);
            }
            other => {
                return Err(Error::Http(format!("Unexpected grant status: {other}")));
            }
        }
    }
}

/// Get the authorization token for an approved grant.
pub fn get_token(
    config: &Config,
    agent_token: &str,
    grant_id: &str,
) -> Result<TokenResponse, Error> {
    let url = format!("{}/api/grants/{}/token", config.server_url, grant_id);

    let resp: TokenResponse = ureq::post(&url)
        .set("Authorization", &format!("Bearer {agent_token}"))
        .call()
        .map_err(|e| Error::Http(format!("Failed to get grant token: {e}")))?
        .into_json()
        .map_err(|e| Error::Http(format!("Failed to parse token response: {e}")))?;

    Ok(resp)
}
