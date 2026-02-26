use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::Error;

#[derive(Debug, Serialize)]
struct ChallengeRequest {
    agent_id: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Debug, Serialize)]
struct AuthenticateRequest {
    agent_id: String,
    challenge: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthenticateResponse {
    pub token: String,
    pub agent_id: String,
    pub name: String,
    pub expires_in: u64,
}

/// Perform challenge-response authentication against the IdP.
/// Returns the agent JWT token.
pub fn authenticate(server_url: &str, agent_id: &str, signing_key: &SigningKey) -> Result<String, Error> {
    // Step 1: Request challenge
    let challenge_url = format!("{server_url}/api/agent/challenge");
    let challenge_body = ChallengeRequest {
        agent_id: agent_id.to_string(),
    };

    let challenge_resp: ChallengeResponse = ureq::post(&challenge_url)
        .send_json(&challenge_body)
        .map_err(|e| Error::Auth(format!("Challenge request failed: {e}")))?
        .into_json()
        .map_err(|e| Error::Auth(format!("Failed to parse challenge response: {e}")))?;

    // Step 2: Sign challenge with pre-loaded key
    let signature = crypto::sign_challenge(signing_key, &challenge_resp.challenge);

    // Step 3: Authenticate with signature
    let auth_url = format!("{server_url}/api/agent/authenticate");
    let auth_body = AuthenticateRequest {
        agent_id: agent_id.to_string(),
        challenge: challenge_resp.challenge,
        signature,
    };

    let auth_resp: AuthenticateResponse = ureq::post(&auth_url)
        .send_json(&auth_body)
        .map_err(|e| Error::Auth(format!("Authentication failed: {e}")))?
        .into_json()
        .map_err(|e| Error::Auth(format!("Failed to parse auth response: {e}")))?;

    Ok(auth_resp.token)
}
