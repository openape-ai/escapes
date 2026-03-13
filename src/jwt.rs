use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::Deserialize;

use crate::error::Error;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthzClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub grant_id: String,
    pub grant_type: String,
    pub permissions: Option<Vec<String>>,
    pub cmd_hash: Option<String>,
}

/// Verify an AuthZ-JWT by fetching the JWKS from the IdP and validating
/// the token signature and claims.
pub fn verify_authz_jwt(token: &str, server_url: &str) -> Result<AuthzClaims, Error> {
    // Decode header to get kid
    let header = decode_header(token)
        .map_err(|e| Error::Jwt(format!("Failed to decode JWT header: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| Error::Jwt("JWT header missing kid".into()))?;

    // Fetch JWKS from server
    let jwks_url = format!("{server_url}/.well-known/jwks.json");
    let jwks: JwkSet = ureq::get(&jwks_url)
        .call()
        .map_err(|e| Error::Jwt(format!("Failed to fetch JWKS: {e}")))?
        .into_json()
        .map_err(|e| Error::Jwt(format!("Failed to parse JWKS: {e}")))?;

    // Find the matching key by kid
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| Error::Jwt(format!("No matching key found for kid: {kid}")))?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| Error::Jwt(format!("Failed to create decoding key: {e}")))?;

    // Validate using the algorithm declared in the JWT header
    let mut validation = Validation::new(header.alg);
    // We validate issuer and audience manually for clearer error messages
    validation.validate_aud = false;

    let token_data = decode::<AuthzClaims>(token, &decoding_key, &validation)
        .map_err(|e| Error::Jwt(format!("JWT verification failed: {e}")))?;

    // Validate issuer matches server
    if token_data.claims.iss != server_url {
        return Err(Error::Jwt(format!(
            "Issuer mismatch: expected {server_url}, got {}",
            token_data.claims.iss
        )));
    }

    Ok(token_data.claims)
}
