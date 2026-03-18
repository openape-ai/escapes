use std::io::Read;

use base64::Engine;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::Deserialize;

use crate::config::Config;
use crate::crypto;
use crate::error::Error;

/// Grant claims from the AuthZ-JWT issued by the IdP.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct GrantClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub target_host: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub grant_id: String,
    pub grant_type: String,
    pub approval: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub cmd_hash: Option<String>,
    pub command: Option<Vec<String>>,
    pub decided_by: Option<String>,
    pub run_as: Option<String>,
}

/// Unverified claims extracted from JWT payload before signature verification.
/// Used to determine which JWKS to fetch.
#[derive(Debug, Deserialize)]
struct UnverifiedClaims {
    iss: String,
}

/// Extract unverified claims from a JWT without signature verification.
/// This is safe because we verify the signature afterwards — we only use
/// the issuer to determine which JWKS endpoint to contact.
fn extract_unverified_claims(token: &str) -> Result<UnverifiedClaims, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("Malformed JWT: expected 3 parts".into()));
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| Error::Jwt(format!("Failed to decode JWT payload: {e}")))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Jwt(format!("Failed to parse JWT payload: {e}")))
}

/// Resolve the grant JWT from CLI arguments.
pub fn resolve_grant_jwt(
    grant_arg: Option<&str>,
    grant_stdin: bool,
    grant_file: Option<&std::path::Path>,
) -> Result<String, Error> {
    if let Some(jwt) = grant_arg {
        return Ok(jwt.to_string());
    }

    if grant_stdin {
        let mut jwt = String::new();
        std::io::stdin()
            .read_to_string(&mut jwt)
            .map_err(|e| Error::Config(format!("Failed to read grant from stdin: {e}")))?;
        return Ok(jwt.trim().to_string());
    }

    if let Some(path) = grant_file {
        let jwt = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read grant file {}: {e}", path.display())))?;
        return Ok(jwt.trim().to_string());
    }

    Err(Error::Config("No grant token provided. Use --grant <jwt>, --grant-stdin, or --grant-file <path>.".into()))
}

/// Verify the grant JWT with full security verification chain:
///
/// 1. Extract issuer from JWT (unverified)
/// 2. Check issuer is in allowed_issuers
/// 3. Fetch JWKS from {issuer}/.well-known/jwks.json
/// 4. Verify JWT signature
/// 5. Check decided_by is in allowed_approvers
/// 6. Check audience is in allowed_audiences
/// 7. Check target_host matches config host
pub fn verify_grant_jwt(token: &str, config: &Config) -> Result<GrantClaims, Error> {
    // Step 1: Extract issuer before any network call
    let unverified = extract_unverified_claims(token)?;

    // Step 2: Check issuer is trusted (reject unknown issuers before fetching JWKS)
    if !config.security.allowed_issuers.contains(&unverified.iss) {
        return Err(Error::Jwt(format!(
            "Issuer '{}' not in allowed_issuers: {:?}",
            unverified.iss, config.security.allowed_issuers
        )));
    }

    // Step 3: Fetch JWKS from the trusted issuer
    let jwks_uri = format!("{}/.well-known/jwks.json", unverified.iss);
    let header = decode_header(token)
        .map_err(|e| Error::Jwt(format!("Failed to decode JWT header: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| Error::Jwt("JWT header missing kid".into()))?;

    let jwks: JwkSet = ureq::get(&jwks_uri)
        .call()
        .map_err(|e| Error::Jwt(format!("Failed to fetch JWKS from {jwks_uri}: {e}")))?
        .into_json()
        .map_err(|e| Error::Jwt(format!("Failed to parse JWKS: {e}")))?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| Error::Jwt(format!("No matching key found for kid: {kid}")))?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| Error::Jwt(format!("Failed to create decoding key: {e}")))?;

    // Step 4: Verify JWT signature
    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false; // we validate audience manually below

    let token_data = decode::<GrantClaims>(token, &decoding_key, &validation)
        .map_err(|e| Error::Jwt(format!("JWT verification failed: {e}")))?;

    let claims = token_data.claims;

    // Step 5: Check decided_by is in allowed_approvers
    if let Some(ref decided_by) = claims.decided_by {
        if !config.security.allowed_approvers.contains(decided_by) {
            return Err(Error::Jwt(format!(
                "Approver '{}' not in allowed_approvers: {:?}",
                decided_by, config.security.allowed_approvers
            )));
        }
    } else {
        return Err(Error::Jwt("Grant token missing decided_by claim".into()));
    }

    // Step 6: Check audience is in allowed_audiences
    if !config.security.allowed_audiences.contains(&claims.aud) {
        return Err(Error::Jwt(format!(
            "Audience '{}' not in allowed_audiences: {:?}",
            claims.aud, config.security.allowed_audiences
        )));
    }

    // Step 7: Check target_host matches this machine
    let effective_host = config.effective_host();
    if claims.target_host != effective_host {
        return Err(Error::Jwt(format!(
            "target_host mismatch: JWT has '{}', this machine is '{}'",
            claims.target_host, effective_host
        )));
    }

    Ok(claims)
}

/// Verify the command matches the grant.
/// Checks both the command array (if present) and cmd_hash.
pub fn verify_command(claims: &GrantClaims, cmd: &[String]) -> Result<(), Error> {
    // If JWT has command array, compare directly
    if let Some(ref grant_cmd) = claims.command {
        if grant_cmd != cmd {
            return Err(Error::CmdHashMismatch {
                expected: grant_cmd.join(" "),
                got: cmd.join(" "),
            });
        }
        return Ok(());
    }

    // Fall back to cmd_hash comparison
    if let Some(ref expected_hash) = claims.cmd_hash {
        let actual_hash = crypto::cmd_hash(cmd);
        if *expected_hash != actual_hash {
            return Err(Error::CmdHashMismatch {
                expected: expected_hash.clone(),
                got: actual_hash,
            });
        }
        return Ok(());
    }

    // No command verification data in JWT — reject
    Err(Error::Jwt("Grant token has neither command nor cmd_hash — cannot verify command".into()))
}

/// Call the IdP consume endpoint to verify and consume the grant.
/// For `once` grants: marks as consumed atomically.
/// For `timed`/`always`: validates the grant is still active.
pub fn consume_grant(claims: &GrantClaims, token: &str) -> Result<(), Error> {
    let consume_url = format!("{}/api/grants/{}/consume", claims.iss, claims.grant_id);

    let response = ureq::post(&consume_url)
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                Error::Http(format!("Grant consume rejected (HTTP {code}): {body}"))
            }
            other => Error::Http(format!("Failed to contact IdP for consume check: {other}")),
        })?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| Error::Http(format!("Failed to parse consume response: {e}")))?;

    // Check for error responses (non-approved grants return 200 with error field)
    if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
        return Err(Error::Jwt(format!("Grant rejected by IdP: {error}")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(overrides: impl FnOnce(&mut GrantClaims)) -> GrantClaims {
        let mut claims = GrantClaims {
            iss: "https://id.example.com".into(),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            target_host: "macmini".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-1".into(),
            grant_type: "once".into(),
            approval: Some("once".into()),
            permissions: None,
            cmd_hash: None,
            command: None,
            decided_by: Some("admin@example.com".into()),
            run_as: None,
        };
        overrides(&mut claims);
        claims
    }

    #[test]
    fn test_extract_unverified_claims() {
        // Build a minimal JWT payload
        let payload = serde_json::json!({
            "iss": "https://id.openape.at",
            "sub": "agent@example.com",
            "aud": "apes",
            "target_host": "macmini",
            "iat": 0,
            "exp": 9999999999u64,
            "jti": "test",
            "grant_id": "g1",
            "grant_type": "once",
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());

        // header.payload.signature — we only need payload for this test
        let fake_jwt = format!("eyJhbGciOiJFZERTQSJ9.{payload_b64}.fake_sig");
        let claims = extract_unverified_claims(&fake_jwt).unwrap();
        assert_eq!(claims.iss, "https://id.openape.at");
    }

    #[test]
    fn test_extract_unverified_claims_malformed() {
        assert!(extract_unverified_claims("not-a-jwt").is_err());
        assert!(extract_unverified_claims("a.b").is_err());
    }

    #[test]
    fn test_verify_command_with_array() {
        let claims = make_claims(|c| {
            c.command = Some(vec!["brew".into(), "install".into(), "ffmpeg".into()]);
        });

        let cmd = vec!["brew".into(), "install".into(), "ffmpeg".into()];
        assert!(verify_command(&claims, &cmd).is_ok());

        let bad_cmd = vec!["brew".into(), "install".into(), "vim".into()];
        assert!(verify_command(&claims, &bad_cmd).is_err());
    }

    #[test]
    fn test_verify_command_with_hash() {
        let cmd = vec!["rm".into(), "-rf".into(), "/tmp/test".into()];
        let hash = crypto::cmd_hash(&cmd);

        let claims = make_claims(|c| {
            c.cmd_hash = Some(hash);
        });

        assert!(verify_command(&claims, &cmd).is_ok());

        let bad_cmd = vec!["rm".into(), "-rf".into(), "/".into()];
        assert!(verify_command(&claims, &bad_cmd).is_err());
    }

    #[test]
    fn test_verify_command_no_data_rejects() {
        let claims = make_claims(|_| {});

        let cmd = vec!["ls".into()];
        assert!(verify_command(&claims, &cmd).is_err());
    }

    #[test]
    fn test_resolve_grant_jwt_from_arg() {
        let jwt = resolve_grant_jwt(Some("eyJhbG.test.jwt"), false, None).unwrap();
        assert_eq!(jwt, "eyJhbG.test.jwt");
    }

    #[test]
    fn test_resolve_grant_jwt_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grant.jwt");
        std::fs::write(&path, "  eyJhbG.file.jwt  \n").unwrap();

        let jwt = resolve_grant_jwt(None, false, Some(&path)).unwrap();
        assert_eq!(jwt, "eyJhbG.file.jwt");
    }

    #[test]
    fn test_resolve_grant_jwt_none_fails() {
        assert!(resolve_grant_jwt(None, false, None).is_err());
    }

    #[test]
    fn test_consume_grant_success() {
        let server = httpmock::MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/api/grants/grant-1/consume")
                .header("Authorization", "Bearer test-token");
            then.status(200)
                .json_body(serde_json::json!({"status": "consumed"}));
        });

        let claims = make_claims(|c| {
            c.iss = server.url("");
            c.command = Some(vec!["brew".into(), "install".into(), "ffmpeg".into()]);
        });

        let result = consume_grant(&claims, "test-token");
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_consume_grant_already_consumed() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/api/grants/grant-1/consume");
            then.status(200)
                .json_body(serde_json::json!({"error": "already_consumed", "status": "used"}));
        });

        let claims = make_claims(|c| {
            c.iss = server.url("");
        });

        let result = consume_grant(&claims, "test-token");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already_consumed"), "Expected already_consumed error, got: {err}");
    }

    #[test]
    fn test_consume_grant_revoked() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/api/grants/grant-1/consume");
            then.status(200)
                .json_body(serde_json::json!({"error": "revoked", "status": "revoked"}));
        });

        let claims = make_claims(|c| {
            c.iss = server.url("");
        });

        let result = consume_grant(&claims, "test-token");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("revoked"), "Expected revoked error, got: {err}");
    }

    #[test]
    fn test_consume_grant_http_error() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/api/grants/grant-1/consume");
            then.status(401)
                .body("Unauthorized");
        });

        let claims = make_claims(|c| {
            c.iss = server.url("");
        });

        let result = consume_grant(&claims, "test-token");
        assert!(result.is_err());
    }
}
