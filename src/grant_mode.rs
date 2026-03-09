use std::io::Read;

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
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

    Err(Error::Config("No grant token provided".into()))
}

/// Verify the grant JWT against the IdP JWKS and return claims.
pub fn verify_grant_jwt(token: &str, config: &Config) -> Result<GrantClaims, Error> {
    let jwks_uri = config.jwks_uri().ok_or_else(|| {
        Error::Config("No JWKS URI configured. Set [idp] issuer or jwks_uri in config.".into())
    })?;

    // Decode header to get kid
    let header = decode_header(token)
        .map_err(|e| Error::Jwt(format!("Failed to decode JWT header: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| Error::Jwt("JWT header missing kid".into()))?;

    // Fetch JWKS from IdP
    let jwks: JwkSet = ureq::get(&jwks_uri)
        .call()
        .map_err(|e| Error::Jwt(format!("Failed to fetch JWKS from {jwks_uri}: {e}")))?
        .into_json()
        .map_err(|e| Error::Jwt(format!("Failed to parse JWKS: {e}")))?;

    // Find matching key by kid
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| Error::Jwt(format!("No matching key found for kid: {kid}")))?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| Error::Jwt(format!("Failed to create decoding key: {e}")))?;

    // Validate with ES256
    let mut validation = Validation::new(Algorithm::ES256);
    // We validate audience manually for clearer error messages
    validation.validate_aud = false;

    let token_data = decode::<GrantClaims>(token, &decoding_key, &validation)
        .map_err(|e| Error::Jwt(format!("JWT verification failed: {e}")))?;

    let claims = token_data.claims;

    // Validate issuer against config
    if let Some(ref expected_issuer) = config.idp.issuer {
        if claims.iss != *expected_issuer {
            return Err(Error::Jwt(format!(
                "Issuer mismatch: expected {expected_issuer}, got {}",
                claims.iss
            )));
        }
    }

    // Validate audience against allowed list
    if !config.security.allowed_audiences.is_empty()
        && !config.security.allowed_audiences.contains(&claims.aud)
    {
        return Err(Error::Jwt(format!(
            "Audience '{}' not in allowed list: {:?}",
            claims.aud, config.security.allowed_audiences
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

    #[test]
    fn test_verify_command_with_array() {
        let claims = GrantClaims {
            iss: "https://id.example.com".into(),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-1".into(),
            grant_type: "once".into(),
            approval: Some("once".into()),
            permissions: None,
            cmd_hash: None,
            command: Some(vec!["brew".into(), "install".into(), "ffmpeg".into()]),
            decided_by: Some("admin@example.com".into()),
            run_as: None,
        };

        // Matching command
        let cmd = vec!["brew".into(), "install".into(), "ffmpeg".into()];
        assert!(verify_command(&claims, &cmd).is_ok());

        // Mismatched command
        let bad_cmd = vec!["brew".into(), "install".into(), "vim".into()];
        assert!(verify_command(&claims, &bad_cmd).is_err());
    }

    #[test]
    fn test_verify_command_with_hash() {
        let cmd = vec!["rm".into(), "-rf".into(), "/tmp/test".into()];
        let hash = crypto::cmd_hash(&cmd);

        let claims = GrantClaims {
            iss: "https://id.example.com".into(),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-1".into(),
            grant_type: "once".into(),
            approval: None,
            permissions: None,
            cmd_hash: Some(hash),
            command: None,
            decided_by: None,
            run_as: None,
        };

        assert!(verify_command(&claims, &cmd).is_ok());

        let bad_cmd = vec!["rm".into(), "-rf".into(), "/".into()];
        assert!(verify_command(&claims, &bad_cmd).is_err());
    }

    #[test]
    fn test_verify_command_no_data_rejects() {
        let claims = GrantClaims {
            iss: "https://id.example.com".into(),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-1".into(),
            grant_type: "once".into(),
            approval: None,
            permissions: None,
            cmd_hash: None,
            command: None,
            decided_by: None,
            run_as: None,
        };

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

        let claims = GrantClaims {
            iss: server.url(""),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-1".into(),
            grant_type: "once".into(),
            approval: Some("once".into()),
            permissions: None,
            cmd_hash: None,
            command: Some(vec!["brew".into(), "install".into(), "ffmpeg".into()]),
            decided_by: None,
            run_as: None,
        };

        let result = consume_grant(&claims, "test-token");
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_consume_grant_already_consumed() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/api/grants/grant-2/consume");
            then.status(200)
                .json_body(serde_json::json!({"error": "already_consumed", "status": "used"}));
        });

        let claims = GrantClaims {
            iss: server.url(""),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-2".into(),
            grant_type: "once".into(),
            approval: None,
            permissions: None,
            cmd_hash: None,
            command: None,
            decided_by: None,
            run_as: None,
        };

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
                .path("/api/grants/grant-3/consume");
            then.status(200)
                .json_body(serde_json::json!({"error": "revoked", "status": "revoked"}));
        });

        let claims = GrantClaims {
            iss: server.url(""),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-3".into(),
            grant_type: "once".into(),
            approval: None,
            permissions: None,
            cmd_hash: None,
            command: None,
            decided_by: None,
            run_as: None,
        };

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
                .path("/api/grants/grant-4/consume");
            then.status(401)
                .body("Unauthorized");
        });

        let claims = GrantClaims {
            iss: server.url(""),
            sub: "agent@example.com".into(),
            aud: "apes".into(),
            iat: 0,
            exp: u64::MAX,
            jti: "test".into(),
            grant_id: "grant-4".into(),
            grant_type: "once".into(),
            approval: None,
            permissions: None,
            cmd_hash: None,
            command: None,
            decided_by: None,
            run_as: None,
        };

        let result = consume_grant(&claims, "test-token");
        assert!(result.is_err());
    }
}
