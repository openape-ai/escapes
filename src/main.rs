mod audit;
mod auth;
mod cli;
mod config;
mod crypto;
mod enroll;
mod error;
mod exec;
mod grants;
mod jwt;

use clap::Parser;

use cli::{Cli, Commands};
use error::Error;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Enroll {
            server,
            agent_name,
        }) => enroll::run(&server, agent_name),
        None => run_sudo(&cli),
    };

    if let Err(e) = result {
        match &e {
            Error::Denied { decided_by, .. } => eprintln!("❌ Denied by {decided_by}"),
            Error::Timeout { secs, .. } => eprintln!("⏰ Timed out after {secs}s — no approval received"),
            _ => eprintln!("{}", e.to_json()),
        }
        std::process::exit(e.exit_code());
    }
}

fn run_sudo(cli: &Cli) -> Result<(), Error> {
    if cli.cmd.is_empty() {
        return Err(Error::Config("No command specified. Usage: apes -- <command> [args...]".into()));
    }

    // 1. Load config + key while still root (files are 0600 root-owned)
    let config = config::Config::load(&cli.config)?;
    let signing_key = crypto::load_signing_key(&config.key_path)?;

    // 2. Compute cmd_hash (pure computation, no I/O)
    let cmd_hash = crypto::cmd_hash(&cli.cmd);

    // 3. Drop privileges — all network I/O runs as real user
    let real_uid = exec::drop_privileges()?;

    // 4. Authenticate (challenge-response, key already in memory)
    let agent_token = auth::authenticate(&config, &signing_key)?;

    // 5. Create grant
    let target = config.effective_target();
    let grant = grants::create_grant(
        &config,
        &agent_token,
        &target,
        &cli.cmd,
        &cmd_hash,
        cli.reason.as_deref(),
    )?;

    // 6. Poll for approval
    let server_domain = config.server_url
        .strip_prefix("https://").or_else(|| config.server_url.strip_prefix("http://"))
        .unwrap_or(&config.server_url)
        .split('/').next()
        .unwrap_or(&config.server_url);
    eprintln!("⏳ Waiting for approval… (grant {})", &grant.id[..8.min(grant.id.len())]);
    eprintln!("   Approve at: {server_domain}");
    let timeout = cli.timeout.unwrap_or(config.poll.timeout_secs);
    let grant = match grants::poll_grant(&config, &agent_token, &grant.id, timeout, config.poll.interval_secs) {
        Ok(g) => g,
        Err(Error::Denied { ref grant_id, ref decided_by }) => {
            audit::log_denied(&config, real_uid, &cli.cmd, &cmd_hash, grant_id, decided_by);
            return Err(Error::Denied { grant_id: grant_id.clone(), decided_by: decided_by.clone() });
        }
        Err(Error::Timeout { ref grant_id, secs }) => {
            audit::log_timeout(&config, real_uid, &cli.cmd, &cmd_hash, grant_id, secs);
            return Err(Error::Timeout { grant_id: grant_id.clone(), secs });
        }
        Err(e) => {
            audit::log_error(&config, real_uid, &cli.cmd, &e.to_string());
            return Err(e);
        }
    };
    eprintln!("✅ Grant approved");

    // 7. Get authorization token
    let authz_response = match grants::get_token(&config, &agent_token, &grant.id) {
        Ok(r) => r,
        Err(e) => {
            audit::log_error(&config, real_uid, &cli.cmd, &e.to_string());
            return Err(e);
        }
    };

    // 8. Verify AuthZ-JWT locally
    let claims = match jwt::verify_authz_jwt(&authz_response.authz_jwt, &config) {
        Ok(c) => c,
        Err(e) => {
            audit::log_error(&config, real_uid, &cli.cmd, &e.to_string());
            return Err(e);
        }
    };

    // 9. Verify cmd_hash in JWT matches our cmd_hash
    let jwt_cmd_hash = claims.cmd_hash.as_deref().unwrap_or("");
    if jwt_cmd_hash != cmd_hash {
        let e = Error::CmdHashMismatch {
            expected: cmd_hash,
            got: jwt_cmd_hash.to_string(),
        };
        audit::log_error(&config, real_uid, &cli.cmd, &e.to_string());
        return Err(e);
    }

    // 10. Elevate privileges
    exec::elevate()?;

    // 11. Sanitize environment
    exec::sanitize_env();

    // 12. Write audit log
    audit::log_run(
        &config,
        real_uid,
        &cli.cmd,
        &cmd_hash,
        &grant,
    );

    // 13. exec the command (replaces this process)
    exec::run_command(&cli.cmd)
}
