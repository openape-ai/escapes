mod audit;
mod cli;
mod config;
mod crypto;
mod error;
mod exec;
mod grant_mode;
mod trust;
mod update;

use clap::Parser;

use cli::{Cli, Commands};
use error::Error;

fn main() {
    let cli = Cli::parse();

    // New-style subcommand dispatch takes precedence.
    if let Some(cmd) = cli.command.as_ref() {
        let result = match cmd {
            Commands::Trust(args) => trust::run(&cli.config, args),
            Commands::Update => update::self_update(),
        };
        if let Err(e) = result {
            eprintln!("{}", e.to_json());
            std::process::exit(e.exit_code());
        }
        return;
    }

    // Deprecated flag: keep working for one release, hint at the new form.
    if cli.update {
        eprintln!(
            "note: `escapes --update` is deprecated — use `escapes update` in future releases."
        );
        if let Err(e) = update::self_update() {
            eprintln!("{}", e.to_json());
            std::process::exit(e.exit_code());
        }
        return;
    }

    if let Err(e) = run(&cli) {
        eprintln!("{}", e.to_json());
        std::process::exit(e.exit_code());
    }
}

fn run(cli: &Cli) -> Result<(), Error> {
    if cli.cmd.is_empty() {
        return Err(Error::Config(
            "No command specified. Usage: escapes --grant <jwt> -- <command> [args...]".into(),
        ));
    }

    // 1. Load config (still root — config is root-owned)
    let config = config::Config::load(&cli.config)?;

    // 2. Resolve the grant JWT from --grant, --grant-stdin, or --grant-file
    let grant_jwt = grant_mode::resolve_grant_jwt(
        cli.grant.as_deref(),
        cli.grant_stdin,
        cli.grant_file.as_deref(),
    )?;

    // 3. Verify JWT: extract issuer, check allowlists, verify signature
    let claims = grant_mode::verify_grant_jwt(&grant_jwt, &config)?;

    // 4. Verify command matches grant
    grant_mode::verify_command(&claims, &cli.cmd)?;

    // 5. Online consume-check at IdP (network required)
    //    For `once`: marks grant as consumed atomically
    //    For `timed`/`always`: validates grant is still active
    eprintln!("verifying grant {}…", &claims.grant_id);
    grant_mode::consume_grant(&claims, &grant_jwt)?;
    eprintln!("grant verified");

    // 6. Elevate privileges
    exec::elevate()?;

    // 7. Sanitize environment
    exec::sanitize_env();

    // 8. Write audit log (while still root — before dropping privileges)
    let real_uid = nix::unistd::getuid();
    let cmd_hash = crypto::cmd_hash(&cli.cmd);
    audit::log_grant_run(&config, &claims, real_uid, &cli.cmd, &cmd_hash);

    // 9. Switch user: CLI flag > JWT claim > config default
    let run_as = cli
        .run_as
        .as_deref()
        .or(claims.run_as.as_deref())
        .unwrap_or(&config.run_as);
    if run_as == "root" {
        exec::become_root()?;
    } else {
        exec::switch_user(run_as)?;
    }

    // 10. exec the command (replaces this process)
    exec::run_command(&cli.cmd)
}
