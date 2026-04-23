use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "escapes",
    about = "Privilege elevation via OpenApe grants",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to config file
    #[arg(long, default_value = "/etc/openape/config.toml", global = true)]
    pub config: PathBuf,

    /// Grant token JWT
    #[arg(long, env = "ESCAPES_GRANT")]
    pub grant: Option<String>,

    /// Read grant token from stdin
    #[arg(long)]
    pub grant_stdin: bool,

    /// Read grant token from file
    #[arg(long)]
    pub grant_file: Option<PathBuf>,

    /// Run command as this user instead of root
    #[arg(long)]
    pub run_as: Option<String>,

    /// Deprecated: use `escapes update` instead
    #[arg(long, hide = true)]
    pub update: bool,

    /// Command and arguments to execute with elevated privileges
    #[arg(last = true)]
    pub cmd: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Configure the trust boundary (allowed issuers + approvers).
    Trust(TrustArgs),

    /// Update escapes to the latest version from GitHub Releases.
    Update,
}

#[derive(clap::Args)]
pub struct TrustArgs {
    /// Issuer URL to trust (e.g. https://id.openape.ai).
    #[arg(long)]
    pub idp: Option<String>,

    /// Comma-separated list of approver emails.
    #[arg(long)]
    pub approvers: Option<String>,

    /// Replace existing trust config instead of merging.
    #[arg(long)]
    pub replace: bool,

    /// Skip IdP reachability + JWKS validation (airgapped bootstrap).
    #[arg(long)]
    pub skip_validation: bool,
}
