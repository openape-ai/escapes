use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "apes", about = "Privilege elevation via OpenApe grants")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to config file
    #[arg(long, default_value = "/etc/apes/config.toml")]
    pub config: PathBuf,

    /// Path to the agent's private key file (legacy mode)
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Grant token JWT (new mode: agent provides pre-approved grant)
    #[arg(long, env = "APES_GRANT")]
    pub grant: Option<String>,

    /// Read grant token from stdin
    #[arg(long)]
    pub grant_stdin: bool,

    /// Read grant token from file
    #[arg(long)]
    pub grant_file: Option<PathBuf>,

    /// Run the command as a different user (e.g. --run-as testuser)
    #[arg(long)]
    pub run_as: Option<String>,

    /// Poll timeout in seconds (overrides config)
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Human-readable reason for the grant request
    #[arg(long)]
    pub reason: Option<String>,

    /// Command and arguments to execute with elevated privileges
    #[arg(last = true)]
    pub cmd: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Enroll an agent on this machine
    Enroll {
        /// OpenApe IdP URL
        #[arg(long)]
        server: String,

        /// Agent email address (used as identifier on the IdP)
        #[arg(long)]
        agent_email: String,

        /// Agent display name
        #[arg(long)]
        agent_name: String,

        /// Path to the agent's private key file (generated if it doesn't exist)
        #[arg(long)]
        key: PathBuf,

        /// Agent already exists on the server — only write local config, skip enrollment URL
        #[arg(long)]
        existing: bool,
    },

    /// Update the server URL for an already enrolled agent
    Update {
        /// Agent email address
        #[arg(long)]
        email: String,

        /// New OpenApe IdP URL
        #[arg(long)]
        server: String,
    },

    /// Remove an enrolled agent from the local config
    Remove {
        /// Agent email address
        #[arg(long)]
        email: String,

        /// Also delete the agent on the remote IdP server
        #[arg(long)]
        remote: bool,
    },
}
