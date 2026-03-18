use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "apes", about = "Privilege elevation via OpenApe grants")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "/etc/apes/config.toml")]
    pub config: PathBuf,

    /// Grant token JWT
    #[arg(long, env = "APES_GRANT")]
    pub grant: Option<String>,

    /// Read grant token from stdin
    #[arg(long)]
    pub grant_stdin: bool,

    /// Read grant token from file
    #[arg(long)]
    pub grant_file: Option<PathBuf>,

    /// Command and arguments to execute with elevated privileges
    #[arg(last = true)]
    pub cmd: Vec<String>,
}
