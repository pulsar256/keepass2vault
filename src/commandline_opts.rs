use clap::Parser;
use std::env;

#[command(
    version = "0.1.0",
    author = "Paul Rogalinski-Pinter, keepass2vault@t00ltime.de",
    about = "Imports all secrets from a keepass file into Hashicorp-vault"
)]
#[derive(Parser, Debug, Clone)]
pub struct CommandlineOpts {
    #[arg(long, default_value = "http://127.0.0.1:8200", env = "VAULT_ADDR")]
    pub vault_addr: String,

    #[arg(long, default_value = None, env = "VAULT_TOKEN")]
    pub vault_token: String,

    #[arg(long, default_value = None, env = "KEEPASS_FILE")]
    pub keepass_file: String,

    #[arg(long, default_value = None, env = "KEEPASS_PASSWORD")]
    pub keepass_password: String,

    #[arg(
        long,
        default_value = "",
        env = "VAULT_PATH_PREFIX",
        help = "vault path prefix"
    )]
    pub path_prefix: String,

    #[arg(
        long,
        default_value = "secret",
        env = "VAULT_MOUNT",
        help = "vault mountpoint of the kv2"
    )]
    pub mount: String,

    #[arg(
        short,
        help = "verbose output if not specified otherwise by the RUST_LOG environment variable.",
        env = "DEBUG"
    )]
    pub verbose: bool,
}

impl CommandlineOpts {
    pub fn setup_logger(&self) {
        if self.verbose {
            if env::var("RUST_LOG").is_err() {
                env::set_var("RUST_LOG", "debug")
            }
        } else {
            if env::var("RUST_LOG").is_err() {
                env::set_var("RUST_LOG", "warn,keepass2vault=info")
            }
        }
        env_logger::init();
    }

    pub fn parse_and_setup_logger() -> Self {
        let opts = Self::parse();
        opts.setup_logger();
        opts
    }
}
