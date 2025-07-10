use clap::Parser;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// The block number.
    #[clap(long)]
    pub block_number: u64,

    /// Aggregation starts with two block proofs.
    #[clap(long)]
    pub start: bool,

    /// The database connection string.
    #[clap(long, env, default_value = "/tmp/.bitvm2-node.db")]
    pub database_url: String,

    /// The log directory.
    #[clap(long, env, default_value = "./logs")]
    pub log_dir: String,

    /// Retry count on failed execution.
    #[clap(long, env, default_value_t = 1)]
    pub execution_retries: usize,

    /// Execute guest.
    #[clap(long)]
    pub exec: bool,
}
