use clap::Parser;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// The block number.
    #[clap(long)]
    pub block_number: u64,

    /// The database connection string.
    #[clap(long, env, default_value = "/tmp/.bitvm2-node.db")]
    pub database_url: String,

    /// Retry count on failed execution.
    #[clap(long, env, default_value_t = 1)]
    pub execution_retries: usize,
}
