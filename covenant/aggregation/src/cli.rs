use clap::Parser;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// Start or restart aggregation block number.
    #[clap(long, env, default_value_t = 1)]
    pub block_number: u64,

    /// Whether it is the initial block of the aggregation.
    /// If it is false, it means a restart​.
    #[clap(long, env)]
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

    /// Whether to execute guest.
    #[clap(long, env)]
    pub exec: bool,

    /// Count blocks once in aggregation.
    #[clap(long, env, default_value_t = 1)]
    pub aggregate_block_count: u64,
}
