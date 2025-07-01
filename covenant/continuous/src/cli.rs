use std::fs;
use std::path::PathBuf;

use alloy_chains::Chain;
use alloy_provider::{network::AnyNetwork, Provider, RootProvider};
use clap::Parser;
use host_executor::Config;
use primitives::genesis::Genesis;
use url::Url;
use zkm_sdk::ZKMProofKind;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// The block number of the block to execute.
    #[clap(long)]
    pub block_number: u64,

    #[clap(flatten)]
    pub provider: ProviderArgs,

    /// The path to the genesis json file to use for the execution.
    #[clap(long)]
    pub genesis_path: Option<PathBuf>,

    /// The database connection string.
    #[clap(long, env, default_value = "/tmp/.bitvm2-node.db")]
    pub database_url: String,

    /// The log directory.
    #[clap(long, env, default_value = "./logs")]
    pub log_dir: String,

    /// The maximum number of concurrent executions.
    #[clap(long, env, default_value_t = 1)]
    pub max_concurrent_executions: usize,

    /// Retry count on failed execution.
    #[clap(long, env, default_value_t = 1)]
    pub execution_retries: usize,

    /// Whether to generate a proof or just execute the block.
    #[clap(long)]
    pub prove: bool,

    /// PagerDuty integration key.
    #[clap(long, env)]
    pub pager_duty_integration_key: Option<String>,
}

impl Args {
    pub async fn as_config(&self) -> eyre::Result<Config> {
        // We don't need RPC when using cache with known chain ID, so we leave it as `Option<Url>`
        // here and decide on whether to panic later.
        //
        // On the other hand chain ID is always needed.
        let (rpc_url, chain_id) = match (self.provider.rpc_url.clone(), self.provider.chain_id) {
            (Some(rpc_url), Some(chain_id)) => (Some(rpc_url), chain_id),
            (None, Some(chain_id)) => {
                match std::env::var(format!("RPC_{chain_id}")) {
                    Ok(rpc_env_var) => {
                        // We don't always need it but if the value exists it has to be valid.
                        (Some(Url::parse(rpc_env_var.as_str())?), chain_id)
                    }
                    Err(_) => {
                        // Not having RPC is okay because we know chain ID.
                        (None, chain_id)
                    }
                }
            }
            (Some(rpc_url), None) => {
                // We can find out about chain ID from RPC.
                let provider = RootProvider::<AnyNetwork>::new_http(rpc_url.clone());

                (Some(rpc_url), provider.get_chain_id().await?)
            }
            (None, None) => {
                eyre::bail!("either --rpc-url or --chain-id must be used")
            }
        };

        let genesis = if let Some(genesis_path) = &self.genesis_path {
            let genesis_json = fs::read_to_string(genesis_path)
                .map_err(|err| eyre::eyre!("Failed to read genesis file: {err}"))?;

            Genesis::Custom(genesis_json)
        } else {
            chain_id.try_into()?
        };

        let chain = Chain::from_id(chain_id);

        let config = Config {
            chain,
            genesis,
            rpc_url,
            cache_dir: None,
            custom_beneficiary: None,
            prove_mode: self.prove.then_some(ZKMProofKind::Compressed),
            opcode_tracking: false,
        };

        Ok(config)
    }
}

/// The arguments for configuring the chain data provider.
#[derive(Debug, Clone, Parser)]
pub struct ProviderArgs {
    /// The rpc url used to fetch data about the block. If not provided, will use the
    /// RPC_{chain_id} env var.
    #[clap(long)]
    pub rpc_url: Option<Url>,
    /// The chain ID. If not provided, requires the rpc_url argument to be provided.
    #[clap(long)]
    pub chain_id: Option<u64>,
}
