use proof_builder::ArgsRotator;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProofBuilderConfig {
    pub header_chain: header_chain_proof::Args,
    pub commit_chain: commit_chain_proof::Args,
    pub state_chain: state_chain_proof::Args,
    pub watchtower: watchtower_proof::Args,
    pub operator: operator_proof::Args,
}

impl ProofBuilderConfig {
    pub(crate) fn new(url: &str) -> anyhow::Result<Self> {
        Self::load(url)
    }

    fn load(url: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(&url)?;
        Ok(toml::from_str(&content)?)
    }

    pub(crate) fn save<R: ArgsRotator + serde::Serialize>(args: R) -> anyhow::Result<R> {
        let new_args = args.rotate();
        let contents = toml::to_string_pretty(&new_args)?;
        std::fs::write(args.path(), contents)?;
        Ok(new_args)
    }
}
