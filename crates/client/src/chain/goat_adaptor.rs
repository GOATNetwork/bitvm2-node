use alloy::sol_types::SolEvent;
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address as EvmAddress,
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Filter,
    sol,
    transports::http::{Client, Http, reqwest::Url},
};
use dotenv;
use std::str::FromStr;
use async_trait::async_trait;
use crate::chain::chain_adaptor::ChainAdaptor;

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IGateway {
        enum PeginStatus {
            None,
            Processing,
            Withdrawbale,
            Locked,
            Claimed
        }
        enum WithdrawStatus {
            None,
            Processing,
            Initialized,
            Canceled,
            Complete,Disproved
        }

        struct PeginData {
            bytes32 peginTxid;
            PeginStatus status;
            uint64 peginAmount;
        }
        struct WithdrawData {
            bytes32 peginTxid;
            address operatorAddress;
            WithdrawStatus status;
            bytes16 instanceId;
            uint256 lockAmount;
        }
        struct OperatorData {
            uint64 stakeAmount;
            bytes1 operatorPubkeyPrefix;
            bytes32 operatorPubkey;
            bytes32 peginTxid;
            bytes32 preKickoffTxid;
            bytes32 kickoffTxid;
            bytes32 take1Txid;
            bytes32 assertInitTxid;
            bytes32[4] assertCommitTxids;
            bytes32 assertFinalTxid;
            bytes32 take2Txid;
        }

        // function postPeginData(bytes16 instanceId, BitvmTxParser.BitcoinTx calldata rawPeginTx, uint256 height, bytes32[] calldata proof, uint256 index);

    }

);

pub struct GoatInitConfig {
    pub rpc_url: Url,
    pub bridge_address: EvmAddress,
    pub bridge_creation_block: u64,
    pub to_block: Option<BlockNumberOrTag>,
}

pub struct GoatAdaptor {
    bridge_address: EvmAddress,
    bridge_creation_block: u64,
    provider: RootProvider<Http<Client>>,
    to_block: Option<BlockNumberOrTag>,
}

#[async_trait]
impl ChainAdaptor for GoatAdaptor {

}

impl GoatAdaptor {
    pub fn new(config: Option<GoatInitConfig>) -> Self {
        if let Some(_config) = config {
            Self::from_config(_config)
        } else {
            dotenv::dotenv().ok();
            let rpc_url_str = dotenv::var("BRIDGE_CHAIN_ADAPTOR_ETHEREUM_RPC_URL")
                .expect("Failed to read BRIDGE_CHAIN_ADAPTOR_ETHEREUM_RPC_URL variable");
            let bridge_address_str = dotenv::var("BRIDGE_CHAIN_ADAPTOR_ETHEREUM_BRIDGE_ADDRESS")
                .expect("Failed to read BRIDGE_CHAIN_ADAPTOR_ETHEREUM_BRIDGE_ADDRESS variable");
            let bridge_creation = dotenv::var("BRIDGE_CHAIN_ADAPTOR_ETHEREUM_BRIDGE_CREATION")
                .expect("Failed to read BRIDGE_CHAIN_ADAPTOR_ETHEREUM_BRIDGE_CREATION variable");
            let to_block = dotenv::var("BRIDGE_CHAIN_ADAPTOR_ETHEREUM_TO_BLOCK");

            let rpc_url = rpc_url_str.parse::<Url>();
            let bridge_address = bridge_address_str.parse::<EvmAddress>();
            Self::from_config(GoatInitConfig {
                rpc_url: rpc_url.unwrap(),
                bridge_address: bridge_address.unwrap(),
                bridge_creation_block: bridge_creation.parse::<u64>().unwrap(),
                to_block: match to_block {
                    Ok(block) => Some(BlockNumberOrTag::from_str(block.as_str()).unwrap()),
                    Err(_) => Some(BlockNumberOrTag::Finalized),
                },
            })
        }
    }

    fn from_config(config: GoatInitConfig) -> Self {
        Self {
            bridge_address: config.bridge_address,
            bridge_creation_block: config.bridge_creation_block,
            provider: ProviderBuilder::new().on_http(config.rpc_url),
            to_block: config.to_block,
        }
    }
}
