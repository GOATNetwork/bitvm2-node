use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address as EvmAddress;
use bitcoin::{Network, PublicKey, key::Keypair};
use bitvm2_lib::keys::NodeMasterKey;
use client::chain::goat_adaptor::GoatInitConfig;
use reqwest::Url;
use std::str::FromStr;

pub const ENV_GOAT_CHAIN_URL: &str = "GOAT_CHAIN_URL";
pub const ENV_GOAT_GATEWAY_CONTRACT_ADDRESS: &str = "GOAT_GATEWAY_CONTRACT_ADDRESS";
pub const ENV_GOAT_GATEWAY_CONTRACT_CREATION: &str = "GOAT_GATEWAY_CONTRACT_CREATION";
pub const ENV_GOAT_GATEWAY_CONTRACT_TO_BLOCK: &str = "GOAT_GATEWAY_CONTRACT_TO_BLOCK";
pub const ENV_GOAT_PRIVATE_KEY: &str = "GOAT_PRIVATE_KEY";
pub const ENV_GOAT_CHAIN_ID: &str = "GOAT_CHAIN_ID";

pub const SCRIPT_CACHE_FILE_NAME: &str = "cache/partial_script.bin";
pub const DUST_AMOUNT: u64 = goat::transactions::base::DUST_AMOUNT;
pub const MAX_CUSTOM_INPUTS: usize = 100;

pub const DEFAULT_CONFIRMATION_TARGET: u16 = 1;

// fee estimate
pub const CHEKSIG_P2WSH_INPUT_VBYTES: u64 = 100;
pub const P2WSH_OUTPUT_VBYTES: u64 = 50;
pub const P2TR_OUTPUT_VBYTES: u64 = 50;
pub const PRE_KICKOFF_BASE_VBYTES: u64 = 200;
pub const PEGIN_BASE_VBYTES: u64 = 200;
pub const CHALLENGE_BASE_VBYTES: u64 = 200;

pub const MIN_SATKE_AMOUNT: u64 = 20_000_000; // 0.2 BTC
pub const STAKE_RATE: u64 = 200; // 2%
pub const MIN_CHALLENGE_AMOUNT: u64 = 3_300_000; // 0.033 BTC
pub const CHALLENGE_RATE: u64 = 0; // 0%

pub const RATE_MULTIPLIER: u64 = 10000;

const COMMITTEE_MEMBER_NUMBER: usize = 3;
const NETWORK: Network = Network::Testnet;

pub fn get_network() -> Network {
    NETWORK
}

pub fn get_bitvm_key() -> Result<Keypair, Box<dyn std::error::Error>> {
    // TODO: what if node restart with different BITVM_SECRET ?
    let bitvm_secret = std::env::var("BITVM_SECRET").expect("BITVM_SECRET is missing");
    Ok(Keypair::from_seckey_str_global(&bitvm_secret)?)
}

pub fn get_node_pubkey() -> Result<PublicKey, Box<dyn std::error::Error>> {
    Ok(NodeMasterKey::new(get_bitvm_key()?).master_keypair().public_key().into())
}

pub fn get_committee_member_num() -> usize {
    COMMITTEE_MEMBER_NUMBER
}

pub fn get_bitvm2_client_config() -> GoatInitConfig {
    let rpc_url_str = std::env::var(ENV_GOAT_CHAIN_URL)
        .expect(format!("Failed to read {} variable", ENV_GOAT_CHAIN_URL).as_str());
    let gateway_address_str = std::env::var(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .expect(format!("Failed to read {} variable", ENV_GOAT_GATEWAY_CONTRACT_ADDRESS).as_str());
    let gateway_creation = std::env::var(ENV_GOAT_GATEWAY_CONTRACT_CREATION)
        .expect(format!("Failed to read {} variable", ENV_GOAT_GATEWAY_CONTRACT_CREATION).as_str());
    let to_block = std::env::var(ENV_GOAT_GATEWAY_CONTRACT_TO_BLOCK);
    let private_key = match std::env::var(ENV_GOAT_PRIVATE_KEY) {
        Ok(key) => Some(key),
        Err(_) => None,
    };
    let chain_id = std::env::var(ENV_GOAT_CHAIN_ID)
        .expect(format!("Failed to read {} variable", ENV_GOAT_CHAIN_ID).as_str());

    let rpc_url = rpc_url_str.parse::<Url>();
    let gateway_address = gateway_address_str.parse::<EvmAddress>();
    GoatInitConfig {
        rpc_url: rpc_url.unwrap(),
        gateway_address: gateway_address.unwrap(),
        gateway_creation_block: gateway_creation.parse::<u64>().unwrap(),
        to_block: match to_block {
            Ok(block) => Some(BlockNumberOrTag::from_str(block.as_str()).unwrap()),
            Err(_) => Some(BlockNumberOrTag::Finalized),
        },
        private_key,
        chain_id: chain_id.parse().expect("fail to parse int"),
    }
}
