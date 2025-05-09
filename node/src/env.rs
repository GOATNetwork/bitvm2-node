#![allow(dead_code)]
use crate::action::NodeInfo;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address as EvmAddress;
use alloy::signers::local::PrivateKeySigner;
// use alloy_signer::{Signer, SignerSync};
use alloy::primitives::Address;
use bitcoin::{Network, PublicKey, key::Keypair};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::keys::NodeMasterKey;
use client::chain::{chain_adaptor::GoatNetwork, goat_adaptor::GoatInitConfig};
use reqwest::Url;
use std::str::FromStr;

pub const ENV_BITVM2_NETWORK: &str = "BITVM2_NETWORK";
pub const ENV_GOAT_CHAIN_URL: &str = "GOAT_CHAIN_URL";
pub const ENV_GOAT_GATEWAY_CONTRACT_ADDRESS: &str = "GOAT_GATEWAY_CONTRACT_ADDRESS";
pub const ENV_GOAT_GATEWAY_CONTRACT_CREATION: &str = "GOAT_GATEWAY_CONTRACT_CREATION";
pub const ENV_GOAT_GATEWAY_CONTRACT_TO_BLOCK: &str = "GOAT_GATEWAY_CONTRACT_TO_BLOCK";
pub const ENV_GOAT_PRIVATE_KEY: &str = "GOAT_PRIVATE_KEY";
pub const ENV_GOAT_ADDRESS: &str = "GOAT_ADDRESS";
pub const ENV_GOAT_CHAIN_ID: &str = "GOAT_CHAIN_ID";
pub const ENV_BITVM_SECRET: &str = "BITVM_SECRET";
pub const ENV_PEER_KEY: &str = "KEY";
pub const ENV_PEER_ID: &str = "PEER_ID";
pub const ENV_ACTOR: &str = "ACTOR";
pub const ENV_IPFS_ENDPOINT: &str = "IPFS_ENDPOINT";
pub const ENV_COMMITTEE_NUM: &str = "COMMITTEE_NUM";

pub const SCRIPT_CACHE_FILE_NAME: &str = "cache/partial_script.bin";
pub const IPFS_GRAPH_CACHE_DIR: &str = "cache/graph_cache/";
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

// reduce costs to facilitate testing
pub const MIN_SATKE_AMOUNT: u64 = 700_000; // 0.007 BTC
pub const STAKE_RATE: u64 = 0; // 0%
pub const MIN_CHALLENGE_AMOUNT: u64 = 300_000; // 0.003 BTC
// pub const MIN_SATKE_AMOUNT: u64 = 20_000_000; // 0.2 BTC
// pub const STAKE_RATE: u64 = 200; // 2%
// pub const MIN_CHALLENGE_AMOUNT: u64 = 3_300_000; // 0.033 BTC
pub const CHALLENGE_RATE: u64 = 0; // 0%

pub const RATE_MULTIPLIER: u64 = 10000;

const COMMITTEE_MEMBER_NUMBER: usize = 2;
const BTC_NETWORK: Network = Network::Testnet;
const GOAT_NETWORK: GoatNetwork = GoatNetwork::Test;

pub const MESSAGE_BROADCAST_MAX_TIMES: i64 = 3;
pub const MESSAGE_EXPIRE_TIME: i64 = 3600 * 24; // 1 days

pub const GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED: i64 = 3600 * 48;
pub const MODIFY_GRAPH_STATUS_TIME_THRESHOLD: i64 = 2;

pub fn get_network() -> Network {
    BTC_NETWORK
}

pub fn get_goat_network() -> GoatNetwork {
    GOAT_NETWORK
}

pub fn get_bitvm_key() -> Result<Keypair, Box<dyn std::error::Error>> {
    // TODO: what if node restart with different BITVM_SECRET ?
    let bitvm_secret = std::env::var(ENV_BITVM_SECRET).expect("{ENV_BITVM_SECRET} is missing");
    Ok(Keypair::from_seckey_str_global(&bitvm_secret)?)
}

pub fn get_node_pubkey() -> Result<PublicKey, Box<dyn std::error::Error>> {
    Ok(NodeMasterKey::new(get_bitvm_key()?).master_keypair().public_key().into())
}

pub fn get_local_node_info() -> NodeInfo {
    let bitvm2_network = BitVM2Network::from_str(
        std::env::var(ENV_BITVM2_NETWORK).unwrap_or("develop".to_string()).as_str(),
    )
    .unwrap();
    let actor =
        Actor::from_str(std::env::var(ENV_ACTOR).unwrap_or("Challenger".to_string()).as_str())
            .unwrap();
    let peer_id = std::env::var(ENV_PEER_ID).expect("Peer ID is missing");
    let bitvm_secret = std::env::var(ENV_BITVM_SECRET).expect("{ENV_BITVM_SECRET} is missing");
    let pubkey = Keypair::from_seckey_str_global(&bitvm_secret)
        .expect("Failed to decode secret key")
        .public_key();
    let goat_address = if let Ok(private_key_hex) = std::env::var(ENV_GOAT_PRIVATE_KEY) {
        let singer =
            PrivateKeySigner::from_str(&private_key_hex).expect("fail to decode goat private key");
        Some(singer.address().to_string())
    } else {
        let mut addr_op = None;
        if let Ok(addr_str) = std::env::var(ENV_GOAT_ADDRESS) {
            if let Ok(addr) = Address::from_str(&addr_str) {
                addr_op = Some(addr.to_string());
            }
        }
        addr_op
    };
    if actor == Actor::Operator && goat_address.is_none() {
        panic!("Operator must set goat address or goat secret key");
    }

    if actor == Actor::Committee {
        let committee_pubkeys = get_committee_pubkeys(bitvm2_network);
        if !committee_pubkeys.contains(&pubkey.to_string()) {
            panic!("Invalidate committee pubkey");
        }
    }

    NodeInfo {
        peer_id,
        actor: actor.to_string(),
        goat_addr: goat_address.unwrap_or("".to_string()),
        btc_pub_key: pubkey.to_string(),
    }
}
pub fn get_committee_member_num() -> usize {
    COMMITTEE_MEMBER_NUMBER
}

pub enum IpfsTxName {
    AssertCommit0,
    AssertCommit1,
    AssertCommit2,
    AssertCommit3,
    AssertFinal,
    AssertInit,
    Challenge,
    Disprove,
    Kickoff,
    Pegin,
    Take1,
    Take2,
}
impl IpfsTxName {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpfsTxName::AssertCommit0 => "assert-commit0.hex",
            IpfsTxName::AssertCommit1 => "assert-commit1.hex",
            IpfsTxName::AssertCommit2 => "assert-commit2.hex",
            IpfsTxName::AssertCommit3 => "assert-commit3.hex",
            IpfsTxName::AssertFinal => "assert-final.hex",
            IpfsTxName::AssertInit => "assert-init.hex",
            IpfsTxName::Challenge => "challenge.hex",
            IpfsTxName::Disprove => "disprove.hex",
            IpfsTxName::Kickoff => "kickoff.hex",
            IpfsTxName::Pegin => "pegin.hex",
            IpfsTxName::Take1 => "take1.hex",
            IpfsTxName::Take2 => "take2.hex",
        }
    }
}

impl FromStr for IpfsTxName {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "assert-commit0.hex" => Ok(IpfsTxName::AssertCommit0),
            "assert-commit1.hex" => Ok(IpfsTxName::AssertCommit1),
            "assert-commit2.hex" => Ok(IpfsTxName::AssertCommit2),
            "assert-commit3.hex" => Ok(IpfsTxName::AssertCommit3),
            "assert-final.hex" => Ok(IpfsTxName::AssertFinal),
            "assert-init.hex" => Ok(IpfsTxName::AssertInit),
            "challenge.hex" => Ok(IpfsTxName::Challenge),
            "disprove.hex" => Ok(IpfsTxName::Disprove),
            "kickoff.hex" => Ok(IpfsTxName::Kickoff),
            "pegin.hex" => Ok(IpfsTxName::Pegin),
            "take1.hex" => Ok(IpfsTxName::Take1),
            "take2.hex" => Ok(IpfsTxName::Take2),
            _ => Err(()),
        }
    }
}

pub fn goat_config_from_env() -> GoatInitConfig {
    if cfg!(feature = "tests") {
        return GoatInitConfig::from_env_for_test();
    }

    let rpc_url_str =
        std::env::var(ENV_GOAT_CHAIN_URL).expect("Failed to read {ENV_GOAT_CHAIN_URL} variable");
    let rpc_url = rpc_url_str.parse::<Url>().expect("Failed to parse {rpc_url_str} to URL");

    let gateway_address_str = std::env::var(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .expect("Failed to read {ENV_GOAT_GATEWAY_CONTRACT_ADDRESS} variable");
    let gateway_address = gateway_address_str
        .parse::<EvmAddress>()
        .expect("Failed to parse {gateway_address_str} to address");

    let gateway_creation = std::env::var(ENV_GOAT_GATEWAY_CONTRACT_CREATION)
        .expect("Failed to read {ENV_GOAT_GATEWAY_CONTRACT_CREATION} variable");
    let gateway_creation_block =
        gateway_creation.parse::<u64>().expect("{ENV_GOAT_GATEWAY_CONTRACT_CREATION} parse");

    let to_block = match std::env::var(ENV_GOAT_GATEWAY_CONTRACT_TO_BLOCK).ok() {
        Some(to_block_str) => BlockNumberOrTag::from_str(to_block_str.as_str()).ok(),
        _ => None,
    };

    let private_key = std::env::var(ENV_GOAT_PRIVATE_KEY).ok();
    let chain_id = std::env::var(ENV_GOAT_CHAIN_ID)
        .expect("Failed to read {ENV_GOAT_CHAIN_ID} variable")
        .parse::<u32>()
        .expect("Failed to parse {chain_id_str} to u32");

    GoatInitConfig {
        rpc_url,
        gateway_address,
        gateway_creation_block,
        to_block,
        private_key,
        chain_id,
    }
}

#[derive(Debug)]
pub enum BitVM2Network {
    Main,
    Test,
    Develop,
}
impl FromStr for BitVM2Network {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Main" => Ok(BitVM2Network::Main),
            "Test" => Ok(BitVM2Network::Test),
            "Develop" => Ok(BitVM2Network::Develop),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for BitVM2Network {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
pub fn get_committee_pubkeys(network: BitVM2Network) -> Vec<String> {
    match network {
        BitVM2Network::Main => {
            vec![]
        }
        BitVM2Network::Test => {
            vec![]
        }
        BitVM2Network::Develop => {
            vec![
                "02452556ed6dbac394cbb7441fbaf06c446d1321467fa5a138895c6c9e246793dd".to_string(),
                "026cc14f56ad7e8fdb323378287895c6c0bcdbb37714c74fba175a0c5f0cd0d56f".to_string(),
            ]
        }
    }
}
