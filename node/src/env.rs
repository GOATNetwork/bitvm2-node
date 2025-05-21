#![allow(dead_code)]
use crate::action::NodeInfo;
use crate::client::chain::utils::{validate_committee, validate_operator};
use crate::client::chain::{chain_adaptor::GoatNetwork, goat_adaptor::GoatInitConfig};
use alloy::primitives::Address as EvmAddress;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use base64::Engine;
use bitcoin::{Network, PublicKey, key::Keypair};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::keys::NodeMasterKey;
use libp2p::PeerId;
use musig2::k256::sha2;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use tracing::info;
use zeroize::Zeroizing;

pub const ENV_GOAT_CHAIN_URL: &str = "GOAT_CHAIN_URL";
pub const ENV_GOAT_GATEWAY_CONTRACT_ADDRESS: &str = "GOAT_GATEWAY_CONTRACT_ADDRESS";
/// Relayer
pub const ENV_GOAT_PRIVATE_KEY: &str = "GOAT_PRIVATE_KEY";
/// Operator
pub const ENV_GOAT_ADDRESS: &str = "GOAT_ADDRESS";
/// Operator(private key), Relayer(private key),  Committee(seed)
pub const ENV_BITVM_SECRET: &str = "BITVM_SECRET";
/// All actors
pub const ENV_PEER_KEY: &str = "PEER_KEY";
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

pub const INSTANCE_PRESIGNED_TIME_EXPIRED: i64 = 3600;
pub const MODIFY_GRAPH_STATUS_TIME_THRESHOLD: i64 = 2;

pub const SYNC_GRAPH_INTERVAL: u64 = 3;
pub const SYNC_GRAPH_MAX_WAIT_SECS: u64 = 30;

pub fn get_network() -> Network {
    BTC_NETWORK
}

pub fn get_goat_network() -> GoatNetwork {
    GOAT_NETWORK
}

/// Get the entropy of WOTS keys for current node
///   Note: SEED should be used on production environment
pub fn get_bitvm_secret() -> String {
    let bitvm_secret = std::env::var(ENV_BITVM_SECRET).expect("{ENV_BITVM_SECRET} is missing");
    if !bitvm_secret.starts_with("seed:") {
        return bitvm_secret;
    }
    // derive private key from seed
    let hashed = Sha256::digest(bitvm_secret.as_bytes());
    let sk = secp256k1::SecretKey::from_slice(&hashed).expect("valid secret key");
    hex::encode(sk.secret_bytes()).to_string()
}

pub fn get_bitvm_key() -> Result<Keypair, Box<dyn std::error::Error>> {
    // TODO: what if node restart with different BITVM_SECRET ?
    let bitvm_secret = get_bitvm_secret();
    Ok(Keypair::from_seckey_str_global(&bitvm_secret)?)
}

pub fn get_node_pubkey() -> Result<PublicKey, Box<dyn std::error::Error>> {
    Ok(NodeMasterKey::new(get_bitvm_key()?).master_keypair().public_key().into())
}

pub fn get_actor() -> Actor {
    Actor::from_str(std::env::var(ENV_ACTOR).unwrap_or("Challenger".to_string()).as_str())
        .expect("Expect one of Committee, Challenger, Operator or Relayer")
}

pub fn get_peer_key() -> String {
    std::env::var(ENV_PEER_KEY).expect("Peer key is missing")
}

pub fn get_peer_id() -> String {
    let local_key = get_peer_key();
    let key_pair = libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(local_key).expect("fail to decode base64"),
    ))
    .expect("failed to gen keypair");
    key_pair.public().to_peer_id().to_string()
}

pub fn get_ipfs_url() -> String {
    let default_url: &str = "http://44.229.236.82:5001";
    std::env::var(ENV_IPFS_ENDPOINT).unwrap_or(default_url.to_string())
}

pub async fn check_node_info() {
    let node_info = get_local_node_info();
    if node_info.actor == Actor::Operator.to_string() && node_info.goat_addr.is_empty() {
        panic!("Operator must set goat address or goat secret key");
    }
    if Actor::Committee.to_string() == node_info.actor
        || Actor::Operator.to_string() == node_info.actor
    {
        let rpc_url = get_goat_url_from_env();
        let gateway_address = get_goat_gateway_contract_from_env();
        let provider = ProviderBuilder::new().on_http(rpc_url);
        let peer_id = PeerId::from_str(&node_info.peer_id).expect("fail to decode");

        if node_info.actor == Actor::Committee.to_string() {
            match validate_committee(&provider, gateway_address, &peer_id.to_bytes()).await {
                Ok(is_legal) => {
                    if is_legal {
                        info!("Committee is legal!");
                    } else {
                        panic!("Committee is illegal as not finish register! ")
                    }
                }
                Err(err) => {
                    panic!("Committee validate failed, err:{err:?}")
                }
            }
        }
        if node_info.actor == Actor::Operator.to_string() {
            match validate_operator(&provider, gateway_address, &peer_id.to_bytes()).await {
                Ok(is_legal) => {
                    if is_legal {
                        info!("Operator is legal!");
                    } else {
                        panic!("Operator is illegal as not finish register! ")
                    }
                }
                Err(err) => {
                    panic!("Operator validate failed, err:{err:?}")
                }
            }
        }
    }
}
pub fn get_local_node_info() -> NodeInfo {
    let actor = get_actor();
    let peer_key = get_peer_id();
    let pubkey_str = if actor != Actor::Relayer {
        get_node_pubkey().expect("fail to get pubkey").to_string()
    } else {
        "".to_string()
    };
    let goat_address = if let Ok(private_key_hex) = std::env::var(ENV_GOAT_PRIVATE_KEY) {
        let singer =
            PrivateKeySigner::from_str(&private_key_hex).expect("fail to decode goat private key");
        Some(singer.address().to_string())
    } else {
        let mut addr_op = None;
        if let Ok(addr_str) = std::env::var(ENV_GOAT_ADDRESS)
            && let Ok(addr) = Address::from_str(&addr_str)
        {
            addr_op = Some(addr.to_string());
        }

        addr_op
    };
    NodeInfo {
        peer_id: peer_key,
        actor: actor.to_string(),
        goat_addr: goat_address.unwrap_or("".to_string()),
        btc_pub_key: pubkey_str,
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

pub fn get_goat_url_from_env() -> Url {
    let rpc_url_str =
        std::env::var(ENV_GOAT_CHAIN_URL).expect("Failed to read {ENV_GOAT_CHAIN_URL} variable");
    rpc_url_str.parse::<Url>().expect("Failed to parse {rpc_url_str} to URL")
}

pub fn get_goat_gateway_contract_from_env() -> EvmAddress {
    let gateway_address_str = std::env::var(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .expect("Failed to read {ENV_GOAT_GATEWAY_CONTRACT_ADDRESS} variable");
    gateway_address_str
        .parse::<EvmAddress>()
        .expect("Failed to parse {gateway_address_str} to address")
}

pub async fn goat_config_from_env() -> GoatInitConfig {
    if cfg!(feature = "tests") {
        return GoatInitConfig::from_env_for_test();
    }
    let rpc_url = get_goat_url_from_env();
    let gateway_address = get_goat_gateway_contract_from_env();
    let private_key = std::env::var(ENV_GOAT_PRIVATE_KEY).ok();
    let chain_id = {
        let provider = ProviderBuilder::new().on_http(rpc_url.clone());
        // Call `eth_chainId`
        provider.get_chain_id().await.expect("cannot get chain_id from {rpc_url}") as u32
    };
    GoatInitConfig { rpc_url, gateway_address, private_key, chain_id }
}

const DEFAULT_PROTO_NAME_BASE: &str = "bitvm2";
pub fn get_proto_base() -> String {
    match std::env::var("PROTO_NAME") {
        Ok(proto_name) => {
            if proto_name.trim().is_empty() {
                DEFAULT_PROTO_NAME_BASE.to_string()
            } else {
                proto_name
            }
        }
        _ => DEFAULT_PROTO_NAME_BASE.to_owned(),
    }
}

pub fn get_rpc_support_actors() -> Vec<Actor> {
    vec![Actor::Relayer]
}
