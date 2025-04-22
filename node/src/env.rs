use bitcoin::{key::Keypair, Network, PublicKey};
use bitvm2_lib::keys::NodeMasterKey;

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
