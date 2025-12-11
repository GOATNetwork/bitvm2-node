use bitcoin::Network;
use tracing::warn;

#[allow(dead_code)]
pub(crate) const ENV_BTC_NETWORK: &str = "BTC_NETWORK";
#[allow(dead_code)]
pub(crate) const ENV_GOAT_NETWORK: &str = "GOAT_NETWORK";
#[allow(dead_code)]
pub(crate) const ENV_GOAT_CHAIN_URL: &str = "GOAT_CHAIN_URL";
pub(crate) const ENV_ESPLORA_URL: &str = "ESPLORA_URL";

pub(crate) const ENV_HEADER_CHAIN_PROOF_BATCH_SIZE: &str = "HEADER_CHAIN_PROOF_BATCH_SIZE";

pub(crate) const ENV_SAVE_TO_FILE: &str = "SAVE_TO_FILE";
pub(crate) const ENV_HEADER_CHAIN_DATA_DIR: &str = "HEADER_CHAIN_DATA_DIR";

pub(crate) const ENV_ENABLE_CHAIN_PROOF_GENERATE: &str = "ENABLE_CHAIN_PROOF_GENERATE";
pub(crate) const ENV_ENABLE_OPERATOR_PROOF_GENERATE: &str = "ENABLE_OPERATOR_PROOF_GENERATE";

pub(crate) const ENV_ENABLE_WATCHTOWER_PROOF_GENERATE: &str = "ENABLE_WATCHTOWER_PROOF_GENERATE";

pub(crate) fn is_start_heard_chain_proof_generate() -> bool {
    match std::env::var(ENV_ENABLE_CHAIN_PROOF_GENERATE) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}
pub(crate) fn is_start_commit_chain_proof_generate() -> bool {
    match std::env::var(ENV_ENABLE_CHAIN_PROOF_GENERATE) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}
pub(crate) fn is_start_watchtower_proof_generate() -> bool {
    match std::env::var(ENV_ENABLE_OPERATOR_PROOF_GENERATE) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}
pub(crate) fn is_start_operator_proof_generate() -> bool {
    match std::env::var(ENV_ENABLE_WATCHTOWER_PROOF_GENERATE) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}

#[allow(dead_code)]
pub(crate) fn get_network() -> Network {
    let network = std::env::var(ENV_BTC_NETWORK).unwrap_or("regtest".to_string());
    match network.as_str() {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => {
            warn!(
                "Unknown BTC network: {network}, expect bitcoin, testnet, signet or regtest, return testnet by default"
            );
            Network::Testnet
        }
    }
}
pub(crate) fn get_esplora_url() -> String {
    std::env::var(ENV_ESPLORA_URL).unwrap_or("http://127.0.0.1:3002".to_string())
}

#[allow(dead_code)]
pub(crate) fn get_goat_chain_url() -> String {
    std::env::var(ENV_GOAT_CHAIN_URL).unwrap_or("https://rpc.testnet3.goat.network".to_string())
}

pub(crate) fn get_header_chain_proof_batch_size() -> i64 {
    if let Ok(batch_size) = std::env::var(ENV_HEADER_CHAIN_PROOF_BATCH_SIZE)
        && let Ok(batch_size) = batch_size.parse::<i64>()
    {
        batch_size
    } else {
        6_i64
    }
}

pub(crate) fn get_data_dir() -> String {
    std::env::var(ENV_HEADER_CHAIN_DATA_DIR).unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp/".to_string())
    })
}

pub(crate) fn is_save_to_file() -> bool {
    match std::env::var(ENV_SAVE_TO_FILE) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}
