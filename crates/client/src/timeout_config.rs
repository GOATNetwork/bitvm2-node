pub const ENV_BTC_REQUEST_TIMEOUT_SECS: &str = "BTC_REQUEST_TIMEOUT_SECS";
pub const DEFAULT_BTC_REQUEST_TIMEOUT_SECS: u64 = 15;
pub const ENV_GOAT_RPC_TIMEOUT_SECS: &str = "GOAT_RPC_TIMEOUT_SECS";
pub const DEFAULT_GOAT_RPC_TIMEOUT_SECS: u64 = 20;

pub fn get_btc_request_timeout_secs() -> u64 {
    std::env::var(ENV_BTC_REQUEST_TIMEOUT_SECS)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|timeout| timeout.clamp(1, 120))
        .unwrap_or(DEFAULT_BTC_REQUEST_TIMEOUT_SECS)
}

pub fn get_goat_rpc_timeout_secs() -> u64 {
    std::env::var(ENV_GOAT_RPC_TIMEOUT_SECS)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|timeout| timeout.clamp(1, 120))
        .unwrap_or(DEFAULT_GOAT_RPC_TIMEOUT_SECS)
}
