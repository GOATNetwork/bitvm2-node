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
