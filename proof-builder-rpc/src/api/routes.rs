pub(crate) const ROOT: &str = "/";
pub(crate) const METRICS: &str = "/metrics";
pub(crate) mod v1 {
    pub(crate) const PROOFS_CHAIN_PROOFS_DESC: &str = "/v1/proofs/chain_proofs_desc";
    pub(crate) const PROOFS_WATCHTOWER_PROOF: &str = "/v1/proofs/watchtower_proofs";
    pub(crate) const PROOFS_WATCHTOWER_PROOF_TIMEOUT: &str = "/v1/proofs/watchtower_proofs_timeout";
    pub(crate) const PROOFS_OPERATOR_PROOF: &str = "/v1/proofs/operator_proofs";
    pub(crate) const PROOFS_OPERATOR_PROOF_TIMEOUT: &str = "/v1/proofs/operator_proofs_timeout";
    pub(crate) const PROOFS_OPERATOR_PROOF_DESC: &str = "/v1/proofs/operator_proofs_desc";
}
