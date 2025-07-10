pub const ROOT: &str = "/";
pub const METRICS: &str = "/metrics";

pub mod v1 {
    pub const NODES_BASE: &str = "/v1/nodes";
    pub const NODES_BY_ID: &str = "/v1/nodes/{:id}";
    pub const NODES_OVERVIEW: &str = "/v1/nodes/overview";

    pub const INSTANCES_BASE: &str = "/v1/instances";
    pub const INSTANCES_SETTINGS: &str = "/v1/instances/settings";
    pub const INSTANCES_BY_ID: &str = "/v1/instances/{:id}";
    pub const INSTANCES_ACTION_BRIDGE_IN: &str = "/v1/instances/action/bridge_in_tx_prepare";
    pub const INSTANCES_OVERVIEW: &str = "/v1/instances/overview";
    pub const GRAPHS_BASE: &str = "/v1/graphs";
    pub const GRAPHS_BY_ID: &str = "/v1/graphs/{:id}";
    pub const GRAPHS_PRESIGN_CHECK: &str = "/v1/graphs/presign_check";
    pub const GRAPHS_TXN_BY_ID: &str = "/v1/graphs/{:id}/txn";
    pub const GRAPHS_TX_BY_ID: &str = "/v1/graphs/{:id}/tx";
    pub const PROOFS_BASE: &str = "/v1/proofs";
    pub const PROOFS_BY_BLOCK_NUMBER: &str = "/v1/proofs/{:block_number}";
    pub const PROOFS_GROTH16_BASE: &str = "/v1/proofs/groth16";
    pub const PROOFS_GROTH16_BY_BLOCK_NUMBER: &str = "/v1/proofs/groth16/{:block_number}";
    pub const PROOFS_OVERVIEW: &str = "/v1/proofs/overview";
}
