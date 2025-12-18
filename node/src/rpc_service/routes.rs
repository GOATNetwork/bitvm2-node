pub(crate) const ROOT: &str = "/";
pub(crate) const METRICS: &str = "/metrics";

pub(crate) mod v1 {
    pub const NODES_BASE: &str = "/v1/nodes";
    pub const NODES_BY_ID: &str = "/v1/nodes/{:id}";
    pub const NODES_OVERVIEW: &str = "/v1/nodes/overview";

    pub const INSTANCES_BASE: &str = "/v1/instances";
    pub const INSTANCES_SETTINGS: &str = "/v1/instances/settings";
    pub const INSTANCES_BRIDGE_IN_REQUEST_TAG: &str = "/v1/instances/bridge-in-request-tag";
    pub const INSTANCES_BRIDGE_OUT_INIT_TAG: &str = "/v1/instances/bridge-out-init-tag";
    pub const INSTANCES_BY_ID: &str = "/v1/instances/{:id}";
    pub const INSTANCES_OVERVIEW: &str = "/v1/instances/overview";
    pub const INSTANCES_UNSIGNED_PEGIN_TXN: &str = "/v1/instances/{:id}/unsigned-pegin-txn";
    pub const INSTANCES_ESCROW_DATA: &str = "/v1/instances/{:id}/escrow-data";
    pub const GRAPHS_BASE: &str = "/v1/graphs";
    pub const GRAPHS_BY_ID: &str = "/v1/graphs/{:id}";
    pub const GRAPHS_READY_TO_KICKOFF: &str = "/v1/graphs/ready-to-kickoff";
    pub const GRAPHS_TXN_BY_ID: &str = "/v1/graphs/{:id}/txn";
    pub const GRAPHS_NEIGHBOR_IDS: &str = "/v1/graphs/{:id}/neighbor-ids";
    pub const GRAPHS_TX_BY_ID: &str = "/v1/graphs/{:id}/tx";
    // pub const PROOFS_BASE: &str = "/v1/proofs";
    pub const PROOFS_CHAIN_PROOFS_DESC: &str = "/v1/proofs/chain_proofs_desc";
    pub const NODES_WATCHTOWER_BASE: &str = "/v1/proofs/watchtower_proofs";
    pub const NODES_OPERATOR_BASE: &str = "/v1/proofs/operator_proofs";
}
