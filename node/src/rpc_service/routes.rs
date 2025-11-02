pub(crate) const ROOT: &str = "/";
pub(crate) const METRICS: &str = "/metrics";

pub(crate) mod v1 {
    pub const NODES_BASE: &str = "/v1/nodes";
    pub const NODES_BY_ID: &str = "/v1/nodes/{:id}";
    pub const NODES_OVERVIEW: &str = "/v1/nodes/overview";

    pub const INSTANCES_BASE: &str = "/v1/instances";
    pub const INSTANCES_SETTINGS: &str = "/v1/instances/settings";
    pub const INSTANCES_BY_ID: &str = "/v1/instances/{:id}";
    pub const INSTANCES_OVERVIEW: &str = "/v1/instances/overview";
    pub const GRAPHS_BASE: &str = "/v1/graphs";
    pub const GRAPHS_BY_ID: &str = "/v1/graphs/{:id}";
    pub const GRAPHS_READY_TO_KICKOFF: &str = "/v1/graphs/ready-to-kickoff";
    pub const GRAPHS_TXN_BY_ID: &str = "/v1/graphs/{:id}/txn";
    pub const GRAPHS_TX_BY_ID: &str = "/v1/graphs/{:id}/tx";
    pub const PROOFS_BASE: &str = "/v1/proofs";
    pub const PROOFS_BLOCKS_DESC: &str = "/v1/proofs/blocks-desc";
}
