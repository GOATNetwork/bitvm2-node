use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::default::Default;
use store::{BridgeInStatus, BridgeOutStatus, Graph, GraphStatus, Instance};

// the input to our `create_user` handler
#[derive(Deserialize, Serialize)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    //.. others
}

/// bridge-in: step1 & step2.1
#[derive(Deserialize, Serialize)]
pub struct BridgeInTransactionPrepare {
    /// UUID
    pub instance_id: String,
    /// testnet3 | mainnet
    pub network: String,
    /// pBTC <-> tBTC | BTC
    // pub bridge_path: String,
    pub amount: u64,
    pub fee_rate: u64,
    pub utxo: Vec<UTXO>,

    // address
    pub from: String, // BTC /charge
    pub to: String, // ETH
}

#[derive(Deserialize, Serialize)]
pub struct BridgeInTransactionPrepareResponse {}

/// bridge-in step2.2  BridgeInTransactionPrepare

/// deps: BridgeInTransactionPrepare
///  handler: operator
///     Operator creates a graph record in database and broadcast the new graph to peers
#[derive(Deserialize)]
pub struct GraphGenerate {
    pub instance_id: String,
    // UUID
    pub graph_id: String,
    //calculate staking amount according to the peg-in amount
}

// UI can go next(step2.3) once one operator responds
#[derive(Deserialize, Serialize)]
pub struct GraphGenerateResponse {
    pub instance_id: String,
    pub graph_id: String,
    // unsigned_txns, operator signature, this steps ask operator to publish unsigned txns
    pub graph_ipfs_unsigned_txns: String,
    // pub graph_ipfs_operator_sig: String,
}

/// bridge-in step 2.3

/// handler: committee
#[derive(Deserialize)]
pub struct GraphPresign {
    pub instance_id: String,
    // pub graph_id: String,
    // the root directory of all graph_ipfs_* files
    pub graph_ipfs_base_url: String,
}

// Committee publishs txn signatures in ipfs url
#[derive(Deserialize, Serialize)]
pub struct GraphPresignResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub graph_ipfs_committee_txns: String,
}

#[derive(Deserialize)]
pub struct GraphPresignCheck {
    pub instance_id: String,
    // get graph_id from nodes' database,
}

#[derive(Deserialize, Serialize)]
pub struct GraphPresignCheckResponse {
    pub instance_id: String,
    pub instance_status: BridgeInStatus,
    pub graph_status: HashMap<String, GraphStatus>,
    pub tx: Option<Instance>,
}

/// bridge-in: step3

/// handler: relayer
#[derive(Deserialize)]
pub struct PegBTCMint {
    // pub instance_id: String,
    pub graph_id: Vec<String>,
    pub pegin_txid: String,
    // TODO: https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/contracts/Gateway.sol#L43
}

#[derive(Deserialize, Serialize)]
pub struct PegBTCMintResponse {
    // 200: success,
}

/// bridge-out step2
#[derive(Deserialize)]
pub struct BridgeOutTransactionPrepare {
    pub instance_id: String,
    // GOAT txid
    pub pegout_txid: String,
    // For double check with operator selected in peg out txn
    pub operator: String,
}

#[derive(Deserialize, Serialize)]
pub struct BridgeOutTransactionPrepareResponse {
    pub instance_id: String,
    pub btc_hashed_timelock_utxo: UTXO,
    /// BTC address
    pub operator_refund_address: String,
}

// handler: committee
#[derive(Deserialize)]
pub struct BridgeOutUserClaimRequest {
    // pub instance_id: String,
    // hex
    pub pegout_txid: String,
    pub signed_claim_txn: String,
}

#[derive(Deserialize, Serialize)]
pub struct BridgeOutUserClaimResponse {
    pub instance_id: String,
    pub claim_txid: String,
}

/// get tx detail
#[derive(Deserialize)]
pub struct InstanceListRequest {
    pub user_address: String,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceListResponse {
    //                               // instance_id -> (txid, bridge_path)
    pub instances: Vec<Instance>, // HashMap<String, (String, String)>
}

#[derive(Deserialize)]
pub struct InstanceGetRequest {
    pub instance_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceGetResponse {
    pub instance: Instance,
}

#[derive(Deserialize)]
pub struct GraphGetRequest {
    pub graph_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct GraphGetResponse {
    pub graph: Graph,
}

#[derive(Deserialize)]
pub struct Pagination{
    pub offset: u32,
    pub limit: u32,
}

/// graph_overview
// All fields can be optional
// if all are none, we fetch all the graph list order by timestamp desc.
#[derive(Deserialize)]
pub struct GraphListRequest {
    pub status: GraphStatus,
    pub operator: String,
    pub pegin_txid: String,
}

#[derive(Deserialize, Serialize)]
pub struct GraphListResponse {
    pub graphs: Vec<Graph>,
    pub total_bridge_in_amount: u64,
    pub total_bridge_in_txn: u32,
    pub total_bridge_out_amount: u64,
    pub total_bridge_out_txn: u32,
    pub online_nodes: u32,
    pub total_nodes: u32,
}
