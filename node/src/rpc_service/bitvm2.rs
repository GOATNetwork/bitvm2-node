use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::default::Default;
use std::str::FromStr;
use uuid::Uuid;
use bitcoin::{Address, Amount, Network, OutPoint, Txid};
use bitcoin::address::NetworkUnchecked;
use goat::transactions::base::Input;
use bitvm2_lib::types::CustomInputs;
use store::{BridgeInStatus, Graph, GraphStatus, Instance};

// the input to our `create_user` handler
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    //.. others
}

/// bridge-in: step1 & step2.1
#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeInTransactionPreparerRequest {
    pub instance_id: String, // UUID
    pub network: String,     // testnet3 | mainnet
    pub amount: i64,
    pub fee_rate: i64,
    pub utxo: Vec<UTXO>,
    pub from: String, // BTC /charge
    pub to: String,   // ETH
}

#[derive(Deserialize, Serialize)]
pub struct BridgeInTransactionPrepareResponse {}

/// bridge-in step2.2  BridgeInTransactionPrepare
/// deps: BridgeInTransactionPrepare
///  handler: Operator creates a graph record in database and broadcast the new graph to peers
/// calculate staking amount according to the peg-in amount
#[derive(Debug, Deserialize)]
pub struct GraphGenerateRequest {
    pub instance_id: String, // UUID
    pub graph_id: String,
}

// UI can go next(step2.3) once one operator responds
#[derive(Deserialize, Serialize, Default)]
pub struct GraphGenerateResponse {
    pub instance_id: String,
    pub graph_id: String,
    // unsigned_txns, operator signature, this steps ask operator to publish unsigned txns
    pub graph_ipfs_unsigned_txns: String,
}

/// bridge-in step 2.3
/// handler: committee
#[derive(Debug, Deserialize)]
pub struct GraphPresignRequest {
    pub instance_id: String,
    pub graph_ipfs_base_url: String, // the root directory of all graph_ipfs_* files
}

// Committee publishs txn signatures in ipfs url
#[derive(Clone, Deserialize, Serialize)]
pub struct GraphPresignResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub graph_ipfs_committee_txns: String,
}

#[derive(Debug, Deserialize)]
pub struct GraphPresignCheckRequest {
    pub instance_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct GraphPresignCheckResponse {
    pub instance_id: String,
    pub instance_status: BridgeInStatus,
    pub graph_status: HashMap<String, GraphStatus>,
    pub tx: Option<Instance>,
}

/// bridge-in: step3
/// handler: relayer
#[derive(Debug, Deserialize)]
pub struct PegBTCMintRequest {
    pub graph_ids: Vec<String>,
    pub pegin_txid: String,
    // TODO: https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/contracts/Gateway.sol#L43
}

#[derive(Deserialize, Serialize)]
pub struct PegBTCMintResponse {}

/// bridge-out step2
#[derive(Debug, Deserialize)]
pub struct BridgeOutTransactionPrepareRequest {
    //TODO
    pub instance_id: String,
    pub operator: String,
}

#[derive(Deserialize, Serialize, Default)]
pub struct BridgeOutTransactionPrepareResponse {
    // TODO
    pub instance_id: String,
}

// // handler: committee
// #[derive(Debug, Deserialize)]
// pub struct BridgeOutUserClaimRequest {
//     pub pegout_txid: String,
//     pub signed_claim_txn: String,
// }
//
// #[derive(Clone, Deserialize, Serialize)]
// pub struct BridgeOutUserClaimResponse {
//     pub instance_id: String,
//     pub claim_txid: String,
// }

/// get tx detail
#[derive(Debug, Deserialize)]
pub struct InstanceListRequest {
    pub user_address: Option<String>,
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
pub struct InstanceUpdateRequest {
    pub instance: Instance,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceUpdateResponse {}

#[derive(Deserialize)]
pub struct GraphGetRequest {
    pub graph_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct GraphGetResponse {
    pub graph: Graph,
}

#[derive(Deserialize)]
pub struct GraphUpdateRequest {
    pub graph: Graph,
}

#[derive(Deserialize, Serialize)]
pub struct GraphUpdateResponse {}

#[derive(Deserialize)]
pub struct Pagination {
    pub offset: u32,
    pub limit: u32,
}

/// graph_overview
// All fields can be optional
// if all are none, we fetch all the graph list order by timestamp desc.
#[derive(Deserialize)]
pub struct GraphListRequest {
    pub status: GraphStatus,
    pub pegin_txid: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GraphListResponse {
    pub graphs: Vec<Graph>,
    pub total_bridge_in_amount: i64,
    pub total_bridge_in_txn: i64,
    pub total_bridge_out_amount: i64,
    pub total_bridge_out_txn: i64,
    pub online_nodes: i64,
    pub total_nodes: i64,
}

const STACK_AMOUNT: Amount = Amount::from_sat(20_000_000);
const FEE_AMOUNT: Amount = Amount::from_sat(2000);
#[derive(Clone, Serialize, Deserialize)]
pub struct P2pUserData {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
}

impl From<&BridgeInTransactionPreparerRequest> for P2pUserData {
    fn from(value: &BridgeInTransactionPreparerRequest) -> Self {
        let network = Network::from_str(&value.network).expect("decode network success");
        let change_address: Address<NetworkUnchecked> =
            value.from.parse().expect("decode btc address");
        let change_address = change_address.require_network(network).expect("set network");

        let inputs: Vec<Input> = value
            .utxo
            .iter()
            .map(|v| Input {
                outpoint: OutPoint { txid: Txid::from_str(&v.txid).unwrap(), vout: v.vout },
                amount: Amount::from_sat(v.value),
            })
            .collect();

        let input_amount: u64 = value.utxo.iter().map(|v| v.value).sum();
        let user_inputs = CustomInputs {
            inputs,
            input_amount: Amount::from_sat(input_amount),
            fee_amount: FEE_AMOUNT, // TODO get fee amount
            change_address,
        };
        let env_address: web3::types::Address = value.to.parse().expect("decode eth address");
        Self {
            instance_id: Uuid::parse_str(&value.instance_id).unwrap(),
            network,
            depositor_evm_address: env_address.0,
            pegin_amount: Amount::from_sat(value.amount as u64),
            user_inputs,
        }
    }
}
