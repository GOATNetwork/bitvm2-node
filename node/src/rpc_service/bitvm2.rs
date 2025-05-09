use crate::env::{CHEKSIG_P2WSH_INPUT_VBYTES, PEGIN_BASE_VBYTES};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Network, OutPoint, Txid};
use bitvm2_lib::types::CustomInputs;
use goat::transactions::base::Input;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::default::Default;
use std::str::FromStr;
use store::{GrapRpcQueryData, Graph, Instance};
use uuid::Uuid;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    //.. others
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InstanceSettingResponse {
    pub bridge_in_amount: Vec<f32>,
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

#[derive(Debug, Deserialize)]
pub struct GraphPresignCheckParams {
    pub instance_id: String,
}

#[derive(Debug, Deserialize)]
pub struct GraphTxGetParams {
    pub tx_name: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct GraphPresignCheckResponse {
    pub instance_id: String,
    pub instance_status: String,
    pub graph_status: HashMap<String, String>,
    pub tx: Option<Instance>,
}

/// get tx detail
#[derive(Debug, Deserialize)]
pub struct InstanceListRequest {
    pub from_addr: Option<String>,
    pub bridge_path: Option<u8>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceWrap {
    pub instance: Option<Instance>,
    pub utxo: Option<Vec<UTXO>>,
    pub confirmations: u32,
    pub target_confirmations: u32,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceListResponse {
    pub instance_wraps: Vec<InstanceWrap>,
    pub total: i64,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceGetResponse {
    pub instance_wrap: InstanceWrap,
}

#[derive(Deserialize)]
pub struct InstanceUpdateRequest {
    pub instance: Instance,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceUpdateResponse {}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceOverviewResponse {
    pub instances_overview: InstanceOverview,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceOverview {
    pub total_bridge_in_amount: i64,
    pub total_bridge_in_txn: i64,
    pub total_bridge_out_amount: i64,
    pub total_bridge_out_txn: i64,
    pub online_nodes: i64,
    pub total_nodes: i64,
}

#[derive(Deserialize, Serialize)]
pub struct GraphGetResponse {
    pub graph: Option<Graph>,
}
#[derive(Deserialize, Serialize)]
pub struct GraphTxnGetResponse {
    #[serde(rename = "assert-commit0")]
    pub assert_commit0: String,
    #[serde(rename = "assert-commit1")]
    pub assert_commit1: String,
    #[serde(rename = "assert-commit2")]
    pub assert_commit2: String,
    #[serde(rename = "assert-commit3")]
    pub assert_commit3: String,
    #[serde(rename = "assert-init")]
    pub assert_init: String,
    #[serde(rename = "assert-final")]
    pub assert_final: String,
    pub challenge: String,
    pub disprove: String,
    pub kickoff: String,
    pub pegin: String,
    pub take1: String,
    pub take2: String,
}
#[derive(Deserialize, Serialize)]
pub struct GraphTxGetResponse {
    pub tx_hex: String,
}

#[derive(Deserialize)]
pub struct GraphUpdateRequest {
    pub graph: Graph,
}

#[derive(Deserialize, Serialize)]
pub struct GraphUpdateResponse {}

#[derive(Debug, Deserialize)]
pub struct GraphQueryParams {
    pub status: Option<String>,
    pub operator: Option<String>,
    pub from_addr: Option<String>,
    pub pegin_txid: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// graph_overview
// All fields can be optional
// if all are none, we fetch all the graph list order by timestamp desc.

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GraphListResponse {
    pub graphs: Vec<GrapRpcQueryDataWrap>,
    pub total: i64,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GrapRpcQueryDataWrap {
    pub graph: GrapRpcQueryData,
    pub confirmations: u32,
    pub target_confirmations: u32,
}

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

        let input_amount: u64 = value.amount as u64;
        let input_size = inputs.len() as u64;
        let user_inputs = CustomInputs {
            inputs,
            input_amount: Amount::from_sat(input_amount),
            //TODO
            fee_amount: Amount::from_sat(
                PEGIN_BASE_VBYTES + CHEKSIG_P2WSH_INPUT_VBYTES * input_size,
            ),
            change_address,
        };
        let env_address =
            alloy::primitives::Address::from_str(&value.to).expect("fail to decode address");
        Self {
            instance_id: Uuid::parse_str(&value.instance_id).unwrap(),
            network,
            depositor_evm_address: env_address.into_array(),
            pegin_amount: Amount::from_sat(value.amount as u64),
            user_inputs,
        }
    }
}
