use super::utils::{deserialize_u256, serialize_u256};
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use store::{Node, NodesOverview};

pub const ALIVE_TIME_JUDGE_THRESHOLD: i64 = 4 * 3600;
pub const NODE_STATUS_ONLINE: &str = "Online";
pub const NODE_STATUS_OFFLINE: &str = "Offline";

/// node_overview
#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct NodeListRequest {
    pub actor: String,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
pub struct NodeQueryParams {
    pub actor: Option<String>,
    pub status: Option<String>,
    pub goat_addr: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeDesc>,
    pub total: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct NodeOverViewResponse {
    pub nodes_overview: NodesOverview,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct NodeDesc {
    pub peer_id: String,
    pub actor: String,
    pub name: String,
    pub service_fee_rate: f64,
    #[serde(serialize_with = "serialize_u256", deserialize_with = "deserialize_u256")]
    pub available_peg_btc: U256,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    #[serde(serialize_with = "serialize_u256", deserialize_with = "deserialize_u256")]
    pub reward: U256,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: String, //dynamic status: online/offline
}

pub trait ToNodeDesc {
    fn to_node_desc(self, time_threshold: i64, current_peer_id: &str) -> NodeDesc;
}

impl ToNodeDesc for Node {
    fn to_node_desc(self, time_threshold: i64, current_peer_id: &str) -> NodeDesc {
        let status = if self.updated_at >= time_threshold || self.peer_id == current_peer_id {
            NODE_STATUS_ONLINE
        } else {
            NODE_STATUS_OFFLINE
        };

        NodeDesc {
            peer_id: self.peer_id.clone(),
            actor: self.actor.clone(),
            name: self.node_name.clone(),
            service_fee_rate: self.service_fee_rate,
            updated_at: self.updated_at,
            status: status.to_string(),
            goat_addr: self.goat_addr.clone(),
            btc_pub_key: self.btc_pub_key.clone(),
            socket_addr: self.socket_addr.clone(),
            reward: U256::from_str(&self.reward).unwrap_or_default(),
            available_peg_btc: U256::from_str(&self.available_peg_btc).unwrap_or_default(),
            created_at: self.created_at,
        }
    }
}
