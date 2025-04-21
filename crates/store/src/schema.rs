use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::str::FromStr;
use uuid::Uuid;

pub const NODE_STATUS_ONLINE: &str = "Online";
pub const NODE_STATUS_OFFLINE: &str = "Offline";

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Node {
    pub peer_id: String,
    pub actor: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub updated_at: i64,
    pub created_at: i64,
}

/// tem query data
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodesOverview {
    pub total: i64,
    pub online_operator: i64,
    pub offline_operator: i64,
    pub online_challenger: i64,
    pub offline_challenger: i64,
    pub online_committee: i64,
    pub offline_committee: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Instance {
    pub instance_id: Uuid,
    pub network: String,
    pub bridge_path: u8,
    pub from_addr: String,
    pub to_addr: String,
    pub amount: i64,    // in sat
    pub status: String, // BridgeInStatus | BridgeOutStutus
    pub goat_txid: String,
    pub btc_txid: String,
    pub pegin_txid: Option<String>,
    pub input_uxtos: String,
    pub fee: i64,
    pub created_at: i64,
    pub updated_at: i64, // updating time
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum BridgeInStatus {
    #[default]
    Submitted,
    Presigned, // includes operator and Committee presigns
    L1Broadcasted,
    L2Minted, // success
}

impl std::fmt::Display for BridgeInStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum BridgeOutStatus {
    #[default]
    L2Locked,
    L1Locked,
    L1Unlocked,
    L2Unlocked,    // success
    L2LockTimeout, // L2Locked -> L2 timeout (operator is offline)
    L1LockTimeout, // L1Locked -> L1 timeout -> L2 timeout (user doesn't presign)
    L1Refunded,
    L2Refunded,
}

impl std::fmt::Display for BridgeOutStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// graph status
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum GraphStatus {
    #[default]
    OperatorPresigned,
    CommitteePresigned,
    KickOff,
    Challenge,
    Assert,
    Take1,
    Take2,
    Disprove,   // fail to reimbursement
    Deprecated, // reimbursement by other operators
}

impl FromStr for GraphStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OperatorPresigned" => Ok(GraphStatus::OperatorPresigned),
            "CommitteePresigned" => Ok(GraphStatus::CommitteePresigned),
            "KickOff" => Ok(GraphStatus::KickOff),
            "Challenge" => Ok(GraphStatus::Challenge),
            "Assert" => Ok(GraphStatus::Assert),
            "Take1" => Ok(GraphStatus::Take1),
            "Take2" => Ok(GraphStatus::Take2),
            "Disprove" => Ok(GraphStatus::Disprove),
            "Deprecated" => Ok(GraphStatus::Deprecated),
            _ => Err(()),
        }
    }
}
impl std::fmt::Display for GraphStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub enum BridgePath {
    BtcToPGBtc = 0,
    PGBtcToBtc = 1,
}
impl BridgePath {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(BridgePath::BtcToPGBtc),
            1 => Some(BridgePath::PGBtcToBtc),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}
/// graph detail
/// Field `graph_ipfs_base_url` is the IFPS address, which serves as a directory address containing the following files within that directory.
/// ├── assert-commit0.hex
/// ├── assert-commit1.hex
/// ├── assert-commit2.hex
/// ├── assert-commit3.hex
/// ├── assert-final.hex
/// ├── assert-init.hex
/// ├── challenge.hex
/// ├── disprove.hex
/// ├── kickoff.hex
/// ├── pegin.hex
/// ├── take1.hex
/// └── take2.hex
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Graph {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub graph_ipfs_base_url: String,
    pub pegin_txid: String,
    pub amount: i64,
    pub status: String, // GraphStatus
    pub kickoff_txid: Option<String>,
    pub challenge_txid: Option<String>,
    pub take1_txid: Option<String>,
    pub assert_init_txid: Option<String>,
    pub assert_commit_txids: Option<String>,
    pub assert_final_txid: Option<String>,
    pub take2_txid_txid: Option<String>,
    pub disprove_txid: Option<String>,
    pub operator: String,
    pub raw_data: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

// query Data
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GrapRpcQueryData {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub bridge_path: u8,
    pub network: String,
    pub from_addr: String,
    pub to_addr: String,
    pub amount: i64,
    pub pegin_txid: String,
    pub status: String, // GraphStatus
    pub kickoff_txid: Option<String>,
    pub challenge_txid: Option<String>,
    pub take1_txid: Option<String>,
    pub assert_init_txid: Option<String>,
    pub assert_commit_txids: Option<String>,
    pub assert_final_txid: Option<String>,
    pub take2_txid_txid: Option<String>,
    pub disprove_txid: Option<String>,
    pub operator: String,
    pub updated_at: i64,
    pub created_at: i64,
}

impl GrapRpcQueryData {
    pub fn get_check_tx_param(&self) -> Result<(Option<String>, u32), String> {
        if self.bridge_path == 0 {
            return Ok((Some(self.pegin_txid.clone()), 6));
        }
        let status = GraphStatus::from_str(&self.status);
        if status.is_err() {
            return Err("Graph status is wrong".to_string());
        }
        match status.unwrap() {
            GraphStatus::OperatorPresigned | GraphStatus::CommitteePresigned => {
                Err("Not start kickOff".to_string())
            }
            GraphStatus::KickOff => Ok((self.kickoff_txid.clone(), 6)),
            GraphStatus::Challenge => Ok((self.challenge_txid.clone(), 6)),
            GraphStatus::Assert => Ok((self.assert_init_txid.clone(), 18)),
            GraphStatus::Take1 => Ok((self.take1_txid.clone(), 6)),
            GraphStatus::Take2 => Ok((self.take2_txid_txid.clone(), 6)),
            GraphStatus::Disprove => Ok((self.disprove_txid.clone(), 6)),
            GraphStatus::Deprecated => Err("graph deprecated".to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum MessageState {
    Pending,
    Processing,
    Processed,
    Failed,
    Expired,
    Cancelled,
}

impl std::fmt::Display for MessageState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for MessageState {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Pending" => Ok(MessageState::Pending),
            "Processing" => Ok(MessageState::Processing),
            "Processed" => Ok(MessageState::Processed),
            "Failed" => Ok(MessageState::Failed),
            "Expired" => Ok(MessageState::Expired),
            "Cancelled" => Ok(MessageState::Cancelled),
            _ => Err(()),
        }
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Message {
    pub id: i64,
    pub actor: String,
    pub from_peer: String,
    pub msg_type: String,
    pub content: Vec<u8>,
    pub state: String,
}
