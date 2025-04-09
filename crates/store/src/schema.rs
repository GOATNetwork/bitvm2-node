use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::str::FromStr;
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Node {
    pub peer_id: String,
    pub actor: String,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Instance {
    pub instance_id: String,
    pub bridge_path: u8,
    pub from_addr: String,
    pub to_addr: String,
    pub amount: i64, // in sat
    pub created_at: i64,
    pub updated_at: i64, // updating time
    pub status: String,  // BridgeInStatus | BridgeOutStutus
    pub goat_txid: String,
    pub btc_txid: String,
    pub pegin_tx: Option<String>,
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
    pub graph_id: String,
    pub instance_id: String,
    pub graph_ipfs_base_url: String,
    pub pegin_txid: String,
    pub amount: i64,
    pub created_at: i64,
    pub status: String, // GraphStatus
    pub challenge_txid: Option<String>,
    pub disprove_txid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilterGraphsInfo {
    pub status: String, // GraphStatus
    pub pegin_txid: String,
    pub offset: u32,
    pub limit: u32,
}
