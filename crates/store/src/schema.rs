use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::str::FromStr;
use uuid::Uuid;

pub const NODE_STATUS_ONLINE: &str = "Online";
pub const NODE_STATUS_OFFLINE: &str = "Offline";
pub const COMMITTEE_PRE_SIGN_NUM: usize = 5;

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Node {
    pub peer_id: String,
    pub actor: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    pub reward: i64,
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
    pub online_relayer: i64,
    pub offline_relayer: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Instance {
    pub instance_id: Uuid,
    pub network: String,
    pub bridge_path: u8,
    pub from_addr: String,
    pub to_addr: String,
    pub amount: i64,    // in sat
    pub status: String, // BridgeInStatus
    pub goat_txid: String,
    pub btc_txid: String,
    pub pegin_txid: Option<String>,
    pub input_uxtos: String,
    pub fee: i64,
    pub created_at: i64,
    pub updated_at: i64, // updating time
}

impl Instance {
    pub fn reverse_btc_txid(&mut self) {
        if let Some(pegin_txid) = self.pegin_txid.clone() {
            self.pegin_txid = Some(reversed_btc_txid(&pegin_txid));
        }
        self.btc_txid = reversed_btc_txid(&self.btc_txid);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum BridgeInStatus {
    #[default]
    Submitted,
    SubmittedFailed,
    Presigned,
    PresignedFailed, // includes operator and Committee presigns
    L1Broadcasted,
    L2Minted, // success
    L2MintedFailed,
}

impl FromStr for BridgeInStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Submitted" => Ok(BridgeInStatus::Submitted),
            "SubmittedFailed" => Ok(BridgeInStatus::SubmittedFailed),
            "Presigned" => Ok(BridgeInStatus::Presigned),
            "PresignedFailed" => Ok(BridgeInStatus::PresignedFailed),
            "L1Broadcasted" => Ok(BridgeInStatus::L1Broadcasted),
            "L2Minted" => Ok(BridgeInStatus::L2Minted),
            "L2MintedFailed" => Ok(BridgeInStatus::L2MintedFailed),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for BridgeInStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// graph status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq)]
pub enum GraphStatus {
    #[default]
    OperatorPresigned,
    CommitteePresigned,
    OperatorDataPushed,
    KickOff,
    Challenge,
    Assert,
    Take1,
    Take2,
    Disprove, // fail to reimbursement

    Created,
    Presigned,
    L2Recorded,
    KickOffing,
    Challenging,
    Asserting,
    Disproving,
    Obsoleted, // reimbursement by other operators
}

impl FromStr for GraphStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OperatorPresigned" => Ok(GraphStatus::OperatorPresigned),
            "CommitteePresigned" => Ok(GraphStatus::CommitteePresigned),
            "OperatorDataPushed" => Ok(GraphStatus::OperatorDataPushed),
            "KickOff" => Ok(GraphStatus::KickOff),
            "Challenge" => Ok(GraphStatus::Challenge),
            "Assert" => Ok(GraphStatus::Assert),
            "Take1" => Ok(GraphStatus::Take1),
            "Take2" => Ok(GraphStatus::Take2),
            "Disprove" => Ok(GraphStatus::Disprove),
            "Obsoleted" => Ok(GraphStatus::Obsoleted),

            "Created" => Ok(GraphStatus::Created),
            "Presigned" => Ok(GraphStatus::Presigned),
            "L2Recorded" => Ok(GraphStatus::L2Recorded),
            "KickOffing" => Ok(GraphStatus::KickOffing),
            "Challenging" => Ok(GraphStatus::Challenging),
            "Asserting" => Ok(GraphStatus::Asserting),
            "Disproving" => Ok(GraphStatus::Disproving),
            _ => Err(()),
        }
    }
}
impl std::fmt::Display for GraphStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub enum BridgePath {
    BTCToPgBTC = 0,
    PgBTCToBTC = 1,
}
impl BridgePath {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(BridgePath::BTCToPgBTC),
            1 => Some(BridgePath::PgBTCToBTC),
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
    pub pre_kickoff_txid: Option<String>,
    pub kickoff_txid: Option<String>,
    pub challenge_txid: Option<String>,
    pub take1_txid: Option<String>,
    pub assert_init_txid: Option<String>,
    pub assert_commit_txids: Option<String>,
    pub assert_final_txid: Option<String>,
    pub take2_txid: Option<String>,
    pub disprove_txid: Option<String>,
    pub operator: String,
    pub raw_data: Option<String>,
    pub bridge_out_start_at: i64,
    pub bridge_out_from_addr: String,
    pub bridge_out_to_addr: String,
    pub init_withdraw_txid: Option<String>,
    pub zkm_version: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Graph {
    pub fn reverse_btc_txid(&mut self) {
        self.pegin_txid = reversed_btc_txid(&self.pegin_txid);
        if let Some(pre_kickoff_txid) = self.pre_kickoff_txid.clone() {
            self.pre_kickoff_txid = Some(reversed_btc_txid(&pre_kickoff_txid));
        }

        if let Some(kickoff_txid) = self.kickoff_txid.clone() {
            self.kickoff_txid = Some(reversed_btc_txid(&kickoff_txid));
        }

        if let Some(challenge_txid) = self.challenge_txid.clone() {
            self.challenge_txid = Some(reversed_btc_txid(&challenge_txid));
        }
        if let Some(take1_txid) = self.take1_txid.clone() {
            self.take1_txid = Some(reversed_btc_txid(&take1_txid));
        }
        if let Some(assert_init_txid) = self.assert_init_txid.clone() {
            self.assert_init_txid = Some(reversed_btc_txid(&assert_init_txid));
        }
        if let Some(assert_commit_txids) = self.assert_commit_txids.clone()
            && let Ok(assert_commit_txids) =
                serde_json::from_str::<Vec<String>>(&assert_commit_txids)
        {
            let assert_commit_txids_re: Vec<String> =
                assert_commit_txids.iter().map(|v| reversed_btc_txid(v)).collect();
            self.assert_commit_txids = serde_json::to_string(&assert_commit_txids_re).ok()
        }

        if let Some(assert_final_txid) = self.assert_final_txid.clone() {
            self.assert_final_txid = Some(reversed_btc_txid(&assert_final_txid));
        }
        if let Some(take2_txid) = self.take2_txid.clone() {
            self.take2_txid = Some(reversed_btc_txid(&take2_txid));
        }
        if let Some(disprove_txid) = self.disprove_txid.clone() {
            self.disprove_txid = Some(reversed_btc_txid(&disprove_txid));
        }
    }
}

pub fn modify_graph_status(ori_status: &str, is_kickoffing: bool) -> String {
    match ori_status {
        "OperatorPresigned" => "Created".to_string(),
        "CommitteePresigned" => "Presigned".to_string(),
        "OperatorDataPushed" => {
            if is_kickoffing {
                "KickOffing".to_string()
            } else {
                "L2Recorded".to_string()
            }
        }
        "KickOff" => "Challenging".to_string(),
        "Challenge" => "Asserting".to_string(),
        "Assert" => "Disproving".to_string(),
        _ => ori_status.to_string(),
    }
}

pub fn convert_to_step_state(ori_status: &str) -> String {
    match ori_status {
        "Created" => "OperatorPresigned".to_string(),
        "Presigned" => "CommitteePresigned".to_string(),
        "L2Recorded" => "OperatorDataPushed".to_string(),
        "KickOffing" => "OperatorDataPushed".to_string(),
        "Challenging" => "KickOff".to_string(),
        "Asserting" => "Challenge".to_string(),
        "Disproving" => "Assert".to_string(),
        _ => ori_status.to_string(),
    }
}

// graph full data contain instance.from and instance.to
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GrapFullData {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub bridge_path: u8,
    pub network: String,
    pub from_addr: String,
    pub to_addr: String,
    pub amount: i64,
    pub pegin_txid: String,
    pub status: String,
    pub kickoff_txid: Option<String>,
    pub challenge_txid: Option<String>,
    pub take1_txid: Option<String>,
    pub assert_init_txid: Option<String>,
    pub assert_commit_txids: Option<String>,
    pub assert_final_txid: Option<String>,
    pub take2_txid: Option<String>,
    pub disprove_txid: Option<String>,
    pub bridge_out_start_at: i64,
    pub bridge_out_from_addr: String,
    pub bridge_out_to_addr: String,
    pub init_withdraw_txid: Option<String>,
    pub operator: String,
    pub updated_at: i64,
    pub created_at: i64,
}

impl GrapFullData {
    pub fn get_check_tx_param(&self) -> Result<(Option<String>, u32), String> {
        let status = GraphStatus::from_str(&self.status);
        if status.is_err() {
            return Err("Graph status is wrong".to_string());
        }
        match status.unwrap() {
            GraphStatus::KickOff => Ok((self.kickoff_txid.clone(), 6)),
            GraphStatus::Challenge => Ok((self.challenge_txid.clone(), 6)),
            GraphStatus::Assert => Ok((self.assert_init_txid.clone(), 18)),
            GraphStatus::Take1 => Ok((self.take1_txid.clone(), 6)),
            GraphStatus::Take2 => Ok((self.take2_txid.clone(), 6)),
            GraphStatus::Disprove => Ok((self.disprove_txid.clone(), 6)),
            _ => Err("not check status".to_string()),
        }
    }
    pub fn reverse_btc_txid(&mut self) {
        self.pegin_txid = reversed_btc_txid(&self.pegin_txid);
        if let Some(kickoff_txid) = self.kickoff_txid.clone() {
            self.kickoff_txid = Some(reversed_btc_txid(&kickoff_txid));
        }
        if let Some(challenge_txid) = self.challenge_txid.clone() {
            self.challenge_txid = Some(reversed_btc_txid(&challenge_txid));
        }
        if let Some(take1_txid) = self.take1_txid.clone() {
            self.take1_txid = Some(reversed_btc_txid(&take1_txid));
        }
        if let Some(assert_init_txid) = self.assert_init_txid.clone() {
            self.assert_init_txid = Some(reversed_btc_txid(&assert_init_txid));
        }
        if let Some(assert_commit_txids) = self.assert_commit_txids.clone()
            && let Ok(assert_commit_txids) =
                serde_json::from_str::<Vec<String>>(&assert_commit_txids)
        {
            let assert_commit_txids_re: Vec<String> =
                assert_commit_txids.iter().map(|v| reversed_btc_txid(v)).collect();
            self.assert_commit_txids = serde_json::to_string(&assert_commit_txids_re).ok()
        }

        if let Some(assert_final_txid) = self.assert_final_txid.clone() {
            self.assert_final_txid = Some(reversed_btc_txid(&assert_final_txid));
        }
        if let Some(take2_txid) = self.take2_txid.clone() {
            self.take2_txid = Some(reversed_btc_txid(&take2_txid));
        }
        if let Some(disprove_txid) = self.disprove_txid.clone() {
            self.disprove_txid = Some(reversed_btc_txid(&disprove_txid));
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
        write!(f, "{self:?}")
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

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct PubKeyCollect {
    pub instance_id: Uuid,
    pub pubkeys: String,
    pub updated_at: i64,
    pub created_at: i64,
}

pub struct PubKeyCollectMetaData {
    pub instance_id: Uuid,
    pub pubkeys: Vec<String>,
    pub updated_at: i64,
    pub created_at: i64,
}
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct NonceCollect {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub nonces: String,
    pub committee_pubkey: String,
    pub partial_sigs: String,
    pub updated_at: i64,
    pub created_at: i64,
}

pub struct NonceCollectMetaData {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub nonces: Vec<[String; COMMITTEE_PRE_SIGN_NUM]>,
    pub committee_pubkey: String,
    pub partial_sigs: Vec<[String; COMMITTEE_PRE_SIGN_NUM]>,
    pub updated_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub enum MessageType {
    BridgeInData,
    CreateInstance,
    CreateGraphPrepare,
    CreateGraph,
    NonceGeneration,
    CommitteePresign,
    GraphFinalize,
    KickoffReady,
    KickoffSent,
    Take1Ready,
    Take1Sent,
    ChallengeSent,
    AssertSent,
    Take2Ready,
    Take2Sent,
    DisproveSent,
}
impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// template query data struct
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GraphTickActionMetaData {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub status: String,
    pub msg_times: i64,
    pub msg_type: String,
    pub kickoff_txid: Option<String>,
    pub take1_txid: Option<String>,
    pub take2_txid: Option<String>,
    pub assert_init_txid: Option<String>,
    pub assert_commit_txids: Option<String>,
    pub assert_final_txid: Option<String>,
    pub challenge_txid: Option<String>,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct MessageBroadcast {
    pub instance_id: Uuid,
    pub graph_id: Option<Uuid>,
    pub msg_type: String,
    pub msg_times: i64,
    pub updated_at: i64,
    pub created_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct ProofWithPis {
    pub instance_id: Uuid,
    pub graph_id: Option<Uuid>,
    pub proof: String,
    pub pis: String,
    pub goat_block_number: i64,
    pub proof_cast: i64,
    pub created_at: i64,
}

fn reversed_btc_txid(tx_id: &str) -> String {
    if let Ok(mut tx_id_vec) = hex::decode(tx_id) {
        tx_id_vec.reverse();
        hex::encode(tx_id_vec)
    } else {
        tx_id.to_string()
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct BlockProof {
    pub block_number: i64,
    pub tx_count: i64,
    pub gas_used: i64,
    pub total_time_to_proof: i64,
    pub proving_time: i64,
    pub proving_cycles: i64,
    pub proof: String,
    pub proof_size: f64,
    pub public_values: String,
    pub verifier_id: String,
    pub zkm_version: String,
    pub state: String,
    pub reason: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct AggregationProof {
    pub block_number: i64,
    pub total_time_to_proof: i64,
    pub proving_time: i64,
    pub proving_cycles: i64,
    pub proof: String,
    pub proof_size: f64,
    pub public_values: String,
    pub verifier_id: String,
    pub zkm_version: String,
    pub state: String,
    pub reason: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Groth16Proof {
    pub block_number: i64,
    pub start_number: i64,
    pub real_numbers: i64,
    pub total_time_to_proof: i64,
    pub proving_time: i64,
    pub proving_cycles: i64,
    pub proof: String,
    pub proof_size: f64,
    pub public_values: String,
    pub verifier_id: String,
    pub zkm_version: String,
    pub state: String,
    pub reason: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct ProofConfig {
    pub id: i64,
    pub block_proof_concurrency: i64,
    pub aggregate_block_count: i64,
    pub start_aggregation_number: i64,
    pub updated_at: i64,
}

/// This data structure is not intended for database table creation ;
/// it serves the purpose of supporting information related to query proofs.
#[derive(Clone, Debug, FromRow)]
pub struct ProofInfo {
    pub block_number: i64,
    pub real_numbers: String,
    pub proving_cycles: i64,
    pub state: String,
    pub proving_time: i64,
    pub proof_size: f64,
    pub zkm_version: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct VerifierKey {
    pub verifier_id: String,
    pub verifier_key: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum WatchContractStatus {
    #[default]
    UnSync,
    Syncing,
    Synced,
    Failed,
}

impl FromStr for WatchContractStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UnSync" => Ok(WatchContractStatus::UnSync),
            "Syncing" => Ok(WatchContractStatus::Syncing),
            "Synced" => Ok(WatchContractStatus::Synced),
            "Failed" => Ok(WatchContractStatus::Failed),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for WatchContractStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct WatchContract {
    pub addr: String,
    pub the_graph_url: String,
    pub gap: i64,
    pub from_height: i64,
    pub status: String,
    pub extra: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum GoatTxType {
    #[default]
    Normal,
    PostPeginData,
    PostOperatorData,
    InitWithdraw,
    CancelWithdraw,
    ProceedWithdraw,
    WithdrawHappyPath,
    WithdrawUnhappyPath,
    WithdrawDisproved,
}

impl FromStr for GoatTxType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Normal" => Ok(GoatTxType::Normal),
            "PostPeginData" => Ok(GoatTxType::PostPeginData),
            "PostOperatorData" => Ok(GoatTxType::PostOperatorData),
            "InitWithdraw" => Ok(GoatTxType::InitWithdraw),
            "CancelWithdraw" => Ok(GoatTxType::CancelWithdraw),
            "ProceedWithdraw" => Ok(GoatTxType::ProceedWithdraw),
            "WithdrawHappyPath" => Ok(GoatTxType::WithdrawHappyPath),
            "WithdrawUnhappyPath" => Ok(GoatTxType::WithdrawUnhappyPath),
            "WithdrawDisproved" => Ok(GoatTxType::WithdrawDisproved),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for GoatTxType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum GoatTxProveStatus {
    #[default]
    NoNeed,
    Pending,
    Proved,
    Failed,
}

impl FromStr for GoatTxProveStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NoNeed" => Ok(GoatTxProveStatus::NoNeed),
            "Pending" => Ok(GoatTxProveStatus::Pending),
            "Proved" => Ok(GoatTxProveStatus::Proved),
            "Failed" => Ok(GoatTxProveStatus::Failed),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for GoatTxProveStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GoatTxRecord {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub tx_type: String,
    pub tx_hash: String,
    pub height: i64,
    pub is_local: bool,
    pub prove_status: String,
    pub extra: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GoatTxProceedWithdrawExtra {
    pub challenge_txid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum ProofType {
    #[default]
    BlockProof,
    AggregationProof,
    Groth16Proof,
}
