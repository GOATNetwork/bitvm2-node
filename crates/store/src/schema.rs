use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use indexmap::IndexMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use strum::{Display, EnumString};
use uuid::Uuid;

pub const NODE_STATUS_ONLINE: &str = "Online";
pub const NODE_STATUS_OFFLINE: &str = "Offline";
pub const COMMITTEE_PRE_SIGN_NUM: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerializableTxid(pub Txid);

impl From<Txid> for SerializableTxid {
    fn from(txid: Txid) -> Self {
        SerializableTxid(txid)
    }
}

impl From<SerializableTxid> for Txid {
    fn from(serializable_txid: SerializableTxid) -> Self {
        serializable_txid.0
    }
}

impl Default for SerializableTxid {
    fn default() -> Self {
        SerializableTxid(Txid::from_byte_array([0u8; 32]))
    }
}
impl Serialize for SerializableTxid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SerializableTxid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tx_str = String::deserialize(deserializer)?;
        Ok(SerializableTxid(Txid::from_str(&tx_str).map_err(serde::de::Error::custom)?))
    }
}
impl sqlx::Type<sqlx::Sqlite> for SerializableTxid {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <String as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Sqlite> for SerializableTxid {
    fn encode_by_ref(
        &self,
        args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let hex_string = self.0.to_string();
        <String as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&hex_string, args)
    }
}

impl sqlx::Decode<'_, sqlx::Sqlite> for SerializableTxid {
    fn decode(
        value: sqlx::sqlite::SqliteValueRef<'_>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let hex_string = <String as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        let txid = Txid::from_str(&hex_string)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(SerializableTxid(txid))
    }
}

macro_rules! define_numeric_array {
    ($name:ident, $size:expr) => {
        define_numeric_array!($name, $size, u8);
    };
    ($name:ident, $size:expr, $type:ty) => {
        #[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
        pub struct $name(pub [$type; $size]);

        impl TryFrom<String> for $name {
            type Error = sqlx::Error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let bytes = hex::decode(value).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

                if bytes.len() != $size * std::mem::size_of::<$type>() {
                    return Err(sqlx::Error::Decode(
                        format!(
                            "Expected {} bytes, got {}",
                            $size * std::mem::size_of::<$type>(),
                            bytes.len()
                        )
                        .into(),
                    ));
                }

                let mut array = [0 as $type; $size];
                for (i, chunk) in bytes.chunks(std::mem::size_of::<$type>()).enumerate() {
                    if i < $size {
                        let mut bytes_array = [0u8; std::mem::size_of::<$type>()];
                        bytes_array.copy_from_slice(chunk);
                        array[i] = <$type>::from_le_bytes(bytes_array);
                    }
                }
                Ok($name(array))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                let mut bytes = Vec::new();
                for &val in &value.0 {
                    bytes.extend_from_slice(&val.to_le_bytes());
                }
                hex::encode(bytes)
            }
        }

        impl sqlx::Type<sqlx::Sqlite> for $name {
            fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
                <String as sqlx::Type<sqlx::Sqlite>>::type_info()
            }
        }

        impl sqlx::Encode<'_, sqlx::Sqlite> for $name {
            fn encode_by_ref(
                &self,
                args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
            ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
                let hex_string = hex::encode(
                    self.0.iter().flat_map(|&val| val.to_le_bytes()).collect::<Vec<_>>(),
                );
                <String as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&hex_string, args)
            }
        }

        impl sqlx::Decode<'_, sqlx::Sqlite> for $name {
            fn decode(
                value: sqlx::sqlite::SqliteValueRef<'_>,
            ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                let string = <String as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
                string
                    .try_into()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
        }
    };
}

define_numeric_array!(ByteArray32, 32);
define_numeric_array!(Int64Array3, 3, i64);

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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CommitteeSignatures {
    pub xonly_pubkey: [u8; 32],
    pub l1_sig: Vec<u8>,
    pub l2_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Display, EnumString)]
pub enum InstanceStatus {
    #[default]
    UserInited, // from contract event request
    // committee won't answer if userRequest is invalid(e.g. insufficient fee)
    CommitteesAnswered,        // enough committee responsed & window expired
    UserBroadcastPeginPrepare, // user pegin prepare
    Presigned,                 // all committee signed PeginConfirm
    PresignedFailed,           // includes operator and Committee presigns
    RelayerL1Broadcasted,      // PeginConfirm broadcast by relayer
    RelayerL2Minted,           // success
    RelayerL2MintedFailed,
    Timeout,      // time to cancle bridgein
    UserCanceled, // user broadcast Pegin-cancel tx
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Instance {
    pub instance_id: Uuid,
    pub network: String,
    pub from_addr: String,
    pub to_addr: String,
    pub amount: i64,
    pub fees: Int64Array3,
    pub input_utxos: String,
    pub status: String,
    pub pegin_request_tx_hash: String, // goat tx hash
    pub pegin_request_height: i64,
    pub user_xonly_pubkey: ByteArray32,
    pub user_change_addr: String,
    pub user_refund_addr: String,
    pub pegin_prepare_txid: Option<SerializableTxid>, // btc txid
    pub pegin_confirm_txid: Option<SerializableTxid>, // btc txid
    pub pegin_cancel_txid: Option<SerializableTxid>,  // btc txid
    pub unsign_pegin_confirm_tx: Option<String>,
    #[sqlx(json)]
    pub committees_answers: IndexMap<String, CommitteeSignatures>,
    pub pegin_data_tx_hash: String,
    pub pegin_prepare_height: i64, // btc lock_time
    pub created_at: i64,
    pub updated_at: i64,
}

/// graph status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum GraphStatus {
    #[default]
    OperatorPresigned,
    CommitteePresigned,
    OperatorDataPushed,
    OperatorKickOff,
    Challenge,
    Disprove,

    //TODO Need to discuss.
    OperatorWatchtowerAndAssertInit,
    WatchtowerChallenge, //
    OperatorWatchtowerChallengeTimeout,
    OperatorChallengeACK,
    OperatorChallengeNACK,
    OperatorAssert,
    AssertTimeout,
    OperatorTake1,
    OperatorTake2,
    OperatorWatchtowerAndAssertNormalFinish,
    OperatorWatchtowerAndAssertDisproved,

    Created,
    Presigned,
    L2Recorded,
    KickOffing,
    Challenging,
    Asserting,
    Disproving,
    Obsoleted, // reimbursement by other operators
    Discarded,
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
    pub kickoff_index: i64,
    pub from_addr: String,
    pub to_addr: String, //operator_receive_address
    pub graph_ipfs_base_url: String,
    pub amount: i64,
    pub challenge_amount: i64,
    pub status: String, // GraphStatus
    pub operator_pubkey: String,
    pub pre_kickoff_txid: Option<SerializableTxid>,
    pub cur_prekickoff_txid: Option<SerializableTxid>,
    pub force_skip_kickoff_txid: Option<SerializableTxid>,
    pub quick_challenge_txid: Option<SerializableTxid>,
    pub challenge_incomplete_kickoff_txid: Option<SerializableTxid>,
    pub pegin_txid: Option<SerializableTxid>,
    pub kickoff_txid: Option<SerializableTxid>,
    pub take1_txid: Option<SerializableTxid>,
    pub challenge_txid: Option<SerializableTxid>,
    pub take2_txid: Option<SerializableTxid>,
    pub watchtower_challenge_init_txid: Option<SerializableTxid>,
    #[sqlx(json)]
    pub watchtower_challenge_timeout_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub nack_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub blockhash_commit_timeout_txid: Option<SerializableTxid>,
    pub assert_init_txid: Option<SerializableTxid>,
    #[sqlx(json)]
    pub assert_commit_timeout_txids: Vec<SerializableTxid>,
    pub init_withdraw_tx_hash: Option<String>,
    pub bridge_out_start_at: i64,
    pub zkm_version: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Graph {
    pub fn get_check_tx_param(&self) -> Result<(Option<String>, u32), String> {
        // todo update
        let status = GraphStatus::from_str(&self.status);
        if status.is_err() {
            return Err("Graph status is wrong".to_string());
        }
        match status.unwrap() {
            _ => Err("not check status".to_string()),
        }
    }

    pub fn reverse_btc_txid(&mut self) {}
}

pub fn modify_graph_status(ori_status: &str, is_kickoffing: bool) -> String {
    // TODO update
    match ori_status {
        "OperatorPresigned" => "Created".to_string(),
        "CommitteePresigned" => "Presigned".to_string(),
        "OperatorDataPushed" => {
            if is_kickoffing {
                "OperatorKickOffing".to_string()
            } else {
                "L2Recorded".to_string()
            }
        }
        "OperatorKickOff" => "Challenging".to_string(),
        "Challenge" => "OperatorAsserting".to_string(),
        "OperatorAssert" => "Disproving".to_string(),
        _ => ori_status.to_string(),
    }
}

pub fn convert_to_step_state(ori_status: &str) -> String {
    // TODO update
    match ori_status {
        "Created" => "OperatorPresigned".to_string(),
        "Presigned" => "CommitteePresigned".to_string(),
        "L2Recorded" => "OperatorDataPushed".to_string(),
        "KickOffing" => "OperatorDataPushed".to_string(),
        "Challenging" => "OperatorKickOff".to_string(),
        "OperatorAsserting" => "Challenge".to_string(),
        "Disproving" => "OperatorAssert".to_string(),
        _ => ori_status.to_string(),
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GraphBtcTxVoutMonitor {
    pub graph_id: Uuid,
    pub txid: SerializableTxid,
    pub height: i64,
    pub vout_len: i64,
    pub monitor_data: String, // GraphStatus
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Display, EnumString)]
pub enum MessageState {
    Pending,
    Processing,
    Processed,
    Failed,
    Expired,
    Cancelled,
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

#[derive(Debug, Clone, PartialEq, Display, EnumString)]
pub enum MessageType {
    None,
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
    InstanceDiscarded,
    RequestNodeInfo,
    ResponseNodeInfo,
    SyncGraphRequest,
    SyncGraph,
}

// template query data struct
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GraphWithBroadcastInfo {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub status: String,
    pub msg_times: i64,
    pub msg_type: String,
    pub kickoff_txid: Option<SerializableTxid>,
    pub watchtower_challenge_init_txid: Option<SerializableTxid>,
    #[sqlx(json)]
    pub watchtower_challenge_timeout_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub nack_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub assert_commit_timeout_txids: Vec<SerializableTxid>,
    pub blockhash_commit_timeout_txid: Option<SerializableTxid>,
    pub take1_txid: Option<SerializableTxid>,
    pub take2_txid: Option<SerializableTxid>,
    pub assert_init_txid: Option<SerializableTxid>,
    pub challenge_txid: Option<SerializableTxid>,
    pub last_msg_send_at: i64,
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
    pub init_number: i64,
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

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum WatchContractStatus {
    #[default]
    UnSync,
    Syncing,
    Synced,
    Failed,
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

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum GoatTxType {
    #[default]
    Normal,
    BridgeInRequest,
    CommitteeAnswer,
    BridgeIn,
    PostPeginData,
    PostOperatorData,
    InitWithdraw,
    CancelWithdraw,
    ProceedWithdraw,
    WithdrawHappyPath,
    WithdrawUnhappyPath,
    WithdrawDisproved,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum GoatTxProcessingStatus {
    #[default]
    Skipped,
    Pending,
    Processed,
    Failed,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GoatTxRecord {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub tx_type: String,
    pub tx_hash: String,
    pub height: i64,
    pub is_local: bool,
    pub processing_status: String,
    pub extra: Option<String>,
    pub created_at: i64,
}
impl GoatTxRecord {
    pub fn new(graph_id: Uuid, tx_type: String) -> Self {
        Self {
            graph_id,
            instance_id: Uuid::nil(),
            tx_type,
            tx_hash: String::new(),
            height: 0,
            is_local: false,
            processing_status: GoatTxProcessingStatus::Skipped.to_string(),
            extra: None,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        }
    }

    pub fn with_instance_id(mut self, instance_id: Uuid) -> Self {
        self.instance_id = instance_id;
        self
    }

    pub fn with_tx_hash(mut self, tx_hash: String) -> Self {
        self.tx_hash = tx_hash;
        self
    }

    pub fn with_height(mut self, height: i64) -> Self {
        self.height = height;
        self
    }

    pub fn is_local(&self) -> bool {
        self.is_local
    }

    pub fn without_extra(mut self, extra: Option<String>) -> Self {
        self.extra = extra;
        self
    }

    pub fn with_is_local(mut self, is_local: bool) -> Self {
        self.is_local = is_local;
        self
    }

    pub fn with_processing_status(mut self, processing_status: String) -> Self {
        self.processing_status = processing_status;
        self
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GraphRawData {
    pub graph_id: Uuid,
    pub raw_data: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GoatTxProceedWithdrawExtra {
    pub challenge_txid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum ProofType {
    #[default]
    BlockProof,
    AggregationProof,
    Groth16Proof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_status_from_str() {
        assert_eq!(GraphStatus::from_str("Created").unwrap(), GraphStatus::Created);
        assert_eq!(
            GraphStatus::from_str("OperatorPresigned").unwrap(),
            GraphStatus::OperatorPresigned
        );
        assert!(GraphStatus::from_str("Invalid").is_err());
    }

    #[test]
    fn test_graph_status_display() {
        assert_eq!(GraphStatus::Created.to_string(), "Created");
        assert_eq!(GraphStatus::OperatorPresigned.to_string(), "OperatorPresigned");
    }

    #[test]
    fn test_bridge_in_status_from_str() {
        assert_eq!(
            InstanceStatus::from_str("RelayerL2Minted").unwrap(),
            InstanceStatus::RelayerL2Minted
        );
        assert!(InstanceStatus::from_str("Invalid").is_err());
    }

    #[test]
    fn test_message_type_from_str() {
        assert_eq!(MessageType::from_str("BridgeInData").unwrap(), MessageType::BridgeInData);
        assert_eq!(MessageType::from_str("CreateInstance").unwrap(), MessageType::CreateInstance);
        assert!(MessageType::from_str("Invalid").is_err());
    }

    #[test]
    fn test_byte_array_macro() {
        let bytes = ByteArray32([1u8; 32]);
        let hex_str: String = bytes.into();
        let parsed: ByteArray32 = hex_str.try_into().unwrap();
        assert_eq!(bytes.0, parsed.0);

        define_numeric_array!(U32Array2, 2, u32);
        let u32_array = U32Array2([123u32, 456u32]);
        let hex_str: String = u32_array.into();
        let parsed: U32Array2 = hex_str.try_into().unwrap();
        assert_eq!(u32_array.0, parsed.0);

        define_numeric_array!(I64Array1, 1, i64);
        let i64_array = I64Array1([-123i64]);
        let hex_str: String = i64_array.into();
        let parsed: I64Array1 = hex_str.try_into().unwrap();
        assert_eq!(i64_array.0, parsed.0);
    }
}
