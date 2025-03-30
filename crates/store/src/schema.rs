use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, Sqlite, SqlitePool, migrate::MigrateDatabase};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum CovenantStep {
    #[default]
    PegIn = 1,
    KickOff,
    Challenge,
    Assert,
    Disprove,
}
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Covenant {
    pub pegin_txid: String,
    pub operator: String,
    // n-n signature public key
    pub covenant_pubkey: String,
    // in sat
    pub pegin_amount: u64,
    //
    pub step: CovenantStep,

    // operator deposit, in SAT
    pub operator_deposit_amount: u64,

    // challenge deposit, in SAT
    pub challenge_deposit_amount: u64,

    // index: the id of
    pub assert_db_id: u64,
    pub disprove_db_id: u64,
}

#[derive(Clone, FromRow, Debug)]
pub struct AssertTx {
    pub id: u64,
    pub assert_txid_list: Vec<String>,
    pub assert_witness_data_ipfs_url: Vec<String>,
}
#[derive(Clone, FromRow, Debug)]
pub struct DisproveTx {
    pub id: u64,
    pub disprove_witness_data_ipfs_url: Vec<String>,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize)]
pub struct Node {
    pub peer_id: String,
    pub role: String,
    pub update_at: std::time::SystemTime,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub bridge_path: String,
    // TODO
}
