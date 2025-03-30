use axum::extract::State;
use axum::{Json, Router, http::StatusCode};
use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{Covenant, Node, Transaction};
use tracing_subscriber::fmt::time;

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct TransactionParams {
    pub bridge_path: String,
    pub pegin_txid: Option<String>,
}

#[axum::debug_handler]
pub async fn create_transaction(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<TransactionParams>,
) -> (StatusCode, Json<Transaction>) {
    // insert your application logic here
    let tx = Transaction {
        bridge_path: payload.bridge_path,
    };
    local_db.create_transaction(tx.clone()).await;
    (StatusCode::OK, Json(tx))
}
#[axum::debug_handler]
pub async fn get_transaction(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<TransactionParams>,
) -> (StatusCode, Json<Transaction>) {
    // insert your application logic here
    let tx = Transaction {
        bridge_path: payload.bridge_path,
    };
    local_db.get_transaction(tx.clone()).await;
    (StatusCode::OK, Json(tx))
}
