use axum::extract::State;
use std::default::Default;
use std::sync::LazyLock;
use serde::{Deserialize, Serialize};
use store::Covenant;
use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
};
use store::localdb::LocalDB;
// NOTE: combine sqlx and axum: https://github.com/tokio-rs/axum/blob/main/examples/sqlx-postgres/src/main.rs

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct CreateCovenant {
    pegin_txid: String,
}

pub async fn create_covenant(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    State(local_db): State<LocalDB>,
    Json(payload): Json<CreateCovenant>,
) -> (StatusCode, Json<Covenant>) {
    // insert your application logic here
    let covenant = Covenant {
        pegin_txid: payload.pegin_txid,
        ..Default::default()
    };
    local_db.create_covenant(covenant.clone()).await;
    (StatusCode::CREATED, Json(covenant))
}