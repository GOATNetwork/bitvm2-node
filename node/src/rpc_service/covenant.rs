use axum::extract::State;
use axum::{Json, http::StatusCode};
use serde::Deserialize;
use std::default::Default;
use std::sync::Arc;
use store::Covenant;
use store::localdb::LocalDB;
// NOTE: combine sqlx and axum: https://github.com/tokio-rs/axum/blob/main/examples/sqlx-postgres/src/main.rs

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct CreateCovenant {
    pegin_txid: String,
}

pub async fn create_covenant(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<CreateCovenant>,
) -> (StatusCode, Json<Covenant>) {
    // insert your application logic here
    let covenant = Covenant { pegin_txid: payload.pegin_txid, ..Default::default() };
    local_db.create_covenant(covenant.clone()).await;
    (StatusCode::CREATED, Json(covenant))
}
