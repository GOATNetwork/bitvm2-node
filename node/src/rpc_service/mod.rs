mod bitvm2;
mod node;

use axum::routing::on;
use node::update_node;

use std::sync::Arc;
use std::sync::LazyLock;
use store::localdb::LocalDB;

use crate::rpc_service::bitvm2::create_instance;
use axum::routing::MethodFilter;
use axum::{
    Router,
    extract::{Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use futures::StreamExt;
use libp2p::{
    core::{Transport, muxing::StreamMuxerBox},
    multiaddr::{Multiaddr, Protocol},
    ping,
    swarm::SwarmEvent,
};
use rand::thread_rng;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::UNIX_EPOCH;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

#[inline(always)]
pub fn current_time_secs() -> u64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Serve the Multiaddr we are listening on and the host files.
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

pub(crate) async fn serve(addr: String, db_path: String) {
    let localdb = Arc::new(LocalDB::new(&format!("sqlite:{db_path}"), true).await);
    let server = Router::new()
        .route("/", get(root))
        .route("/nodes", post(update_node))
        .route("/instances", post(create_instance))
        //        .route("/instances/graphs", post(create_graph))
        .with_state(localdb);

    let listener = TcpListener::bind(addr).await.unwrap();
    println!("RPC listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, server).await.unwrap();
}
