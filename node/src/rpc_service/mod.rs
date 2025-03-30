mod covenant;
mod node;
mod transaction;

use axum::routing::on;
use covenant::create_covenant;
use node::update_node;

use std::sync::Arc;
use std::sync::LazyLock;
use store::localdb::LocalDB;

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
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use crate::rpc_service::transaction::{create_transaction, get_transaction};

/// Serve the Multiaddr we are listening on and the host files.
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

pub(crate) async fn serve(addr: String) {
    let localdb = Arc::new(LocalDB::new("sqlite:/tmp/.bitvm2-node.db", true).await);
    let server = Router::new()
        .route("/", get(root))
        .route("/covenants", post(create_covenant))
        .route("/nodes", post(update_node))
        .route("/transactions", post(create_transaction))
        .route("/transactions", get(get_transaction))
        .with_state(localdb);

    let listener = TcpListener::bind(addr).await.unwrap();
    println!("RPC listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, server).await.unwrap();
}
