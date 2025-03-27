mod covenant;
mod node;

use covenant::create_covenant;

use store::localdb::LocalDB;
use std::sync::Mutex;
use std::sync::LazyLock;

use axum::{
    Router,
    extract::{Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse},
    routing::{post, get},
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


/// Serve the Multiaddr we are listening on and the host files.
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

pub(crate) async fn serve(addr: String) {
    tracing_subscriber::fmt::init();
    let localdb = LocalDB::new("~/.bitvm2-node.db", true).await;
    let server = Router::new()
        .route("/", get(root))
        .route("/covenants", post(create_covenant))
        .with_state(localdb);


    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, server).await.unwrap();
}
