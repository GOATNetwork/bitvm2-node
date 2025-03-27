use axum::{
    extract::{Path, State},
    http::{header::CONTENT_TYPE, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use futures::StreamExt;
use libp2p::{
    core::{muxing::StreamMuxerBox, Transport},
    multiaddr::{Multiaddr, Protocol},
    ping,
    swarm::SwarmEvent,
};
use std::net::{Ipv4Addr, SocketAddr};
use rand::thread_rng;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
/// Serve the Multiaddr we are listening on and the host files.
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}
pub(crate) async fn serve(libp2p_transport: Multiaddr) {
    let server = Router::new()
        .route("/", get(root))
//        .route("/:path", get(get_static_file))
        .layer(
            // allow cors
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET]),
        );

    axum::serve(
        TcpListener::bind("127.0.0.1:8080").await.unwrap(),
        server.into_make_service(),
    )
        .await
        .unwrap();
}