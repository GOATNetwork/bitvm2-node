use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use libp2p_metrics::Registry;
use prometheus_client::encoding::text::encode;
use tokio::net::TcpListener;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text;charset=utf-8;version=1.0.0";

pub(crate) async fn metrics_server(registry: Registry) -> Result<(), std::io::Error> {
    // Serve on localhost.
    let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let service = MetricService::new(registry);
    let server = Router::new().route("/metrics", get(respond_with_metrics)).with_state(service);
    let tcp_listener = TcpListener::bind(addr).await?;
    let local_addr = tcp_listener.local_addr()?;
    tracing::info!(metrics_server=%format!("http://{}/metrics", local_addr));
    axum::serve(tcp_listener, server.into_make_service()).await?;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct MetricService {
    reg: Arc<Mutex<Registry>>,
}

async fn respond_with_metrics(state: State<MetricService>) -> impl IntoResponse {
    let mut sink = String::new();
    let reg = state.get_reg();
    encode(&mut sink, &reg.lock().unwrap()).unwrap();
    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, METRICS_CONTENT_TYPE)], sink)
}

type SharedRegistry = Arc<Mutex<Registry>>;

impl MetricService {
    fn new(registry: Registry) -> Self {
        Self { reg: Arc::new(Mutex::new(registry)) }
    }

    fn get_reg(&self) -> SharedRegistry {
        Arc::clone(&self.reg)
    }
}
