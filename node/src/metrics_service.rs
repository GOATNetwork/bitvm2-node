use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use crate::rpc_service::AppState;
use axum::middleware::Next;
use axum::{
    Router, extract::Request, extract::State, http::StatusCode, response::IntoResponse,
    routing::get,
};
use http::HeaderMap;
use libp2p_metrics::Registry;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use tokio::net::TcpListener;
use tokio::time::Instant;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text;charset=utf-8;version=1.0.0";

#[allow(dead_code)]
pub(crate) async fn metrics_server(registry: Registry) -> Result<(), std::io::Error> {
    // Serve on localhost.
    let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let service = MetricService::new(registry);
    let server = Router::new().route("/metrics", get(respond_with_metrics)).with_state(service);
    let tcp_listener = TcpListener::bind(addr).await?;
    let local_addr = tcp_listener.local_addr()?;
    tracing::info!(metrics_server=%format!("http://{local_addr}/metrics"));
    axum::serve(tcp_listener, server.into_make_service()).await?;
    Ok(())
}

#[derive(Clone)]
#[allow(dead_code)]
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
    #[allow(dead_code)]
    fn new(registry: Registry) -> Self {
        Self { reg: Arc::new(Mutex::new(registry)) }
    }

    #[allow(dead_code)]
    fn get_reg(&self) -> SharedRegistry {
        Arc::clone(&self.reg)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRequestLabels {
    method: String,
    path: String,
    status: u16,
}

#[derive(Clone, Debug)]
pub struct MetricsState {
    pub registry: Arc<Mutex<Registry>>,
    http_requests_total: Family<HttpRequestLabels, Counter>,
    http_request_duration_seconds: Histogram,
    http_requests_in_flight: prometheus_client::metrics::gauge::Gauge,
}

impl MetricsState {
    pub fn new(registry: Arc<Mutex<Registry>>) -> Self {
        let http_requests_total = Family::default();
        registry.lock().unwrap().register(
            "http_requests_totl",
            "Total number of requests",
            http_requests_total.clone(),
        );

        let http_request_duration_seconds = Histogram::new(exponential_buckets(1.01, 2.0, 10));
        registry.lock().unwrap().register(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            http_request_duration_seconds.clone(),
        );
        let http_requests_in_flight = prometheus_client::metrics::gauge::Gauge::default();
        registry.lock().unwrap().register(
            "http_requests_in_flight",
            "Number of HTTP requests currently being processed",
            http_requests_in_flight.clone(),
        );

        Self {
            registry,
            // registry: Arc::new(registry),
            http_requests_total,
            http_request_duration_seconds,
            http_requests_in_flight,
        }
    }
}

// State<Arc<AppState>>,
pub async fn metrics_middleware(
    state: State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let path = if let Some(route) = request.extensions().get::<axum::extract::MatchedPath>() {
        route.as_str().to_owned()
    } else {
        request.uri().path().to_owned()
    };
    let method = request.method().to_string();
    let response = next.run(request).await;
    state.metrics_state.http_requests_in_flight.dec();
    let status = response.status().as_u16();
    state
        .metrics_state
        .http_requests_total
        .get_or_create(&HttpRequestLabels { method, path, status })
        .inc();

    state.metrics_state.http_request_duration_seconds.observe(start.elapsed().as_secs_f64());
    response
}

pub async fn metrics_handler(State(app_state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, METRICS_CONTENT_TYPE.parse().unwrap());
    let mut buffer = String::new();
    encode(&mut buffer, &app_state.metrics_state.registry.lock().unwrap()).unwrap();
    (headers, buffer)
}
