use crate::api::ApiState;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::IntoResponse;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text;charset=utf-8;version=1.0.0";
#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRequestLabels {
    method: String,
    path: String,
    status: u16,
}
#[derive(Clone, Debug)]
pub(super) struct ApiMetricsState {
    pub registry: Arc<Mutex<Registry>>,
    http_requests_total: Family<HttpRequestLabels, Counter>,
    http_request_duration_seconds: Histogram,
    http_requests_in_flight: prometheus_client::metrics::gauge::Gauge,
}

impl ApiMetricsState {
    pub(super) fn new() -> Self {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let http_requests_total = Family::default();
        registry.lock().unwrap().register(
            "http_requests_total",
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
            http_requests_total,
            http_request_duration_seconds,
            http_requests_in_flight,
        }
    }
}

pub(super) async fn metrics_middleware(
    state: State<Arc<ApiState>>,
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

pub(super) async fn metrics_handler(State(app_state): State<Arc<ApiState>>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, METRICS_CONTENT_TYPE.parse().unwrap());
    let mut buffer = String::new();
    encode(&mut buffer, &app_state.metrics_state.registry.lock().unwrap()).unwrap();
    (headers, buffer)
}
