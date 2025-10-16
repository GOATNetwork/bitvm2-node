use axum::Json;
use http::StatusCode;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

pub type ApiResult<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ErrorResponse>)>;
