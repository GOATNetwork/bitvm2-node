use axum::Json;
use http::StatusCode;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

pub type ApiResult<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ErrorResponse>)>;

/// Trait extension for Result to easily convert errors to API error format
pub trait ApiErrorExt<T> {
    /// Convert error to API error format with the given error code
    fn api_error(self, error_code: &str) -> Result<T, (StatusCode, Json<ErrorResponse>)>;
}

impl<T, E: std::fmt::Display> ApiErrorExt<T> for Result<T, E> {
    fn api_error(self, error_code: &str) -> Result<T, (StatusCode, Json<ErrorResponse>)> {
        self.map_err(|e| to_api_error(error_code, e))
    }
}

/// Helper function to convert any error into ApiResult error format
pub fn to_api_error<E: std::fmt::Display>(
    error_code: &str,
    error: E,
) -> (StatusCode, Json<ErrorResponse>) {
    tracing::warn!("error_code: {error_code},  error: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: error_code.to_string(), message: error.to_string() }),
    )
}
