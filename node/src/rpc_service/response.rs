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

/// Helper function to create a successful ApiResult response
///
/// Wraps the provided data in an `Ok` variant with HTTP 200 status code.
/// The data type `T` must implement `Serialize` for JSON serialization.
///
/// # Parameters
///
/// - `data`: The data to be serialized and returned in the response
///
/// # Returns
///
/// Returns `ApiResult<T>` with `Ok((StatusCode::OK, Json(data)))`
pub fn ok_response<T: Serialize>(data: T) -> ApiResult<T> {
    Ok((StatusCode::OK, Json(data)))
}

/// Helper function to create an error ApiResult response
///
/// Creates an error response with HTTP 500 status code. The error type `T` is not
/// used in the error case but is required for type compatibility with `ApiResult<T>`.
///
/// # Parameters
///
/// - `error`: Error code string identifier
/// - `message`: Human-readable error message
///
/// # Returns
///
/// Returns `ApiResult<T>` with `Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse)))`
pub fn error_response<T>(error: String, message: String) -> ApiResult<T> {
    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error, message })))
}
