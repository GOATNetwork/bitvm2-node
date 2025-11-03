pub mod bitvm2_handler;
pub mod node_handler;
pub mod proof_handler;

// Re-export all handler functions for better documentation visibility
pub use bitvm2_handler::*;
pub use node_handler::*;
pub use proof_handler::*;

// todo remove me later
pub(crate) fn is_use_mock_data() -> bool {
    match std::env::var("ENABLE_MOCK_DATA") {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}
