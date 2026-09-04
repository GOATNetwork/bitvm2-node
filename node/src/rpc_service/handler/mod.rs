pub mod bitvm_handler;
pub mod debug_handler;
pub mod node_handler;
pub mod proof_handler;

// Re-export all handler functions for better documentation visibility
pub use bitvm_handler::*;
pub use debug_handler::*;
pub use node_handler::*;
pub use proof_handler::*;
