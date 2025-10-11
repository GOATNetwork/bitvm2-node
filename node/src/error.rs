use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum SpecialError {
    #[error("Invalid Pegin Request: {0}")]
    InvalidPeginRequest(String),

    #[error("Invalid Pegin Data: {0}")]
    InvalidPeginData(String),

    #[error("Invalid Graph: {0}")]
    InvalidGraph(String),

    #[error("Contract Call Reverted: {0}")]
    EvmReverted(String),

    #[error("Invalid Committee: {0}")]
    InvalidCommittee(String),

    #[error("Insufficient Balance: {0}")]
    InsufficientBalance(String),

    #[error("Other Error: {0}")]
    Other(String),
}
