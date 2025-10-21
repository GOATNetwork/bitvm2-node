use crate::env::{GraphBtcTxName, get_network};
use crate::rpc_service::response::ErrorResponse;
use alloy::primitives::Address as EvmAddress;
use axum::Json;
use axum::http::StatusCode;
use bitcoin::{Address, AddressType, PublicKey};
use bitvm2_lib::actors::Actor;
use libp2p::PeerId;
use std::str::FromStr;
use uuid::Uuid;

/// Input validation error response

/// Validation result type
pub type ValidationResult<T> = Result<T, (StatusCode, Json<ErrorResponse>)>;

/// Input validation utilities
pub struct InputValidator;

impl InputValidator {
    /// Validate UUID format
    pub fn validate_uuid(uuid_str: &str, field_name: &str) -> ValidationResult<Uuid> {
        if uuid_str.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_UUID".to_string(),
                    message: format!("{} cannot be empty", field_name),
                }),
            ));
        }

        // Check UUID format
        match Uuid::parse_str(uuid_str) {
            Ok(uuid) => Ok(uuid),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_UUID_FORMAT".to_string(),
                    message: format!("{} is not a valid UUID format", field_name),
                }),
            )),
        }
    }

    /// Validate goat address format
    pub fn validata_goat_address(
        goat_addr_str: &str,
        field_name: &str,
    ) -> ValidationResult<String> {
        match EvmAddress::from_str(goat_addr_str) {
            Ok(goat_addr) => Ok(goat_addr.to_string()),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_GOAT_FORMAT".to_string(),
                    message: format!("{} is not a valid goat format", field_name),
                }),
            )),
        }
    }

    /// Validate btc address format
    pub fn validate_btc_address(addr_str: &str, field_name: &str) -> ValidationResult<()> {
        let mut validate = false;
        if let Ok(addr_unchecked) = Address::from_str(addr_str)
            && let Ok(addr) = addr_unchecked.require_network(get_network())
        {
            validate = matches!(
                addr.address_type(),
                Some(AddressType::P2wpkh) | Some(AddressType::P2wsh) | Some(AddressType::P2tr)
            )
        }

        if !validate {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_BTC_SEGWIT_ADDRESS".to_string(),
                    message: format!("{} is not a valid segwit btc address", field_name),
                }),
            ));
        }
        Ok(())
    }

    /// Validate btc pub key
    pub fn validate_btc_pub_key(btc_pubkey: &str, field_name: &str) -> ValidationResult<()> {
        if let Err(_) = PublicKey::from_str(btc_pubkey) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_BTC_PUBKEY".to_string(),
                    message: format!("{} is not a valid btc pub key", field_name),
                }),
            ));
        }
        Ok(())
    }

    /// Validate peer_id
    pub fn validate_peer_id(addr_str: &str, field_name: &str) -> ValidationResult<()> {
        if let Err(_) = PeerId::from_str(addr_str) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_PEER_ID".to_string(),
                    message: format!("{} is not a valid peer id", field_name),
                }),
            ));
        }

        Ok(())
    }

    /// Validate string length
    pub fn validate_string_length(
        value: &str,
        field_name: &str,
        min_len: usize,
        max_len: usize,
    ) -> ValidationResult<()> {
        if value.len() < min_len {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "STRING_TOO_SHORT".to_string(),
                    message: format!("{} must be at least {} characters long", field_name, min_len),
                }),
            ));
        }

        if value.len() > max_len {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "STRING_TOO_LONG".to_string(),
                    message: format!("{} must be at most {} characters long", field_name, max_len),
                }),
            ));
        }

        Ok(())
    }

    /// Validate tx_name parameter
    pub fn validate_tx_name(tx_name: &str) -> ValidationResult<GraphBtcTxName> {
        match GraphBtcTxName::from_str(tx_name) {
            Ok(tx_name_enum) => Ok(tx_name_enum),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_TX_NAME_TYPE".to_string(),
                    message: format!(
                        "Invalid tx_name: {}. Valid values are: pegin.hex, kickoff.hex, pre-kickoff.hex, \
                        watchtower-challenge-init.hex, assert-init.hex, challenge.hex, take1.hex, take2.hex, disprove.hex",
                        tx_name
                    ),
                }),
            )),
        }
    }

    /// Validate pagination parameters
    pub fn validate_pagination(
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> ValidationResult<(u32, u32)> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(10);

        if offset > 10000 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_OFFSET".to_string(),
                    message: "offset cannot exceed 10000".to_string(),
                }),
            ));
        }

        if limit == 0 || limit > 100 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_LIMIT".to_string(),
                    message: "limit must be between 1 and 100".to_string(),
                }),
            ));
        }

        Ok((offset, limit))
    }

    /// Validate numeric range
    pub fn validate_amount(amount: i64, field_name: &str) -> ValidationResult<()> {
        if amount <= 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_AMOUNT".to_string(),
                    message: format!("{} must be greater than 0", field_name),
                }),
            ));
        }

        if amount > 21_000_000_000_000 {
            // 21M BTC in satoshis
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "AMOUNT_TOO_LARGE".to_string(),
                    message: format!("{} exceeds maximum allowed value", field_name),
                }),
            ));
        }

        Ok(())
    }

    /// Validate status field
    pub fn validate_actor(actor: &str, field_name: &str) -> ValidationResult<()> {
        if let Err(_) = Actor::from_str(actor) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_ACTOR".to_string(),
                    message: format!("{} invalid actor", field_name),
                }),
            ));
        }
        Ok(())
    }
}
