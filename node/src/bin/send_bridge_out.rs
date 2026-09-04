//! bridge-out: user bridge-out helper (init-tag + escrow-data + swap-initialize) via the node API.
//!
//! Modes:
//! - init-tag: initialize a bridge-out instance record
//! - escrow-data: query escrow data by instance id
//! - swap-initialize: call swap contract initialize and derive escrow hash from tx logs
//!
//! The node API must be reachable at --rpc-url for init-tag/escrow-data.
//! The GOAT RPC/private key environment must be configured for swap-initialize.

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address as EvmAddress, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result, anyhow, bail};
use bitvm_noded::env::{
    ENV_GOAT_PRIVATE_KEY, ENV_GOAT_SWAP_CONTRACT_ADDRESS, get_goat_network, goat_config_from_env,
};
use clap::{Parser, Subcommand};
use client::goat_chain::{GOATClient, SwapEscrowData};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
const PAY_IN_FLAG: u64 = 0x02;
const ZERO_B256_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_NONCE_TIME_OFFSET_SECS: u64 = 700_000_000;
const DEFAULT_NONCE_RANDOM_BITS: u32 = 24;
const DEFAULT_PRIORITY_FEE_WEI: u64 = 5_000_000;
const DEFAULT_MAX_BASE_FEE_WEI: u64 = 2_000_000_000;
const DEFAULT_BASE_FEE_MULTIPLIER_NUM: u64 = 125;
const DEFAULT_BASE_FEE_MULTIPLIER_DEN: u64 = 100;
const PEG_BTC_DECIMALS: usize = 18;

#[derive(Parser, Debug)]
#[command(
    name = "bridge-out",
    version,
    about = "Bridge-out helper (via node API and GOAT RPC)",
    long_about = "Initialize bridge-out tag, query escrow data, and call swap initialize with escrow hash extraction from tx logs."
)]
struct Args {
    /// Node API base URL
    #[arg(long, default_value = "http://localhost:8080")]
    rpc_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize bridge-out tag
    InitTag {
        /// Source GOAT address
        #[arg(long)]
        from_addr: String,

        /// Destination BTC address
        #[arg(long)]
        to_addr: String,

        /// Escrow hash (0x-prefixed 32-byte hex)
        #[arg(long)]
        escrow_hash: Option<String>,

        /// Swap initialize tx hash (0x-prefixed 32-byte hex), used to auto-derive escrow hash from logs
        #[arg(long)]
        swap_init_tx_hash: Option<String>,

        /// GOAT swap contract address; fallback to GOAT_SWAP_CONTRACT_ADDRESS
        #[arg(long)]
        contract_address: Option<String>,
    },

    /// Query escrow data by instance id
    EscrowData {
        /// Instance id
        #[arg(long)]
        instance_id: Uuid,
    },

    /// Fetch escrow params from payInvoice, call swap initialize, and print escrow hash from tx logs
    SwapInitialize {
        /// payInvoice endpoint URL (chain query included)
        #[arg(
            long,
            default_value = "https://152-32-185-32.nodes.atomiq.exchange:8443/tobtc/payInvoice?chain=GOAT"
        )]
        pay_invoice_url: String,

        /// BTC receive address, sent to payInvoice as `address`
        #[arg(long)]
        btc_address: String,

        /// Requested amount in pegBTC (human-readable, e.g. 0.01). Converted to base units automatically.
        #[arg(long)]
        amount: String,

        /// Whether this quote is exact-in
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        exact_in: bool,

        /// Bitcoin confirmation target
        #[arg(long, default_value_t = 3)]
        confirmation_target: u32,

        /// Required confirmations
        #[arg(long, default_value_t = 2)]
        confirmations: u32,

        /// Token address
        #[arg(long)]
        token: String,

        /// Offerer GOAT address
        #[arg(long)]
        offerer: String,

        /// Additional params JSON object merged into payInvoice body
        #[arg(long)]
        additional_params_json: Option<String>,

        /// GOAT private key; fallback to GOAT_PRIVATE_KEY
        #[arg(long, env = ENV_GOAT_PRIVATE_KEY)]
        goat_private_key: Option<String>,

        /// GOAT swap contract address; fallback to GOAT_SWAP_CONTRACT_ADDRESS
        #[arg(long)]
        contract_address: Option<String>,

        /// Max seconds to wait for tx receipt
        #[arg(long, default_value_t = 60)]
        max_wait_secs: u64,
    },
}

#[derive(Debug, Serialize)]
struct BridgeOutInitTagApiRequest {
    contract_address: String,
    from_addr: String,
    to_addr: String,
    escrow_hash: String,
}

#[derive(Debug, Deserialize)]
struct EscrowDataApiResponse {
    instance_id: String,
    escrow: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    error: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct PayInvoiceEnvelope {
    code: i64,
    msg: String,
    data: Option<PayInvoiceResponseData>,
}

#[derive(Debug, Deserialize)]
struct PayInvoiceResponseData {
    data: PayInvoiceEscrowRaw,
    prefix: String,
    timeout: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct PayInvoiceEscrowRaw {
    offerer: String,
    claimer: String,
    token: String,
    #[serde(rename = "refundHandler")]
    refund_handler: String,
    #[serde(rename = "claimHandler")]
    claim_handler: String,
    #[serde(rename = "payOut")]
    pay_out: bool,
    #[serde(rename = "payIn")]
    pay_in: bool,
    reputation: bool,
    sequence: JsonValue,
    #[serde(rename = "claimData")]
    claim_data: String,
    #[serde(rename = "refundData")]
    refund_data: String,
    amount: JsonValue,
    #[serde(rename = "depositToken")]
    deposit_token: String,
    #[serde(rename = "securityDeposit")]
    security_deposit: JsonValue,
    #[serde(rename = "claimerBounty")]
    claimer_bounty: JsonValue,
    #[allow(dead_code)]
    kind: Option<JsonValue>,
    #[serde(rename = "extraData")]
    extra_data: Option<JsonValue>,
    #[serde(rename = "successActionCommitment")]
    success_action_commitment: Option<String>,
}

#[derive(Debug)]
enum EscrowHashInput {
    Provided(String),
    FromSwapInitTx(String),
}

fn join_base_path(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

fn bridge_out_init_tag_url(base_url: &str) -> String {
    join_base_path(base_url, "/v1/instances/bridge-out-init-tag")
}

fn escrow_data_url(base_url: &str, instance_id: &Uuid) -> String {
    join_base_path(base_url, &format!("/v1/instances/{instance_id}/escrow-data"))
}

fn parse_api_error(body: &str) -> Option<ApiError> {
    serde_json::from_str::<ApiError>(body).ok()
}

fn resolve_contract_address(contract_address: Option<String>) -> Result<String> {
    if let Some(addr) = contract_address {
        return Ok(addr);
    }

    std::env::var(ENV_GOAT_SWAP_CONTRACT_ADDRESS).map_err(|_| {
        anyhow!(
            "missing --contract-address and env {ENV_GOAT_SWAP_CONTRACT_ADDRESS}, one of them is required"
        )
    })
}

fn normalize_32byte_hex(value: &str, field_name: &str) -> Result<String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(hex).map_err(|e| anyhow!("{field_name} is not a valid hex string: {e}"))?;
    if bytes.len() != 32 {
        bail!("{field_name} must be exactly 32 bytes, got {}", bytes.len());
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn parse_hex_bytes(value: &str, field_name: &str) -> Result<Vec<u8>> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.is_empty() {
        return Ok(vec![]);
    }
    let bytes =
        hex::decode(hex).map_err(|e| anyhow!("{field_name} is not a valid hex string: {e}"))?;
    Ok(bytes)
}

fn parse_bytes32(value: &str, field_name: &str) -> Result<[u8; 32]> {
    let normalized = normalize_32byte_hex(value, field_name)?;
    let hex = normalized.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| anyhow!("{field_name} decode failed: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_u256(value: &str, field_name: &str) -> Result<U256> {
    if let Some(hex) = value.strip_prefix("0x") {
        let bytes =
            hex::decode(hex).map_err(|e| anyhow!("{field_name} is not valid hex u256: {e}"))?;
        if bytes.len() > 32 {
            bail!("{field_name} exceeds 32 bytes for u256");
        }
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        return Ok(U256::from_be_bytes(padded));
    }

    U256::from_str(value).map_err(|e| anyhow!("{field_name} is not valid decimal u256: {e}"))
}

fn parse_u256_from_json_value(value: &JsonValue, field_name: &str) -> Result<U256> {
    match value {
        JsonValue::String(v) => parse_u256(v, field_name),
        JsonValue::Number(v) => parse_u256(&v.to_string(), field_name),
        _ => bail!("{field_name} must be a string or number"),
    }
}

fn convert_pegbtc_amount_to_base_units(amount: &str) -> Result<String> {
    let amount = amount.trim();
    if amount.is_empty() {
        bail!("amount must not be empty");
    }
    if amount.starts_with('-') {
        bail!("amount must be non-negative");
    }

    let mut parts = amount.split('.');
    let int_part = parts.next().unwrap_or_default();
    let frac_part = parts.next();
    if parts.next().is_some() {
        bail!("amount must be a valid decimal number");
    }

    let int_part = if int_part.is_empty() { "0" } else { int_part };
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        bail!("amount integer part must contain digits only");
    }

    let frac_part = frac_part.unwrap_or("");
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        bail!("amount fractional part must contain digits only");
    }
    if frac_part.len() > PEG_BTC_DECIMALS {
        bail!("amount has too many decimal places, max {PEG_BTC_DECIMALS}");
    }

    let mut base_units = String::with_capacity(int_part.len() + PEG_BTC_DECIMALS);
    base_units.push_str(int_part);
    base_units.push_str(frac_part);
    base_units.push_str(&"0".repeat(PEG_BTC_DECIMALS - frac_part.len()));
    let normalized = base_units.trim_start_matches('0');
    let normalized = if normalized.is_empty() { "0" } else { normalized };

    U256::from_str(normalized)
        .map_err(|e| anyhow!("amount out of range for u256 after conversion: {e}"))?;
    Ok(normalized.to_string())
}

fn generate_default_nonce(unix_seconds: u64, random_24_bits: u32) -> String {
    let timestamp_part = unix_seconds.saturating_sub(DEFAULT_NONCE_TIME_OFFSET_SECS);
    let random_part = u64::from(random_24_bits & 0x00ff_ffff);
    ((timestamp_part << DEFAULT_NONCE_RANDOM_BITS) | random_part).to_string()
}

fn generate_default_fee_rate(base_fee_per_gas: U256) -> String {
    let mut adjusted_base_fee = (base_fee_per_gas * U256::from(DEFAULT_BASE_FEE_MULTIPLIER_NUM))
        / U256::from(DEFAULT_BASE_FEE_MULTIPLIER_DEN);
    let max_base_fee = U256::from(DEFAULT_MAX_BASE_FEE_WEI);
    if adjusted_base_fee > max_base_fee {
        adjusted_base_fee = max_base_fee;
    }
    format!("{},{}", adjusted_base_fee, U256::from(DEFAULT_PRIORITY_FEE_WEI))
}

async fn generate_default_nonce_and_fee_rate() -> Result<(String, String)> {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs();
    let nonce = generate_default_nonce(unix_seconds, rand::random::<u32>());

    let cfg = goat_config_from_env().await;
    let provider = ProviderBuilder::new().connect_http(cfg.rpc_url.clone());
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .with_context(|| format!("failed to get latest block from GOAT RPC {}", cfg.rpc_url))?
        .ok_or_else(|| anyhow!("latest block not found on GOAT RPC {}", cfg.rpc_url))?;
    let base_fee_per_gas = block.header.base_fee_per_gas.ok_or_else(|| {
        anyhow!("latest block missing base_fee_per_gas on GOAT RPC {}", cfg.rpc_url)
    })?;
    let fee_rate = generate_default_fee_rate(U256::from(base_fee_per_gas));
    Ok((nonce, fee_rate))
}

fn parse_json_object(value: &str, field_name: &str) -> Result<serde_json::Map<String, JsonValue>> {
    let parsed: JsonValue =
        serde_json::from_str(value).map_err(|e| anyhow!("{field_name} is not valid JSON: {e}"))?;
    match parsed {
        JsonValue::Object(map) => Ok(map),
        _ => bail!("{field_name} must be a JSON object"),
    }
}

fn parse_extra_data_from_json(value: Option<&JsonValue>) -> Result<Bytes> {
    match value {
        None | Some(JsonValue::Null) => Ok(Bytes::default()),
        Some(JsonValue::String(v)) => Ok(Bytes::from(parse_hex_bytes(v, "extraData")?)),
        _ => bail!("extraData must be null or hex string"),
    }
}

fn build_flags(sequence: U256, pay_out: bool, pay_in: bool, reputation: bool) -> Result<U256> {
    if sequence > (U256::MAX >> 64) {
        bail!("sequence is too large, must fit within 192 bits");
    }
    let mut flags = sequence << 64;
    if pay_out {
        flags += U256::from(1u64);
    }
    if pay_in {
        flags += U256::from(PAY_IN_FLAG);
    }
    if reputation {
        flags += U256::from(4u64);
    }
    Ok(flags)
}

fn should_pay_in(flags: U256) -> bool {
    (flags & U256::from(PAY_IN_FLAG)) == U256::from(PAY_IN_FLAG)
}

fn requires_token_approval(sender: EvmAddress, escrow: &SwapEscrowData) -> bool {
    let native_token = EvmAddress::ZERO;
    should_pay_in(escrow.flags) && escrow.offerer == sender && escrow.token != native_token
}

fn compute_initialize_value_wei(sender: EvmAddress, escrow: &SwapEscrowData) -> U256 {
    let native_token = EvmAddress::ZERO;
    let mut value = U256::ZERO;
    if should_pay_in(escrow.flags) && escrow.offerer == sender && escrow.token == native_token {
        value += escrow.amount;
    }
    if escrow.deposit_token == native_token {
        let total_deposit = if escrow.security_deposit > escrow.claimer_bounty {
            escrow.security_deposit
        } else {
            escrow.claimer_bounty
        };
        value += total_deposit;
    }
    value
}

async fn ensure_token_approval(
    goat_client: &GOATClient,
    sender: EvmAddress,
    swap_contract: EvmAddress,
    escrow: &SwapEscrowData,
) -> Result<()> {
    if !requires_token_approval(sender, escrow) {
        return Ok(());
    }

    let owner = sender.into_array();
    let spender = swap_contract.into_array();
    let allowance = goat_client
        .peg_btc_allowance(&owner, &spender)
        .await
        .context("failed to query token allowance before swap initialize")?;
    if allowance >= escrow.amount {
        eprintln!(
            "token allowance already sufficient, allowance={}, required={}",
            allowance, escrow.amount
        );
        return Ok(());
    }

    eprintln!(
        "token allowance insufficient, approving token spend now, allowance={}, required={}",
        allowance, escrow.amount
    );
    let approve_tx_hash = goat_client
        .peg_btc_approve(&spender, escrow.amount)
        .await
        .context("failed to send token approve tx before swap initialize")?;
    eprintln!("token approve submitted: {approve_tx_hash}");

    let latest_allowance = goat_client
        .peg_btc_allowance(&owner, &spender)
        .await
        .context("failed to re-check token allowance after approve")?;
    if latest_allowance < escrow.amount {
        bail!(
            "token allowance still insufficient after approve, allowance={}, required={}",
            latest_allowance,
            escrow.amount
        );
    }
    eprintln!("token allowance after approve: {}, required={}", latest_allowance, escrow.amount);
    Ok(())
}

fn resolve_escrow_hash_input(
    escrow_hash: Option<String>,
    swap_init_tx_hash: Option<String>,
) -> Result<EscrowHashInput> {
    match (escrow_hash, swap_init_tx_hash) {
        (Some(escrow_hash), _) => {
            Ok(EscrowHashInput::Provided(normalize_32byte_hex(&escrow_hash, "escrow_hash")?))
        }
        (None, Some(tx_hash)) => Ok(EscrowHashInput::FromSwapInitTx(normalize_32byte_hex(
            &tx_hash,
            "swap_init_tx_hash",
        )?)),
        (None, None) => {
            bail!("one of --escrow-hash or --swap-init-tx-hash must be provided")
        }
    }
}

async fn derive_escrow_hash_from_swap_init_tx(
    swap_init_tx_hash: &str,
    contract_address: &str,
) -> Result<String> {
    let swap_contract_address = EvmAddress::from_str(contract_address)
        .map_err(|e| anyhow!("invalid swap contract address {contract_address}: {e}"))?;
    let goat_client = GOATClient::new(goat_config_from_env().await, get_goat_network());
    let escrow_hash = goat_client
        .extract_initialize_escrow_hash_from_tx(swap_init_tx_hash, swap_contract_address)
        .await
        .with_context(|| format!("failed to parse initialize log from tx {swap_init_tx_hash}"))?;
    escrow_hash.ok_or_else(|| {
        anyhow!(
            "Initialize event with escrowHash not found in tx {swap_init_tx_hash} logs for contract {contract_address}"
        )
    })
}

async fn submit_swap_initialize_tx(
    goat_private_key: Option<String>,
    contract_address: Option<String>,
    max_wait_secs: u64,
    escrow: SwapEscrowData,
    signature: Bytes,
    timeout: U256,
    extra_data: Bytes,
) -> Result<(String, String)> {
    let contract_address = resolve_contract_address(contract_address)?;
    let swap_contract = EvmAddress::from_str(&contract_address)
        .map_err(|e| anyhow!("invalid swap contract address {contract_address}: {e}"))?;

    let mut cfg = goat_config_from_env().await;
    if goat_private_key.is_none() && cfg.private_key.is_none() {
        bail!("missing GOAT private key (--goat-private-key or GOAT_PRIVATE_KEY)");
    }
    if goat_private_key.is_some() {
        cfg = cfg.with_private_key(goat_private_key);
    }
    cfg = cfg.with_peg_btc_address(Some(escrow.token));
    let goat_client = GOATClient::new(cfg, get_goat_network());
    let sender = goat_client.get_default_signer_address();
    ensure_token_approval(&goat_client, sender, swap_contract, &escrow).await?;
    let value_wei = compute_initialize_value_wei(sender, &escrow);
    let result = goat_client
        .swap_initialize(
            swap_contract,
            escrow,
            signature,
            timeout,
            extra_data,
            value_wei,
            max_wait_secs,
        )
        .await?;
    Ok((result.tx_hash, result.escrow_hash))
}

async fn call_pay_invoice(
    client: &reqwest::Client,
    args: &Commands,
) -> Result<(PayInvoiceResponseData, Option<String>, Option<String>, u64)> {
    let Commands::SwapInitialize {
        pay_invoice_url,
        btc_address,
        amount,
        exact_in,
        confirmation_target,
        confirmations,
        token,
        offerer,
        additional_params_json,
        goat_private_key,
        contract_address,
        max_wait_secs,
    } = args
    else {
        bail!("invalid command for call_pay_invoice");
    };

    let (nonce, fee_rate) = generate_default_nonce_and_fee_rate().await?;
    let amount_base_units = convert_pegbtc_amount_to_base_units(amount)?;
    eprintln!("auto-generated nonce: {nonce}");
    eprintln!("auto-generated feeRate: {fee_rate}");
    eprintln!("converted amount (pegBTC -> base units): {amount_base_units}");

    let mut body = serde_json::Map::new();
    if let Some(params_json) = additional_params_json {
        body.extend(parse_json_object(params_json, "additional_params_json")?);
    }
    body.insert("address".to_string(), JsonValue::String(btc_address.clone()));
    body.insert("amount".to_string(), JsonValue::String(amount_base_units));
    body.insert("exactIn".to_string(), JsonValue::Bool(*exact_in));
    body.insert("confirmationTarget".to_string(), JsonValue::from(*confirmation_target));
    body.insert("confirmations".to_string(), JsonValue::from(*confirmations));
    body.insert("nonce".to_string(), JsonValue::String(nonce));
    body.insert("token".to_string(), JsonValue::String(token.clone()));
    body.insert("offerer".to_string(), JsonValue::String(offerer.clone()));
    body.insert("feeRate".to_string(), JsonValue::String(fee_rate));

    let resp = client
        .post(pay_invoice_url)
        .json(&JsonValue::Object(body))
        .send()
        .await
        .with_context(|| format!("failed to reach payInvoice API at {pay_invoice_url}"))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        if let Some(api_err) = parse_api_error(&text) {
            bail!("payInvoice API error ({}): {}", api_err.error, api_err.message);
        }
        bail!("payInvoice API returned {status}: {text}");
    }

    let envelope: PayInvoiceEnvelope =
        serde_json::from_str(&text).context("failed to parse payInvoice response body")?;
    if envelope.code != 20000 {
        bail!("payInvoice business error (code {}): {}", envelope.code, envelope.msg);
    }

    let data = envelope.data.ok_or_else(|| anyhow!("payInvoice response missing data"))?;

    Ok((data, goat_private_key.clone(), contract_address.clone(), *max_wait_secs))
}

fn parse_escrow_from_pay_invoice(
    quote: &PayInvoiceResponseData,
) -> Result<(SwapEscrowData, Bytes, U256, Bytes)> {
    let escrow_raw = &quote.data;
    let sequence = parse_u256_from_json_value(&escrow_raw.sequence, "sequence")?;
    let flags =
        build_flags(sequence, escrow_raw.pay_out, escrow_raw.pay_in, escrow_raw.reputation)?;

    let success_action_commitment =
        escrow_raw.success_action_commitment.as_deref().unwrap_or(ZERO_B256_HEX);
    let escrow = SwapEscrowData {
        offerer: EvmAddress::from_str(&escrow_raw.offerer)
            .map_err(|e| anyhow!("invalid offerer address {}: {e}", escrow_raw.offerer))?,
        claimer: EvmAddress::from_str(&escrow_raw.claimer)
            .map_err(|e| anyhow!("invalid claimer address {}: {e}", escrow_raw.claimer))?,
        amount: parse_u256_from_json_value(&escrow_raw.amount, "amount")?,
        token: EvmAddress::from_str(&escrow_raw.token)
            .map_err(|e| anyhow!("invalid token address {}: {e}", escrow_raw.token))?,
        flags,
        claim_handler: EvmAddress::from_str(&escrow_raw.claim_handler).map_err(|e| {
            anyhow!("invalid claimHandler address {}: {e}", escrow_raw.claim_handler)
        })?,
        claim_data: parse_bytes32(&escrow_raw.claim_data, "claimData")?,
        refund_handler: EvmAddress::from_str(&escrow_raw.refund_handler).map_err(|e| {
            anyhow!("invalid refundHandler address {}: {e}", escrow_raw.refund_handler)
        })?,
        refund_data: parse_bytes32(&escrow_raw.refund_data, "refundData")?,
        security_deposit: parse_u256_from_json_value(
            &escrow_raw.security_deposit,
            "securityDeposit",
        )?,
        claimer_bounty: parse_u256_from_json_value(&escrow_raw.claimer_bounty, "claimerBounty")?,
        deposit_token: EvmAddress::from_str(&escrow_raw.deposit_token).map_err(|e| {
            anyhow!("invalid depositToken address {}: {e}", escrow_raw.deposit_token)
        })?,
        success_action_commitment: parse_bytes32(
            success_action_commitment,
            "successActionCommitment",
        )?,
    };
    let signature = Bytes::from(parse_hex_bytes(&quote.signature, "signature")?);
    let timeout = parse_u256(&quote.timeout, "timeout")?;
    let extra_data = parse_extra_data_from_json(escrow_raw.extra_data.as_ref())?;
    Ok((escrow, signature, timeout, extra_data))
}

async fn run_swap_initialize_from_pay_invoice(
    client: &reqwest::Client,
    args: &Commands,
) -> Result<(String, String)> {
    let (quote, goat_private_key, contract_address, max_wait_secs) =
        call_pay_invoice(client, args).await?;
    eprintln!("payInvoice prefix: {}", quote.prefix);
    let (escrow, signature, timeout, extra_data) = parse_escrow_from_pay_invoice(&quote)?;
    submit_swap_initialize_tx(
        goat_private_key,
        contract_address,
        max_wait_secs,
        escrow,
        signature,
        timeout,
        extra_data,
    )
    .await
}

async fn call_bridge_out_init_tag(
    client: &reqwest::Client,
    base_url: &str,
    body: &BridgeOutInitTagApiRequest,
) -> Result<()> {
    let url = bridge_out_init_tag_url(base_url);
    let resp = client
        .put(&url)
        .json(body)
        .send()
        .await
        .with_context(|| format!("failed to reach node API at {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if let Some(api_err) = parse_api_error(&text) {
            bail!("API error ({}): {}", api_err.error, api_err.message);
        }
        bail!("API returned {status}: {text}");
    }

    Ok(())
}

async fn call_get_escrow_data(
    client: &reqwest::Client,
    base_url: &str,
    instance_id: &Uuid,
) -> Result<EscrowDataApiResponse> {
    let url = escrow_data_url(base_url, instance_id);
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to reach node API at {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if let Some(api_err) = parse_api_error(&text) {
            bail!("API error ({}): {}", api_err.error, api_err.message);
        }
        bail!("API returned {status}: {text}");
    }

    resp.json().await.context("failed to parse escrow data response")
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let client = reqwest::Client::new();

    match &args.command {
        Commands::InitTag {
            from_addr,
            to_addr,
            escrow_hash,
            swap_init_tx_hash,
            contract_address,
        } => {
            let contract_address = resolve_contract_address(contract_address.clone())?;
            if escrow_hash.is_some() && swap_init_tx_hash.is_some() {
                eprintln!(
                    "both --escrow-hash and --swap-init-tx-hash provided, using --escrow-hash"
                );
            }
            let escrow_hash =
                match resolve_escrow_hash_input(escrow_hash.clone(), swap_init_tx_hash.clone())? {
                    EscrowHashInput::Provided(escrow_hash) => escrow_hash,
                    EscrowHashInput::FromSwapInitTx(swap_init_tx_hash) => {
                        let tx_hash =
                            normalize_32byte_hex(&swap_init_tx_hash, "swap_init_tx_hash")?;
                        let derived =
                            derive_escrow_hash_from_swap_init_tx(&tx_hash, &contract_address)
                                .await?;
                        eprintln!("derived escrow hash from swap init tx {tx_hash}: {derived}");
                        derived
                    }
                };

            let body = BridgeOutInitTagApiRequest {
                contract_address,
                from_addr: from_addr.clone(),
                to_addr: to_addr.clone(),
                escrow_hash,
            };

            call_bridge_out_init_tag(&client, &args.rpc_url, &body).await?;
            println!("bridge-out init-tag submitted successfully");
        }
        Commands::EscrowData { instance_id } => {
            let resp = call_get_escrow_data(&client, &args.rpc_url, instance_id).await?;
            println!("instance_id: {}", resp.instance_id);
            println!("escrow: {}", resp.escrow.as_deref().unwrap_or("null"));
            println!("error: {}", resp.error.as_deref().unwrap_or("null"));
        }
        Commands::SwapInitialize { .. } => {
            let (tx_hash, escrow_hash) =
                run_swap_initialize_from_pay_invoice(&client, &args.command).await?;
            println!("swap initialize submitted: {tx_hash}");
            println!("escrow_hash (from Initialize log): {escrow_hash}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_bridge_out_init_tag_url() {
        assert_eq!(
            bridge_out_init_tag_url("http://localhost:8080/"),
            "http://localhost:8080/v1/instances/bridge-out-init-tag"
        );
    }

    #[test]
    fn test_escrow_data_url() {
        let instance_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        assert_eq!(
            escrow_data_url("http://localhost:8080", &instance_id),
            "http://localhost:8080/v1/instances/123e4567-e89b-12d3-a456-426614174000/escrow-data"
        );
    }

    #[test]
    fn test_parse_api_error() {
        let body = r#"{"error":"PUT_BRIDGE_OUT_INIT_TAG_ERROR","message":"invalid"}"#;
        let parsed = parse_api_error(body);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.error, "PUT_BRIDGE_OUT_INIT_TAG_ERROR");
        assert_eq!(parsed.message, "invalid");
    }

    #[test]
    fn test_resolve_contract_address_arg_priority() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(
                ENV_GOAT_SWAP_CONTRACT_ADDRESS,
                "0x2222222222222222222222222222222222222222",
            );
        }
        let value = resolve_contract_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .unwrap();
        assert_eq!(value, "0x1111111111111111111111111111111111111111");
    }

    #[test]
    fn test_resolve_contract_address_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(
                ENV_GOAT_SWAP_CONTRACT_ADDRESS,
                "0x3333333333333333333333333333333333333333",
            );
        }
        let value = resolve_contract_address(None).unwrap();
        assert_eq!(value, "0x3333333333333333333333333333333333333333");
    }

    #[test]
    fn test_resolve_contract_address_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var(ENV_GOAT_SWAP_CONTRACT_ADDRESS);
        }
        let err = resolve_contract_address(None).unwrap_err().to_string();
        assert!(err.contains("GOAT_SWAP_CONTRACT_ADDRESS"));
    }

    #[test]
    fn test_resolve_escrow_hash_input_uses_provided() {
        let input = resolve_escrow_hash_input(
            Some(format!("0x{}", "11".repeat(32))),
            Some(format!("0x{}", "22".repeat(32))),
        )
        .unwrap();
        match input {
            EscrowHashInput::Provided(v) => assert_eq!(v, format!("0x{}", "11".repeat(32))),
            EscrowHashInput::FromSwapInitTx(_) => panic!("expected provided escrow hash"),
        }
    }

    #[test]
    fn test_resolve_escrow_hash_input_from_tx() {
        let input =
            resolve_escrow_hash_input(None, Some(format!("0x{}", "aa".repeat(32)))).unwrap();
        match input {
            EscrowHashInput::FromSwapInitTx(v) => assert_eq!(v, format!("0x{}", "aa".repeat(32))),
            EscrowHashInput::Provided(_) => panic!("expected tx hash source"),
        }
    }

    #[test]
    fn test_resolve_escrow_hash_input_missing() {
        let err = resolve_escrow_hash_input(None, None).unwrap_err().to_string();
        assert!(err.contains("--escrow-hash"));
    }

    #[test]
    fn test_resolve_escrow_hash_input_invalid_len() {
        let err =
            resolve_escrow_hash_input(Some("0x12".to_string()), None).unwrap_err().to_string();
        assert!(err.contains("exactly 32 bytes"));
    }

    #[test]
    fn test_parse_u256_decimal_and_hex() {
        assert_eq!(parse_u256("10", "amount").unwrap(), U256::from(10u64));
        assert_eq!(parse_u256("0x0a", "amount").unwrap(), U256::from(10u64));
    }

    #[test]
    fn test_parse_u256_from_json_value() {
        assert_eq!(
            parse_u256_from_json_value(&JsonValue::String("10".to_string()), "amount").unwrap(),
            U256::from(10u64)
        );
        assert_eq!(
            parse_u256_from_json_value(&JsonValue::from(15u64), "amount").unwrap(),
            U256::from(15u64)
        );
    }

    #[test]
    fn test_build_flags() {
        let flags = build_flags(U256::from(7u64), true, true, false).unwrap();
        let expected = (U256::from(7u64) << 64) + U256::from(3u64);
        assert_eq!(flags, expected);
        assert!(should_pay_in(flags));
    }

    #[test]
    fn test_generate_default_nonce() {
        let nonce = generate_default_nonce(700_000_001, 0x12_34_56);
        let expected = ((1u64 << 24) | 0x12_34_56u64).to_string();
        assert_eq!(nonce, expected);
    }

    #[test]
    fn test_generate_default_nonce_masks_high_bits() {
        let nonce = generate_default_nonce(700_000_001, 0xab_cd_ef_12);
        let expected = ((1u64 << 24) | 0xcd_ef_12u64).to_string();
        assert_eq!(nonce, expected);
    }

    #[test]
    fn test_generate_default_fee_rate() {
        let fee_rate = generate_default_fee_rate(U256::from(100u64));
        assert_eq!(fee_rate, "125,5000000");
    }

    #[test]
    fn test_generate_default_fee_rate_with_cap() {
        let fee_rate = generate_default_fee_rate(U256::from(1_000_000_000_000u64));
        assert_eq!(fee_rate, "2000000000,5000000");
    }

    #[test]
    fn test_convert_pegbtc_amount_to_base_units() {
        assert_eq!(convert_pegbtc_amount_to_base_units("0.01").unwrap(), "10000000000000000");
        assert_eq!(convert_pegbtc_amount_to_base_units("1").unwrap(), "1000000000000000000");
        assert_eq!(convert_pegbtc_amount_to_base_units(".5").unwrap(), "500000000000000000");
        assert_eq!(convert_pegbtc_amount_to_base_units("0").unwrap(), "0");
    }

    #[test]
    fn test_convert_pegbtc_amount_to_base_units_invalid_precision() {
        let err =
            convert_pegbtc_amount_to_base_units("0.1234567890123456789").unwrap_err().to_string();
        assert!(err.contains("too many decimal places"));
    }

    #[test]
    fn test_compute_initialize_value_wei() {
        let offerer = EvmAddress::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let claimer = EvmAddress::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let escrow = SwapEscrowData {
            offerer,
            claimer,
            amount: U256::from(100u64),
            token: EvmAddress::ZERO,
            flags: U256::from(PAY_IN_FLAG),
            claim_handler: EvmAddress::from_str("0x3333333333333333333333333333333333333333")
                .unwrap(),
            claim_data: [0u8; 32],
            refund_handler: EvmAddress::from_str("0x4444444444444444444444444444444444444444")
                .unwrap(),
            refund_data: [0u8; 32],
            security_deposit: U256::from(8u64),
            claimer_bounty: U256::from(5u64),
            deposit_token: EvmAddress::ZERO,
            success_action_commitment: [0u8; 32],
        };
        assert_eq!(compute_initialize_value_wei(offerer, &escrow), U256::from(108u64));
    }

    #[test]
    fn test_requires_token_approval_true_for_payin_erc20_offerer() {
        let sender = EvmAddress::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let escrow = SwapEscrowData {
            offerer: sender,
            claimer: EvmAddress::from_str("0x2222222222222222222222222222222222222222").unwrap(),
            amount: U256::from(100u64),
            token: EvmAddress::from_str("0x3333333333333333333333333333333333333333").unwrap(),
            flags: U256::from(PAY_IN_FLAG),
            claim_handler: EvmAddress::from_str("0x4444444444444444444444444444444444444444")
                .unwrap(),
            claim_data: [0u8; 32],
            refund_handler: EvmAddress::from_str("0x5555555555555555555555555555555555555555")
                .unwrap(),
            refund_data: [0u8; 32],
            security_deposit: U256::ZERO,
            claimer_bounty: U256::ZERO,
            deposit_token: EvmAddress::ZERO,
            success_action_commitment: [0u8; 32],
        };
        assert!(requires_token_approval(sender, &escrow));
    }

    #[test]
    fn test_requires_token_approval_false_for_native_or_non_payin() {
        let sender = EvmAddress::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let mut escrow = SwapEscrowData {
            offerer: sender,
            claimer: EvmAddress::from_str("0x2222222222222222222222222222222222222222").unwrap(),
            amount: U256::from(100u64),
            token: EvmAddress::ZERO,
            flags: U256::from(PAY_IN_FLAG),
            claim_handler: EvmAddress::from_str("0x4444444444444444444444444444444444444444")
                .unwrap(),
            claim_data: [0u8; 32],
            refund_handler: EvmAddress::from_str("0x5555555555555555555555555555555555555555")
                .unwrap(),
            refund_data: [0u8; 32],
            security_deposit: U256::ZERO,
            claimer_bounty: U256::ZERO,
            deposit_token: EvmAddress::ZERO,
            success_action_commitment: [0u8; 32],
        };
        assert!(!requires_token_approval(sender, &escrow));

        escrow.token = EvmAddress::from_str("0x3333333333333333333333333333333333333333").unwrap();
        escrow.flags = U256::ZERO;
        assert!(!requires_token_approval(sender, &escrow));
    }
}
