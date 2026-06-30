use crate::action::{
    ChallengeSent, DisproveSent, GOATMessage, GOATMessageContent, KickoffSent, NodeInfo,
    PreKickoffSent, SolderingProofReady, Take1Sent, Take2Sent, push_local_unhandled_messages,
    send_to_peer,
};
use crate::env::*;
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::soldering_payload_store::{
    is_soldering_proof_s3_path, soldering_proof_payload_store_path,
    write_soldering_proof_store_payload,
};
use alloy::primitives::{Address as EvmAddress, Signature as EvmSignature};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, BlockHash, CompressedPublicKey, EcdsaSighashType, Network, OutPoint,
    PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use bitcoin_light_client_circuit::{
    VK_HASH_SIZE, build_watchtower_commitment, decode_operator_public_outputs,
};
use bitvm::treepp::*;
use bitvm_lib::actors::Actor;
use bitvm_lib::committee::*;
use bitvm_lib::keys::{OperatorMasterKey, VerifierMasterKey, WatchtowerMasterKey};
use bitvm_lib::operator::*;
use bitvm_lib::timelocks::{connector_f_timelock_blocks, default_timelock_config};
use bitvm_lib::types::{
    BitvmGcCircuitData, BitvmGcGraph, BitvmGcGraphParameters, BitvmGcInstanceParameters,
    PrekickoffParameters, SimplifiedBitvmGcGraph, UserInfo,
};
use bitvm_lib::verifier::*;
use bitvm_lib::watchtower::*;
use client::Utxo as ClientUtxo;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use esplora_client::Utxo;
use goat::connectors::{
    base::TaprootConnector,
    kickoff_connectors::{ForceSkipConnector, KickoffConnector, PrekickoffConnector},
};
use goat::constants::TimelockConfig;
use goat::contexts::base::generate_n_of_n_public_key;
use goat::scripts::{generate_opreturn_script, p2a_output};
use goat::transactions::base::{Input, output_topology};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::PrekickoffTransaction;
use goat::transactions::signing::populate_p2wsh_witness;
use indexmap::IndexMap;
use libp2p::{PeerId, Swarm};
use musig2::{PartialSignature, PubNonce};
use p3_bn254_fr::Bn254Fr;
use p3_field::{FieldAlgebra, PrimeField};
use rand::Rng;
use reqwest::Url;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub const SELF_SENDER: &str = "self";
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{
    GraphQuery, GraphUpdate, InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor,
};

use crate::env;
use crate::rpc_service::routes::v1::{
    NODES_OPERATOR_BASE, NODES_WATCHTOWER_BASE, PROOFS_WATCHTOWER_PROOF_TIMEOUT,
};

use crate::scheduled_tasks::get_goat_message_content_type;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    ChallengeSubStatus, VerifierChallengeStatus,
};
use bitcoin_light_client_circuit::hash_operator_constant;
use bitvm_lib::babe_adapter::{
    BabeProverState, BabeVerifierPrivateState, CACSetupPackage, FinalizedInstanceData,
    SolderingData, compact_soldering_proof_payload,
};
use bitvm_lib::transactions::base::BaseTransaction;
use client::goat_chain::{DisproveTxType, GraphData, PeginStatus, WithdrawStatus};
use client::http_client::async_client::HttpAsyncClient;
use proof_builder::{
    OperatorProofRequest, OperatorProofResponse, ProofData, WatchtowerProofRequest,
    WatchtowerProofResponse, WatchtowerProofTimeoutUpdateRequest,
    WatchtowerProofTimeoutUpdateResponse,
};
use store::{
    BridgeOutGlobalStats, ByteArray32, Graph, GraphRawData, GraphStatus, Instance,
    InstanceBridgeInStatus, Message, MessageState, MessageType, Node, PeginGraphProcessData,
    PeginInstanceProcessData, SerializableTxid, UInt64Array3,
};
use stun_client::{Attribute, Class, Client};
use tracing::{error, info, warn};
use uuid::Uuid;
use zkm_recursion_core::stark::KoalaBearPoseidon2Outer;
use zkm_sdk::ZKMProofWithPublicValues;
use zkm_stark::PartStarkVerifyingKey;
use zkm_verifier::{
    Groth16Verifier, IMM_GROTH16_VK_BYTES, convert_ark_imm_wrap_vk, decode_zkm_vkey_hash,
    load_ark_public_inputs_from_bytes,
};

pub(crate) const BRIDGE_OUT_GLOBAL_STATS_ID: i64 = 1;

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

#[derive(Clone)]
pub struct ValidatedOperatorProof {
    pub proof: Groth16Proof,
    pub public_inputs: PublicInputs,
    pub verifying_key: VerifyingKey,
    pub public_values: Vec<u8>,
    pub vk_hash: String,
    pub zkm_version: String,
}

#[derive(Clone)]
pub struct OperatorStatement {
    pub static_input: ark_bn254::Fr,
    pub vk_hash: [u8; 32],
    pub zkm_version: String,
    pub constant: [u8; 32],
}

pub mod todo_funcs {
    #![allow(dead_code, unreachable_code, unused_variables)]

    use super::*;
    use bitvm_lib::timelocks::estimated_block_interval_secs;
    use bitvm_lib::types::SimplifiedBitvmGcGraph;

    // other operations
    pub fn avg_block_time_secs(network: Network) -> u64 {
        estimated_block_interval_secs(network) as u64
    }
    pub fn min_required_operator() -> usize {
        // todo!("get min required operator number")
        1
    }
    pub fn min_required_watchtower() -> usize {
        // todo!("get min required watchtower number")
        1
    }
    pub fn min_required_verifier() -> usize {
        // todo!("get verifier num")
        1
    }

    /// Validates the graph's ordered watchtower selection against the contract registry and bound constant.
    pub(super) fn validate_watchtower_selection(
        selected: &[XOnlyPublicKey],
        registered: &[XOnlyPublicKey],
        graph_id: [u8; 16],
        genesis_txid: [u8; 32],
        constant: [u8; 32],
    ) -> Result<()> {
        use std::collections::HashSet;

        if selected.len() < min_required_watchtower() {
            bail!(SpecialError::InvalidGraph(format!(
                "insufficient watchtowers: have {}, required {}",
                selected.len(),
                min_required_watchtower()
            )));
        }
        if selected.len() > 256 {
            bail!(SpecialError::InvalidGraph(format!(
                "too many watchtowers: {}, max 256",
                selected.len()
            )));
        }

        let mut seen = HashSet::new();
        for key in selected {
            if !seen.insert(*key) {
                bail!(SpecialError::InvalidGraph(
                    "duplicate watchtower pubkey in graph".to_string()
                ));
            }
            if !registered.contains(key) {
                bail!(SpecialError::InvalidGraph(format!("watchtower {} is not registered", key)));
            }
        }

        let key_bytes = selected.iter().map(XOnlyPublicKey::serialize).collect::<Vec<_>>();
        let expected = hash_operator_constant(graph_id, genesis_txid, &key_bytes);
        if constant != expected {
            bail!(SpecialError::InvalidGraph(
                "operator constant mismatch for graph watchtower list".to_string()
            ));
        }
        Ok(())
    }

    pub async fn validate_graph_instance_parameters(
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        parameters: &BitvmGcInstanceParameters,
    ) -> Result<()> {
        let expected = super::read_instance_info_from_goat(goat_client, parameters.instance_id)
            .await
            .map_err(|e| {
                SpecialError::InvalidGraph(format!(
                    "failed to load instance parameters from GoatChain: {e}"
                ))
            })?;
        if parameters != &expected {
            bail!(SpecialError::InvalidGraph(
                "instance parameters mismatch with GoatChain peg-in data".to_string()
            ));
        }

        for input in &expected.user_info.inputs {
            let funding_tx = btc_client.get_tx(&input.outpoint.txid).await.map_err(|e| {
                SpecialError::InvalidGraph(format!(
                    "failed to load peg-in funding transaction {}: {e}",
                    input.outpoint.txid
                ))
            })?;
            let Some(funding_tx) = funding_tx else {
                bail!(SpecialError::InvalidGraph(format!(
                    "peg-in funding transaction {} not found on Bitcoin",
                    input.outpoint.txid
                )));
            };
            let funding_output =
                funding_tx.output.get(input.outpoint.vout as usize).ok_or_else(|| {
                    SpecialError::InvalidGraph(format!(
                        "peg-in funding outpoint {}:{} does not exist",
                        input.outpoint.txid, input.outpoint.vout
                    ))
                })?;
            if funding_output.value != input.amount {
                bail!(SpecialError::InvalidGraph(format!(
                    "peg-in funding amount mismatch for {}:{}: graph={}, bitcoin={}",
                    input.outpoint.txid,
                    input.outpoint.vout,
                    input.amount.to_sat(),
                    funding_output.value.to_sat()
                )));
            }
        }

        let pegin_deposit_txid = expected
            .build_pegin_tx()
            .map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to reconstruct peg-in deposit: {e}"))
            })?
            .0
            .tx()
            .compute_txid();
        if btc_client
            .get_tx(&pegin_deposit_txid)
            .await
            .map_err(|e| {
                SpecialError::InvalidGraph(format!(
                    "failed to load peg-in deposit transaction {pegin_deposit_txid}: {e}"
                ))
            })?
            .is_none()
        {
            bail!(SpecialError::InvalidGraph(format!(
                "peg-in deposit transaction {pegin_deposit_txid} not found on Bitcoin"
            )));
        }

        Ok(())
    }

    pub async fn validate_init_graph(
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        graph: &SimplifiedBitvmGcGraph,
    ) -> Result<()> {
        if !graph.operator_pre_signed() {
            bail!(SpecialError::InvalidGraph(
                "graph is missing operator pre-signatures".to_string()
            ));
        }
        // Basic structural and on-chain consistency checks for an incoming graph proposal.
        // Return SpecialError::InvalidGraph on any validation failure.
        // 1) Rebuild full graph (ensures signatures present if flags are set and tx graph is coherent)
        let full_graph = BitvmGcGraph::from_simplified(graph)
            .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;
        verify_graph_operator_pre_signatures(&full_graph).map_err(|e| {
            SpecialError::InvalidGraph(format!("invalid operator pre-signatures: {e}"))
        })?;

        // 2) Bind all instance and peg-in parameters to GoatChain and Bitcoin.
        validate_graph_instance_parameters(
            btc_client,
            goat_client,
            &graph.parameters.instance_parameters,
        )
        .await?;

        // 3) Challenge amount and assert-commit count must match local constants
        if graph.parameters.challenge_amount != super::todo_funcs::challenge_amount() {
            bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
        }

        // 4) Watchtower config sanity: number of watchtowers should match number of hashlocks and registry size
        let watchtowers_on_chain =
            goat_client.committee_mana_get_watchtowers().await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to load watchtowers from chain: {e}"))
            })?;

        validate_watchtower_selection(
            &graph.parameters.watchtower_pubkeys,
            &watchtowers_on_chain,
            *graph.parameters.graph_id.as_bytes(),
            get_genesis_sequencer_commit_id(),
            graph.parameters.pubin_disprove_constant,
        )?;

        // 5) Operator stake sanity: verify operator is registered and has enough locked stake
        let op_pk_bytes = graph.parameters.operator_pubkey.to_bytes();
        let xonly: [u8; 32] = op_pk_bytes[1..33]
            .try_into()
            .map_err(|_| SpecialError::InvalidGraph("invalid operator pubkey".to_string()))?;
        let operator_addr =
            goat_client.stake_mana_pubkey_to_address(&xonly).await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to query operator address: {e}"))
            })?;
        if operator_addr == [0u8; 20] {
            bail!(SpecialError::InvalidGraph("operator not registered".to_string()));
        }
        let min_stake_amount = goat_client.gateway_get_min_stake_amount().await.map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to query min stake amount: {e}"))
        })?;
        let locked_stake =
            goat_client.stake_mana_lock_stake_of(&operator_addr).await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to query operator locked stake: {e}"))
            })?;
        if locked_stake < min_stake_amount {
            bail!(SpecialError::InvalidGraph(format!(
                "insufficient operator stake: locked={locked_stake}, min={min_stake_amount}"
            )));
        }

        Ok(())
    }
    pub async fn validate_finalized_graph(
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        graph: &SimplifiedBitvmGcGraph,
        endorse_sigs: &[(PublicKey, EvmAddress, Vec<u8>)],
    ) -> Result<()> {
        if !graph.operator_pre_signed() || !graph.committee_pre_signed() {
            bail!(SpecialError::InvalidGraph(
                "finalized graph is missing operator or committee pre-signatures".to_string()
            ));
        }
        // 1) Rebuild full graph to ensure structure is coherent and txns derivable
        let full_graph = BitvmGcGraph::from_simplified(graph)
            .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;
        verify_graph_operator_pre_signatures(&full_graph).map_err(|e| {
            SpecialError::InvalidGraph(format!("invalid operator pre-signatures: {e}"))
        })?;
        verify_graph_committee_pre_signatures(&full_graph).map_err(|e| {
            SpecialError::InvalidGraph(format!("invalid committee pre-signatures: {e}"))
        })?;

        // 2) Repeat the full instance and peg-in binding for nodes that did not see CreateGraph.
        validate_graph_instance_parameters(
            btc_client,
            goat_client,
            &graph.parameters.instance_parameters,
        )
        .await?;

        let instance_id = graph.parameters.instance_parameters.instance_id;
        if graph.parameters.challenge_amount != super::todo_funcs::challenge_amount() {
            bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
        }

        let watchtowers_on_chain =
            goat_client.committee_mana_get_watchtowers().await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to load watchtowers from chain: {e}"))
            })?;
        validate_watchtower_selection(
            &graph.parameters.watchtower_pubkeys,
            &watchtowers_on_chain,
            *graph.parameters.graph_id.as_bytes(),
            get_genesis_sequencer_commit_id(),
            graph.parameters.pubin_disprove_constant,
        )?;

        // 3) Validate endorsements: unique, from legitimate committee members, and signatures recover to the provided EVM address
        use std::collections::HashSet;
        let mut seen_committee: HashSet<PublicKey> = HashSet::new();
        let mut seen_evm: HashSet<EvmAddress> = HashSet::new();
        let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await.map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to load instance data: {e}"))
        })?;
        if pegin_data.committee_pubkeys.len() != pegin_data.committee_addresses.len() {
            bail!(SpecialError::InvalidGraph(
                "on-chain committee pubkey and address counts differ".to_string()
            ));
        }
        if endorse_sigs.len() != pegin_data.committee_pubkeys.len() {
            bail!(SpecialError::InvalidGraph(format!(
                "endorsement count {} does not match instance committee count {}",
                endorse_sigs.len(),
                pegin_data.committee_pubkeys.len()
            )));
        }

        for (pk, evm_addr, sig) in endorse_sigs.iter() {
            // no duplicates
            if !seen_committee.insert(*pk) {
                bail!(SpecialError::InvalidGraph(
                    "duplicate committee pubkey in endorsements".to_string()
                ));
            }
            if !seen_evm.insert(*evm_addr) {
                bail!(SpecialError::InvalidGraph(
                    "duplicate evm address in endorsements".to_string()
                ));
            }

            // map pubkey -> expected evm address from GoatChain
            let mut found = false;
            for i in 0..pegin_data.committee_pubkeys.len() {
                let on_chain_pk =
                    PublicKey::from_slice(&pegin_data.committee_pubkeys[i]).map_err(|e| {
                        SpecialError::InvalidGraph(format!(
                            "invalid committee pubkey on-chain: {e}"
                        ))
                    })?;
                if &on_chain_pk == pk {
                    found = true;
                    let expected_addr = pegin_data.committee_addresses[i];
                    if &expected_addr != evm_addr {
                        bail!(SpecialError::InvalidGraph(
                            "committee evm address mismatch".to_string()
                        ));
                    }
                    break;
                }
            }
            if !found {
                bail!(SpecialError::InvalidGraph("endorser not in committee set".to_string()));
            }

            // cryptographically verify the endorsement against the graph digest
            let ok = super::verify_graph_endorsement(goat_client, evm_addr, &full_graph, sig)
                .await
                .map_err(|e| {
                    SpecialError::InvalidGraph(format!("failed to verify endorsement: {e}"))
                })?;
            if !ok {
                bail!(SpecialError::InvalidGraph("invalid endorsement signature".to_string()));
            }
        }

        Ok(())
    }
    pub fn prekickoff_replenishment_amount() -> Amount {
        Amount::from_sat(500000)
    }
    pub fn min_prekickoff_input_amount() -> Amount {
        Amount::from_sat(200000)
    }
    pub fn challenge_amount() -> Amount {
        Amount::from_sat(20000)
    }
    pub fn prekickoff_fee_amount(replenish_fee_inputs_num: usize) -> Amount {
        let tx_vbytes = PRE_KICKOFF_BASE_VBYTES
            + (replenish_fee_inputs_num as u64 * CHEKSIG_P2WSH_INPUT_VBYTES);
        Amount::from_sat(tx_vbytes)
    }
}

pub mod evm_swap_utils {
    use super::*;
    use crate::utils::evm_swap_utils::IEscrowManager::{EscrowData, IEscrowManagerCalls};
    use alloy::primitives::{B256, keccak256};
    use alloy::rpc::types::trace::geth::{CallConfig, CallFrame, GethDebugTracingOptions};
    use alloy::sol;
    use alloy::sol_types::SolInterface;
    use alloy::sol_types::SolValue;

    sol! {
        interface IEscrowManager {
            event Initialize(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address claimHandler, address refundHandler);
            event Claim(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address claimHandler, bytes witnessResult); // for BitcoinNoncedOutputClaimHandler, Claim.witnessResult = payout_btc_txid
            event Refund(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address refundHandler, bytes witnessResult);
            event ExecutionError(bytes32 indexed escrowHash, bytes error);
            #[derive(Debug)]
            struct EscrowData {
                //Account funding the escrow
                address offerer;
                //Account entitled to claim the funds from the escrow
                address claimer;

                //Amount of tokens in the escrow
                uint256 amount;
                //Token of the escrow
                address token;

                //Misc escrow data flags, currently defined: payIn, payOut, reputation.
                //It is recommended to randomize the other unused bits in the flags to act as a salt,
                // such that no 2 escrow data are the same, even if all the other data in them match.
                uint256 flags;

                //Address of the IClaimHandler deciding if this escrow is claimable
                // use BitcoinNoncedOutputClaimHandler for Goat -> Bitcoin swaps
                address claimHandler;
                //Data provided to the claim handler along with the witness to check claimability
                // for BitcoinNoncedOutputClaimHandler, this is the hash commitment of the claim data, see hash_claim_commitment
                bytes32 claimData;

                //Address of the IRefundHandler deciding if this escrow is refundable
                // use TimelockRefundHandler for Goat -> Bitcoin swaps
                address refundHandler;
                //Data provided to the refund handler along with the witness to check for refundability
                // for TimelockRefundHandler, this is the timestamp after which refund is possible
                bytes32 refundData;

                //Security deposit taken by the offerer if swap expires without claimer claiming (i.e. options premium)
                uint256 securityDeposit;
                //Claimer bounty that can be claimed by a 3rd party claimer if he were to claim this swap on behalf of claimer
                uint256 claimerBounty;
                //Deposit token of the swap used for securityDeposit and claimerBounty
                address depositToken;

                //ExecutionAction hash commitment to be executed on claim, left 0x0 if no execution should happen on claim
                bytes32 successActionCommitment;
            }
            function initialize(EscrowData calldata escrow, bytes calldata signature, uint256 timeout, bytes memory _extraData) external payable {}
            function claim(EscrowData calldata escrow, bytes calldata witness) external {}
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ClaimData {
        pub txid: Txid,
        pub nonce: u64,
        pub output_amount: u64,
        pub output_script: Vec<u8>,
        pub confirmations: u32,
        pub btc_relay_contract: EvmAddress,
        pub witness: String,
    }

    pub fn hash_escrow_data(escrow: &EscrowData) -> B256 {
        let encoded = escrow.abi_encode();
        keccak256(&encoded)
    }

    pub fn hash_claim_commitment(claim_data: &ClaimData) -> B256 {
        // txoHash = keccak256(uint64 nonce || uint64 outputAmount || keccak256(bytes outputScript))
        // Commitment: C = abi.encodePacked(bytes32 txoHash, uint32 confirmations, address btcRelayContract)
        // Witness: W = C || StoredBlockHeader blockheader || uint32 vout || bytes transaction || uint32 position || bytes32[] merkleProof
        sol! {
            interface IClaimHandlerHelper {
                struct Txo {
                    uint64 nonce;
                    uint64 outputAmount;
                    bytes32 outputScriptHash;
                }
                struct ClaimCommitment {
                    bytes32 TxoHash;
                    uint32 confirmations;
                    address btcRelayContract;
                }
            }
        }
        let output_script_hash = keccak256(&claim_data.output_script);
        let txo = IClaimHandlerHelper::Txo {
            nonce: claim_data.nonce,
            outputAmount: claim_data.output_amount,
            outputScriptHash: output_script_hash,
        };
        let txo_hash = keccak256(txo.abi_encode_packed());
        let claim_commitment = IClaimHandlerHelper::ClaimCommitment {
            TxoHash: txo_hash,
            confirmations: claim_data.confirmations,
            btcRelayContract: claim_data.btc_relay_contract,
        };
        keccak256(claim_commitment.abi_encode_packed())
    }

    fn find_escrow_data(
        call: &CallFrame,
        swap_contract_address: &EvmAddress,
        escrow_hash: &[u8; 32],
    ) -> anyhow::Result<Option<EscrowData>> {
        if call.to == Some(*swap_contract_address)
            && let Ok(calldata) = IEscrowManagerCalls::abi_decode(&call.input)
            && let IEscrowManagerCalls::initialize(args) = calldata
        {
            let computed_hash = hash_escrow_data(&args.escrow);
            if &computed_hash.0 == escrow_hash {
                return Ok(Some(args.escrow));
            }
        }

        for sub_call in &call.calls {
            if let Some(escrow_data) =
                find_escrow_data(sub_call, swap_contract_address, escrow_hash)?
            {
                return Ok(Some(escrow_data));
            }
        }
        Ok(None)
    }

    pub async fn extract_escrow_data_from_tx(
        goat_client: &GOATClient,
        tx_hash: &str,
        swap_contract_address: &EvmAddress,
        escrow_hash: &[u8; 32],
    ) -> anyhow::Result<Option<EscrowData>> {
        let trace_opts = GethDebugTracingOptions::call_tracer(CallConfig::default());
        let trace_raw = goat_client.debug_trace_tx(tx_hash, Some(trace_opts)).await?;
        let call_trace = trace_raw.try_into_call_frame()?;
        if let Some(escrow_data) =
            find_escrow_data(&call_trace, swap_contract_address, escrow_hash)?
        {
            Ok(Some(escrow_data))
        } else {
            Ok(None)
        }
    }

    fn claim_data_from_witness(witness: &[u8]) -> anyhow::Result<ClaimData> {
        // txoHash = keccak256(uint64 nonce || uint64 outputAmount || keccak256(bytes outputScript))
        // Witness: W = bytes32 txoHash
        //  || uint32 confirmations
        //  || address btcRelayContract
        //  || StoredBlockHeader(160-bytes) blockheader
        //  || uint32 vout
        //  || bytes transaction (32-byte length prefix + data)
        //  || uint32 position || bytes32[] merkleProof
        // claimData.nonce = or(shl(24, locktimeSub500M), and(firstNSequence, 0x00FFFFFF))
        // claimData.output_amount = W.transaction.outputs[vout].value
        // claimData.output_script = W.transaction.outputs[vout].scriptPubKey

        let mut offset = 0;

        // 1. txoHash (32 bytes)
        if witness.len() < 32 {
            anyhow::bail!("witness too short for txoHash");
        }
        offset += 32;

        // 2. confirmations (4 bytes)
        if witness.len() < offset + 4 {
            anyhow::bail!("witness too short for confirmations");
        }
        let confirmations = u32::from_be_bytes(witness[offset..offset + 4].try_into()?);
        offset += 4;

        // 3. btcRelayContract (20 bytes)
        if witness.len() < offset + 20 {
            anyhow::bail!("witness too short for btcRelayContract");
        }
        let btc_relay_contract = EvmAddress::from_slice(&witness[offset..offset + 20]);
        offset += 20;

        // 4. StoredBlockHeader (160 bytes)
        if witness.len() < offset + 160 {
            anyhow::bail!("witness too short for blockheader");
        }
        offset += 160;

        // 5. vout (4 bytes)
        if witness.len() < offset + 4 {
            anyhow::bail!("witness too short for vout");
        }
        let vout = u32::from_be_bytes(witness[offset..offset + 4].try_into()?);
        offset += 4;

        // 6. transaction (32-byte length prefix + data)
        if witness.len() < offset + 32 {
            anyhow::bail!("witness too short for transaction length");
        }
        let tx_len = alloy::primitives::U256::from_be_slice(&witness[offset..offset + 32]);
        offset += 32;

        let tx_len_usize: usize =
            tx_len.try_into().map_err(|_| anyhow::anyhow!("tx length too large"))?;

        if witness.len() < offset + tx_len_usize {
            anyhow::bail!("witness too short for transaction data");
        }
        let tx_bytes = &witness[offset..offset + tx_len_usize];

        let tx: Transaction = deserialize(tx_bytes)?;

        if vout as usize >= tx.output.len() {
            anyhow::bail!("vout index out of bounds");
        }
        let output = &tx.output[vout as usize];

        if tx.input.is_empty() {
            anyhow::bail!("transaction has no inputs");
        }
        let first_input_sequence = tx.input[0].sequence.to_consensus_u32();

        let lock_time = tx.lock_time.to_consensus_u32();
        let lock_time_val =
            if lock_time >= 500_000_000 { lock_time - 500_000_000 } else { lock_time };

        let nonce = ((lock_time_val as u64) << 24) | ((first_input_sequence as u64) & 0x00ffffff);

        Ok(ClaimData {
            txid: tx.compute_txid(),
            nonce,
            output_amount: output.value.to_sat(),
            output_script: output.script_pubkey.to_bytes(),
            confirmations,
            btc_relay_contract,
            witness: hex::encode(witness),
        })
    }

    // for BitcoinNoncedOutputClaimHandler
    fn find_claim_data(
        tx_hash: &str,
        call: &CallFrame,
        swap_contract_address: &EvmAddress,
        escrow_hash: &[u8; 32],
    ) -> anyhow::Result<Option<ClaimData>> {
        if call.to == Some(*swap_contract_address)
            && let Ok(calldata) = IEscrowManagerCalls::abi_decode(&call.input)
            && let IEscrowManagerCalls::claim(args) = calldata
        {
            let computed_hash = hash_escrow_data(&args.escrow);
            if &computed_hash.0 == escrow_hash {
                return match claim_data_from_witness(&args.witness) {
                    Ok(claim_data) => Ok(Some(claim_data)),
                    Err(e) => {
                        warn!("fail to decode claim data for tx: {tx_hash}, error:{e}");
                        Ok(None)
                    }
                };
            }
        }

        for sub_call in &call.calls {
            if let Some(claim_data) =
                find_claim_data(tx_hash, sub_call, swap_contract_address, escrow_hash)?
            {
                return Ok(Some(claim_data));
            }
        }
        Ok(None)
    }

    pub async fn extract_claim_data_from_tx(
        goat_client: &GOATClient,
        tx_hash: &str,
        swap_contract_address: &EvmAddress,
        escrow_hash: &[u8; 32],
    ) -> anyhow::Result<Option<ClaimData>> {
        let trace_opts = GethDebugTracingOptions::call_tracer(CallConfig::default());
        let trace_raw = goat_client.debug_trace_tx(tx_hash, Some(trace_opts)).await?;
        let call_trace = trace_raw.try_into_call_frame()?;
        if let Some(claim_data) =
            find_claim_data(tx_hash, &call_trace, swap_contract_address, escrow_hash)?
        {
            Ok(Some(claim_data))
        } else {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn test_find_escrow_data() {
        unsafe {
            std::env::set_var(crate::env::ENV_GOAT_CHAIN_URL, "https://rpc.testnet3.goat.network");
        }
        let tx_hash = "0x6027024dc57b847120074efed67c3e31534988f70b6b1e5043b248e7740a295c";
        let goat_client = GOATClient::new(
            crate::env::goat_config_from_env().await,
            client::goat_chain::GoatNetwork::Test,
        );
        let swap_contract_address =
            EvmAddress::from_str("0xe510D5781C6C849284Fb25Dc20b1684cEC445C8B").unwrap();
        let escrow_hash: [u8; 32] =
            hex::decode("521a1d007f9fdf41b18ad6f1ccfeaf8fd67d0b04608ce3d8950526e55e4eca28")
                .unwrap()
                .try_into()
                .unwrap();
        let escrow_data = extract_escrow_data_from_tx(
            &goat_client,
            tx_hash,
            &swap_contract_address,
            &escrow_hash,
        )
        .await
        .unwrap();
        assert!(escrow_data.is_some());
        let expected_claim_hash =
            B256::from_str("0xc69e4a62e0c904b341245656ba191790356d771bd4a7a00bed2780a5abad8c63")
                .unwrap();
        assert_eq!(escrow_data.unwrap().claimData, expected_claim_hash);
    }

    #[test]
    fn test_hash_claim_commitment() {
        // example data from an actual swap on testnet:
        // goat initialize txid: 0x6027024dc57b847120074efed67c3e31534988f70b6b1e5043b248e7740a295c
        // goat claim txid: 0xc2b26508a28f349c7ee1e189914dc5815b77d1abaa5ce6a60449f69bd1e7e64a
        // btc payout txid: 033d4024aca7f6dda6b01e7f0a2bb0fdd15160cc9b2559b55c6f65962362d74e
        let claim_data = ClaimData {
            txid: Txid::from_slice(&[0_u8; 32]).unwrap(),
            nonce: 17872110975047329u64,
            output_amount: 9511u64,
            output_script: hex::decode(
                "5120a5d06cb76aaf6287b93a8ee73d9678e32b039354e6df4019bbd60087e347f5cc",
            )
            .unwrap(),
            confirmations: 2u32,
            btc_relay_contract: EvmAddress::from_str("0x3887B02217726bB36958Dd595e57293fB63D5082")
                .unwrap(),
            witness: "".to_string(),
        };
        let commitment_hash = hash_claim_commitment(&claim_data);

        let expected_hash =
            B256::from_str("0xc69e4a62e0c904b341245656ba191790356d771bd4a7a00bed2780a5abad8c63")
                .unwrap();
        assert_eq!(commitment_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_find_claim_data() {
        unsafe {
            std::env::set_var(crate::env::ENV_GOAT_CHAIN_URL, "https://rpc.testnet3.goat.network");
        }
        let tx_hash = "0xc2b26508a28f349c7ee1e189914dc5815b77d1abaa5ce6a60449f69bd1e7e64a";
        let goat_client = GOATClient::new(
            crate::env::goat_config_from_env().await,
            client::goat_chain::GoatNetwork::Test,
        );
        let swap_contract_address =
            EvmAddress::from_str("0xe510D5781C6C849284Fb25Dc20b1684cEC445C8B").unwrap();
        let escrow_hash: [u8; 32] =
            hex::decode("521a1d007f9fdf41b18ad6f1ccfeaf8fd67d0b04608ce3d8950526e55e4eca28")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_claim_data = ClaimData {
            txid: Txid::from_str("033d4024aca7f6dda6b01e7f0a2bb0fdd15160cc9b2559b55c6f65962362d74e").unwrap(),
            nonce: 17872110975047329u64,
            output_amount: 9511u64,
            output_script: hex::decode(
                "5120a5d06cb76aaf6287b93a8ee73d9678e32b039354e6df4019bbd60087e347f5cc",
            )
                .unwrap(),
            confirmations: 2u32,
            btc_relay_contract: EvmAddress::from_str("0x3887B02217726bB36958Dd595e57293fB63D5082")
                .unwrap(),
            witness: "8977831297fa2d7156898a8d26bb9e276a83cf907d739eb64ff98a0092e9250e000000023887b022\
            17726bb36958dd595e57293fb63d508200600020bfe2760399ccb567289b120361316911b13e937aa0f2742bb7\
            0b000000000000efaf19dc26fadb8b1cd69e76c6d1f51123f6d22407755f865b65b446cf863c3c5fbe3769f0ff\
            0f1ad88a60f10000000000000000000000000000000000000000000017b6e253602b5f4cc25000494e876937b2\
            636937bd246937bd2a6937bd2d6937bd306937bd6f6937bd8f6937bda66937bde76937bdf96937be07000000000\
            00000000000000000000000000000000000000000000000000000000000008902000000018c3db50ef29dbdddf9\
            628cd968667688cd37560ef5e64131efc3a1e4cf4e739c0100000000a1d60dfe022725000000000000225120a5d\
            06cb76aaf6287b93a8ee73d9678e32b039354e6df4019bbd60087e347f5ccf61a010000000000225120eb3e0c2d\
            d6b344c6efaa771306a29e864c65d536dfac8f89a87680285af7acad1afc4b5d000000060000000000000000000\
            000000000000000000000000000000000000000000003f7cfe6eed4929eea954c8e1358704c6dec19e2826f7223\
            ff7d0eff92c1addf20fd2b876e05846a100c38bd3c30619c66437abb97bc5fc21e2595fbb8a514f5341ebf1f8dd\
            26752879de5c581667aaf183b18c1b5a111f4a24061d2c44aea2fd1".to_string(),
        };
        let claim_data =
            extract_claim_data_from_tx(&goat_client, tx_hash, &swap_contract_address, &escrow_hash)
                .await
                .unwrap();
        assert!(claim_data.is_some());
        assert_eq!(claim_data.unwrap(), expected_claim_data);
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::redundant_pattern_matching)]
#[allow(clippy::collapsible_else_if)]
pub(crate) async fn refresh_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: Option<&BitvmGcGraph>,
    scan_from_status: Option<GraphStatus>,
    scan_from_sub_status: Option<ChallengeSubStatus>,
) -> Result<(GraphStatus, Option<ChallengeSubStatus>, Option<GraphChainScan>)> {
    let Some(graph) = graph else {
        let status = scan_from_status.unwrap_or(GraphStatus::OperatorPresigned);
        return Ok((status, scan_from_sub_status, None));
    };

    let scan = scan_graph_chain_state(
        btc_client,
        goat_client,
        graph,
        scan_from_status,
        scan_from_sub_status,
    )
    .await?;

    if let Some(challenge_txid) = scan.challenge_txid {
        update_graph_challenge_txid_if_needed(local_db, graph_id, challenge_txid).await?;
    }

    update_graph_status(
        local_db,
        instance_id,
        graph_id,
        scan.status,
        Some(scan.sub_status.clone()),
    )
    .await?;

    Ok((scan.status, Some(scan.sub_status.clone()), Some(scan)))
}

#[derive(Clone, Debug)]
struct DetectedDisprove {
    disprove_type: DisproveTxType,
    index: usize,
    challenge_start_txid: Option<Txid>,
    challenge_finish_txid: Txid,
}

#[derive(Clone, Debug)]
pub(crate) struct GraphChainScan {
    status: GraphStatus,
    sub_status: ChallengeSubStatus,
    challenge_txid: Option<Txid>,
    #[allow(dead_code)]
    watchtower_challenge_init_on_chain: bool,
    #[allow(dead_code)]
    operator_assert_on_chain: bool,
    disprove: Option<DetectedDisprove>,
}

fn normalize_challenge_sub_status(
    mut sub_status: ChallengeSubStatus,
    watchtower_num: usize,
    verifier_num: usize,
) -> ChallengeSubStatus {
    sub_status.watchtower_challenge_status.resize(watchtower_num, false);
    sub_status.verifier_challenge_status.resize(verifier_num, VerifierChallengeStatus::None);
    sub_status
}

fn connector_a_outpoint(graph: &BitvmGcGraph) -> Result<OutPoint> {
    graph
        .kickoff
        .connector_a_input()
        .map(|input| input.outpoint)
        .map_err(|e| anyhow!("failed to get connector-a input: {e}"))
}

fn connector_d_outpoint(graph: &BitvmGcGraph) -> Result<OutPoint> {
    graph
        .operator_assert
        .connector_d_input()
        .map(|input| input.outpoint)
        .map_err(|e| anyhow!("failed to get connector-d input: {e}"))
}

#[allow(dead_code)]
fn guardian_connector_outpoint(graph: &BitvmGcGraph) -> Result<OutPoint> {
    graph
        .kickoff
        .guardian_connector_input()
        .map(|input| input.outpoint)
        .map_err(|e| anyhow!("failed to get guardian connector input: {e}"))
}

async fn update_graph_challenge_txid_if_needed(
    local_db: &LocalDB,
    graph_id: Uuid,
    challenge_txid: Txid,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let Some(graph) = storage_processor.find_graph(&graph_id).await? else {
        warn!("graph: {graph_id} not found, skip updating challenge txid");
        return Ok(());
    };
    if graph.challenge_txid.as_ref().map(|txid| txid.0) != Some(challenge_txid) {
        storage_processor
            .update_graph(&GraphUpdate::new(graph_id).with_challenge_txid(challenge_txid.into()))
            .await?;
    }
    Ok(())
}

#[allow(dead_code)]
async fn detect_guardian_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    challenge_start_txid: Option<Txid>,
) -> Result<Option<DetectedDisprove>> {
    let quick_challenge_txid = graph.quick_challenge.tx().compute_txid();
    if tx_on_chain(btc_client, &quick_challenge_txid).await? {
        return Ok(Some(DetectedDisprove {
            disprove_type: DisproveTxType::QuickChallenge,
            index: 0,
            challenge_start_txid,
            challenge_finish_txid: quick_challenge_txid,
        }));
    }

    let challenge_incomplete_kickoff_txid = graph.challenge_incomplete_kickoff.tx().compute_txid();
    if tx_on_chain(btc_client, &challenge_incomplete_kickoff_txid).await? {
        return Ok(Some(DetectedDisprove {
            disprove_type: DisproveTxType::ChallengeIncompleteKickoff,
            index: 0,
            challenge_start_txid,
            challenge_finish_txid: challenge_incomplete_kickoff_txid,
        }));
    }
    Ok(None)
}

async fn detect_connector_d_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    challenge_start_txid: Option<Txid>,
) -> Result<Option<DetectedDisprove>> {
    let connector_d = connector_d_outpoint(graph)?;
    let Some(spent_txid) =
        outpoint_spent_txid(btc_client, &connector_d.txid, connector_d.vout as u64).await?
    else {
        return Ok(None);
    };

    if spent_txid == graph.take2.tx().compute_txid() {
        return Ok(None);
    }

    for (index, disprove) in graph.disproves.iter().enumerate() {
        if spent_txid == disprove.tx().compute_txid() {
            return Ok(Some(DetectedDisprove {
                disprove_type: DisproveTxType::Disprove,
                index,
                challenge_start_txid,
                challenge_finish_txid: spent_txid,
            }));
        }
    }

    Ok(Some(DetectedDisprove {
        disprove_type: DisproveTxType::PubinDisprove,
        index: 0,
        challenge_start_txid: None,
        challenge_finish_txid: spent_txid,
    }))
}

async fn detect_watchtower_flow_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> Result<Option<DetectedDisprove>> {
    for (index, nack) in graph.operator_challenge_nacks.iter().enumerate() {
        let txid = nack.tx().compute_txid();
        if tx_on_chain(btc_client, &txid).await? {
            return Ok(Some(DetectedDisprove {
                disprove_type: DisproveTxType::OperatorChallengeNack,
                index,
                challenge_start_txid: None,
                challenge_finish_txid: txid,
            }));
        }
    }

    let txid = graph.operator_commit_timeout.tx().compute_txid();
    if tx_on_chain(btc_client, &txid).await? {
        return Ok(Some(DetectedDisprove {
            disprove_type: DisproveTxType::OperatorCommitTimeout,
            index: 0,
            challenge_start_txid: None,
            challenge_finish_txid: txid,
        }));
    }

    Ok(None)
}

async fn scan_graph_chain_state(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph: &BitvmGcGraph,
    scan_from_status: Option<GraphStatus>,
    scan_from_sub_status: Option<ChallengeSubStatus>,
) -> Result<GraphChainScan> {
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.verifier_asserts.len();
    let mut sub_status = normalize_challenge_sub_status(
        scan_from_sub_status.unwrap_or_default(),
        watchtower_num,
        verifier_num,
    );
    let mut current_status = match scan_from_status {
        Some(s) => s,
        None => {
            if graph.committee_pre_signed() {
                GraphStatus::CommitteePresigned
            } else {
                return Ok(GraphChainScan {
                    status: GraphStatus::OperatorPresigned,
                    sub_status,
                    challenge_txid: None,
                    watchtower_challenge_init_on_chain: false,
                    operator_assert_on_chain: false,
                    disprove: None,
                });
            }
        }
    };

    let prekickoff_txid = graph.cur_prekickoff.tx().compute_txid();
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let take1_txid = graph.take1.tx().compute_txid();
    let take2_txid = graph.take2.tx().compute_txid();

    // check if Graph has been posted on GoatChain
    if current_status == GraphStatus::CommitteePresigned {
        let graph_data_on_goat = goat_client.gateway_get_graph_data(&graph_id).await?;
        if graph_data_on_goat.operator_pubkey != [0u8; 32] {
            current_status = GraphStatus::OperatorDataPushed;
        }
    }
    // check if Graph has been obsoleted on GoatChain
    if current_status == GraphStatus::OperatorDataPushed {
        let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
        let withdraw_data = goat_client.gateway_get_withdraw_data(&graph_id).await?;
        // NOTE: maybe obesolete graph when pegin is claimed rather than processing?
        if pegin_data.status != PeginStatus::Withdrawable
            && withdraw_data.status == WithdrawStatus::None
        {
            current_status = GraphStatus::Obsoleted;
        }
    }
    // check Prekickoff
    if matches!(
        current_status,
        GraphStatus::OperatorPresigned
            | GraphStatus::CommitteePresigned
            | GraphStatus::OperatorDataPushed
            | GraphStatus::Obsoleted
    ) {
        if !tx_on_chain(btc_client, &prekickoff_txid).await? {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid: None,
                watchtower_challenge_init_on_chain: false,
                operator_assert_on_chain: false,
                disprove: None,
            });
        } else {
            current_status = if current_status == GraphStatus::OperatorDataPushed {
                GraphStatus::PreKickoff
            } else {
                // for GraphStatus::OperatorPresigned/CommitteePresigned:
                // if prekickoff is on-chain while graph data not yet posted,
                // it means this graph will never be posted and operator is going to skip it,
                // mark it as Obsoleted so that it can be skipped later
                //
                // for GraphStatus::Obsoleted: if the graph is obsoleted,
                // keep it as Obsoleted so that it can be skipped later
                GraphStatus::Obsoleted
            };
        }
    }
    // check Kickoff/SkipKickoff
    if matches!(current_status, GraphStatus::PreKickoff | GraphStatus::Obsoleted) {
        let kickoff_connector_vout = 1;
        if let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &prekickoff_txid, kickoff_connector_vout).await?
        {
            if spent_txid != kickoff_txid {
                return Ok(GraphChainScan {
                    status: GraphStatus::Skipped,
                    sub_status,
                    challenge_txid: None,
                    watchtower_challenge_init_on_chain: false,
                    operator_assert_on_chain: false,
                    disprove: None,
                });
            } else {
                current_status = GraphStatus::OperatorKickOff;
            }
        } else {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid: None,
                watchtower_challenge_init_on_chain: false,
                operator_assert_on_chain: false,
                disprove: None,
            });
        }
    }

    let mut challenge_txid = None;
    if current_status == GraphStatus::OperatorKickOff
        && let Some(disprove) = detect_guardian_disprove(btc_client, graph, challenge_txid).await?
    {
        sub_status.disprove_type = Some(disprove.disprove_type);
        sub_status.disprove_index = disprove.index as i32;
        return Ok(GraphChainScan {
            status: GraphStatus::Disprove,
            sub_status,
            challenge_txid,
            watchtower_challenge_init_on_chain: false,
            operator_assert_on_chain: false,
            disprove: Some(disprove),
        });
    }
    if current_status == GraphStatus::OperatorKickOff {
        let connector_a = connector_a_outpoint(graph)?;
        if let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &connector_a.txid, connector_a.vout as u64).await?
        {
            if spent_txid != take1_txid {
                current_status = GraphStatus::Challenge;
                challenge_txid = Some(spent_txid);
            } else {
                return Ok(GraphChainScan {
                    status: GraphStatus::OperatorTake1,
                    sub_status,
                    challenge_txid: None,
                    watchtower_challenge_init_on_chain: false,
                    operator_assert_on_chain: false,
                    disprove: None,
                });
            }
        } else {
            return Ok(GraphChainScan {
                status: GraphStatus::OperatorKickOff,
                sub_status,
                challenge_txid: None,
                watchtower_challenge_init_on_chain: false,
                operator_assert_on_chain: false,
                disprove: None,
            });
        }
    }

    if current_status == GraphStatus::Challenge && challenge_txid.is_none() {
        let connector_a = connector_a_outpoint(graph)?;
        if let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &connector_a.txid, connector_a.vout as u64).await?
            && spent_txid != take1_txid
        {
            challenge_txid = Some(spent_txid);
        }
    }

    let mut watchtower_challenge_init_on_chain = false;
    let mut operator_assert_on_chain = false;
    if current_status == GraphStatus::Challenge {
        if let Some(disprove) = detect_guardian_disprove(btc_client, graph, challenge_txid).await? {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: Some(disprove),
            });
        }

        if let Some(disprove) = detect_watchtower_flow_disprove(btc_client, graph).await? {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: Some(disprove),
            });
        }

        let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
        watchtower_challenge_init_on_chain =
            tx_on_chain(btc_client, &watchtower_challenge_init_txid).await?;
        if watchtower_challenge_init_on_chain {
            for watchtower_index in 0..watchtower_num {
                let watchtower_vout =
                    output_topology::watchtower_challenge_init::watchtower_connector(
                        watchtower_index,
                    ) as u64;
                let spent = outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    watchtower_vout,
                )
                .await?
                .is_some();
                if let Some(status) =
                    sub_status.watchtower_challenge_status.get_mut(watchtower_index)
                {
                    *status = spent;
                }
            }
        }
        if !watchtower_challenge_init_on_chain {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain: false,
                disprove: None,
            });
        }
        let operator_assert_txid = graph.operator_assert.tx().compute_txid();
        operator_assert_on_chain = tx_on_chain(btc_client, &operator_assert_txid).await?;
        if !operator_assert_on_chain {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: None,
            });
        }
        // TBD: add GraphStatus::Assert
    }

    if current_status == GraphStatus::Challenge {
        if let Some(disprove) = detect_guardian_disprove(btc_client, graph, challenge_txid).await? {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: Some(disprove),
            });
        }

        if let Some(disprove) = detect_watchtower_flow_disprove(btc_client, graph).await? {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: Some(disprove),
            });
        }

        // TBD: add GraphStatus::Assert
        let mut detected_disprove = None;
        for verifier_index in 0..verifier_num {
            let verifier_assert_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
            let disprove_txid = graph.disproves[verifier_index].tx().compute_txid();
            if tx_on_chain(btc_client, &verifier_assert_txid).await? {
                if let Some(spent_txid) =
                    outpoint_spent_txid(btc_client, &verifier_assert_txid, 0).await?
                {
                    if spent_txid == disprove_txid {
                        sub_status.verifier_challenge_status[verifier_index] =
                            VerifierChallengeStatus::Disproved;
                        sub_status.disprove_type = Some(DisproveTxType::Disprove);
                        sub_status.disprove_index = verifier_index as i32;
                        detected_disprove = Some(DetectedDisprove {
                            disprove_type: DisproveTxType::Disprove,
                            index: verifier_index,
                            challenge_start_txid: challenge_txid,
                            challenge_finish_txid: spent_txid,
                        });
                        current_status = GraphStatus::Disprove;
                    } else {
                        sub_status.verifier_challenge_status[verifier_index] =
                            VerifierChallengeStatus::ProverAnswered;
                    }
                } else {
                    sub_status.verifier_challenge_status[verifier_index] =
                        VerifierChallengeStatus::VerifierAsserted;
                }
            }
        }
        if current_status == GraphStatus::Disprove {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: detected_disprove,
            });
        }
        if let Some(disprove) =
            detect_connector_d_disprove(btc_client, graph, challenge_txid).await?
        {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: Some(disprove),
            });
        }
        if tx_on_chain(btc_client, &take2_txid).await? {
            return Ok(GraphChainScan {
                status: GraphStatus::OperatorTake2,
                sub_status,
                challenge_txid,
                watchtower_challenge_init_on_chain,
                operator_assert_on_chain,
                disprove: None,
            });
        }
    }

    Ok(GraphChainScan {
        status: current_status,
        sub_status,
        challenge_txid,
        watchtower_challenge_init_on_chain,
        operator_assert_on_chain,
        disprove: None,
    })
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy)]
enum GraphCompensateEventKind {
    PreKickoffSent, // OperatorDataPushed -> PreKickoff
    KickoffSent,    // PreKickoff -> OperatorKickOff
    Take1Sent,      // OperatorKickOff -> OperatorTake1
    ChallengeSent,  // OperatorKickOff -> Challenge
    DisproveSent,   // Challenge -> Disprove
    Take2Sent,      // Challenge -> OperatorTake2
}

fn map_transition_to_event(from: GraphStatus, to: GraphStatus) -> Option<GraphCompensateEventKind> {
    use GraphStatus::*;
    match (from, to) {
        (OperatorDataPushed, PreKickoff) => Some(GraphCompensateEventKind::PreKickoffSent),
        (PreKickoff, OperatorKickOff) => Some(GraphCompensateEventKind::KickoffSent),
        (OperatorKickOff, OperatorTake1) => Some(GraphCompensateEventKind::Take1Sent),
        (OperatorKickOff, Challenge) => Some(GraphCompensateEventKind::ChallengeSent),
        (Challenge, Disprove) => Some(GraphCompensateEventKind::DisproveSent),
        (OperatorKickOff, Disprove) => Some(GraphCompensateEventKind::DisproveSent),
        (Challenge, OperatorTake2) => Some(GraphCompensateEventKind::Take2Sent),
        _ => None,
    }
}

async fn upsert_graph_compensate_message(
    local_db: &LocalDB,
    graph_id: Uuid,
    sub_type: Option<String>,
    actor: Actor,
    message_content: GOATMessageContent,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    upsert_message(
        &mut storage_processor,
        false,
        graph_id,
        sub_type,
        SELF_SENDER.to_string(),
        actor,
        message_content,
        0,
        0,
    )
    .await
}

async fn push_graph_compensate_message(
    local_db: &LocalDB,
    graph_id: Uuid,
    actor: Actor,
    message_content: GOATMessageContent,
) -> Result<()> {
    let message = GOATMessage::new(actor, message_content);
    push_local_unhandled_messages(local_db, graph_id, &message, 0).await
}

#[allow(dead_code)]
async fn should_emit_wrongly_challenge_timeout(
    btc_client: &BTCClient,
    challenge_assert_txid: Txid,
) -> Result<bool> {
    let status = btc_client.get_tx_status(&challenge_assert_txid).await?;
    let Some(block_height) = status.block_height else {
        return Ok(false);
    };
    let current_height = btc_client.get_height().await?;
    Ok(current_height >= block_height + disprove_timelock(get_network()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn compensate_graph_events(
    local_db: &LocalDB,
    _btc_client: &BTCClient,
    instance_id: Uuid,
    graph_id: Uuid,
    _graph: Option<&BitvmGcGraph>,
    scan: Option<&GraphChainScan>,
    scan_from_status: Option<GraphStatus>,
    compensate_from_status: GraphStatus,
    final_status: GraphStatus,
) -> Result<()> {
    let Some(scan) = scan else {
        tracing::debug!(
            "Skip graph compensation for {instance_id}:{graph_id}: chain scan result is missing"
        );
        return Ok(());
    };

    let scan_start = scan_from_status.unwrap_or(compensate_from_status);
    let effective_from = if scan_start.is_after(&compensate_from_status) {
        scan_start
    } else {
        compensate_from_status
    };
    if !effective_from.is_before(&final_status) {
        tracing::debug!(
            "Skip graph compensation for {instance_id}:{graph_id}: effective_from={effective_from:?}, final_status={final_status:?}"
        );
        return Ok(());
    }

    let mut rev_path = vec![final_status];
    let mut cursor = final_status;
    while cursor != effective_from {
        let Some(prev) = cursor.get_previous_status() else {
            tracing::debug!(
                "Skip graph compensation for {instance_id}:{graph_id}: cannot walk from {final_status:?} back to {effective_from:?}"
            );
            return Ok(());
        };
        rev_path.push(prev);
        cursor = prev;
    }
    rev_path.reverse();

    for window in rev_path.windows(2) {
        let [from, to] = window else {
            continue;
        };
        let Some(event) = map_transition_to_event(*from, *to) else {
            continue;
        };

        match event {
            GraphCompensateEventKind::PreKickoffSent => {
                push_graph_compensate_message(
                    local_db,
                    graph_id,
                    Actor::Verifier,
                    GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
                )
                .await?;
            }
            GraphCompensateEventKind::KickoffSent => {
                push_graph_compensate_message(
                    local_db,
                    graph_id,
                    Actor::All,
                    GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
                )
                .await?;
            }
            GraphCompensateEventKind::Take1Sent => {
                push_graph_compensate_message(
                    local_db,
                    graph_id,
                    Actor::Committee,
                    GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }),
                )
                .await?;
            }
            GraphCompensateEventKind::ChallengeSent => {
                if let Some(challenge_txid) = scan.challenge_txid {
                    push_graph_compensate_message(
                        local_db,
                        graph_id,
                        Actor::Operator,
                        GOATMessageContent::ChallengeSent(ChallengeSent {
                            instance_id,
                            graph_id,
                            challenge_txid,
                        }),
                    )
                    .await?;
                }
            }
            GraphCompensateEventKind::DisproveSent => {
                let disprove = scan.disprove.clone().ok_or_else(|| {
                    anyhow!(
                        "Graph {instance_id}:{graph_id} reached Disprove but no disprove transaction was detected"
                    )
                })?;
                upsert_graph_compensate_message(
                    local_db,
                    graph_id,
                    Some(disprove.index.to_string()),
                    Actor::Committee,
                    GOATMessageContent::DisproveSent(DisproveSent {
                        instance_id,
                        graph_id,
                        disprove_type: disprove.disprove_type,
                        index: disprove.index,
                        challenge_start_txid: disprove.challenge_start_txid,
                        challenge_finish_txid: disprove.challenge_finish_txid,
                    }),
                )
                .await?;
            }
            GraphCompensateEventKind::Take2Sent => {
                push_graph_compensate_message(
                    local_db,
                    graph_id,
                    Actor::Committee,
                    GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }),
                )
                .await?;
            }
        }
    }

    Ok(())
}

pub fn build_graph_data(graph: &BitvmGcGraph) -> Result<GraphData> {
    // operator pubkey: first byte is prefix, next 32 bytes are key
    let op_pk_bytes = graph.parameters.operator_pubkey.to_bytes();
    let operator_pubkey_prefix = op_pk_bytes[0];
    let operator_pubkey: [u8; 32] =
        op_pk_bytes[1..33].try_into().map_err(|_| anyhow!("invalid operator pubkey length"))?;

    // compute txids for all required transactions
    let pegin_txid = graph.pegin.finalize().compute_txid().to_byte_array();
    let kickoff_txid = graph.kickoff.finalize().compute_txid().to_byte_array();
    let take1_txid = graph.take1.finalize().compute_txid().to_byte_array();
    let take2_txid = graph.take2.finalize().compute_txid().to_byte_array();
    let watchtower_challenge_init_txid =
        graph.watchtower_challenge_init.finalize().compute_txid().to_byte_array();
    let prover_assert_txid = graph.operator_assert.finalize().compute_txid().to_byte_array();
    let disprove_txids: Vec<[u8; 32]> =
        graph.disproves.iter().map(|tx| tx.finalize().compute_txid().to_byte_array()).collect();
    let watchtower_challenge_timeout_txids: Vec<[u8; 32]> = graph
        .watchtower_challenge_timeouts
        .iter()
        .map(|tx| tx.finalize().compute_txid().to_byte_array())
        .collect();
    let operator_challenge_nack_txids: Vec<[u8; 32]> = graph
        .operator_challenge_nacks
        .iter()
        .map(|tx| tx.finalize().compute_txid().to_byte_array())
        .collect();
    let operator_commit_timeout_txid =
        graph.operator_commit_timeout.finalize().compute_txid().to_byte_array();

    Ok(GraphData {
        operator_pubkey_prefix,
        operator_pubkey,
        pegin_txid,
        kickoff_txid,
        take1_txid,
        take2_txid,
        watchtower_challenge_init_txid,
        prover_assert_txid,
        disprove_txids,
        watchtower_challenge_timeout_txids,
        operator_challenge_nack_txids,
        operator_commit_timeout_txid,
    })
}

pub async fn get_graph_digest(goat_client: &GOATClient, graph: &BitvmGcGraph) -> Result<[u8; 32]> {
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    let graph_data = build_graph_data(graph)?;
    goat_client.gateway_get_post_graph_digest(&instance_id, &graph_id, graph_data).await
}

pub async fn validate_committee(
    goat_client: &GOATClient,
    peer_id: &PeerId,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<()> {
    // return SpecialError::InvalidCommittee if not valid
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    for (i, pk) in pegin_data.committee_pubkeys.iter().enumerate() {
        let pk = PublicKey::from_slice(pk)?;
        if &pk == committee_pubkey {
            let addr = pegin_data.committee_addresses[i];
            let stored_peer_id = goat_client.committee_mana_get_committee_peer_id(&addr).await?;
            if stored_peer_id.to_vec() != peer_id.to_bytes() {
                bail!(SpecialError::InvalidCommittee(
                    "committee pubkey & peer id mismatch".to_string()
                ));
            }
            return Ok(());
        }
    }
    bail!(SpecialError::InvalidCommittee(
        "committee pubkey not found in instance's committee pubkeys".to_string()
    ))
}
pub async fn validate_committee_with_evm_address(
    goat_client: &GOATClient,
    peer_id: &PeerId,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
    committee_evm_address: &EvmAddress,
) -> Result<()> {
    // return SpecialError::InvalidCommittee if not valid
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    for i in 0..pegin_data.committee_pubkeys.len() {
        let pk = PublicKey::from_slice(&pegin_data.committee_pubkeys[i])?;
        let addr = &pegin_data.committee_addresses[i];
        if addr == committee_evm_address {
            if &pk != committee_pubkey {
                bail!(SpecialError::InvalidCommittee(
                    "committee evm address & pubkey mismatch".to_string()
                ));
            }
            let stored_peer_id = goat_client.committee_mana_get_committee_peer_id(addr).await?;
            if stored_peer_id.to_vec() != peer_id.to_bytes() {
                bail!(SpecialError::InvalidCommittee(
                    "committee evm address & peer id mismatch".to_string()
                ));
            }
            return Ok(());
        }
    }
    bail!(SpecialError::InvalidCommittee(
        "committee evm address not found in instance's committee addresses".to_string()
    ))
}

pub async fn validate_graph_id_on_goat(
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let graph_data_on_goat = goat_client.gateway_get_graph_data(&graph_id).await?;
    if graph_data_on_goat.operator_pubkey == [0u8; 32] {
        bail!("Graph {graph_id} not found on GoatChain")
    }
    let all_instance_graph_ids =
        goat_client.gateway_get_graph_ids_by_instance_id(&instance_id).await?;
    if !all_instance_graph_ids.contains(&graph_id) {
        bail!("graph_id: {graph_id} and instance_id {instance_id} mismatch")
    }
    Ok(())
}

pub async fn read_pegin_request(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<(UserInfo, Amount)> {
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    if pegin_data.status != PeginStatus::Pending {
        bail!("Invalid PeginRequest: expired or already processed");
    }
    let network = get_network();
    let user_change_address = Address::from_str(&pegin_data.user_change_addr)
        .map_err(|e| SpecialError::InvalidPeginRequest(format!("invalid user_change_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_change_addr network: {e}"))
        })?;
    let user_refund_address = Address::from_str(&pegin_data.user_refund_addr)
        .map_err(|e| SpecialError::InvalidPeginRequest(format!("invalid user_refund_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_refund_addr network: {e}"))
        })?;
    let user_xonly_pubkey =
        XOnlyPublicKey::from_slice(&pegin_data.user_xonly_pubkey).map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_xonly_pubkey: {e}"))
        })?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_sats),
        })
        .collect();
    // TODO: we need to run our own bitcoin node in case of downtime or ddos attack.
    for input in &inputs {
        if !outpoint_available(btc_client, &input.outpoint.txid, input.outpoint.vout.into()).await?
        {
            bail!(SpecialError::InvalidPeginRequest(format!(
                "input {}:{} is not available",
                input.outpoint.txid, input.outpoint.vout
            )));
        }
    }
    let user_info = UserInfo {
        depositor_evm_address: pegin_data.depositor_address,
        txn_fees: pegin_data.txn_fees,
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    Ok((user_info, Amount::from_sat(pegin_data.pegin_amount_sats)))
}

pub async fn read_instance_info_from_goat(
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<BitvmGcInstanceParameters> {
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    let network = get_network();
    let user_change_address = Address::from_str(&pegin_data.user_change_addr)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_change_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginData(format!("invalid user_change_addr network: {e}"))
        })?;
    let user_refund_address = Address::from_str(&pegin_data.user_refund_addr)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_refund_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginData(format!("invalid user_refund_addr network: {e}"))
        })?;
    let user_xonly_pubkey = XOnlyPublicKey::from_slice(&pegin_data.user_xonly_pubkey)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_xonly_pubkey: {e}")))?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_sats),
        })
        .collect();
    let user_info = UserInfo {
        depositor_evm_address: pegin_data.depositor_address,
        txn_fees: pegin_data.txn_fees,
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    let committee_pubkeys = match goat_client.gateway_get_committee_pubkeys(&instance_id).await {
        Ok(pks) => pks,
        Err(e) => {
            if let Some(msg) = e.downcast_ref::<SpecialError>() {
                match msg {
                    SpecialError::EvmReverted(err_msg) => {
                        bail!(SpecialError::InvalidPeginData(format!(
                            "fail to get committee pubkeys: {err_msg}"
                        )))
                    }
                    _ => bail!(e),
                }
            } else {
                bail!(e)
            }
        }
    };
    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    Ok(BitvmGcInstanceParameters {
        network,
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(pegin_data.pegin_amount_sats),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}

pub async fn is_take1_timelock_expired(
    client: &BTCClient,
    kickoff_height: u32,
    timelock_config: &TimelockConfig,
) -> Result<bool> {
    let lock_blocks = take1_timelock_with_config(get_network(), timelock_config);
    let current_height = client.get_height().await?;
    Ok(current_height >= kickoff_height + lock_blocks)
}

pub async fn is_take2_timelock_expired(
    client: &BTCClient,
    operator_assert_height: u32,
    watchtower_challenge_init_height: u32,
    timelock_config: &TimelockConfig,
) -> Result<bool> {
    let network = get_network();
    let connector_d_lock_blocks = take2_timelock_with_config(network, timelock_config);
    let connector_f_lock_blocks = connector_f_timelock_blocks(network, timelock_config);
    let current_height = client.get_height().await?;
    Ok(current_height >= operator_assert_height + connector_d_lock_blocks
        && current_height >= watchtower_challenge_init_height + connector_f_lock_blocks)
}

pub async fn get_fee_rate(client: &BTCClient) -> Result<f64> {
    match client.network() {
        //TODO mempool api /fee-estimates failed, fix it latter
        Network::Testnet | Network::Testnet4 | Network::Regtest => Ok(5.0),
        _ => {
            let res = client.get_fee_estimates().await?;
            Ok(*res.get(&DEFAULT_CONFIRMATION_TARGET).ok_or(anyhow!(
                "fee for {DEFAULT_CONFIRMATION_TARGET} confirmation target not found"
            ))?)
        }
    }
}

pub async fn get_nst_fee_rate(client: &BTCClient) -> Result<f64> {
    Ok(get_fee_rate(client).await? * 3.0)
}

pub async fn broadcast_nonstandard_tx(btc_client: &BTCClient, tx: &Transaction) -> Result<()> {
    match broadcast_tx(btc_client, tx).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let network = btc_client.network();
            let base_url = get_mara_slipstream_api_base_url(network);
            let submit_url = format!("{}/transactions", base_url.trim_end_matches('/'));
            let tx_hex = hex::encode(serialize(tx));

            warn!(
                "normal broadcast failed, fallback to MARA slipstream api. network: {network:?}, url: {submit_url}, err: {e}"
            );

            let response = reqwest::Client::new()
                .post(&submit_url)
                .json(&serde_json::json!({ "tx_hex": tx_hex }))
                .send()
                .await
                .map_err(|fallback_err| {
                    anyhow!(
                        "fallback broadcast request failed. normal error: {e}; fallback error: {fallback_err}"
                    )
                })?;

            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read response body>".to_string());

            if !status.is_success() {
                bail!(
                    "fallback broadcast failed. normal error: {e}; fallback status: {status}; fallback body: {body}"
                );
            }

            let status_field = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string));
            if let Some(status_field) = status_field
                && !status_field.eq_ignore_ascii_case("success")
            {
                bail!(
                    "fallback broadcast returned non-success status. normal error: {e}; fallback body: {body}"
                );
            }

            Ok(())
        }
    }
}

/// Broadcasts a raw transaction to the Bitcoin network using the mempool API.
///
/// Requirements:
/// - The mempool API URL must be configured.
/// - The transaction should already be fully signed.
pub async fn broadcast_tx(client: &BTCClient, tx: &Transaction) -> Result<()> {
    client.broadcast(tx).await?;
    Ok(())
}

pub async fn broadcast_package(
    client: &BTCClient,
    txns: &[Transaction],
    fallback_on_failure: bool,
) -> Result<()> {
    match client.broadcast_package(txns).await {
        Ok(_) => {}
        Err(e) => {
            if fallback_on_failure {
                tracing::warn!(
                    "broadcast_package failed: {}, falling back to broadcasting one by one",
                    e
                );
                for tx in txns {
                    broadcast_tx(client, tx).await?;
                }
            } else {
                // Surface the original error when fallback is disabled
                return Err(e);
            }
        }
    }
    Ok(())
}

fn gen_watchtower_commitment(graph_id: Uuid, proof_data: ProofData) -> Result<Vec<u8>> {
    let graph_id = graph_id.as_bytes();
    let proof =
        proof_data.proof.as_slice().try_into().map_err(|_| anyhow!("invalid proof length"))?;
    let public_inputs = proof_data
        .public_inputs
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid public inputs length"))?;
    if proof_data.vk.len() != VK_HASH_SIZE {
        bail!("invalid vk_hash length");
    }
    if proof_data.zkm_version.is_empty() {
        bail!("missing zkm_version");
    }

    Ok(build_watchtower_commitment(
        graph_id,
        proof,
        &public_inputs,
        &proof_data.vk,
        &proof_data.zkm_version,
    ))
}

// proof network
/// Returns:
/// - `Ok(Some(WatchtowerCommitment), _)` if watchtower proof is available
/// - `Ok(None, wait_secs)` if watchtower proof is not yet available, with suggested wait time
pub async fn get_watchtower_commitment(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    http_client: &HttpAsyncClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<(Option<Vec<u8>>, usize)> {
    let mut storage_processor = local_db.acquire().await?;
    if let Some(graph) = storage_processor.find_graph(&graph_id).await?
        && let Some(challenge_init_txid) = graph.watchtower_challenge_init_txid
    {
        // check if challenge_txid is confirmed
        let tx_status = btc_client.get_tx_status(&challenge_init_txid.0).await?;
        if !tx_status.confirmed {
            warn!("graph {graph_id} challenge tx is not confirmed");
            return Ok((None, get_watchtower_proof_wait_secs()));
        }

        let base_url = Url::parse(
            &get_proof_build_rpc_host()
                .ok_or_else(|| anyhow::anyhow!("failed to get proof_build_rpc_host"))?,
        )?;
        let url = base_url.join(NODES_WATCHTOWER_BASE)?;

        let response = http_client
            .post_response_json::<WatchtowerProofResponse, WatchtowerProofRequest>(
                url.as_str(),
                &WatchtowerProofRequest {
                    instance_id: instance_id.to_string(),
                    graph_id: graph_id.to_string(),
                    public_key: env::get_node_pubkey()?.to_string(),
                    challenge_init_txid: challenge_init_txid.0.to_string(),
                    execution_layer_block_number: graph.proceed_withdraw_height, // NOTE: this number may be zero
                },
            )
            .await?;
        match response.proof_data {
            Some(proof_data) => {
                let watchtower_commitment = gen_watchtower_commitment(graph_id, proof_data)?;
                Ok((Some(watchtower_commitment), 0))
            }
            None => Ok((None, get_watchtower_proof_wait_secs())),
        }
    } else {
        warn!("graph:{graph_id} not found or related txn is none",);
        bail!("No graph in db");
    }
}

#[tracing::instrument(name = "get_watchtower_challenge_info", skip(btc_client))]
pub async fn get_watchtower_challenge_info(
    btc_client: &BTCClient,
    watchtower_challenge_init_txid: &SerializableTxid,
    watchtower_timeout_txids: &[Txid],
    num_watchtowers: usize,
) -> Result<(Vec<Option<String>>, Vec<bool>)> {
    let mut challenge_txids = Vec::with_capacity(num_watchtowers);
    let mut included_watchtowers = Vec::with_capacity(num_watchtowers);
    for index in 0..num_watchtowers {
        let challenge_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(index) as u64;
        let spent_txid =
            outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid.0, challenge_vout)
                .await?;
        match spent_txid {
            Some(txid) => {
                let status = btc_client.get_tx_status(&txid).await?;
                if !status.confirmed {
                    bail!("watchtower branch tx {txid} at index {index} is not confirmed yet");
                }

                let is_timeout = watchtower_timeout_txids
                    .get(index)
                    .is_some_and(|timeout_txid| txid == *timeout_txid);
                if is_timeout {
                    challenge_txids.push(None);
                    included_watchtowers.push(false);
                } else {
                    challenge_txids.push(Some(txid.to_string()));
                    included_watchtowers.push(true);
                }
            }
            None => {
                challenge_txids.push(None);
                included_watchtowers.push(false);
            }
        }
    }
    Ok((challenge_txids, included_watchtowers))
}

/// Returns `(btc_best_block_hash, included_watchtowers_bitmap)` from already-fetched
/// `get_watchtower_challenge_info` output.
pub async fn compute_operator_pubin_blockhash_and_bitmap(
    btc_client: &BTCClient,
    challenge_txids: &[Option<String>],
    included_watchtowers_bits: &[bool],
) -> Result<([u8; 32], [u8; 32])> {
    let btc_best_block_hash = {
        let mut largest: Option<(u32, BlockHash)> = None;
        for txid in challenge_txids.iter().flatten() {
            let status = btc_client.get_tx_status(&Txid::from_str(txid)?).await?;
            let (height, hash) = match (status.block_height, status.block_hash) {
                (Some(height), Some(hash)) => (height, hash),
                _ => bail!("watchtower challenge tx {txid} is not confirmed yet"),
            };
            if largest.is_none_or(|(h, _)| height > h) {
                largest = Some((height, hash));
            }
        }
        largest
            .map(|(_, hash)| hash.to_byte_array())
            .ok_or_else(|| anyhow!("no confirmed watchtower challenge tx available"))?
    };

    let mut included_watchtowers = [0u8; 32];
    for (i, &included) in included_watchtowers_bits.iter().enumerate() {
        if included && i < 256 {
            included_watchtowers[i / 8] |= 1 << (i % 8);
        }
    }

    Ok((btc_best_block_hash, included_watchtowers))
}

async fn get_operator_committed_blockhash(
    btc_client: &BTCClient,
    challenge_txids: &[Option<String>],
    included_watchtowers_bits: &[bool],
    graph_id: Uuid,
) -> Result<Option<String>> {
    match compute_operator_pubin_blockhash_and_bitmap(
        btc_client,
        challenge_txids,
        included_watchtowers_bits,
    )
    .await
    {
        Ok((btc_best_block_hash, _)) => {
            Ok(Some(BlockHash::from_byte_array(btc_best_block_hash).to_string()))
        }
        Err(e) => {
            warn!("operator proof inputs are not ready for graph {graph_id}: {e}");
            Ok(None)
        }
    }
}

/// Assembles the 96-byte guest pubin:
pub fn build_operator_guest_pubin(
    btc_best_block_hash: &[u8; 32],
    pubin_disprove_constant: &[u8; 32],
    included_watchtowers: &[u8; 32],
) -> [u8; 96] {
    let mut pubin = [0u8; 96];
    pubin[0..32].copy_from_slice(btc_best_block_hash);
    pubin[32..64].copy_from_slice(pubin_disprove_constant);
    pubin[64..96].copy_from_slice(included_watchtowers);
    pubin
}

fn load_part_stark_vk_for_zkm_version(zkm_version: &str) -> Result<Vec<u8>> {
    catch_unwind(AssertUnwindSafe(|| Groth16Verifier::get_part_stark_vk(zkm_version).to_vec()))
        .map_err(|_| anyhow!("failed to load part_stark_vk for zkm_version {zkm_version}"))
}

fn combined_operator_vk_hash(operator_vk_hash: &str, zkm_version: &str) -> Result<[u8; 32]> {
    if !operator_vk_hash.starts_with("0x") {
        bail!("configured operator vk hash must use 0x-prefixed Ziren encoding");
    }
    let raw_vk_hash = decode_zkm_vkey_hash(operator_vk_hash)
        .map_err(|e| anyhow!("invalid configured operator vk hash: {e:?}"))?;
    let part_vk: PartStarkVerifyingKey<KoalaBearPoseidon2Outer> =
        bincode::deserialize(&load_part_stark_vk_for_zkm_version(zkm_version)?)
            .context("deserialize operator partial STARK verifying key")?;
    let base = Bn254Fr::from_canonical_u32(256);
    let mut field_hash = Bn254Fr::ZERO;
    for byte in raw_vk_hash {
        field_hash = field_hash * base + Bn254Fr::from_canonical_u32(byte as u32);
    }
    let combined = zkm_recursion_core::hash_vkey_with_part_vk(&part_vk, field_hash);
    let bytes = combined.as_canonical_biguint().to_bytes_be();
    if bytes.len() > 32 {
        bail!("combined operator verifying key hash exceeds BN254 field encoding");
    }
    let mut encoded = [0u8; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(encoded)
}

fn operator_identity() -> Result<([u8; 32], String, ark_bn254::Fr)> {
    let vk_hash = get_operator_vk_hash()?;
    let zkm_version = get_operator_zkm_version()?;
    let combined_hash =
        combined_operator_vk_hash(&format!("0x{}", hex::encode(vk_hash)), &zkm_version)?;
    let static_input = load_ark_public_inputs_from_bytes(&combined_hash, &[0u8; 32])[0];
    Ok((vk_hash, zkm_version, static_input))
}

pub fn derive_operator_static_input() -> Result<ark_bn254::Fr> {
    Ok(operator_identity()?.2)
}

pub fn derive_operator_statement(
    graph_id: Uuid,
    watchtower_pubkeys: &[XOnlyPublicKey],
) -> Result<OperatorStatement> {
    let (vk_hash, zkm_version, static_input) = operator_identity()?;
    let key_bytes = watchtower_pubkeys.iter().map(XOnlyPublicKey::serialize).collect::<Vec<_>>();
    let constant =
        hash_operator_constant(*graph_id.as_bytes(), get_genesis_sequencer_commit_id(), &key_bytes);
    Ok(OperatorStatement { static_input, vk_hash, zkm_version, constant })
}

/// Returns:
/// - `Ok(Some(OperatorProof), _)` if operator proof is available and valid
/// - `Ok(None, wait_secs)` if operator proof is not yet available
pub async fn get_operator_proof(
    local_db: &LocalDB,
    http_client: &HttpAsyncClient,
    bitvm_graph: &BitvmGcGraph,
    btc_client: &BTCClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<(Option<ValidatedOperatorProof>, usize)> {
    let mut storage_processor = local_db.acquire().await?;
    let Some(graph) = storage_processor.find_graph(&graph_id).await? else {
        warn!("graph:{graph_id} not found");
        bail!("No graph in db");
    };
    drop(storage_processor);

    if graph.proceed_withdraw_height <= 0 {
        warn!("graph {graph_id} proceed_withdraw_height <= 0, waiting to been updated");
        return Ok((None, get_operator_proof_wait_secs()));
    }

    let watchtower_challenge_init_txid = graph
        .watchtower_challenge_init_txid
        .ok_or_else(|| anyhow::anyhow!("watchtower_challenge_init_txid is none"))?;
    let num_challenger = bitvm_graph.parameters.watchtower_pubkeys.len();
    let watchtower_timeout_txids: Vec<Txid> =
        bitvm_graph.watchtower_challenge_timeouts.iter().map(|tx| tx.tx().compute_txid()).collect();
    let (watchtower_challenge_txids, included_watchtowers) = match get_watchtower_challenge_info(
        btc_client,
        &watchtower_challenge_init_txid,
        &watchtower_timeout_txids,
        num_challenger,
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            warn!("Failed to get watchtower challenge info: {e}");
            return Ok((None, get_operator_proof_wait_secs()));
        }
    };
    let Some(operator_committed_blockhash) = get_operator_committed_blockhash(
        btc_client,
        &watchtower_challenge_txids,
        &included_watchtowers,
        graph_id,
    )
    .await?
    else {
        return Ok((None, get_operator_proof_wait_secs()));
    };

    let base_url = Url::parse(
        &get_proof_build_rpc_host()
            .ok_or_else(|| anyhow::anyhow!("failed to get proof_build_rpc_host"))?,
    )?;
    let operator_url = base_url.join(NODES_OPERATOR_BASE)?;
    let operator_response = http_client
        .post_response_json::<OperatorProofResponse, OperatorProofRequest>(
            operator_url.as_str(),
            &OperatorProofRequest {
                instance_id: instance_id.to_string(),
                graph_id: graph_id.to_string(),
                operator_committed_blockhash,
                execution_layer_block_number: graph.proceed_withdraw_height,
                watchtower_challenge_txids,
                included_watchtowers,
                watchtower_challenge_init_txid: watchtower_challenge_init_txid.0.to_string(),
                watchtower_challenge_pubkeys: bitvm_graph
                    .parameters
                    .watchtower_pubkeys
                    .iter()
                    .map(|pk| pk.public_key(secp256k1::Parity::Even).to_string())
                    .collect(),
            },
        )
        .await?;

    let Some(proof_data) = operator_response.proof_data else {
        if let Some(error) = operator_response.error {
            info!("operator proof is not ready for graph_id:{graph_id}: {error}");
        }
        return Ok((None, get_operator_proof_wait_secs()));
    };

    let statement =
        derive_operator_statement(graph_id, &bitvm_graph.parameters.watchtower_pubkeys)?;
    if statement.constant != bitvm_graph.parameters.pubin_disprove_constant {
        bail!("graph operator constant does not match its watchtower list");
    }

    let proof: ZKMProofWithPublicValues = bincode::deserialize(proof_data.proof.as_slice())
        .map_err(|err| anyhow!("failed to deserialize operator proof: {err}"))?;

    let operator_vk_hash_raw = decode_zkm_vkey_hash(&proof_data.vk)
        .map_err(|e| anyhow!("invalid operator proof vk hash: {e:?}"))?;
    if operator_vk_hash_raw != statement.vk_hash {
        bail!("operator proof vk hash does not match configured operator identity");
    }
    if proof.zkm_version != statement.zkm_version || proof_data.zkm_version != statement.zkm_version
    {
        bail!("operator proof Ziren version does not match configured operator identity");
    }

    let outputs = decode_operator_public_outputs(&proof.public_values.to_vec())
        .map_err(|e| anyhow!("invalid operator public outputs: {e}"))?;
    if outputs.constant != statement.constant {
        bail!("operator proof constant does not match graph setup");
    }

    let part_stark_vk = load_part_stark_vk_for_zkm_version(&proof.zkm_version)?;
    let ark_proof =
        convert_ark_imm_wrap_vk(&proof, &proof_data.vk, &IMM_GROTH16_VK_BYTES, &part_stark_vk)
            .map_err(|e| anyhow!("failed to convert operator proof to ark format: {e}"))?;
    let Some(static_input) = ark_proof.public_inputs.first() else {
        bail!("operator proof has no public inputs");
    };
    if *static_input != statement.static_input {
        bail!("operator proof static public input does not match graph setup statement");
    }

    Ok((
        Some(ValidatedOperatorProof {
            proof: ark_proof.proof,
            public_inputs: ark_proof.public_inputs.into(),
            verifying_key: ark_proof.groth16_vk.into(),
            public_values: proof.public_values.to_vec(),
            vk_hash: proof_data.vk,
            zkm_version: proof.zkm_version,
        }),
        0,
    ))
}

pub async fn verifier_force_skip_kickoff(client: &BTCClient, graph: &BitvmGcGraph) -> Result<Txid> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_master_keypair = verifier_master_key.master_keypair();
    let verifier_receive_address =
        node_p2wsh_address(get_network(), &verifier_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (force_skip_kickoff_tx, anchor_added) =
        build_force_skip_kickoff_tx(graph, verifier_receive_address, fee_rate)?;
    if anchor_added {
        let anchor_vout = force_skip_kickoff_tx.output.len() as u64 - 1;
        let force_skip_kickoff_tx_total_input_amount =
            graph.force_skip_kickoff.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        let child_tx = build_cpfp_txns(
            client,
            &force_skip_kickoff_tx,
            anchor_vout,
            force_skip_kickoff_tx_total_input_amount,
        )
        .await?;
        match child_tx {
            Some(tx) => {
                broadcast_package(client, &[force_skip_kickoff_tx.clone(), tx], true).await?
            }
            None => broadcast_tx(client, &force_skip_kickoff_tx).await?,
        }
    } else {
        broadcast_tx(client, &force_skip_kickoff_tx).await?;
    }
    Ok(force_skip_kickoff_tx.compute_txid())
}

pub async fn verifier_quick_challenge(client: &BTCClient, graph: &BitvmGcGraph) -> Result<Txid> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_master_keypair = verifier_master_key.master_keypair();
    let verifier_receive_address =
        node_p2wsh_address(get_network(), &verifier_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (quick_challenge_tx, anchor_added) =
        build_quick_challenge_tx(graph, verifier_receive_address, fee_rate)?;
    if anchor_added {
        let anchor_vout = quick_challenge_tx.output.len() as u64 - 1;
        let quick_challenge_tx_total_input_amount =
            graph.quick_challenge.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        let child_tx = build_cpfp_txns(
            client,
            &quick_challenge_tx,
            anchor_vout,
            quick_challenge_tx_total_input_amount,
        )
        .await?;
        match child_tx {
            Some(tx) => broadcast_package(client, &[quick_challenge_tx.clone(), tx], true).await?,
            None => broadcast_tx(client, &quick_challenge_tx).await?,
        }
    } else {
        broadcast_tx(client, &quick_challenge_tx).await?;
    }
    Ok(quick_challenge_tx.compute_txid())
}

pub async fn fund_address(
    client: &BTCClient,
    node_keypair: Keypair,
    address: Address,
    amount: Amount,
) -> Result<OutPoint> {
    let txins = Vec::new();
    let txouts = vec![TxOut { script_pubkey: address.script_pubkey(), value: amount }];
    let txid =
        build_sign_and_broadcast_tx(client, node_keypair, txins, Amount::ZERO, txouts).await?;
    Ok(OutPoint { txid, vout: 0 })
}

pub async fn build_sign_and_broadcast_tx(
    client: &BTCClient,
    node_keypair: Keypair,
    txins: Vec<TxIn>,
    total_input_amount: Amount,
    txouts: Vec<TxOut>,
) -> Result<Txid> {
    let txouts = if txouts.is_empty() {
        // bitcoin network does not allow a transaction without outputs
        vec![TxOut { value: Amount::ZERO, script_pubkey: generate_opreturn_script(vec![]) }]
    } else {
        txouts
    };
    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: txins,
        output: txouts,
    };
    let fixed_inputs_num = tx.input.len();
    let total_output_amount: Amount = tx.output.iter().map(|o| o.value).sum();
    let fee_rate = get_fee_rate(client).await?;
    let node_address = node_p2wsh_address(get_network(), &node_keypair.public_key().into());
    let shortfall =
        Amount::from_sat(total_output_amount.to_sat().saturating_sub(total_input_amount.to_sat()));
    match get_proper_utxo_set(
        client,
        tx.weight().to_vbytes_ceil(),
        node_address.clone(),
        shortfall,
        fee_rate,
    )
    .await?
    {
        Some((inputs, _, change_amount)) => {
            for input in &inputs {
                tx.input.push(TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                });
            }
            if change_amount > Amount::from_sat(DUST_AMOUNT) {
                tx.output.push(TxOut {
                    script_pubkey: node_address.script_pubkey(),
                    value: change_amount,
                });
            }
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut tx,
                    i + fixed_inputs_num,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_keypair,
                )?;
            }
            broadcast_tx(client, &tx).await?;
            Ok(tx.compute_txid())
        }
        None => {
            let current_balance = client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance} < shortfall: {shortfall}"
            )));
        }
    }
}

pub async fn build_sign_and_broadcast_non_standard_tx(
    client: &BTCClient,
    node_keypair: Keypair,
    mut tx: Transaction,
    total_input_amount: Amount,
) -> Result<Txid> {
    let fixed_inputs_num = tx.input.len();
    let total_output_amount: Amount = tx.output.iter().map(|o| o.value).sum();
    let fee_rate = get_nst_fee_rate(client).await?;
    let node_address = node_p2wsh_address(get_network(), &node_keypair.public_key().into());
    let shortfall =
        Amount::from_sat(total_output_amount.to_sat().saturating_sub(total_input_amount.to_sat()));
    match get_proper_utxo_set(
        client,
        tx.weight().to_vbytes_ceil(),
        node_address.clone(),
        shortfall,
        fee_rate,
    )
    .await?
    {
        Some((inputs, _, change_amount)) => {
            for input in &inputs {
                tx.input.push(TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                });
            }
            if change_amount > Amount::from_sat(DUST_AMOUNT) {
                tx.output.push(TxOut {
                    script_pubkey: node_address.script_pubkey(),
                    value: change_amount,
                });
            }
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut tx,
                    i + fixed_inputs_num,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_keypair,
                )?;
            }
            broadcast_nonstandard_tx(client, &tx).await?;
            Ok(tx.compute_txid())
        }
        None => {
            let current_balance = client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance} < shortfall: {shortfall}"
            )));
        }
    }
}

pub async fn build_cpfp_txns(
    btc_client: &BTCClient,
    parent_tx: &Transaction,
    anchor_vout: u64,
    parent_tx_total_input_amount: Amount,
) -> Result<Option<Transaction>> {
    let network = get_network();
    if network == Network::Regtest || network == Network::Testnet || network == Network::Testnet4 {
        // skip cpfp in test network for testing convenience
        return Ok(None);
    }
    let node_master_keypair = get_bitvm_key()?;
    let node_address = node_p2wsh_address(network, &node_master_keypair.public_key().into());
    let total_output_amount: Amount = parent_tx.output.iter().map(|o| o.value).sum();
    let fee_rate = get_fee_rate(btc_client).await?;
    let fee_amount =
        Amount::from_sat((parent_tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if total_output_amount + fee_amount <= parent_tx_total_input_amount {
        return Ok(None);
    };
    let shortfall = total_output_amount + fee_amount - parent_tx_total_input_amount;
    match get_proper_utxo_set(
        btc_client,
        ANCHOR_CHILD_BASE_VBYTES,
        node_address.clone(),
        shortfall,
        fee_rate,
    )
    .await?
    {
        Some((inputs, _, change_amount)) => {
            let mut child_tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            };
            if change_amount > Amount::from_sat(DUST_AMOUNT) {
                child_tx.output.push(TxOut {
                    script_pubkey: node_address.script_pubkey(),
                    value: change_amount,
                });
            } else {
                // add an op_return output to avoid no-output transaction
                child_tx.output.push(TxOut {
                    script_pubkey: generate_opreturn_script(vec![]),
                    value: Amount::ZERO,
                });
            }
            for input in &inputs {
                child_tx.input.push(TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                });
            }
            child_tx.input.push(TxIn {
                previous_output: OutPoint {
                    txid: parent_tx.compute_txid(),
                    vout: anchor_vout as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            });
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut child_tx,
                    i,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_master_keypair,
                )?;
            }
            Ok(Some(child_tx))
        }
        None => {
            let current_balance = btc_client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance}"
            )))
        }
    }
}

pub async fn broadcast_tx_with_cpfp(
    btc_client: &BTCClient,
    parent_tx: Transaction,
    parent_tx_total_input_amount: Amount,
) -> Result<()> {
    let anchor_output = p2a_output();
    let anchor_vout = parent_tx
        .output
        .iter()
        .position(|output| output == &anchor_output)
        .ok_or_else(|| anyhow!("cannot CPFP transaction without a P2A anchor output"))?;
    if let Some(duplicate_vout) = parent_tx
        .output
        .iter()
        .enumerate()
        .skip(anchor_vout + 1)
        .find_map(|(vout, output)| if output == &anchor_output { Some(vout) } else { None })
    {
        bail!("transaction has multiple P2A anchor outputs at {anchor_vout} and {duplicate_vout}");
    };
    let child_tx =
        build_cpfp_txns(btc_client, &parent_tx, anchor_vout as u64, parent_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(btc_client, &[parent_tx, tx], true).await?,
        None => broadcast_tx(btc_client, &parent_tx).await?,
    };
    Ok(())
}

/// Returns:
/// - `Ok(None)` if given address does not have enough btc,
/// - `Ok(Some((utxos, fee_amount, change_amount)))`
pub async fn get_proper_utxo_set(
    client: &BTCClient,
    base_vbytes: u64,
    address: Address,
    target_amount: Amount,
    fee_rate: f64,
) -> Result<Option<(Vec<Input>, Amount, Amount)>> {
    fn estimate_tx_vbytes(base_vbytes: u64, extra_inputs: usize, extra_outputs: usize) -> u64 {
        // p2wsh inputs/outputs
        base_vbytes
            + (extra_inputs as u64 * CHEKSIG_P2WSH_INPUT_VBYTES)
            + (extra_outputs as u64 * P2WSH_OUTPUT_VBYTES)
    }
    fn to_input(utxos: Vec<Utxo>) -> Vec<Input> {
        utxos
            .into_iter()
            .map(|utxo| Input {
                outpoint: OutPoint { txid: utxo.txid, vout: utxo.vout },
                amount: utxo.value,
            })
            .collect()
    }
    tracing::debug!("get utxos from: {address}");

    let utxos = client.get_address_utxo(address).await?;
    let mut sorted_utxos = utxos;
    sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total_value = Amount::ZERO;

    for utxo in sorted_utxos.into_iter().take(MAX_CUSTOM_INPUTS) {
        selected.push(utxo.clone());
        total_value += utxo.value;

        let num_inputs = selected.len();
        let num_outputs = 1; // change
        let tx_vbytes = estimate_tx_vbytes(base_vbytes, num_inputs, num_outputs);
        let fee = Amount::from_sat((tx_vbytes as f64 * fee_rate).ceil() as u64);

        if total_value >= target_amount + fee {
            let change = total_value - target_amount - fee;
            return Ok(Some((to_input(selected), fee, change)));
        }
    }

    Ok(None)
}

/// Returns:
/// - `Ok((Empty, None))` if given address does not have enough btc,
/// - `Ok((Empty, Some((SplitTx, Vec<TxinAmount>))))` if UTXO cannot be properly grouped, and a split transaction is needed, needing user to sign and broadcast
/// - `Ok(Vec<Vec<Inputs>>, None))`
pub async fn get_proper_utxo_sets(
    client: &BTCClient,
    address: Address,
    target_amounts: Vec<Amount>,
    fee_rate: f64,
) -> Result<(Vec<Vec<Input>>, Option<(Transaction, Vec<Amount>)>)> {
    let mut utxos = client.get_address_utxo(address.clone()).await?;

    let total_available_sat: u64 = utxos.iter().map(|u| u.value.to_sat()).sum();

    let total_target_sat: u64 = target_amounts.iter().map(|a| a.to_sat()).sum();

    if total_available_sat <= total_target_sat {
        return Ok((Vec::new(), None));
    }

    let mut targets_with_idx: Vec<(usize, Amount)> =
        target_amounts.clone().into_iter().enumerate().collect();
    targets_with_idx.sort_by(|a, b| b.1.to_sat().cmp(&a.1.to_sat()));

    utxos.sort_by(|a, b| b.value.to_sat().cmp(&a.value.to_sat()));

    let mut available_indices: Vec<usize> = (0..utxos.len()).collect();

    use std::collections::HashMap;
    let mut temp_groups: HashMap<usize, Vec<Input>> = HashMap::new();

    for (original_idx, target) in targets_with_idx {
        let mut group: Vec<Input> = Vec::new();
        let mut sum_sat: u64 = 0;

        let i = 0;
        while i < available_indices.len() && sum_sat < target.to_sat() {
            let utxo_idx = available_indices[i];
            let utxo = utxos[utxo_idx].clone();
            sum_sat += utxo.value.to_sat();
            group.push(Input {
                outpoint: OutPoint { txid: utxo.txid, vout: utxo.vout },
                amount: utxo.value,
            });
            available_indices.remove(i);
        }

        if sum_sat < target.to_sat() {
            // if all UTXOs are used but target not met, need to build a split transaction (already checked that total_available > total_target)
            let script_pubkey = address.script_pubkey();
            let base_outputs: Vec<TxOut> = target_amounts
                .iter()
                .map(|amt| TxOut { value: *amt, script_pubkey: script_pubkey.clone() })
                .collect();
            let tx_ins: Vec<TxIn> = utxos
                .iter()
                .map(|u| TxIn {
                    previous_output: OutPoint { txid: u.txid, vout: u.vout },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                })
                .collect();
            let txin_amounts: Vec<Amount> = utxos.iter().map(|u| u.value).collect();

            let n_inputs = tx_ins.len() as u64;
            let n_outputs = base_outputs.len() as u64 + 1;
            let est_vbytes =
                100u64 + n_inputs * CHEKSIG_P2WSH_INPUT_VBYTES + n_outputs * P2WSH_OUTPUT_VBYTES;
            let est_fee_sat = (est_vbytes as f64 * fee_rate).ceil() as u64;

            if total_available_sat < total_target_sat + est_fee_sat {
                return Ok((Vec::new(), None));
            }

            let change_sat = total_available_sat
                .checked_sub(total_target_sat + est_fee_sat)
                .ok_or_else(|| anyhow!("overflow when calculating change"))?;

            let mut tx_outs = base_outputs;

            if change_sat >= DUST_AMOUNT {
                tx_outs.push(TxOut {
                    value: Amount::from_sat(change_sat),
                    script_pubkey: script_pubkey.clone(),
                });
            }

            let split_tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: tx_ins,
                output: tx_outs,
            };
            return Ok((Vec::new(), Some((split_tx, txin_amounts))));
        }

        temp_groups.insert(original_idx, group);
    }

    let mut ordered: Vec<(usize, Vec<Input>)> = temp_groups.into_iter().collect();
    ordered.sort_by_key(|(idx, _)| *idx);
    let grouped: Vec<Vec<Input>> = ordered.into_iter().map(|(_, g)| g).collect();

    Ok((grouped, None))
}

pub fn node_p2wsh_script(pubkey: &PublicKey) -> ScriptBuf {
    script! {
        { *pubkey }
        OP_CHECKSIG
    }
    .compile()
}
pub fn node_p2wsh_address(network: Network, pubkey: &PublicKey) -> Address {
    Address::p2wsh(&node_p2wsh_script(pubkey), network)
}

pub fn node_sign(
    tx: &mut Transaction,
    input_index: usize,
    input_value: Amount,
    sighash_type: EcdsaSighashType,
    node_keypair: &Keypair,
) -> Result<()> {
    let node_pubkey = node_keypair.public_key();
    populate_p2wsh_witness(
        tx,
        input_index,
        sighash_type,
        &node_p2wsh_script(&node_pubkey.into()),
        input_value,
        &vec![node_keypair],
    );
    Ok(())
}

pub async fn build_genesis_prekickoff_tx(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<PrekickoffTransaction> {
    let watchtower_num = goat_client.committee_mana_get_watchtowers().await?.len();
    let verifier_num = todo_funcs::min_required_verifier();
    let network = get_network();
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let node_keypair = operator_master_key.master_keypair();
    let operator_taproot_public_key = node_keypair.x_only_public_key().0;
    let cur_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    let next_kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let init_amount = todo_funcs::prekickoff_replenishment_amount();
    let cur_prekickoff_connector_input = Input {
        outpoint: fund_address(
            btc_client,
            node_keypair,
            cur_prekickoff_connector.generate_taproot_address(),
            init_amount,
        )
        .await?,
        amount: init_amount,
    };
    let fee_amount = todo_funcs::prekickoff_fee_amount(0);
    PrekickoffTransaction::new_for_validation(
        &cur_prekickoff_connector,
        &next_force_skip_connector,
        &next_kickoff_connector,
        &next_prekickoff_connector,
        cur_prekickoff_connector_input,
        vec![],
        vec![],
        fee_amount.to_sat(),
        watchtower_num,
        verifier_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {e}"))
}

pub async fn build_prekickoff_params(
    btc_client: &BTCClient,
    graph_nonce: u64,
    cur_prekickoff_txn: PrekickoffTransaction,
) -> Result<PrekickoffParameters> {
    let prekickoff_remaining_amount = cur_prekickoff_txn
        .prekickoff_connector_input()
        .map_err(|e| anyhow!("failed to get pre-kickoff connector input: {e}"))?
        .amount;
    let (replenish_fee_inputs, replenish_fee_prev_outs, fee_amount) = if prekickoff_remaining_amount
        >= todo_funcs::min_prekickoff_input_amount()
    {
        // no need to replenish funds
        (vec![], vec![], todo_funcs::prekickoff_fee_amount(0))
    } else {
        let network = get_network();
        let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
        let master_keypair = operator_master_key.master_keypair();
        let nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce);
        let nonce_address = node_p2wsh_address(network, &nonce_keypair.public_key().into());
        let replenishment_amount = todo_funcs::prekickoff_replenishment_amount();
        let mut replenish_fee_inputs: Vec<Input> = btc_client
            .get_address_utxo(nonce_address.clone())
            .await?
            .into_iter()
            .map(|u| Input { outpoint: OutPoint { txid: u.txid, vout: u.vout }, amount: u.value })
            .collect();
        let current_balance: Amount = replenish_fee_inputs.iter().map(|i| i.amount).sum();
        if current_balance < replenishment_amount {
            let shortfall = replenishment_amount - current_balance;
            let extra_input = Input {
                outpoint: fund_address(
                    btc_client,
                    master_keypair,
                    nonce_address.clone(),
                    shortfall,
                )
                .await?,
                amount: shortfall,
            };
            replenish_fee_inputs.push(extra_input);
        };
        let replenish_fee_prev_outs: Vec<TxOut> = replenish_fee_inputs
            .iter()
            .map(|i| TxOut { value: i.amount, script_pubkey: nonce_address.script_pubkey() })
            .collect();
        let fee_amount = todo_funcs::prekickoff_fee_amount(replenish_fee_inputs.len());
        (replenish_fee_inputs, replenish_fee_prev_outs, fee_amount)
    };
    Ok(PrekickoffParameters {
        cur_prekickoff_txn,
        replenish_fee_inputs,
        replenish_fee_prev_outs,
        fee_amount: fee_amount.to_sat(),
    })
}

pub async fn build_graph_params(
    _local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_parameters: BitvmGcInstanceParameters,
    prekickoff_parameters: PrekickoffParameters,
    bitvm_gc_circuit_datas: Vec<BitvmGcCircuitData>,
    graph_nonce: u64,
    graph_id: Uuid,
) -> Result<BitvmGcGraphParameters> {
    let instance_id = instance_parameters.instance_id;
    let network = instance_parameters.network;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_pubkey = operator_master_keypair.public_key().into();
    let operator_receive_address =
        node_p2wsh_address(instance_parameters.network, &operator_pubkey);
    let (_, operator_assert_wots_pubkey) =
        operator_master_key.assert_wots_keypair_for_graph(graph_id);
    let (_, operator_commit_pubin_wots_pubkey) =
        operator_master_key.commit_pubin_wots_keypair_for_graph(graph_id);
    let watchtower_pubkeys = goat_client.committee_mana_get_watchtowers().await?;
    let watchtower_ack_hashlocks = (0..watchtower_pubkeys.len())
        .map(|index| {
            bitcoin::hashes::hash160::Hash::hash(
                &operator_master_key.preimage_for_graph(graph_id, index),
            )
            .to_byte_array()
        })
        .collect();
    let pubin_disprove_constant =
        get_guest_constant_value(instance_id, graph_id, &watchtower_pubkeys)?;
    // Local graph construction selects the full on-chain registry; passing the same list twice
    // intentionally reuses the helper's size and uniqueness checks.
    todo_funcs::validate_watchtower_selection(
        &watchtower_pubkeys,
        &watchtower_pubkeys,
        *graph_id.as_bytes(),
        get_genesis_sequencer_commit_id(),
        pubin_disprove_constant,
    )?;
    Ok(BitvmGcGraphParameters {
        instance_parameters,
        prekickoff_parameters,
        timelock_config: default_timelock_config(network),
        graph_id,
        graph_nonce,
        challenge_amount: todo_funcs::challenge_amount(),
        operator_pubkey,
        operator_assert_wots_pubkey,
        operator_commit_pubin_wots_pubkey,
        operator_receive_address,
        watchtower_pubkeys,
        watchtower_ack_hashlocks,
        pubin_disprove_constant,
        gc_data: bitvm_gc_circuit_datas,
    })
}

pub async fn operator_skip_graph(btc_client: &BTCClient, graph: &mut BitvmGcGraph) -> Result<()> {
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_receive_address =
        node_p2wsh_address(get_network(), &operator_master_keypair.public_key().into());
    let operator_graph_keypair = operator_master_key.master_keypair();
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce - 1);
        for i in 1..prekickoff_tx.input.len() {
            let input_value = graph.cur_prekickoff.input_amounts[i];
            node_sign(
                &mut prekickoff_tx,
                i,
                input_value,
                bitcoin::EcdsaSighashType::All,
                &operator_nonce_keypair,
            )?;
        }
    }
    let anchor_vout = prekickoff_tx.output.len() as u64 - 1;
    let prekickoff_tx_total_input_amount =
        graph.cur_prekickoff.input_amounts.clone().into_iter().sum();
    let child_tx =
        build_cpfp_txns(btc_client, &prekickoff_tx, anchor_vout, prekickoff_tx_total_input_amount)
            .await?;
    let prekickoff_txid = prekickoff_tx.compute_txid();
    match operator_sign_skip_kickoff(
        operator_graph_keypair,
        graph,
        operator_receive_address,
        get_fee_rate(btc_client).await?,
    )? {
        Some(skip_kickoff_tx) => {
            let skip_kickoff_txid = skip_kickoff_tx.compute_txid();
            if !tx_on_chain(btc_client, &prekickoff_txid).await? {
                broadcast_package(btc_client, &[prekickoff_tx, skip_kickoff_tx], true).await?;
                if let Some(child_tx) = child_tx {
                    broadcast_tx(btc_client, &child_tx).await?;
                }
            } else if !tx_on_chain(btc_client, &skip_kickoff_txid).await? {
                if let Some(child_tx) = child_tx {
                    broadcast_package(btc_client, &[skip_kickoff_tx, child_tx], true).await?;
                } else {
                    broadcast_tx(btc_client, &skip_kickoff_tx).await?;
                }
            }
        }
        None => match child_tx {
            Some(tx) => {
                if !tx_on_chain(btc_client, &prekickoff_txid).await? {
                    broadcast_package(btc_client, &[prekickoff_tx, tx], true).await?;
                }
            }
            None => {
                if !tx_on_chain(btc_client, &prekickoff_txid).await? {
                    broadcast_tx(btc_client, &prekickoff_tx).await?;
                }
            }
        },
    };
    Ok(())
}

pub async fn operator_kickoff(btc_client: &BTCClient, graph: &mut BitvmGcGraph) -> Result<()> {
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce - 1);
        for i in 1..prekickoff_tx.input.len() {
            let input_value = graph.cur_prekickoff.input_amounts[i];
            node_sign(
                &mut prekickoff_tx,
                i,
                input_value,
                bitcoin::EcdsaSighashType::All,
                &operator_nonce_keypair,
            )?;
        }
    }
    let prekickoff_txid = prekickoff_tx.compute_txid();
    let anchor_vout = prekickoff_tx.output.len() as u64 - 1;
    let prekickoff_tx_total_input_amount =
        graph.cur_prekickoff.input_amounts.clone().into_iter().sum();
    let prekickoff_child_tx =
        build_cpfp_txns(btc_client, &prekickoff_tx, anchor_vout, prekickoff_tx_total_input_amount)
            .await?;

    let kickoff_tx = operator_sign_kickoff(operator_graph_keypair, graph)?;
    let kickoff_txid = kickoff_tx.compute_txid();
    let anchor_vout = kickoff_tx.output.len() as u64 - 1;
    let kickoff_tx_total_input_amount = graph.kickoff.prev_outs().iter().map(|o| o.value).sum();
    let kickoff_child_tx =
        build_cpfp_txns(btc_client, &kickoff_tx, anchor_vout, kickoff_tx_total_input_amount)
            .await?;

    // If a tx is already on-chain, skip rebroadcasting and move to the next one.
    let mut kickoff_child_broadcasted = false;
    if !tx_on_chain(btc_client, &prekickoff_txid).await? {
        // Parent not on-chain yet: broadcast parent and kickoff together as a package.
        broadcast_package(btc_client, &[prekickoff_tx, kickoff_tx], true).await?;
    } else if !tx_on_chain(btc_client, &kickoff_txid).await? {
        // Parent is on-chain, but kickoff isn't: try kickoff (and its CPFP child if present).
        if let Some(child) = kickoff_child_tx.as_ref() {
            broadcast_package(btc_client, &[kickoff_tx, child.clone()], true).await?;
            kickoff_child_broadcasted = true;
        } else {
            broadcast_tx(btc_client, &kickoff_tx).await?;
        }
    }

    // Ensure both transactions are seen on-chain and then handle CPFP children.
    if !tx_on_chain(btc_client, &prekickoff_txid).await? {
        bail!("prekickoff tx not on chain after broadcasting");
    }
    if let Some(prekickoff_child_tx) = prekickoff_child_tx
        && let Err(e) = broadcast_tx(btc_client, &prekickoff_child_tx).await
    {
        tracing::warn!("failed to broadcast prekickoff child tx: {e}");
    }
    if !tx_on_chain(btc_client, &kickoff_txid).await? {
        bail!("kickoff tx not on chain after broadcasting");
    }
    if !kickoff_child_broadcasted
        && let Some(kickoff_child_tx) = kickoff_child_tx
        && let Err(e) = broadcast_tx(btc_client, &kickoff_child_tx).await
    {
        tracing::warn!("failed to broadcast kickoff child tx: {e}");
    }
    Ok(())
}

pub async fn send_challenge_tx(btc_client: &BTCClient, graph: &BitvmGcGraph) -> Result<Txid> {
    let (mut challenge_tx, _) = export_challenge_tx(graph)?;
    let challenge_keypair = VerifierMasterKey::new(get_bitvm_key()?).master_keypair();
    let verifier_evm_address = get_node_goat_address()
        .ok_or_else(|| anyhow::anyhow!("failed to get node goat address".to_string()))?;
    challenge_tx.output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: generate_opreturn_script(verifier_evm_address.to_vec()),
    });
    let connector_a_input = graph
        .kickoff
        .connector_a_input()
        .map_err(|e| anyhow!("failed to get connector-a input: {e}"))?;
    build_sign_and_broadcast_tx(
        btc_client,
        challenge_keypair,
        challenge_tx.input,
        connector_a_input.amount,
        challenge_tx.output,
    )
    .await
}

pub async fn send_watchtower_challenge_tx(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    watchtower_index: usize,
    commitment_data: Vec<u8>,
) -> Result<Txid> {
    let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
    let fee_rate = get_fee_rate(btc_client).await?;
    let watchtower_challenge_tx_base_vbytes =
        estimate_watchtower_challenge_vbytes(commitment_data.len());
    let node_address = node_p2wsh_address(get_network(), &watchtower_keypair.public_key().into());
    match get_proper_utxo_set(
        btc_client,
        watchtower_challenge_tx_base_vbytes as u64,
        node_address.clone(),
        Amount::ZERO,
        fee_rate,
    )
    .await?
    {
        Some((inputs, fee_amount, _)) => {
            let mut watchtower_challenge_tx = build_watchtower_challenge_tx(
                graph,
                &watchtower_keypair,
                watchtower_index,
                &commitment_data,
                inputs.clone(),
                &node_address,
                fee_amount,
            )
            .unwrap();
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut watchtower_challenge_tx,
                    i + 1,
                    input.amount,
                    EcdsaSighashType::All,
                    &watchtower_keypair,
                )?;
            }
            broadcast_tx(btc_client, &watchtower_challenge_tx).await?;
            Ok(watchtower_challenge_tx.compute_txid())
        }
        None => {
            let current_balance = btc_client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance}"
            )));
        }
    }
}

pub async fn endorse_graph(goat_client: &GOATClient, graph: &BitvmGcGraph) -> Result<EvmSignature> {
    let signer = PrivateKeySigner::from_str(&get_node_goat_private_key()?)?;
    let graph_digest = get_graph_digest(goat_client, graph).await?;
    let sig = signer.sign_hash(&graph_digest.into()).await?;
    Ok(sig)
}

pub async fn endorse_pegin(
    goat_client: &GOATClient,
    instance_id: Uuid,
    pegin_txid: &Txid,
) -> Result<EvmSignature> {
    let signer = PrivateKeySigner::from_str(&get_node_goat_private_key()?)?;
    let pegin_digest = goat_client.gateway_get_post_pegin_digest(&instance_id, pegin_txid).await?;
    let sig = signer.sign_hash(&pegin_digest.into()).await?;
    Ok(sig)
}

pub async fn verify_pegin_endorsement(
    goat_client: &GOATClient,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
    pegin_txid: &Txid,
    signature: &[u8],
) -> Result<bool> {
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    let expected_evm_address = pegin_data
        .committee_pubkeys
        .iter()
        .zip(pegin_data.committee_addresses.iter())
        .find_map(|(pubkey, evm_address)| {
            PublicKey::from_slice(pubkey)
                .ok()
                .filter(|on_chain_pubkey| on_chain_pubkey == committee_pubkey)
                .map(|_| *evm_address)
        })
        .ok_or_else(|| anyhow!("committee pubkey {committee_pubkey} not found on-chain"))?;
    let pegin_digest = goat_client.gateway_get_post_pegin_digest(&instance_id, pegin_txid).await?;
    let sig = EvmSignature::try_from(signature)?;
    sig.recover_address_from_prehash(&pegin_digest.into())
        .map(|addr| addr == expected_evm_address)
        .map_err(|e| e.into())
}

pub async fn verify_graph_endorsement(
    goat_client: &GOATClient,
    evm_address: &EvmAddress,
    graph: &BitvmGcGraph,
    signature: &[u8],
) -> Result<bool> {
    let graph_digest = get_graph_digest(goat_client, graph).await?;
    let sig = EvmSignature::try_from(signature)?;
    sig.recover_address_from_prehash(&graph_digest.into())
        .map(|addr| &addr == evm_address)
        .map_err(|e| e.into())
}

/// Validates whether the given kickoff transaction has been confirmed on Layer 1.
pub async fn tx_on_chain(client: &BTCClient, txid: &Txid) -> Result<bool> {
    match client.get_tx(txid).await? {
        Some(_) => Ok(true),
        _ => Ok(false),
    }
}

pub async fn tx_confirmed(client: &BTCClient, txid: &Txid) -> Result<bool> {
    Ok(client.get_tx_status(txid).await?.confirmed)
}

pub async fn outpoint_available(client: &BTCClient, txid: &Txid, vout: u64) -> Result<bool> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => Ok(!status.spent),
        _ => Ok(false),
    }
}

pub async fn outpoint_spent_txid(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<Txid>> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => Ok(status.txid),
        _ => Ok(None),
    }
}

pub async fn outpoint_spent_txin(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<(Txid, u64, TxIn)>> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => {
            if let Some(spent_txid) = status.txid
                && let Some(vin) = status.vin
                && let Some(spent_tx) = client.get_tx(&spent_txid).await?
            {
                Ok(spent_tx.input.get(vin as usize).cloned().map(|txin| (spent_txid, vin, txin)))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn generate_message_id(business_id: Uuid, msg_type: String, sub_type: Option<String>) -> String {
    match sub_type {
        Some(sub_type) => {
            format!("{business_id}_{msg_type}_{sub_type}")
        }
        None => format!("{business_id}_{msg_type}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_message(
    storage_processor: &mut StorageProcessor<'_>,
    is_update: bool,
    business_id: Uuid,
    sub_type: Option<String>,
    from_peer: String,
    actor: Actor,
    message_content: GOATMessageContent,
    weight: i64,
    lock_time: i64,
) -> Result<()> {
    let message = GOATMessage::new(actor.clone(), message_content.clone());
    let msg_type = get_goat_message_content_type(&message_content);
    let message_id = generate_message_id(business_id, msg_type.to_string().clone(), sub_type);
    if is_update || storage_processor.find_messages_by_id(&message_id).await?.is_none() {
        if let Some(cancel_msg_type) = match msg_type {
            MessageType::AssertSent => Some(MessageType::WatchtowerChallengeInitSent),
            _ => None,
        } {
            notify_to_cancel_proof_task(storage_processor, business_id, cancel_msg_type).await?;
        }

        storage_processor
            .upsert_message(Message {
                message_id,
                business_id,
                actor: actor.to_string(),
                from_peer,
                msg_type: msg_type.to_string(),
                content: message.serialize_message().await?,
                weight,
                lock_time_until: current_time_secs() + lock_time,
                state: MessageState::Pending.to_string(),
                message_version: 0,
            })
            .await?;
    } else {
        info!("{message_id} is already created for create action");
    }

    Ok(())
}

pub async fn notify_to_cancel_proof_task(
    storage_processor: &mut StorageProcessor<'_>,
    business_id: Uuid,
    msg_type: MessageType,
) -> Result<()> {
    // AssertInitSent is removed; update related logic if needed;
    if !matches!(msg_type, MessageType::WatchtowerChallengeInitSent) {
        warn!("notify_to_cancel_proof_task: input wrong message type:{msg_type}");
        return Ok(());
    }

    let host = match get_proof_build_rpc_host() {
        Some(host) => Url::parse(&host)?,
        None => {
            warn!("notify_to_cancel_proof_task:failed to get proof_build_rpc_host");
            return Ok(());
        }
    };

    if let Some(message) =
        storage_processor.find_message_by_business_id(&business_id, &msg_type.to_string()).await?
        && let Some(graph) = storage_processor.find_graph(&business_id).await?
    {
        if MessageState::Pending.to_string() != message.state {
            warn!(
                "message {business_id}, msg_type: {msg_type} no need to cancel.as state is {}",
                message.state
            );
            return Ok(());
        }

        // It will only be called a few times under limited conditions, so we just create a new object
        let http_client = HttpAsyncClient::new(None);
        let notify_result = match msg_type {
            MessageType::WatchtowerChallengeInitSent => {
                let url = host.join(PROOFS_WATCHTOWER_PROOF_TIMEOUT)?;
                let response  = http_client
                    .post_response_json::<WatchtowerProofTimeoutUpdateResponse, WatchtowerProofTimeoutUpdateRequest>(
                        url.as_str(),
                        &WatchtowerProofTimeoutUpdateRequest {
                            instance_id: graph.instance_id.to_string(),
                            graph_id: graph.graph_id.to_string(),
                            public_key: get_node_pubkey()?.to_string(),

                        },
                    )
                    .await?;
                info!("call {}, response:{:?}", PROOFS_WATCHTOWER_PROOF_TIMEOUT, response);
                response.data.is_some()
            }
            _ => false,
        };
        if notify_result {
            // cancel unfinished p2p message; when notify success!
            storage_processor
                .update_messages_state_by_business_id(
                    &business_id,
                    Some(msg_type.to_string()),
                    MessageState::Pending.to_string(),
                    MessageState::Cancelled.to_string(),
                )
                .await?;
        }
    } else {
        warn!("message {business_id}, msg_type: {msg_type} or graph {business_id} not fund in DB");
    }

    Ok(())
}

/// store new graph, graph_raw_data, and update instance_id
pub async fn get_bitvm_graph_from_db(
    _local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<BitvmGcGraph> {
    Err(anyhow!("graph:{graph_id} not found"))
}

pub async fn get_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<GraphStatus>> {
    let mut storage_process = local_db.acquire().await?;
    let graph_op = storage_process.find_graph(&graph_id).await?;
    if graph_op.is_none() {
        return Ok(None);
    };
    let graph = graph_op.unwrap();
    if graph.instance_id.ne(&instance_id) {
        bail!(
            "grap with graph_id:{graph_id} has instance_id:{} not match exp instance:{instance_id}",
            graph.instance_id,
        );
    }
    Ok(Some(
        GraphStatus::from_str(&graph.status)
            .map_err(|_| anyhow!("unknown graph status: {}", graph.status))?,
    ))
}

/// Returns:
/// - `Ok(true)` tx confirmed,
/// - `Ok(false)` tx not confirmed, exceeds the maximum waiting time
pub async fn wait_tx_confirmation(
    btc_client: &BTCClient,
    txid: &Txid,
    interval: u64,
    max_wait_secs: u64,
) -> Result<bool> {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let start_time = Instant::now();
    loop {
        if start_time.elapsed().as_secs() > max_wait_secs {
            // println!("Timeout: Transaction not confirmed after {} seconds", max_wait_secs);
            return Ok(false);
        };
        // FIXME: should not use esplora directly
        match btc_client.get_tx_status(txid).await {
            Ok(status) => {
                if let Some(_height) = status.block_height {
                    // println!("Transaction confirmed in block {}", height);
                    return Ok(true);
                } else {
                    // println!("Transaction unconfirmed, polling again...");
                }
            }
            Err(e) => {
                bail!("Failed to fetch transaction status: {e}");
            }
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

#[allow(dead_code)]
pub async fn wait_tx_appear(
    btc_client: &BTCClient,
    txid: &Txid,
    interval: u64,
    max_wait_secs: u64,
) -> Result<bool> {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let start_time = Instant::now();
    loop {
        if start_time.elapsed().as_secs() > max_wait_secs {
            // println!("Timeout: Transaction not appear after {} seconds", max_wait_secs);
            return Ok(false);
        };
        match btc_client.get_tx(txid).await {
            Ok(tx) => {
                if tx.is_some() {
                    return Ok(true);
                }
            }
            Err(e) => {
                bail!("Failed to fetch transaction status: {e}");
            }
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

pub mod defer {
    pub struct Defer<F: FnOnce()> {
        cleanup: Option<F>,
    }
    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Self { cleanup: Some(f) }
        }
        pub fn dismiss(&mut self) {
            self.cleanup = None;
        }
    }
    impl<F: FnOnce()> Drop for Defer<F> {
        fn drop(&mut self) {
            if let Some(cleanup) = self.cleanup.take() {
                cleanup();
            }
        }
    }
    #[macro_export]
    macro_rules! defer {
        ($name:ident, $cleanup:block) => {
            let mut $name = $crate::utils::defer::Defer::new(|| $cleanup);
        };
    }
    #[macro_export]
    macro_rules! dismiss_defer {
        ($name:ident) => {
            $name.dismiss();
        };
    }
}

pub async fn save_node_info(local_db: &LocalDB, node_info: &NodeInfo) -> Result<()> {
    info!("save_node_info for {}", node_info.peer_id);
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    let _ = storage_process
        .upsert_node(&Node {
            peer_id: node_info.peer_id.clone(),
            actor: node_info.actor.clone(),
            node_name: node_info.node_name.clone(),
            goat_addr: node_info.goat_addr.clone(),
            btc_pub_key: node_info.btc_pub_key.clone(),
            socket_addr: node_info.socket_addr.clone(),
            reward: "0".to_string(),
            service_fee_rate: node_info.service_fee_rate,
            available_peg_btc: node_info.available_peg_btc.clone(),
            updated_at: current_time,
            created_at: current_time,
        })
        .await;
    Ok(())
}

pub async fn save_local_info(local_db: &LocalDB) {
    let node = get_local_node_info();
    match save_node_info(local_db, &node).await {
        Ok(_) => {}
        Err(err) => tracing::error!("save local node err: {err}"),
    }
}

pub async fn update_node_timestamp(local_db: &LocalDB, peer_id: &str) -> Result<()> {
    tracing::info!("update timestamp for {peer_id}");
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    match storage_process.update_node_timestamp(peer_id, current_time).await {
        Ok(_) => {}
        Err(err) => warn!("{err}"),
    };
    Ok(())
}

pub async fn detect_heart_beat(swarm: &mut Swarm<AllBehaviours>) -> Result<()> {
    tracing::info!("start detect_heart_beat");
    let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
    // send to actor
    let actors = get_rpc_support_actors();
    for actor in actors {
        match send_to_peer(swarm, GOATMessage::new(actor, message_content.clone())).await {
            Ok(_) => {}
            Err(err) => warn!("{err}"),
        }
    }
    Ok(())
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen_range(0..255)).collect()
}

pub fn get_rand_btc_address_p2wpkh(network: Network) -> String {
    let secp = Secp256k1::new();
    Address::p2wpkh(
        &CompressedPublicKey::try_from(PrivateKey::generate(network).public_key(&secp))
            .expect("Could not compress public key"),
        network,
    )
    .to_string()
}

pub fn get_rand_btc_address_p2pkh(network: Network) -> String {
    let secp = Secp256k1::new();
    Address::p2pkh(
        CompressedPublicKey::try_from(PrivateKey::generate(network).public_key(&secp))
            .expect("Could not compress public key"),
        network,
    )
    .to_string()
}

pub fn get_rand_goat_address() -> String {
    EvmAddress::from_slice(&generate_random_bytes(20)).to_string()
}

pub fn strip_hex_prefix_owned(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") { s[2..].to_string() } else { s.to_string() }
}

/// Retrieve the server's public IP via NAT protocol and combine it with
/// the configured RPC monitoring port`rpc_addr` to generate the external RPC service address.
pub async fn set_node_external_socket_addr_env(rpc_addr: &str) -> Result<()> {
    if get_proof_server_url().is_some() || std::env::var(ENV_EXTERNAL_SOCKET_ADDR).is_ok() {
        // not provide proof server
        return Ok(());
    }
    let addr = SocketAddr::from_str(rpc_addr)?;
    let mut client = Client::new("0.0.0.0:0", None).await?;
    let message_res = client.binding_request("stun.l.google.com:19302", None).await;
    if message_res.is_err() {
        warn!("fail to get message from stun.l.google.com:19302, err :{:?}", message_res.err());
        return Ok(());
    }
    let message = message_res?;
    if message.get_class() != Class::SuccessResponse {
        warn!(
            "fail to get message from stun.l.google.com:19302, return class :{:?}",
            message.get_class()
        );
        return Ok(());
    }
    if let Some(socket_addr) = Attribute::get_xor_mapped_address(&message) {
        unsafe {
            std::env::set_var(
                ENV_EXTERNAL_SOCKET_ADDR,
                SocketAddr::new(socket_addr.ip(), addr.port()).to_string(),
            );
        }
    }
    Ok(())
}

pub fn reflect_goat_address(addr_op: Option<String>) -> (bool, Option<String>) {
    if let Some(addr) = addr_op
        && let Ok(addr) = EvmAddress::from_str(&addr)
    {
        return (true, Some(addr.to_string()));
    }
    (false, None)
}

pub async fn pop_batch_local_unhandle_msg(
    local_db: &LocalDB,
    _actor: Actor,
    lock_time_until: i64,
    offset: i64,
    limit: i64,
) -> Result<Vec<Message>> {
    let mut tx = local_db.start_transaction().await?;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    tx.set_messages_expired(current_time - MESSAGE_EXPIRE_TIME).await?;
    tx.delete_old_messages(current_time - MESSAGE_EXPIRE_TIME).await?;
    let messages = tx
        .filter_messages(
            MessageState::Pending.to_string(),
            0,
            lock_time_until,
            current_time - MESSAGE_EXPIRE_TIME,
            limit,
            offset,
        )
        .await?;
    tx.commit().await?;
    Ok(messages)
}

pub async fn operator_scan_ready_proof(
    _local_db: &LocalDB,
    _remote_proof_server_socket: Option<String>,
    _uri: &str,
) -> Result<()> {
    tracing::info!("start operator_scan_ready_proof");
    // todo
    Ok(())
}

pub fn generate_local_key() -> libp2p::identity::Keypair {
    libp2p::identity::Keypair::generate_ed25519()
}

pub fn temp_sqlite_db_path() -> String {
    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    format!("sqlite:{}", tmp_db.path().as_os_str().to_str().unwrap())
}

// contract calls

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InstanceProcessDataItem {
    pub pub_nonce: Option<PubNonce>,
    pub partial_sign: Option<PartialSignature>,
    pub endorse_signature: Vec<u8>,
}
pub type InstanceProcessDataMap = IndexMap<PublicKey, InstanceProcessDataItem>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct GraphProcessDataItem {
    pub committee_pub_nonce: Option<CommitteePubNonces>,
    pub partial_sigs: Option<CommitteePartialSignatures>,
    pub committee_evm_address: Option<EvmAddress>,
    pub endorse_signature: Vec<u8>,
}
pub type GraphProcessDataMap = IndexMap<PublicKey, GraphProcessDataItem>;

pub fn order_committee_values<T: Clone>(
    committee_pubkeys: &[PublicKey],
    values: Vec<(PublicKey, T)>,
    label: &str,
) -> Result<Vec<T>> {
    for (idx, (pubkey, _)) in values.iter().enumerate() {
        if !committee_pubkeys.contains(pubkey) {
            bail!("{label} contains non-committee pubkey {pubkey}");
        }
        if values.iter().skip(idx + 1).any(|(other, _)| other == pubkey) {
            bail!("{label} contains duplicate pubkey {pubkey}");
        }
    }

    committee_pubkeys
        .iter()
        .map(|committee_pubkey| {
            values
                .iter()
                .find(|(pubkey, _)| pubkey == committee_pubkey)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| anyhow!("{label} missing pubkey {committee_pubkey}"))
        })
        .collect()
}

// db operations
pub async fn get_current_prekickoff_tx(
    local_db: &LocalDB,
    operator_pubkey: &PublicKey,
) -> Result<Option<(u64, PrekickoffTransaction)>> {
    // return (latest_graph.nonce + 1 , latest_graph.next_prekickoff_tx)
    // return None if no graph yet
    let mut storage_processor = local_db.acquire().await?;
    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_order("kickoff_index DESC".to_string())
                .with_limit(1),
        )
        .await?;

    if !graphs.is_empty()
        && let Some(graph_raw_data) =
            storage_processor.find_graph_raw_data(&graphs[0].graph_id).await?
    {
        let simplified_graph =
            parse_graph_raw_data(graph_raw_data.raw_data, graphs[0].graph_id).await?;

        Ok(Some((
            (graphs[0].kickoff_index + 1) as u64,
            BitvmGcGraph::from_simplified(&simplified_graph)?.next_prekickoff,
        )))
    } else {
        Ok(None)
    }
}

pub struct GenerateInstanceParams {
    pub instance_id: Uuid,
    pub user_info: UserInfo,
    pub pegin_amount: Amount,
    pub pegin_request_tx_hash: String,
    pub pegin_request_height: i64,
    pub pegin_timestamp: i64,
}
pub async fn generate_instance(
    btc_client: &BTCClient,
    params: GenerateInstanceParams,
) -> Result<Instance> {
    let from_addr = if !params.user_info.inputs.is_empty()
        && let Some(tx) = btc_client.get_tx(&params.user_info.inputs[0].outpoint.txid).await?
    {
        let tx_scripts =
            tx.output[params.user_info.inputs[0].outpoint.vout as usize].script_pubkey.clone();
        Address::from_script(&tx_scripts, env::get_network())
            .map(|addr| addr.to_string())
            .unwrap_or_default()
    } else {
        warn!(
            "failed to decode instance {} from_address from pegin_request as input_utxos is empty or decode address failed",
            params.instance_id
        );
        "".to_string()
    };
    let input_utxos = params
        .user_info
        .inputs
        .iter()
        .map(|input| ClientUtxo {
            txid: input.outpoint.txid.to_byte_array(),
            vout: input.outpoint.vout,
            amount_sats: input.amount.to_sat(),
        })
        .collect::<Vec<_>>();
    let current_time = current_time_secs();

    Ok(Instance {
        instance_id: params.instance_id,
        is_bridge_in: true,
        network: get_network().to_string(),
        from_addr,
        to_addr: EvmAddress::from(&params.user_info.depositor_evm_address).to_string(),
        amount: params.pegin_amount.to_sat() as i64,
        fees: UInt64Array3(params.user_info.txn_fees),
        input_utxos: serde_json::to_string(&input_utxos)?,
        status: InstanceBridgeInStatus::UserInited.to_string(),
        goat_tx_hash: params.pegin_request_tx_hash,
        goat_tx_height: params.pegin_request_height,
        user_xonly_pubkey: ByteArray32(params.user_info.user_xonly_pubkey.clone().serialize()),
        user_change_addr: params.user_info.user_change_address.clone().to_string(),
        user_refund_addr: params.user_info.user_refund_address.clone().to_string(),
        btc_txid: None,
        pegin_confirm_txid: None,
        pegin_cancel_txid: None,
        committees_answers: IndexMap::new(),
        pegin_data_tx_hash: "".to_string(),
        btc_height: 0,
        parameters: None,
        escrow_hash: None,
        bridge_out_lock_time: 0,
        post_pegin_txhash: None,
        bridge_out_amount: "0".to_string(),
        status_updated_at: params.pegin_timestamp,
        created_at: current_time,
        updated_at: current_time,
    })
}

pub async fn store_pegin_request(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    params: GenerateInstanceParams,
) -> Result<()> {
    // store instance info to local db
    let mut storage_processor = local_db.acquire().await?;
    let instance = generate_instance(btc_client, params).await?;
    storage_processor.upsert_instance(&instance).await?;
    Ok(())
}

pub async fn store_instance_parameters(
    local_db: &LocalDB,
    instance_params: &BitvmGcInstanceParameters,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let incoming_parameters_hash = instance_params.parameters_hash()?;
    if let Some(existing_parameters) =
        storage_processor.get_instance_parameters_by_id(&instance_params.instance_id).await?
    {
        let existing_instance_params: BitvmGcInstanceParameters =
            serde_json::from_str(&existing_parameters)?;
        let existing_parameters_hash = existing_instance_params.parameters_hash()?;
        if existing_parameters_hash != incoming_parameters_hash {
            bail!(SpecialError::InvalidPeginData(format!(
                "instance parameters changed for instance_id {}: existing={}, incoming={}",
                instance_params.instance_id,
                hex::encode(existing_parameters_hash),
                hex::encode(incoming_parameters_hash)
            )));
        }
    }
    storage_processor
        .update_instance_parameters(
            &instance_params.instance_id,
            &serde_json::to_string(&instance_params)?,
        )
        .await?;
    Ok(())
}
pub async fn get_instance_parameters(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Option<BitvmGcInstanceParameters>> {
    let mut storage_processor = local_db.acquire().await?;
    if let Some(instance) = storage_processor.find_instance(&instance_id).await? {
        Ok(if let Some(parameters) = instance.parameters {
            Some(serde_json::from_str(&parameters)?)
        } else {
            gen_instance_parameters_local(&instance).ok()
        })
    } else {
        Ok(None)
    }
}

fn convert_graph(bitvm_graph: &BitvmGcGraph, current_time: i64) -> Graph {
    let mut status = GraphStatus::OperatorPresigned.to_string();
    if bitvm_graph.committee_pre_signed() {
        status = GraphStatus::CommitteePresigned.to_string();
    }

    Graph {
        graph_id: bitvm_graph.parameters.graph_id,
        instance_id: bitvm_graph.parameters.instance_parameters.instance_id,
        kickoff_index: bitvm_graph.parameters.graph_nonce as i64,
        from_addr: "".to_string(),
        to_addr: "".to_string(),
        amount: bitvm_graph.parameters.instance_parameters.pegin_amount.to_sat() as i64,
        challenge_amount: bitvm_graph.parameters.challenge_amount.to_sat() as i64,
        status,
        sub_status: "".to_string(),
        operator_pubkey: bitvm_graph.parameters.operator_pubkey.to_string(),
        cur_prekickoff_txid: Some(bitvm_graph.cur_prekickoff.finalize().compute_txid().into()),
        next_prekickoff: Some(bitvm_graph.next_prekickoff.finalize().compute_txid().into()),
        force_skip_kickoff_txid: Some(
            bitvm_graph.force_skip_kickoff.finalize().compute_txid().into(),
        ),
        quick_challenge_txid: Some(bitvm_graph.quick_challenge.finalize().compute_txid().into()),
        challenge_incomplete_kickoff_txid: Some(
            bitvm_graph.challenge_incomplete_kickoff.finalize().compute_txid().into(),
        ),
        pegin_txid: Some(bitvm_graph.pegin.finalize().compute_txid().into()),
        kickoff_txid: Some(bitvm_graph.kickoff.finalize().compute_txid().into()),
        take1_txid: Some(bitvm_graph.take1.finalize().compute_txid().into()),
        challenge_txid: None,
        take2_txid: Some(bitvm_graph.take2.finalize().compute_txid().into()),
        watchtower_challenge_init_txid: Some(
            bitvm_graph.watchtower_challenge_init.finalize().compute_txid().into(),
        ),
        operator_assert_txid: Some(bitvm_graph.operator_assert.finalize().compute_txid().into()),
        verifier_assert_txids: bitvm_graph
            .verifier_asserts
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        disprove_txids: bitvm_graph
            .disproves
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        watchtower_challenge_timeout_txids: bitvm_graph
            .watchtower_challenge_timeouts
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        operator_challenge_nack_txids: bitvm_graph
            .operator_challenge_nacks
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        operator_commit_timeout_txid: Some(
            bitvm_graph.operator_commit_timeout.finalize().compute_txid().into(),
        ),
        init_withdraw_tx_hash: None,
        bridge_out_start_at: 0,
        status_updated_at: current_time,
        proceed_withdraw_height: 0,
        created_at: current_time,
        updated_at: current_time,
    }
}

pub async fn store_graph(local_db: &LocalDB, simple_graph: &SimplifiedBitvmGcGraph) -> Result<()> {
    let mut tx = local_db.start_transaction().await?;
    let bitvm_graph: BitvmGcGraph = BitvmGcGraph::from_simplified(simple_graph)?;
    let graph_id = simple_graph.parameters.graph_id;
    let instance_id = simple_graph.parameters.instance_parameters.instance_id;
    let current_time = current_time_secs();
    let mut graph = convert_graph(&bitvm_graph, current_time);
    let incoming_parameters_hash = simple_graph.parameters_hash()?;

    if let Some(existing_raw_data) = tx.find_graph_raw_data(&graph_id).await? {
        let existing_graph = parse_graph_raw_data(existing_raw_data.raw_data, graph_id).await?;
        let existing_parameters_hash = existing_graph.parameters_hash()?;
        if existing_parameters_hash != incoming_parameters_hash {
            bail!(SpecialError::InvalidGraph(format!(
                "graph parameters changed for graph_id {graph_id}: existing={}, incoming={}",
                hex::encode(existing_parameters_hash),
                hex::encode(incoming_parameters_hash)
            )));
        }
        if existing_graph.operator_pre_signed() && !simple_graph.operator_pre_signed() {
            bail!(SpecialError::InvalidGraph(format!(
                "graph {graph_id} cannot be downgraded after operator pre-signatures are stored"
            )));
        }
        if existing_graph.committee_pre_signed() && !simple_graph.committee_pre_signed() {
            bail!(SpecialError::InvalidGraph(format!(
                "graph {graph_id} cannot be downgraded after committee pre-signatures are stored"
            )));
        }
    }

    if let Some(node_info) =
        tx.get_node_by_btc_pub_key(&bitvm_graph.parameters.operator_pubkey.to_string()).await?
    {
        graph.from_addr = node_info.goat_addr.clone();
        graph.to_addr =
            node_p2wsh_address(get_network(), &bitvm_graph.parameters.operator_pubkey).to_string();
    }

    tx.upsert_graph(&graph).await?;
    if bitvm_graph.committee_pre_signed() {
        tx.update_instance(
            &InstanceUpdate::new_with_instance_id(instance_id)
                .with_status(InstanceBridgeInStatus::Presigned.to_string()),
        )
        .await?;
    }

    let raw_data = serialize_graph_raw_data(simple_graph, graph_id).await?;
    tx.upsert_graph_raw_data(GraphRawData {
        graph_id,
        raw_data,
        created_at: current_time,
        updated_at: current_time,
    })
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Parse raw graph data JSON string to SimplifiedBitvmGcGraph using spawn_blocking
/// to handle large data and potential stack overflow issues
pub async fn parse_graph_raw_data(
    raw_data: String,
    graph_id: Uuid,
) -> Result<SimplifiedBitvmGcGraph> {
    let raw_data_len = raw_data.len();
    let raw_data_clone = raw_data.clone();
    let parse_result = tokio::task::spawn_blocking(move || {
        serde_json::from_str::<SimplifiedBitvmGcGraph>(&raw_data_clone)
    })
    .await;

    match parse_result {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => {
            // Normal JSON parsing error
            error!("Failed to parse graph data for graph_id {graph_id}: {e}");
            error!("Raw data length: {raw_data_len} bytes");
            Err(e.into())
        }
        Err(join_err) => {
            // spawn_blocking task failed (thread panic or task cancelled)
            let msg = if join_err.is_panic() {
                format!("Thread panic while parsing graph data for graph_id {graph_id}")
            } else if join_err.is_cancelled() {
                format!("Task cancelled while parsing graph data for graph_id {graph_id}")
            } else {
                format!(
                    "Task join error while parsing graph data for graph_id {graph_id}: {join_err}"
                )
            };
            error!("{msg}");
            error!("Raw data length: {raw_data_len} bytes");
            Err(anyhow::anyhow!("{msg}"))
        }
    }
}

/// Serialize SimplifiedBitvmGcGraph to JSON string using spawn_blocking
/// to handle large data and potential stack overflow issues
pub async fn serialize_graph_raw_data(
    graph: &SimplifiedBitvmGcGraph,
    graph_id: Uuid,
) -> Result<String> {
    let graph_clone = graph.clone();
    let serialize_result =
        tokio::task::spawn_blocking(move || serde_json::to_string(&graph_clone)).await;

    match serialize_result {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => {
            // Normal JSON serialization error
            error!("Failed to serialize graph data for graph_id {graph_id}: {e}");
            Err(e.into())
        }
        Err(join_err) => {
            // spawn_blocking task failed (thread panic or task cancelled)
            let msg = if join_err.is_panic() {
                format!("Thread panic while serializing graph data for graph_id {graph_id}")
            } else if join_err.is_cancelled() {
                format!("Task cancelled while serializing graph data for graph_id {graph_id}")
            } else {
                format!(
                    "Task join error while serializing graph data for graph_id {graph_id}: {join_err}",
                )
            };
            error!("{msg}");
            Err(anyhow::anyhow!("{graph_id}"))
        }
    }
}

pub async fn get_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<SimplifiedBitvmGcGraph>> {
    let mut storage_process = local_db.acquire().await?;
    if let Some(graph_raw_data) = storage_process.find_graph_raw_data(&graph_id).await?
        && let Ok(simplified_graph) = parse_graph_raw_data(graph_raw_data.raw_data, graph_id).await
    {
        Ok(Some(simplified_graph))
    } else {
        Ok(None)
    }
}

pub async fn get_graph_by_instance_id_and_operator_pubkey(
    local_db: &LocalDB,
    instance_id: Uuid,
    operator_pubkey: &PublicKey,
) -> Result<Option<SimplifiedBitvmGcGraph>> {
    let mut storage_process = local_db.acquire().await?;
    if let Some(graph_id) = storage_process
        .get_graph_id_by_instance_id_and_operator_pubkey(&instance_id, &operator_pubkey.to_string())
        .await?
        && let Some(graph_raw_data) = storage_process.find_graph_raw_data(&graph_id).await?
        && let Ok(simplified_graph) = parse_graph_raw_data(graph_raw_data.raw_data, graph_id).await
    {
        Ok(Some(simplified_graph))
    } else {
        Ok(None)
    }
}

pub async fn get_latest_pegout_finalized_graph(
    local_db: &LocalDB,
    operator_pubkey: &PublicKey,
) -> Result<Option<(u64, Uuid)>> {
    // get latest pegout finalized graph nonce & id from local db
    let statuses: Vec<String> =
        GraphStatus::get_closed_status().iter().map(|status| status.to_string()).collect();
    let mut storage_processor = local_db.acquire().await?;
    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_statuses(statuses)
                .with_order("kickoff_index DESC".to_string())
                .with_limit(1),
        )
        .await?;
    if graphs.is_empty() {
        Ok(None)
    } else {
        Ok(Some((graphs[0].kickoff_index as u64, graphs[0].graph_id)))
    }
}

pub async fn get_graph_id_by_nonce(
    local_db: &LocalDB,
    graph_nonce: u64,
    operator_pubkey: &PublicKey,
) -> Result<Option<(Uuid, Uuid)>> {
    // get instance_id & graph_id by graph_nonce and operator_pubkey from local db
    let mut storage_processor = local_db.acquire().await?;
    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_kickoff_index(graph_nonce as i64)
                .with_limit(1),
        )
        .await?;
    if graphs.is_empty() { Ok(None) } else { Ok(Some((graphs[0].instance_id, graphs[0].graph_id))) }
}

pub async fn upsert_pegin_instance_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    process_data_map: &InstanceProcessDataMap,
) -> Result<()> {
    let current_time = current_time_secs();
    storage_processor
        .upsert_pegin_instance_process_data(&PeginInstanceProcessData {
            instance_id,
            process_data: serde_json::to_string(process_data_map)?,
            updated_at: current_time,
            created_at: current_time,
        })
        .await?;
    Ok(())
}

pub async fn find_pegin_instance_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
) -> Result<InstanceProcessDataMap> {
    if let Ok(Some(data)) = storage_processor.find_pegin_instance_process_data(&instance_id).await
        && let Ok(process_data) = serde_json::from_str(data.process_data.as_str())
    {
        Ok(process_data)
    } else {
        Ok(IndexMap::new())
    }
}

pub async fn upsert_pegin_graph_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
    instance_id: Uuid,
    is_endorsed: bool,
    process_data_map: &GraphProcessDataMap,
) -> Result<()> {
    let current_time = current_time_secs();
    storage_processor
        .upsert_pegin_graph_process_data(&PeginGraphProcessData {
            graph_id,
            instance_id,
            is_endorsed,
            process_data: serde_json::to_string(process_data_map)?,
            updated_at: current_time,
            created_at: current_time,
        })
        .await?;
    Ok(())
}

pub async fn find_pegin_graph_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
) -> Result<(bool, GraphProcessDataMap)> {
    if let Ok(Some(data)) = storage_processor.find_pegin_graph_process_data(&graph_id).await
        && let Ok(process_data) = serde_json::from_str(data.process_data.as_str())
    {
        Ok((data.is_endorsed, process_data))
    } else {
        Ok((false, IndexMap::new()))
    }
}

pub async fn store_committee_pub_nonces_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    pub_nonces: CommitteePubNonces,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    if let Some(existing_pub_nonces) =
        process_data.get(&committee_pubkey).and_then(|v| v.committee_pub_nonce.as_ref())
        && existing_pub_nonces != &pub_nonces
    {
        bail!(SpecialError::InvalidGraph(format!(
            "committee pub nonces changed for graph {graph_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.committee_pub_nonce = Some(pub_nonces.clone()))
        .or_insert_with(|| GraphProcessDataItem {
            committee_pub_nonce: Some(pub_nonces),
            partial_sigs: None,
            committee_evm_address: None,
            endorse_signature: vec![],
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}
pub async fn get_committee_pub_nonces_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, CommitteePubNonces)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.committee_pub_nonce.as_ref().map(|nonce| (*k, nonce.clone())))
        .collect::<Vec<(PublicKey, CommitteePubNonces)>>())
}
pub async fn store_committee_partial_sigs_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    partial_sigs: CommitteePartialSignatures,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    if let Some(existing_partial_sigs) =
        process_data.get(&committee_pubkey).and_then(|v| v.partial_sigs.as_ref())
        && existing_partial_sigs != &partial_sigs
    {
        bail!(SpecialError::InvalidGraph(format!(
            "committee partial signatures changed for graph {graph_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.partial_sigs = Some(partial_sigs.clone()))
        .or_insert_with(|| GraphProcessDataItem {
            committee_pub_nonce: None,
            partial_sigs: Some(partial_sigs),
            committee_evm_address: None,
            endorse_signature: vec![],
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}
pub async fn get_committee_partial_sigs_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, CommitteePartialSignatures)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.partial_sigs.as_ref().map(|nonce| (*k, nonce.clone())))
        .collect::<Vec<(PublicKey, CommitteePartialSignatures)>>())
}

pub async fn get_committee_partial_sigs_for_graph_member(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<Option<CommitteePartialSignatures>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data.get(committee_pubkey).and_then(|v| v.partial_sigs.clone()))
}
pub async fn store_committee_endorsement_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    committee_evm_address: EvmAddress,
    endorse_signature: Vec<u8>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| {
            v.endorse_signature = endorse_signature.clone();
            v.committee_evm_address = Some(committee_evm_address);
        })
        .or_insert_with(|| GraphProcessDataItem {
            committee_pub_nonce: None,
            partial_sigs: None,
            committee_evm_address: Some(committee_evm_address),
            endorse_signature,
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}
pub async fn store_committee_endorsements_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;

    for (committee_pubkey, committee_evm_address, endorse_signature) in endorse_sigs {
        process_data
            .entry(committee_pubkey)
            .and_modify(|v| {
                v.endorse_signature = endorse_signature.clone();
                v.committee_evm_address = Some(committee_evm_address);
            })
            .or_insert_with(|| GraphProcessDataItem {
                committee_pub_nonce: None,
                partial_sigs: None,
                committee_evm_address: Some(committee_evm_address),
                endorse_signature,
            });
    }
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}
pub async fn get_committee_endorsements_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, EvmAddress, Vec<u8>)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| {
            if !v.endorse_signature.is_empty() {
                v.committee_evm_address
                    .as_ref()
                    .map(|evm_addr| (*k, *evm_addr, v.endorse_signature.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<(PublicKey, EvmAddress, Vec<u8>)>>())
}
pub async fn mark_graph_as_endorsed(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.update_pegin_graph_endorsed(&graph_id, true).await?;
    Ok(())
}
pub async fn get_endorsed_graph_count(local_db: &LocalDB, instance_id: Uuid) -> Result<usize> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor.get_pegin_graph_endorsed_len_by_instance_id(&instance_id, true).await?
        as usize)
}
pub async fn store_committee_pub_nonce_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    pub_nonce: PubNonce,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some(existing_pub_nonce) =
        process_data.get(&committee_pubkey).and_then(|v| v.pub_nonce.as_ref())
        && existing_pub_nonce != &pub_nonce
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "committee pub nonce changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.pub_nonce = Some(pub_nonce.clone()))
        .or_insert_with(|| InstanceProcessDataItem {
            pub_nonce: Some(pub_nonce),
            partial_sign: None,
            endorse_signature: vec![],
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}
pub async fn get_committee_pub_nonce_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<Option<PubNonce>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data.get(committee_pubkey).and_then(|v| v.pub_nonce.clone()))
}
pub async fn get_committee_pub_nonces_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, PubNonce)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.pub_nonce.as_ref().map(|pub_nonce| (*k, pub_nonce.clone())))
        .collect())
}
pub async fn store_committee_partial_sig_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    partial_sigs: PartialSignature,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some(existing_partial_sig) =
        process_data.get(&committee_pubkey).and_then(|v| v.partial_sign.as_ref())
        && existing_partial_sig != &partial_sigs
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "committee partial signature changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.partial_sign = Some(partial_sigs))
        .or_insert_with(|| InstanceProcessDataItem {
            pub_nonce: None,
            partial_sign: Some(partial_sigs),
            endorse_signature: vec![],
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}

pub async fn get_committee_partial_sigs_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, PartialSignature)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.partial_sign.as_ref().map(|partial_sign| (*k, *partial_sign)))
        .collect())
}

pub async fn get_committee_partial_sig_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<Option<PartialSignature>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data.get(committee_pubkey).and_then(|v| v.partial_sign))
}

pub async fn store_committee_endorse_sig_for_pegin(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    endorse_sig: Vec<u8>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some(existing_endorse_sig) =
        process_data.get(&committee_pubkey).map(|v| v.endorse_signature.as_slice())
        && !existing_endorse_sig.is_empty()
        && existing_endorse_sig != endorse_sig.as_slice()
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "committee endorse signature changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.endorse_signature = endorse_sig.clone())
        .or_insert_with(|| InstanceProcessDataItem {
            pub_nonce: None,
            partial_sign: None,
            endorse_signature: endorse_sig,
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}
pub async fn get_committee_endorse_sigs_for_pegin(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, Vec<u8>)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| {
            if !v.endorse_signature.is_empty() {
                Some((*k, v.endorse_signature.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<(PublicKey, Vec<u8>)>>())
}

pub async fn graph_exists(local_db: &LocalDB, instance_id: Uuid, graph_id: Uuid) -> Result<bool> {
    let mut storage_processor = local_db.acquire().await?;
    if let Some(graph) = storage_processor.find_graph(&graph_id).await?
        && graph.instance_id == instance_id
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn try_update_graph_challenge_txid(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_id: Uuid,
    kickoff_txid: Txid,
    connector_a_vout: u64,
    take1_txid: Txid,
) -> Result<()> {
    let graph = {
        let mut storage_processor = local_db.acquire().await?;
        match storage_processor.find_graph(&graph_id).await? {
            Some(graph) => graph,
            None => {
                warn!("graph{graph_id} not in db");
                return Ok(());
            }
        }
    };

    if graph.challenge_txid.is_none()
        && let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
        && spent_txid != take1_txid
    {
        info!(
            "try_update_graph_challenge_txid update challenge_txid: {spent_txid} for graph {graph_id}"
        );
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .update_graph(&GraphUpdate::new(graph_id).with_challenge_txid(spent_txid.into()))
            .await?;
    } else {
        info!("try_update_graph_challenge_txid no need to challenge_txid for graph {graph_id}");
    }
    Ok(())
}

pub async fn update_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    new_status: GraphStatus,
    sub_status: Option<ChallengeSubStatus>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    match storage_processor.find_graph(&graph_id).await? {
        Some(graph) => {
            if graph.status == new_status.to_string()
                && let Some(ref sub_status) = sub_status
                && *sub_status == ChallengeSubStatus::default()
            {
                warn!(
                    "graph: {graph_id}, new_status: {new_status} is equal old status and ChallengeSubStatus is None, so not update"
                );
                return Ok(());
            }
        }
        None => {
            warn!("graph: {graph_id} is not update, so not update");
            return Ok(());
        }
    }

    if new_status == GraphStatus::CommitteePresigned {
        storage_processor
            .update_instance(
                &InstanceUpdate::new_with_instance_id(instance_id)
                    .with_status(InstanceBridgeInStatus::Presigned.to_string()),
            )
            .await?;
    }

    let mut graph_update = GraphUpdate::new(graph_id).with_status(new_status.to_string());
    if let Some(sub_status) = sub_status {
        graph_update = graph_update.with_sub_status(serde_json::to_string(&sub_status)?);
    }

    storage_processor.update_graph(&graph_update).await?;
    Ok(())
}
pub async fn get_graph_ids_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<Uuid>> {
    let mut storage_processor = local_db.acquire().await?;
    let graphs = storage_processor.get_graphs_by_instance_id(&instance_id).await?;
    Ok(graphs.into_iter().map(|v| v.graph_id).collect())
}

pub fn gen_instance_parameters_local(
    instance: &Instance,
) -> anyhow::Result<BitvmGcInstanceParameters> {
    let network = Network::from_str(&instance.network)?;
    let committee_pubkeys: Vec<PublicKey> = instance
        .committees_answers
        .iter()
        .map(|(_k, v)| PublicKey::from_slice(v).unwrap())
        .collect();

    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    let utxos: Vec<client::Utxo> = serde_json::from_str(&instance.input_utxos)?;
    Ok(BitvmGcInstanceParameters {
        network,
        instance_id: instance.instance_id,
        user_info: gen_user_info(
            network,
            &instance.to_addr,
            &instance.user_change_addr.clone(),
            &instance.user_refund_addr.clone(),
            utxos,
            instance.fees.0,
            &instance.user_xonly_pubkey.0,
        )?,
        pegin_amount: Amount::from_sat(instance.amount as u64),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}

fn gen_user_info(
    network: Network,
    depositor_evm_address: &str,
    user_change_addr: &str,
    user_refund_addr: &str,
    utxos: Vec<client::Utxo>,
    txn_fees: [u64; 3],
    user_xonly_pubkey: &[u8; 32],
) -> anyhow::Result<UserInfo> {
    let user_change_address: Address<NetworkUnchecked> = Address::from_str(user_change_addr)?;
    let user_refund_addr: Address<NetworkUnchecked> = Address::from_str(user_refund_addr)?;
    let inputs = utxos
        .into_iter()
        .map(|utxo| Input {
            outpoint: OutPoint { txid: Txid::from_slice(&utxo.txid).unwrap(), vout: utxo.vout },
            amount: Amount::from_sat(utxo.amount_sats),
        })
        .collect();
    Ok(UserInfo {
        depositor_evm_address: EvmAddress::from_str(depositor_evm_address)?.into_array(),
        txn_fees,
        inputs,
        user_xonly_pubkey: XOnlyPublicKey::from_slice(user_xonly_pubkey)?,
        user_change_address: user_change_address.require_network(network)?,
        user_refund_address: user_refund_addr.require_network(network)?,
    })
}

pub async fn check_bridge_in_uxto_available_or_self_spent(
    btc_client: &BTCClient,
    target_txid: Option<String>,
    utxos: &[client::Utxo],
) -> Result<bool> {
    for utxo in utxos {
        if let Ok(txid) = Txid::from_slice(&utxo.txid)
            && let Ok(Some(status)) = btc_client.get_output_status(&txid, utxo.vout as u64).await
            && status.spent
        {
            if let Some(target_txid) = target_txid
                && let Some(txid) = status.txid
                && txid.to_string() == target_txid
            {
                return Ok(true);
            }
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) async fn find_instances_by_escrow_hash<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    escrow_hash: &str,
) -> anyhow::Result<Option<Instance>> {
    let (instances, size) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_is_bridge_in(false)
                .with_escrow_hash(escrow_hash.to_string())
                .with_order("escrow_hash, created_at ASC".to_string()),
        )
        .await?;
    if size > 0 { Ok(Some(instances[0].clone())) } else { Ok(None) }
}

pub fn get_guest_constant_value(
    _instance_id: Uuid,
    graph_id: Uuid,
    watchtower_pubkeys: &[XOnlyPublicKey],
) -> Result<[u8; 32]> {
    let key_bytes = watchtower_pubkeys.iter().map(XOnlyPublicKey::serialize).collect::<Vec<_>>();
    Ok(hash_operator_constant(graph_id.into_bytes(), get_genesis_sequencer_commit_id(), &key_bytes))
}
pub(crate) async fn get_bridge_out_global_stats<'a>(
    storage_processor: &mut StorageProcessor<'a>,
) -> Result<BridgeOutGlobalStats> {
    match storage_processor.find_bridge_out_global_stats_by_id(BRIDGE_OUT_GLOBAL_STATS_ID).await? {
        Some(global_stats) => Ok(global_stats),
        None => Ok(BridgeOutGlobalStats {
            id: BRIDGE_OUT_GLOBAL_STATS_ID,
            initial_txn: 0,
            initial_amount: "0".to_string(),
            claim_txn: 0,
            claim_amount: "0".to_string(),
            refund_txn: 0,
            refund_amount: "0".to_string(),
            created_at: 0,
            updated_at: 0,
        }),
    }
}

pub async fn get_largest_watchtower_challenge_block(
    graph: &BitvmGcGraph,
    btc_client: &BTCClient,
) -> anyhow::Result<BlockHash> {
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let mut largest_watchtower_challenge_block_height = 0u32;
    let mut largest_watchtower_challenge_block_hash: BlockHash =
        BlockHash::from_slice(&[0u8; 32]).unwrap();
    for watchtower_index in 0..graph.parameters.watchtower_pubkeys.len() {
        let watchtower_challenge_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        match outpoint_spent_txid(
            btc_client,
            &watchtower_challenge_init_txid,
            watchtower_challenge_vout,
        )
        .await
        {
            Ok(Some(txid)) => {
                let tx_status = btc_client.get_tx_status(&txid).await?;
                if let Some(block_height) = tx_status.block_height {
                    if block_height > largest_watchtower_challenge_block_height {
                        largest_watchtower_challenge_block_height = block_height;
                        largest_watchtower_challenge_block_hash = tx_status.block_hash.unwrap();
                    }
                } else {
                    anyhow::bail!(
                        "Watchtower challenge tx {txid} for graph {}, index: {watchtower_index} not confirmed yet",
                        graph.parameters.graph_id
                    );
                }
            }
            Ok(None) => {
                anyhow::bail!(
                    "Watchtower challenge connector {watchtower_index} for graph {}, index: {watchtower_index} not spent yet",
                    graph.parameters.graph_id
                );
            }
            Err(e) => {
                anyhow::bail!(
                    "Error checking watchtower challenge connector graph: {}, index: {watchtower_index} spent status: {e}",
                    graph.parameters.graph_id
                );
            }
        }
    }
    Ok(largest_watchtower_challenge_block_hash)
}

pub(crate) fn babe_setup_state_root(local_db: &LocalDB) -> PathBuf {
    std::env::var_os(ENV_BABE_SETUP_STATE_DIR)
        .filter(|path| !path.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let db_path = local_db
                .path
                .strip_prefix("sqlite://")
                .or_else(|| local_db.path.strip_prefix("sqlite:"))
                .unwrap_or(&local_db.path);
            PathBuf::from(db_path)
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".bitvm-babe-state")
        })
}

fn babe_setup_state_path(local_db: &LocalDB, instance_id: Uuid, graph_id: Uuid) -> PathBuf {
    babe_setup_state_root(local_db).join(instance_id.to_string()).join(format!("{graph_id}.json"))
}

pub(crate) fn soldering_payload_hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub(crate) fn soldering_payload_hash_hex(payload_hash: &[u8; 32]) -> String {
    payload_hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) async fn pending_graph_belongs_to_operator(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    operator_pubkey: &PublicKey,
) -> Result<bool> {
    let mut storage = local_db.acquire().await?;
    Ok(storage.find_pending_graph_init_by_graph_id(&graph_id).await?.is_some_and(|pending| {
        pending.instance_id == instance_id && pending.operator_pubkey == operator_pubkey.to_string()
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_soldering_proof_to_operator(
    swarm: &mut Swarm<AllBehaviours>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_index: usize,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<()> {
    let compact_payload = compact_soldering_proof_payload(opened, finalized, soldering)?;
    let payload = bincode::serialize(&compact_payload)
        .context("serialize compact soldering proof payload")?;
    let payload_hash = soldering_payload_hash(&payload);
    let total_len = payload.len();
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        verifier_index,
        &payload_hash,
    )?;
    let store_mode = if is_soldering_proof_s3_path(&store_base_path) { "s3" } else { "local" };
    if let Err(err) =
        write_soldering_proof_store_payload(&payload_path, &payload).await.with_context(|| {
            format!("write soldering proof payload to configured store path {payload_path}")
        })
    {
        tracing::error!(
            store_mode,
            total_len,
            payload_hash = %soldering_payload_hash_hex(&payload_hash),
            payload_path = %payload_path,
            error = %err,
            "failed to write soldering proof payload to store"
        );
        return Err(err);
    }
    tracing::info!(
        store_mode,
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        payload_path = %payload_path,
        "send compact soldering proof ready from payload store"
    );
    let message_content = GOATMessageContent::SolderingProofReady(SolderingProofReady {
        instance_id,
        graph_id,
        verifier_index,
        payload_hash,
        total_len,
    });
    send_to_peer(swarm, GOATMessage::new(Actor::Operator, message_content)).await?;

    Ok(())
}

fn load_babe_setup_state_from_path(path: &Path) -> Result<Option<BabeSetupState>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read BABE setup state {}", path.display())),
    }
}

fn save_babe_setup_state_to_path(path: &Path, state: &BabeSetupState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create BABE setup state dir {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(state)?;
    std::fs::write(path, bytes)
        .with_context(|| format!("write BABE setup state {}", path.display()))
}

pub(crate) fn load_babe_setup_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<BabeSetupState>> {
    load_babe_setup_state_from_path(&babe_setup_state_path(local_db, instance_id, graph_id))
}

pub(crate) fn save_babe_setup_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    state: &BabeSetupState,
) -> Result<()> {
    save_babe_setup_state_to_path(&babe_setup_state_path(local_db, instance_id, graph_id), state)
}

pub(crate) fn update_babe_setup_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    update: impl FnOnce(&mut BabeSetupState),
) -> Result<BabeSetupState> {
    let mut state = load_babe_setup_state(local_db, instance_id, graph_id)?.unwrap_or_default();
    update(&mut state);
    save_babe_setup_state(local_db, instance_id, graph_id, &state)?;
    Ok(state)
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BabeSetupState {
    pub verifier: Option<VerifierBabeSetupState>,
    pub operator: Option<OperatorBabeSetupState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierBabeSetupState {
    pub verifier_pubkey: PublicKey,
    pub setup_package: CACSetupPackage,
    pub private_state: BabeVerifierPrivateState,
    pub verifier_index: Option<usize>,
    pub finalized_indices: Vec<usize>,
    pub opened: Vec<(usize, u64)>,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: Option<SolderingData>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OperatorVerifierCandidate {
    pub verifier_peer_id: Vec<u8>,
    pub verifier_pubkey: PublicKey,
    pub setup_package: CACSetupPackage,
    pub verifier_index: Option<usize>,
    pub selected_circuit_indexes: Vec<usize>,
    pub gc_data: Option<BitvmGcCircuitData>,
    #[serde(default)]
    pub prover_state: Option<BabeProverState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OperatorBabeSetupState {
    pub frozen_verifier_pubkeys: Option<Vec<PublicKey>>,
    pub candidates: Vec<OperatorVerifierCandidate>,
    #[serde(default)]
    pub asserted_operator_proof: Option<Vec<u8>>,
}

#[cfg(test)]
mod commit_pubin_tests {
    use super::*;
    use bitcoin::BlockHash;
    use client::btc_chain::BTCClient;
    use esplora_client::{Tx, TxStatus, Vin};
    use store::SerializableTxid;

    fn make_txid(byte: u8) -> Txid {
        Txid::from_slice(&[byte; 32]).unwrap()
    }

    fn make_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_slice(&[byte; 32]).unwrap()
    }

    fn create_confirmed_tx(
        txid: Txid,
        spends: &[(Txid, u32)],
        height: u32,
        block_hash: BlockHash,
    ) -> Tx {
        Tx {
            txid,
            version: 2,
            locktime: 0,
            vin: spends
                .iter()
                .map(|(prev_txid, vout)| Vin {
                    txid: *prev_txid,
                    vout: *vout,
                    prevout: None,
                    scriptsig: ScriptBuf::default(),
                    witness: vec![],
                    sequence: 1,
                    is_coinbase: false,
                })
                .collect(),
            vout: vec![],
            size: 1,
            weight: 1,
            status: TxStatus {
                confirmed: true,
                block_height: Some(height),
                block_hash: Some(block_hash),
                block_time: Some(1_000_000),
            },
            fee: 0,
        }
    }

    #[tokio::test]
    async fn test_get_watchtower_challenge_info_partial_inclusion() {
        let (btc_client, mock_adaptor) = BTCClient::new_mock_client();

        let watchtower_init_txid = make_txid(0x00);
        let challenge_txid_wt0 = make_txid(0x01);
        let block_hash = make_block_hash(0xAA);

        let challenge_vout_0 =
            output_topology::watchtower_challenge_init::watchtower_connector(0) as u32;
        let ack_vout_0 = output_topology::watchtower_challenge_init::ack_connector(0) as u32;

        // watchtower 0 spent its challenge connector and ACK connector; watchtower 1 is unresolved.
        mock_adaptor.set_tx(
            challenge_txid_wt0,
            create_confirmed_tx(
                challenge_txid_wt0,
                &[(watchtower_init_txid, challenge_vout_0)],
                100,
                block_hash,
            ),
        );
        let ack_txid_wt0 = make_txid(0x02);
        mock_adaptor.set_tx(
            ack_txid_wt0,
            create_confirmed_tx(
                ack_txid_wt0,
                &[(watchtower_init_txid, ack_vout_0)],
                101,
                block_hash,
            ),
        );

        let (txids, bits) = get_watchtower_challenge_info(
            &btc_client,
            &SerializableTxid::from(watchtower_init_txid),
            &[],
            2, // 2 watchtowers
        )
        .await
        .unwrap();

        assert_eq!(txids, vec![Some(challenge_txid_wt0.to_string()), None]);
        assert_eq!(bits, vec![true, false]);
    }

    #[tokio::test]
    async fn test_compute_operator_pubin_blockhash_and_bitmap() {
        let (btc_client, mock_adaptor) = BTCClient::new_mock_client();

        let init_txid = make_txid(0x00);
        let challenge_txid_wt0 = make_txid(0x01);
        let challenge_txid_wt2 = make_txid(0x02);
        let block_hash_low = make_block_hash(0x10);
        let block_hash_high = make_block_hash(0x20);

        let challenge_vout_0 =
            output_topology::watchtower_challenge_init::watchtower_connector(0) as u32;
        let challenge_vout_2 =
            output_topology::watchtower_challenge_init::watchtower_connector(2) as u32;

        // wt0 confirmed at height 100, wt2 at height 200 (highest)
        mock_adaptor.set_tx(
            challenge_txid_wt0,
            create_confirmed_tx(
                challenge_txid_wt0,
                &[(init_txid, challenge_vout_0)],
                100,
                block_hash_low,
            ),
        );
        mock_adaptor.set_tx(
            challenge_txid_wt2,
            create_confirmed_tx(
                challenge_txid_wt2,
                &[(init_txid, challenge_vout_2)],
                200,
                block_hash_high,
            ),
        );

        let challenge_txids =
            vec![Some(challenge_txid_wt0.to_string()), None, Some(challenge_txid_wt2.to_string())];
        let bits = vec![true, false, true];

        let (best_hash, bitmap) =
            compute_operator_pubin_blockhash_and_bitmap(&btc_client, &challenge_txids, &bits)
                .await
                .unwrap();

        // block at height 200 wins
        assert_eq!(best_hash, block_hash_high.to_byte_array());

        // bits 0 and 2 set → byte 0 = 0b0000_0101
        assert_eq!(bitmap[0], 0b0000_0101u8);
        assert_eq!(&bitmap[1..], &[0u8; 31]);
    }
}
