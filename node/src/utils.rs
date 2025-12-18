use crate::action::{
    GOATMessage, GOATMessageContent, NodeInfo, push_local_unhandled_messages, send_to_peer,
};
use crate::env::*;
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use alloy::primitives::{Address as EvmAddress, Signature as EvmSignature};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, PrivateKey,
    PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use bitvm::treepp::*;
use bitvm2_lib::actors::Actor;
use bitvm2_lib::challenger::*;
use bitvm2_lib::committee::*;
use bitvm2_lib::keys::{ChallengerMasterKey, OperatorMasterKey, WatchtowerMasterKey};
use bitvm2_lib::operator::*;
use bitvm2_lib::types::{
    Bitvm2Graph, Bitvm2GraphParameters, Bitvm2InstanceParameters, Groth16Proof,
    PrekickoffParameters, PublicInputs, SimplifiedBitvm2Graph, UserInfo, VerifyingKey,
};
use bitvm2_lib::watchtower::*;
use client::Utxo as ClientUtxo;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use esplora_client::Utxo;
use goat::connectors::{
    base::TaprootConnector,
    kickoff_connectors::{ForceSkipConnector, KickoffConnector, PrekickoffConnector},
};
use goat::contexts::base::generate_n_of_n_public_key;
use goat::disprove_scripts::hash160;
use goat::scripts::generate_opreturn_script;
use goat::transactions::base::Input;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::signing::populate_p2wsh_witness;
use libp2p::{PeerId, Swarm};
use rand::Rng;
use secp256k1::Secp256k1;

use anyhow::{Result, anyhow, bail};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use goat::transactions::prekickoff::PrekickoffTransaction;
use indexmap::IndexMap;
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use store::ipfs::IPFS;
use store::localdb::{
    GraphQuery, GraphUpdate, InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor,
};
use store::{
    ByteArray32, Graph, GraphRawData, GraphStatus, Instance, InstanceBridgeInStatus, Message,
    MessageState, Node, PeginGraphProcessData, PeginInstanceProcessData, UInt64Array3,
};
use stun_client::{Attribute, Class, Client};

use crate::env;
use crate::scheduled_tasks::get_goat_message_content_type;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    AssertCommitStatus, ChallengeSubStatus, CommitBlockHashStatus, WatchtowerChallengeStatus,
};
use bitvm2_lib::transactions::base::BaseTransaction;
use client::goat_chain::{DisproveTxType, GraphData, PeginStatus, WithdrawStatus};
use client::http_client::async_client::HttpAsyncClient;
use tracing::{error, info, warn};
use uuid::Uuid;

pub mod todo_funcs {
    #![allow(dead_code, unreachable_code, unused_variables)]

    use super::*;
    use crate::rpc_service::proof::{
        OperatorProofRequest, OperatorProofResponse, WatchtowerProofRequest,
        WatchtowerProofResponse,
    };
    use crate::rpc_service::routes::v1::{NODES_OPERATOR_BASE, NODES_WATCHTOWER_BASE};
    use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
    use bitvm2_lib::types::{GuestInputs, SimplifiedBitvm2Graph};
    use goat::{
        connectors::assert_connectors::chunk_assert_commit, disprove_scripts::NUM_GUEST_PUBS_ASSERT,
    };

    // proof network

    /// Returns:
    /// - `Ok(Some(WatchtowerProof), _)` if watchtower proof is available
    /// - `Ok(None, wait_secs)` if watchtower proof is not yet available, with suggested wait time
    pub async fn get_watchtower_proof(
        local_db: &LocalDB,
        http_client: &HttpAsyncClient,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<(Option<Vec<u8>>, usize)> {
        let mut storage_processor = local_db.acquire().await?;
        if let Some(graph) = storage_processor.find_graph(&graph_id).await?
            && let (Some(challenge_txid), Some(challenge_init_txid)) =
                (graph.challenge_txid, graph.watchtower_challenge_init_txid)
        {
            let url = format!(
                "http://{}{}",
                get_proof_build_rpc_host()
                    .ok_or_else(|| anyhow::anyhow!("failed to get proof_build_rpc_host"))?,
                NODES_WATCHTOWER_BASE
            );
            let response = http_client
                .post_response_json::<WatchtowerProofResponse, WatchtowerProofRequest>(
                    &url,
                    &WatchtowerProofRequest {
                        instance_id: instance_id.to_string(),
                        graph_id: graph_id.to_string(),
                        public_key: "".to_string(), // todo need to get public key
                        challenge_txid: challenge_txid.0.to_string(),
                        challenge_init_txid: challenge_init_txid.0.to_string(),
                        execution_layer_block_number: graph.proceed_withdraw_height,
                    },
                )
                .await?;

            if response.proof_data.is_none() {
                bail!("failed to get proof_data: error: {:?}", response.error);
            }
            // todo parse response and  return res
        } else {
            warn!("graph:{graph_id} not found or related txn is none",);
            bail!("No graph in db");
        }

        Ok((Some(b"watchtower_proof".to_vec()), 0))
    }
    pub async fn get_operator_proof_blockhash(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<[u8; 32]> {
        Ok([0xbbu8; 32])
    }

    /// Returns:
    /// - `Ok(Some(OperatorProof), _)` if operator proof is available
    /// - `Ok(None, wait_secs)` if operator proof is not yet available, with suggested wait time
    pub async fn get_operator_proof(
        local_db: &LocalDB,
        http_client: &HttpAsyncClient,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<(Option<(GuestInputs, Groth16Proof, PublicInputs, VerifyingKey)>, usize)> {
        let mut storage_processor = local_db.acquire().await?;
        if let Some(graph) = storage_processor.find_graph(&graph_id).await? {
            let url = format!(
                "http://{}{}",
                get_proof_build_rpc_host()
                    .ok_or_else(|| anyhow::anyhow!("failed to get proof_build_rpc_host"))?,
                NODES_OPERATOR_BASE
            );
            let response = http_client
                .post_response_json::<OperatorProofResponse, OperatorProofRequest>(
                    &url,
                    &OperatorProofRequest {
                        instance_id: instance_id.to_string(),
                        graph_id: graph_id.to_string(),
                        execution_layer_block_number: graph.proceed_withdraw_height,
                    },
                )
                .await?;

            if response.proof_data.is_none() {
                bail!("failed to get proof_data: error: {:?}", response.error);
            }

            // todo parse response and  return res
        } else {
            warn!("graph:{graph_id} not found");
            bail!("No graph in db");
        }

        // rm me later
        let proof = hex::decode(
            "b6ef2c5aa48a2f599a13bc4d8010e4d0190aeb05ff79e21266aff8dde6353d1756191f0959c787f6dedfc0c47751aed2648775101285b9da2d6c4e912e74891f884bd672f94f4d78528fb10b5410a94b53bcef07f99952ef72b68c72a5c4ff2a3de7c314ffbf17df018a753f070448c2f698706d4c2b99bdb06f928cffe1bea0",
        )?;
        let pis = hex::decode(
            "02000000000000002000000000000000721db33a295a3b29a61c7360486e6d8346288822dc5cab652722e34d4b423d002000000000000000cfdc2f035c3699c6d17563570ea05a3d6d08302487937dd079a6b1671d484c0d",
        )?;
        let proof = goat::proof::deserialize_proof(proof);
        let pis = goat::proof::deserialize_pubin(pis);
        let pk = get_operator_proof_vk(http_client, instance_id, graph_id).await?;
        let guest_inputs = [
            get_guest_constant_value(instance_id, graph_id).await?,
            [0xffu8; 32], // use [0u8; 32] to test non-inclusion challenge
        ];
        Ok((Some((guest_inputs, proof, pis, pk)), 0))
    }
    pub async fn get_operator_proof_vk(
        http_client: &HttpAsyncClient,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<VerifyingKey> {
        // todo update
        let zkm_v1_vk_bytes = hex::decode(
            "e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19ffdb10cf9f7e2b08673477187c33a695a397702cf22005900724518b57f92f2ce08f8dfe36ca3eff63b1743d64812936d8cab0d74c063d260e20a9a3339b2a8c0300000000000000d17e1efc51d15eef04bde8dc794edc9e5788eb7539171d3a49d970ab9215b89c9ab6c5ab119ca81927393ef29332a1d15ac5f197b878ea89a1f8f686b747011eaad636dcb52cdfd674d155ddd67d21186fbdd1c0a62ebd74dcd6ddc6784b819e",
        )?;
        Ok(goat::proof::deserialize_vk(zkm_v1_vk_bytes))
    }
    pub async fn get_guest_constant_value(instance_id: Uuid, graph_id: Uuid) -> Result<[u8; 32]> {
        Ok([0xccu8; 32])
    }

    // other operations
    pub fn avg_block_time_secs(network: Network) -> u64 {
        match network {
            Network::Bitcoin => 600, // 10 minutes
            Network::Testnet => 300, // 5 minutes
            Network::Regtest => 60,  // 1 minute
            Network::Signet => 60,   // 1 minute
            _ => 600,                // default to 10 minutes
        }
    }
    pub fn assert_commmit_num() -> usize {
        let use_compact = false;
        let wots32_num = NUM_GUEST_PUBS_ASSERT + NUM_PUBS + NUM_U256;
        let wots16_num = NUM_HASH;
        chunk_assert_commit(wots32_num, wots16_num, use_compact).len()
    }
    pub fn min_required_operator() -> usize {
        // todo!("get min required operator number")
        1
    }
    pub fn min_required_watchtower() -> usize {
        // todo!("get min required watchtower number")
        1
    }
    pub async fn publish_graph_to_ipfs(ipfs: &IPFS, graph: &Bitvm2Graph) -> Result<String> {
        todo!("publish graph to ipfs")
    }
    pub async fn validate_init_graph(
        local_db: &LocalDB,
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        graph: &SimplifiedBitvm2Graph,
    ) -> Result<()> {
        // Basic structural and on-chain consistency checks for an incoming graph proposal.
        // Return SpecialError::InvalidGraph on any validation failure.
        // 1) Rebuild full graph (ensures signatures present if flags are set and tx graph is coherent)
        let full_graph = Bitvm2Graph::from_simplified(graph)
            .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;

        // 2) Network must match local node network
        let net = get_network();
        if graph.parameters.instance_parameters.network != net {
            bail!(SpecialError::InvalidGraph(format!(
                "network mismatch: graph={:?} local={:?}",
                graph.parameters.instance_parameters.network, net
            )));
        }

        // 3) Committee pubkeys must match what's registered on GoatChain for this instance
        let instance_id = graph.parameters.instance_parameters.instance_id;
        let committee_on_chain =
            goat_client.gateway_get_committee_pubkeys(&instance_id).await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to load committee from chain: {e}"))
            })?;
        if committee_on_chain != graph.parameters.instance_parameters.committee_pubkeys {
            bail!(SpecialError::InvalidGraph(
                "committee pubkeys mismatch with GoatChain".to_string()
            ));
        }

        // 4) Challenge amount and assert-commit count must match local constants
        if graph.parameters.challenge_amount != super::todo_funcs::challenge_amount() {
            bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
        }
        if graph.assert_commit_num != super::todo_funcs::assert_commmit_num() {
            bail!(SpecialError::InvalidGraph("unexpected assert_commit_num".to_string()));
        }

        // 5) Watchtower config sanity: number of watchtowers should match number of hashlocks and registry size
        let watchtowers_on_chain =
            goat_client.committee_mana_get_watchtowers().await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to load watchtowers from chain: {e}"))
            })?;
        if graph.parameters.watchtower_pubkeys.len() != graph.parameters.hashlocks.len() {
            bail!(SpecialError::InvalidGraph(
                "watchtower_pubkeys and hashlocks length mismatch".to_string()
            ));
        }
        // deduplicate watchtower pubkeys: reject graphs that contain duplicate watchtower entries
        {
            use std::collections::HashSet;
            let mut seen = HashSet::new();
            for pk in &graph.parameters.watchtower_pubkeys {
                if !seen.insert(*pk) {
                    bail!(SpecialError::InvalidGraph(
                        "duplicate watchtower pubkey in graph".to_string()
                    ));
                }
            }
        }
        // allow unregistered watchtowers as long as enough registered ones exist
        let required = super::todo_funcs::min_required_watchtower();
        let valid_registered = graph
            .parameters
            .watchtower_pubkeys
            .iter()
            .filter(|pk| watchtowers_on_chain.contains(pk))
            .count();
        if valid_registered < required {
            bail!(SpecialError::InvalidGraph(format!(
                "insufficient registered watchtowers: have {valid_registered}, required {required}"
            )));
        }

        // 6) Operator stake sanity: verify operator is registered and has enough locked stake
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
        goat_client: &GOATClient,
        graph: &SimplifiedBitvm2Graph,
        endorse_sigs: &[(PublicKey, EvmAddress, Vec<u8>)],
    ) -> Result<()> {
        // 1) Rebuild full graph to ensure structure is coherent and txns derivable
        let full_graph = Bitvm2Graph::from_simplified(graph)
            .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;

        // 2) Repeat key static checks (network, committee set, counts)
        let net = get_network();
        if graph.parameters.instance_parameters.network != net {
            bail!(SpecialError::InvalidGraph(format!(
                "network mismatch: graph={:?} local={:?}",
                graph.parameters.instance_parameters.network, net
            )));
        }
        let instance_id = graph.parameters.instance_parameters.instance_id;
        let committee_on_chain =
            goat_client.gateway_get_committee_pubkeys(&instance_id).await.map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to load committee from chain: {e}"))
            })?;
        if committee_on_chain != graph.parameters.instance_parameters.committee_pubkeys {
            bail!(SpecialError::InvalidGraph(
                "committee pubkeys mismatch with GoatChain".to_string()
            ));
        }
        if graph.parameters.watchtower_pubkeys.len() != graph.parameters.hashlocks.len() {
            bail!(SpecialError::InvalidGraph(
                "watchtower_pubkeys and hashlocks length mismatch".to_string()
            ));
        }
        if graph.parameters.challenge_amount != super::todo_funcs::challenge_amount() {
            bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
        }
        if graph.assert_commit_num != super::todo_funcs::assert_commmit_num() {
            bail!(SpecialError::InvalidGraph("unexpected assert_commit_num".to_string()));
        }

        // 3) Validate endorsements: unique, from legitimate committee members, and signatures recover to the provided EVM address
        use std::collections::HashSet;
        let mut seen_committee: HashSet<PublicKey> = HashSet::new();
        let mut seen_evm: HashSet<EvmAddress> = HashSet::new();
        let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await.map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to load instance data: {e}"))
        })?;

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
        Amount::from_sat(100000)
    }
    pub fn challenge_amount() -> Amount {
        Amount::from_sat(20000)
    }
    pub fn prekickoff_fee_amount(replenish_fee_inputs_num: usize) -> Amount {
        let tx_vbytes = PRE_KICKOFF_BASE_VBYTES
            + (replenish_fee_inputs_num as u64 * CHEKSIG_P2WSH_INPUT_VBYTES);
        Amount::from_sat(tx_vbytes)
    }
    pub async fn get_preimage(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
        index: usize,
    ) -> Result<Vec<u8>> {
        let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
        Ok(operator_master_key.preimage_for_graph(graph_id, index))
    }
    pub async fn broadcast_nonstandard_tx(btc_client: &BTCClient, tx: &Transaction) -> Result<()> {
        match broadcast_tx(btc_client, tx).await {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!("broadcast_nonstandard_tx not implemented yet: {} , Skipped", e);
                Ok(())
            }
        }
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
    graph: Option<&Bitvm2Graph>,
    scan_from_status: Option<GraphStatus>,
    scan_from_sub_status: Option<ChallengeSubStatus>,
) -> Result<(GraphStatus, Option<ChallengeSubStatus>)> {
    let graph = match graph {
        Some(g) => g,
        None => {
            let g = get_graph(local_db, instance_id, graph_id).await?;
            match g {
                Some(g) => &Bitvm2Graph::from_simplified(&g)?,
                None => bail!("Graph {graph_id} not found in local db"),
            }
        }
    };
    let mut current_status = match scan_from_status {
        Some(s) => s,
        None => {
            if graph.committee_pre_signed() {
                GraphStatus::CommitteePresigned
            } else {
                return Ok((GraphStatus::OperatorPresigned, None));
            }
        }
    };
    let mut sub_status = match scan_from_sub_status {
        Some(s) => s,
        None => ChallengeSubStatus {
            watchtower_challenge_status: WatchtowerChallengeStatus::None,
            commit_blockhash_status: CommitBlockHashStatus::None,
            assert_commit_status: AssertCommitStatus::None,
            disprove_type: None,
            disprove_index: 0,
        },
    };
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
        // TBD: obesolete graph when pegin is claimed rather than processing
        if pegin_data.status != PeginStatus::Withdrawable
            && withdraw_data.status == WithdrawStatus::None
        {
            current_status = GraphStatus::Obsoleted;
        }
    }
    // check Prekickoff
    let prekickoff_txid = graph.cur_prekickoff.tx().compute_txid();
    if matches!(
        current_status,
        GraphStatus::OperatorPresigned
            | GraphStatus::CommitteePresigned
            | GraphStatus::OperatorDataPushed
            | GraphStatus::Obsoleted
    ) {
        if !tx_on_chain(btc_client, &prekickoff_txid).await? {
            update_graph_status(local_db, instance_id, graph_id, current_status, None).await?;
            return Ok((current_status, None));
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
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    if matches!(current_status, GraphStatus::PreKickoff | GraphStatus::Obsoleted) {
        let kickoff_connector_vout = 1;
        if let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &prekickoff_txid, kickoff_connector_vout).await?
        {
            if spent_txid != kickoff_txid {
                update_graph_status(local_db, instance_id, graph_id, GraphStatus::Skipped, None)
                    .await?;
                return Ok((GraphStatus::Skipped, None));
            } else {
                current_status = GraphStatus::OperatorKickOff;
            }
        } else {
            update_graph_status(local_db, instance_id, graph_id, current_status, None).await?;
            return Ok((current_status, None));
        }
    }
    // check Take1/Challenge
    let take1_txid = graph.take1.tx().compute_txid();
    let connector_a_vout = 0;
    if current_status == GraphStatus::OperatorKickOff {
        if let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
        {
            if spent_txid != take1_txid {
                current_status = GraphStatus::Challenge;
            } else {
                update_graph_status(
                    local_db,
                    instance_id,
                    graph_id,
                    GraphStatus::OperatorTake1,
                    None,
                )
                .await?;
                return Ok((GraphStatus::OperatorTake1, None));
            }
        } else {
            update_graph_status(
                local_db,
                instance_id,
                graph_id,
                GraphStatus::OperatorKickOff,
                None,
            )
            .await?;
            return Ok((GraphStatus::OperatorKickOff, None));
        }
    }
    // check Take2/Disprove
    let take2_txid = graph.take2.tx().compute_txid();
    if current_status == GraphStatus::Challenge {
        let connector_e_vout = 3;
        if let Some(spent_txid) =
            outpoint_spent_txid(btc_client, &kickoff_txid, connector_e_vout).await?
        {
            let (current_status, sub_status) = if spent_txid != take2_txid {
                sub_status.disprove_type = Some(DisproveTxType::Disprove);
                (GraphStatus::Disprove, Some(sub_status))
            } else {
                (GraphStatus::OperatorTake2, None)
            };
            update_graph_status(local_db, instance_id, graph_id, current_status, sub_status)
                .await?;
            return Ok((current_status, sub_status));
        }
    }
    // check Watchtower-Challenge & Assert-Commit process
    if current_status == GraphStatus::Challenge {
        // check Watchtower Challenge process
        let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
        if tx_on_chain(btc_client, &watchtower_challenge_init_txid).await? {
            sub_status.watchtower_challenge_status = WatchtowerChallengeStatus::OperatorInit;
            sub_status.commit_blockhash_status = CommitBlockHashStatus::None; // set None
            let watchtower_num = graph.parameters.watchtower_pubkeys.len();
            let connector_g_vout = watchtower_num * 2;
            let connector_f_vout = watchtower_num * 2 + 1;
            if let Some(spent_txid) = outpoint_spent_txid(
                btc_client,
                &watchtower_challenge_init_txid,
                connector_f_vout as u64,
            )
            .await?
            {
                // this must not be Take2 because Take2 is already checked above
                current_status = GraphStatus::Disprove;
                let spent_tx = btc_client.get_tx(&spent_txid).await?.unwrap();
                let first_input_vout = spent_tx.input[0].previous_output.vout;
                if first_input_vout == connector_g_vout as u32 {
                    sub_status.commit_blockhash_status =
                        CommitBlockHashStatus::OperatorCommitTimeout;
                    sub_status.disprove_type = Some(DisproveTxType::OperatorCommitTimeout);
                    sub_status.watchtower_challenge_status =
                        WatchtowerChallengeStatus::WatchtowerChallengeDisproveFinished;
                } else {
                    sub_status.disprove_type = Some(DisproveTxType::OperatorNack);
                    sub_status.disprove_index = (first_input_vout / 2) as i32;
                    sub_status.watchtower_challenge_status =
                        WatchtowerChallengeStatus::WatchtowerChallengeDisproveFinished;
                }
                update_graph_status(
                    local_db,
                    instance_id,
                    graph_id,
                    current_status,
                    Some(sub_status),
                )
                .await?;
                return Ok((current_status, Some(sub_status)));
            } else if let Some(watchtower_challenge_init_height) =
                btc_client.get_tx_status(&watchtower_challenge_init_txid).await?.block_height
            {
                let current_height = btc_client.get_height().await?;
                if current_height > watchtower_challenge_init_height + nack_timelock(get_network())
                {
                    for i in 0..watchtower_num {
                        let ack_connector_vout = i * 2 + 1;
                        if let None = outpoint_spent_txid(
                            btc_client,
                            &watchtower_challenge_init_txid,
                            ack_connector_vout as u64,
                        )
                        .await?
                        {
                            sub_status.watchtower_challenge_status =
                                WatchtowerChallengeStatus::OperatorACKTimeout;
                            break;
                        }
                    }
                } else if current_height
                    > watchtower_challenge_init_height
                        + watchtower_challenge_timeout_timelock(get_network())
                {
                    for i in 0..watchtower_num {
                        let challenge_connector_vout = i * 2;
                        if let None = outpoint_spent_txid(
                            btc_client,
                            &watchtower_challenge_init_txid,
                            challenge_connector_vout as u64,
                        )
                        .await?
                        {
                            sub_status.watchtower_challenge_status =
                                WatchtowerChallengeStatus::WatchtowerChallengeTimeout;
                            break;
                        }
                    }
                }
                if current_height
                    > watchtower_challenge_init_height
                        + commit_blockhash_timeout_timelock(get_network())
                {
                    let connector_g_vout = watchtower_num * 2;
                    if let None = outpoint_spent_txid(
                        btc_client,
                        &watchtower_challenge_init_txid,
                        connector_g_vout as u64,
                    )
                    .await?
                    {
                        sub_status.commit_blockhash_status =
                            CommitBlockHashStatus::OperatorCommitTimeout;
                    }
                }
            }
            if let Some(_) = outpoint_spent_txid(
                btc_client,
                &watchtower_challenge_init_txid,
                connector_g_vout as u64,
            )
            .await?
            {
                // this must be OperatorCommit because OperatorCommitTimeout is already checked above
                sub_status.commit_blockhash_status = CommitBlockHashStatus::OperatorCommit;
            }
        }
        // check Assert Commit process
        let assert_init_txid = graph.assert_init.tx().compute_txid();
        if tx_on_chain(btc_client, &assert_init_txid).await? {
            sub_status.assert_commit_status = AssertCommitStatus::OperatorInit;
            let assert_commit_num = graph.assert_commit_timeout_txns.len();
            let connector_d_vout = assert_commit_num;
            if let Some(spent_txid) =
                outpoint_spent_txid(btc_client, &assert_init_txid, connector_d_vout as u64).await?
            {
                // this must not be Take2 because Take2 is already checked above
                current_status = GraphStatus::Disprove;
                let spent_tx = btc_client.get_tx(&spent_txid).await?.unwrap();
                let first_input_vout = spent_tx.input[0].previous_output.vout;
                sub_status.disprove_type = Some(DisproveTxType::AssertTimeout);
                sub_status.disprove_index = first_input_vout as i32;
                update_graph_status(
                    local_db,
                    instance_id,
                    graph_id,
                    current_status,
                    Some(sub_status),
                )
                .await?;
                return Ok((current_status, Some(sub_status)));
            } else {
                if let Some(assert_init_height) =
                    btc_client.get_tx_status(&assert_init_txid).await?.block_height
                {
                    let current_height = btc_client.get_height().await?;
                    if current_height
                        > assert_init_height + assert_commit_timeout_timelock(get_network())
                    {
                        for i in 0..assert_commit_num {
                            let assert_connector_vout = i;
                            if let None = outpoint_spent_txid(
                                btc_client,
                                &assert_init_txid,
                                assert_connector_vout as u64,
                            )
                            .await?
                            {
                                sub_status.assert_commit_status =
                                    AssertCommitStatus::OperatorCommitTimeout;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    update_graph_status(local_db, instance_id, graph_id, current_status, Some(sub_status)).await?;
    Ok((current_status, Some(sub_status)))
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
        (Challenge, OperatorTake2) => Some(GraphCompensateEventKind::Take2Sent),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn compensate_graph_events(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: Option<&Bitvm2Graph>,
    scan_from_status: Option<GraphStatus>,
    compensate_from_status: GraphStatus,
    final_status: GraphStatus,
    final_sub_status: Option<ChallengeSubStatus>,
) -> Result<()> {
    use GOATMessageContent::*;

    let scan_start = scan_from_status.unwrap_or(compensate_from_status);

    let effective_from = if scan_start.is_after(&compensate_from_status) {
        scan_start
    } else {
        compensate_from_status
    };

    if !effective_from.is_before(&final_status) {
        tracing::debug!(
            "Skip compensating graph events: effective_from {effective_from:?} is not before final_status {final_status:?}",
        );
        return Ok(());
    }

    let mut rev_path = Vec::new();
    let mut cur = final_status;
    loop {
        rev_path.push(cur);
        if cur == effective_from {
            break;
        }
        cur = match cur.get_previous_status() {
            Some(prev) => prev,
            None => {
                tracing::debug!(
                    "Stop compensating graph events early: no previous status for {cur:?} while targeting {effective_from:?}",
                );
                return Ok(());
            }
        };
    }
    rev_path.reverse();

    for window in rev_path.windows(2) {
        let s_from = window[0];
        let s_to = window[1];

        if let Some(kind) = map_transition_to_event(s_from, s_to) {
            match kind {
                GraphCompensateEventKind::PreKickoffSent => {
                    let prekickoff_sent =
                        PreKickoffSent(crate::action::PreKickoffSent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &prekickoff_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::KickoffSent => {
                    let kickoff_sent =
                        KickoffSent(crate::action::KickoffSent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &kickoff_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::Take1Sent => {
                    let take1_sent = Take1Sent(crate::action::Take1Sent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &take1_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::ChallengeSent => {
                    let graph = match graph {
                        Some(g) => g,
                        None => {
                            let g = get_graph(local_db, instance_id, graph_id).await?;
                            match g {
                                Some(g) => &Bitvm2Graph::from_simplified(&g)?,
                                None => bail!("Graph {graph_id} not found in local db"),
                            }
                        }
                    };
                    let kickoff_txid = graph.kickoff.tx().compute_txid();
                    let take1_txid = graph.take1.tx().compute_txid();
                    let connector_a_vout = 0;
                    if let Some(challenge_txid) =
                        outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
                        && challenge_txid != take1_txid
                    {
                        let challenge_sent = ChallengeSent(crate::action::ChallengeSent {
                            instance_id,
                            graph_id,
                            challenge_txid,
                        });
                        let message = GOATMessage::from_typed(Actor::All, &challenge_sent)?;
                        push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                    }
                }
                GraphCompensateEventKind::DisproveSent => {
                    let sub_status = match final_sub_status {
                        Some(ref s) => s,
                        None => {
                            tracing::error!(
                                "No final_sub_status provided for DisproveSent compensation!"
                            );
                            continue;
                        }
                    };
                    let disprove_type = match sub_status.disprove_type {
                        Some(t) => t,
                        None => {
                            tracing::error!(
                                "No disprove_type in final_sub_status for DisproveSent compensation!"
                            );
                            continue;
                        }
                    };
                    let graph = match graph {
                        Some(g) => g,
                        None => {
                            let g = get_graph(local_db, instance_id, graph_id).await?;
                            match g {
                                Some(g) => &Bitvm2Graph::from_simplified(&g)?,
                                None => bail!("Graph {graph_id} not found in local db"),
                            }
                        }
                    };
                    let kickoff_txid = graph.kickoff.tx().compute_txid();
                    let take1_txid = graph.take1.tx().compute_txid();
                    let connector_a_vout = 0;
                    let challenge_start_txid = if let Some(challenge_txid) =
                        outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
                    {
                        if challenge_txid == take1_txid {
                            tracing::error!("Take1 found for DisproveSent compensation!");
                            continue;
                        }
                        Some(challenge_txid)
                    } else {
                        None
                    };
                    let challenge_finish_txid = match disprove_type {
                        DisproveTxType::Disprove => {
                            let connector_e_vout = 3;
                            outpoint_spent_txid(btc_client, &kickoff_txid, connector_e_vout)
                                .await?
                                .ok_or(anyhow!(
                                    "No Disprove txn found for DisproveSent compensation!"
                                ))?
                        }
                        DisproveTxType::OperatorCommitTimeout => {
                            let watchtower_num = graph.parameters.watchtower_pubkeys.len();
                            let connector_f_vout = watchtower_num * 2 + 1;
                            let watchtower_challenge_init_txid =
                                graph.watchtower_challenge_init.tx().compute_txid();
                            outpoint_spent_txid(
                                btc_client,
                                &watchtower_challenge_init_txid,
                                connector_f_vout as u64,
                            )
                            .await?
                            .ok_or(anyhow!(
                                "No OperatorCommitTimeout txn found for DisproveSent compensation!"
                            ))?
                        }
                        DisproveTxType::OperatorNack => {
                            let watchtower_num = graph.parameters.watchtower_pubkeys.len();
                            let connector_f_vout = watchtower_num * 2 + 1;
                            let watchtower_challenge_init_txid =
                                graph.watchtower_challenge_init.tx().compute_txid();
                            outpoint_spent_txid(
                                btc_client,
                                &watchtower_challenge_init_txid,
                                connector_f_vout as u64,
                            )
                            .await?
                            .ok_or(anyhow!(
                                "No OperatorNack txn found for DisproveSent compensation!"
                            ))?
                        }
                        DisproveTxType::AssertTimeout => {
                            let assert_commit_num = graph.assert_commit_timeout_txns.len();
                            let connector_d_vout = assert_commit_num;
                            let assert_init_txid = graph.assert_init.tx().compute_txid();
                            outpoint_spent_txid(
                                btc_client,
                                &assert_init_txid,
                                connector_d_vout as u64,
                            )
                            .await?
                            .ok_or(anyhow!(
                                "No AssertTimeout txn found for DisproveSent compensation!"
                            ))?
                        }
                        DisproveTxType::QuickChallenge => {
                            let guardian_connector_vout = 4;
                            outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout)
                                .await?
                                .ok_or(anyhow!(
                                    "No QuickChallenge txn found for DisproveSent compensation!"
                                ))?
                        }
                        DisproveTxType::ChallengeIncompleteKickoff => {
                            let guardian_connector_vout = 4;
                            outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout)
                                .await?
                                .ok_or(
                                    anyhow!("No ChallengeIncompleteKickoff txn found for DisproveSent compensation!")
                                )?
                        }
                    };
                    let disprove_sent = DisproveSent(crate::action::DisproveSent {
                        instance_id,
                        graph_id,
                        disprove_type,
                        index: sub_status.disprove_index as usize,
                        challenge_start_txid,
                        challenge_finish_txid,
                    });
                    let message = GOATMessage::from_typed(Actor::All, &disprove_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::Take2Sent => {
                    let take2_sent = Take2Sent(crate::action::Take2Sent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &take2_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
            }
        }
    }

    Ok(())
}

pub fn build_graph_data(graph: &Bitvm2Graph) -> Result<GraphData> {
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
    let commit_timout_txid =
        graph.blockhash_commit_timeout.finalize().compute_txid().to_byte_array();
    let assert_timeout_txids: Vec<[u8; 32]> = graph
        .assert_commit_timeout_txns
        .iter()
        .map(|tx| tx.finalize().compute_txid().to_byte_array())
        .collect();
    let nack_txids: Vec<[u8; 32]> =
        graph.nack_txns.iter().map(|tx| tx.finalize().compute_txid().to_byte_array()).collect();

    Ok(GraphData {
        operator_pubkey_prefix,
        operator_pubkey,
        pegin_txid,
        kickoff_txid,
        take1_txid,
        take2_txid,
        commit_timout_txid,
        assert_timeout_txids,
        nack_txids,
    })
}

pub async fn get_graph_digest(goat_client: &GOATClient, graph: &Bitvm2Graph) -> Result<[u8; 32]> {
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
) -> Result<Bitvm2InstanceParameters> {
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
    Ok(Bitvm2InstanceParameters {
        network,
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(pegin_data.pegin_amount_sats),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}

pub async fn is_take1_timelock_expired(client: &BTCClient, kickoff_height: u32) -> Result<bool> {
    let lock_blocks = take1_timelock(get_network());
    let current_height = client.get_height().await?;
    Ok(current_height >= kickoff_height + lock_blocks)
}

pub async fn is_take2_timelock_expired(
    client: &BTCClient,
    watchtower_challenge_init_height: u32,
    assert_init_height: u32,
) -> Result<bool> {
    let lock_blocks = take2_timelocks(get_network());
    let current_height = client.get_height().await?;
    Ok(current_height >= watchtower_challenge_init_height + lock_blocks.0
        || current_height >= assert_init_height + lock_blocks.1)
}

/// Loads partial scripts from a local cache file.
/// If cache file does not exist, generate partial scripts by vk an cache it
pub async fn get_partial_scripts(local_db: &LocalDB) -> Result<Vec<ScriptBuf>> {
    let scripts_cache_path = SCRIPT_CACHE_FILE_NAME;
    if Path::new(scripts_cache_path).exists() {
        let file = File::open(scripts_cache_path)?;
        let reader = BufReader::new(file);
        let scripts_bytes: Vec<ScriptBuf> = bincode::deserialize_from(reader)?;
        Ok(scripts_bytes)
    } else {
        let partial_scripts = generate_partial_scripts(&get_vk(local_db).await?);
        if let Some(parent) = Path::new(scripts_cache_path).parent() {
            fs::create_dir_all(parent)?;
        };
        let file = File::create(scripts_cache_path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &partial_scripts)?;
        Ok(partial_scripts)
    }
}

pub async fn get_disprove_scripts(
    local_db: &LocalDB,
    graph_params: &Bitvm2GraphParameters,
) -> Result<Vec<ScriptBuf>> {
    let partial_scripts = get_partial_scripts(local_db).await?;
    let (mut disprove_scripts, disprove_scripts_1) = generate_disprove_scripts(
        &partial_scripts,
        graph_params.operator_wots_pubkeys.clone(),
        &graph_params.guest_constant_value,
        &graph_params.hashlocks,
    );
    disprove_scripts.extend(disprove_scripts_1);
    Ok(disprove_scripts)
}

pub async fn get_fee_rate(client: &BTCClient) -> Result<f64> {
    match client.network() {
        //TODO mempool api /fee-estimates failed, fix it latter
        Network::Testnet | Network::Regtest => Ok(2.0),
        _ => {
            let res = client.get_fee_estimates().await?;
            Ok(*res.get(&DEFAULT_CONFIRMATION_TARGET).ok_or(anyhow!(
                "fee for {DEFAULT_CONFIRMATION_TARGET} confirmation target not found"
            ))?)
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

const ASSERT_COMMIT_CACHE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct CachedAssertCommitInput {
    txin: Vec<u8>,
    amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
struct CachedAssertCommitInputs {
    version: u32,
    inputs: Vec<CachedAssertCommitInput>,
}

fn assert_commit_cache_path(graph_id: Uuid) -> PathBuf {
    Path::new(ASSERT_COMMITS_CACHE_DIR).join(format!("{graph_id}.json"))
}

fn load_assert_commit_inputs_from_cache(graph_id: Uuid) -> Option<Vec<(TxIn, Amount)>> {
    let path = assert_commit_cache_path(graph_id);
    if !path.exists() {
        return None;
    }
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            warn!("failed to open assert-commit cache {path:?}: {err:?}");
            return None;
        }
    };
    let reader = BufReader::new(file);
    let cached: CachedAssertCommitInputs = match serde_json::from_reader(reader) {
        Ok(data) => data,
        Err(err) => {
            warn!("failed to deserialize assert-commit cache {path:?}: {err:?}");
            return None;
        }
    };
    if cached.version != ASSERT_COMMIT_CACHE_VERSION {
        warn!(
            "assert-commit cache version mismatch for {path:?}, expecting {ASSERT_COMMIT_CACHE_VERSION}, got {}",
            cached.version
        );
        return None;
    }
    let mut inputs = Vec::with_capacity(cached.inputs.len());
    for item in cached.inputs {
        match deserialize::<TxIn>(&item.txin) {
            Ok(txin) => inputs.push((txin, Amount::from_sat(item.amount_sat))),
            Err(err) => {
                warn!("failed to decode txin from cache {path:?}: {err:?}");
                return None;
            }
        }
    }
    Some(inputs)
}

fn store_assert_commit_inputs_in_cache(graph_id: Uuid, inputs: &[(TxIn, Amount)]) -> Result<()> {
    fs::create_dir_all(ASSERT_COMMITS_CACHE_DIR)?;
    let path = assert_commit_cache_path(graph_id);
    let file = File::create(&path)?;
    let writer = BufWriter::new(file);
    let payload = CachedAssertCommitInputs {
        version: ASSERT_COMMIT_CACHE_VERSION,
        inputs: inputs
            .iter()
            .map(|(txin, amount)| CachedAssertCommitInput {
                txin: serialize(txin),
                amount_sat: amount.to_sat(),
            })
            .collect(),
    };
    serde_json::to_writer(writer, &payload)?;
    Ok(())
}

fn cleanup_assert_commit_cache(graph_id: Uuid) -> Result<()> {
    let path = assert_commit_cache_path(graph_id);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub async fn challenger_force_skip_kickoff(
    client: &BTCClient,
    graph: &Bitvm2Graph,
) -> Result<Txid> {
    let challenger_master_key = ChallengerMasterKey::new(get_bitvm_key()?);
    let challenger_master_keypair = challenger_master_key.master_keypair();
    let challenger_receive_address =
        node_p2wsh_address(get_network(), &challenger_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (force_skip_kickoff_tx, anchor_added) =
        build_force_skip_kickoff_tx(graph, challenger_receive_address, fee_rate)?;
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

pub async fn challenger_quick_challenge(client: &BTCClient, graph: &Bitvm2Graph) -> Result<Txid> {
    let challenger_master_key = ChallengerMasterKey::new(get_bitvm_key()?);
    let challenger_master_keypair = challenger_master_key.master_keypair();
    let challenger_receive_address =
        node_p2wsh_address(get_network(), &challenger_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (quick_challenge_tx, anchor_added) =
        build_quick_challenge_tx(graph, challenger_receive_address, fee_rate)?;
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

pub async fn build_cpfp_txns(
    btc_client: &BTCClient,
    parent_tx: &Transaction,
    anchor_vout: u64,
    parent_tx_total_input_amount: Amount,
) -> Result<Option<Transaction>> {
    let network = get_network();
    if network == Network::Regtest || network == Network::Testnet {
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
    let assert_commit_num = todo_funcs::assert_commmit_num();
    let watchtower_num = goat_client.committee_mana_get_watchtowers().await?.len();
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
        assert_commit_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {e}"))
}

pub async fn build_prekickoff_params(
    btc_client: &BTCClient,
    graph_nonce: u64,
    cur_prekickoff_txn: PrekickoffTransaction,
) -> Result<PrekickoffParameters> {
    let prekickoff_remaining_amount = cur_prekickoff_txn.tx().output[2].value;
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
    local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_parameters: Bitvm2InstanceParameters,
    prekickoff_parameters: PrekickoffParameters,
    graph_nonce: u64,
    graph_id: Uuid,
) -> Result<Bitvm2GraphParameters> {
    let instance_id = instance_parameters.instance_id;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_pubkey = operator_master_keypair.public_key().into();
    let operator_receive_address =
        node_p2wsh_address(instance_parameters.network, &operator_pubkey);
    let operator_wots_pubkeys = operator_master_key.wots_keypair_for_graph(graph_id).1;
    let watchtower_pubkeys = goat_client.committee_mana_get_watchtowers().await?;
    let mut hashlocks = vec![];
    for index in 0..watchtower_pubkeys.len() {
        let preimage = todo_funcs::get_preimage(local_db, instance_id, graph_id, index).await?;
        let hashlock = hash160(&preimage);
        hashlocks.push(hashlock);
    }
    let guest_constant_value = todo_funcs::get_guest_constant_value(instance_id, graph_id).await?;
    Ok(Bitvm2GraphParameters {
        instance_parameters,
        prekickoff_parameters,
        graph_id,
        graph_nonce,
        challenge_amount: todo_funcs::challenge_amount(),
        operator_pubkey,
        operator_wots_pubkeys,
        operator_receive_address,
        watchtower_pubkeys,
        hashlocks,
        guest_constant_value,
    })
}

pub async fn operator_skip_graph(btc_client: &BTCClient, graph: &mut Bitvm2Graph) -> Result<()> {
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_receive_address =
        node_p2wsh_address(get_network(), &operator_master_keypair.public_key().into());
    let operator_graph_keypair = operator_master_key.master_keypair();
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce);
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

pub async fn operator_kickoff(btc_client: &BTCClient, graph: &mut Bitvm2Graph) -> Result<()> {
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce);
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

/// Return values: (Some(split_txid), has_pending_fee_inputs, Some(wait_proof_gen_secs))
/// - `split_txid`: If a split transaction was broadcasted to consolidate UTXOs for fees, its txid is returned here.
/// - `has_pending_fee_inputs`: Indicates whether some of UTXOs for fees are still pending.
/// - `wait_proof_gen_secs`: If proof generation is still in progress, this returns the estimated time in seconds to wait before retrying.
pub async fn operator_send_assert_commit(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    http_client: &HttpAsyncClient,
    graph: &mut Bitvm2Graph,
) -> Result<(Option<Txid>, bool, Option<usize>)> {
    // Prepare keys and proof materials
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let node_keypair = operator_master_key.master_keypair();
    let node_public_key: PublicKey = node_keypair.public_key().into();
    let node_address = node_p2wsh_address(get_network(), &node_public_key);
    let fee_rate = get_fee_rate(btc_client).await?;

    // Ensure assert-init is confirmed before sending commits
    let assert_init_txid = graph.assert_init.tx().compute_txid();
    if !tx_confirmed(btc_client, &assert_init_txid).await? {
        bail!("assert-init not confirmed yet, skip assert-commit broadcast");
    }

    // Build or load signed inputs for each assert-commit connector
    let assert_commit_inputs = if let Some(inputs) = load_assert_commit_inputs_from_cache(graph_id)
    {
        tracing::info!("loaded assert-commit inputs from cache for graph_id:{graph_id}");
        inputs
    } else {
        let wots_secret_keys = operator_master_key.wots_keypair_for_graph(graph_id).0;
        let (guest_inputs, proof, groth16_pubin, vk) = match todo_funcs::get_operator_proof(
            local_db,
            http_client,
            instance_id,
            graph_id,
        )
        .await?
        {
            (Some(proof_data), _) => proof_data,
            (None, wait_secs) => {
                tracing::info!(
                    "operator proof generation in progress for graph_id:{graph_id}, wait and retry {wait_secs}s later"
                );
                return Ok((None, false, Some(wait_secs)));
            }
        };
        let inputs = operator_sign_assert_commit(
            node_keypair,
            graph,
            &wots_secret_keys,
            guest_inputs,
            proof,
            groth16_pubin,
            &vk,
        )?;
        if let Err(err) = store_assert_commit_inputs_in_cache(graph_id, &inputs) {
            tracing::warn!("failed to write assert-commit cache for graph_id:{graph_id}: {err:?}");
        }
        inputs
    };

    fn estimate_fee_funding_amount(txin: &TxIn, fee_rate: f64) -> Amount {
        let sample_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin.clone()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: generate_opreturn_script(vec![]),
            }],
        };
        let base_vbytes = sample_tx.weight().to_vbytes_ceil();
        let est_vbytes = base_vbytes + CHEKSIG_P2WSH_INPUT_VBYTES + P2WSH_OUTPUT_VBYTES;
        let est_fee = (est_vbytes as f64 * fee_rate).ceil() as u64;
        Amount::from_sat(est_fee + DUST_AMOUNT + 1_000)
    }

    // filter out already-spent assert-commit connectors
    let mut pending_assert_commit_txins: Vec<(usize, TxIn, Amount)> = vec![];
    let mut required_fees: Vec<Amount> = vec![];
    for (i, (txin, amount)) in assert_commit_inputs.into_iter().enumerate() {
        if outpoint_spent_txid(btc_client, &assert_init_txid, i as u64).await?.is_none() {
            let est_fee = estimate_fee_funding_amount(&txin, fee_rate);
            pending_assert_commit_txins.push((i, txin, amount));
            required_fees.push(est_fee);
        }
    }
    if pending_assert_commit_txins.is_empty() {
        tracing::info!("no assert-commit inputs to send (all spent)");
        if let Err(err) = cleanup_assert_commit_cache(graph_id) {
            tracing::warn!(
                "failed to cleanup assert-commit cache for graph_id:{graph_id}: {err:?}"
            );
        }
        return Ok((None, false, None));
    }

    // get available fee UTXOs from node address
    let (utxo_sets, split_tx) =
        get_proper_utxo_sets(btc_client, node_address.clone(), required_fees.clone(), fee_rate)
            .await?;

    // broadcast split tx if needed
    if let Some((mut split_tx, txin_amounts)) = split_tx {
        for (i, amount) in txin_amounts.iter().enumerate().take(split_tx.input.len()) {
            node_sign(&mut split_tx, i, *amount, EcdsaSighashType::All, &node_keypair)?;
        }
        let split_txid = split_tx.compute_txid();
        broadcast_tx(btc_client, &split_tx).await?;
        return Ok((Some(split_txid), false, None));
    } else if utxo_sets.is_empty() {
        let current_balance = btc_client
            .get_address_utxo(node_address)
            .await?
            .iter()
            .map(|u| u.value)
            .sum::<Amount>();
        let required_total_fee: Amount = required_fees.into_iter().sum();
        bail!(SpecialError::InsufficientBalance(format!(
            "Not enough balance to complete the transaction, current_balance: {current_balance}, required: {required_total_fee}"
        )));
    };

    // build, sign and broadcast assert-commit txns
    let mut has_pending_fee_input = false;
    for (i, (origin_index, assert_commit_txin, _assert_commit_input_amount)) in
        pending_assert_commit_txins.into_iter().enumerate()
    {
        let fee_inputs = &utxo_sets[i];
        let fee_inputs_total = fee_inputs.iter().map(|input| input.amount).sum::<Amount>();
        let mut current_has_pending_fee_input = false;
        for inputs in fee_inputs.iter() {
            if !tx_confirmed(btc_client, &inputs.outpoint.txid).await? {
                current_has_pending_fee_input = true;
                break;
            }
        }
        if current_has_pending_fee_input {
            has_pending_fee_input = true;
            continue;
        }

        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        tx.input.push(assert_commit_txin);
        for input in fee_inputs {
            tx.input.push(TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            });
        }

        let fee = required_fees[i];
        let change_value = fee_inputs_total - fee;
        if change_value > Amount::from_sat(DUST_AMOUNT) {
            tx.output
                .push(TxOut { value: change_value, script_pubkey: node_address.script_pubkey() });
        } else {
            let op_return_script = generate_opreturn_script(
                format!("assert-commit-{origin_index}").as_bytes().to_vec(),
            );
            tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: op_return_script });
        }

        for (fee_index, fee_input) in fee_inputs.iter().enumerate() {
            let input_index = 1 + fee_index;
            node_sign(
                &mut tx,
                input_index,
                fee_input.amount,
                EcdsaSighashType::All,
                &node_keypair,
            )?;
        }

        broadcast_tx(btc_client, &tx).await?;
    }

    if !has_pending_fee_input && let Err(err) = cleanup_assert_commit_cache(graph_id) {
        warn!("failed to cleanup assert-commit cache for graph_id:{graph_id}: {err:?}");
    }

    Ok((None, has_pending_fee_input, None))
}

pub async fn send_challenge_tx(btc_client: &BTCClient, graph: &Bitvm2Graph) -> Result<Txid> {
    let (mut challenge_tx, _) = export_challenge_tx(graph)?;
    let challenge_keypair = ChallengerMasterKey::new(get_bitvm_key()?).master_keypair();
    let challenger_evm_address = get_node_goat_address()
        .ok_or_else(|| anyhow::anyhow!("failed to get node goat address".to_string()))?;
    challenge_tx.output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: generate_opreturn_script(challenger_evm_address.to_vec()),
    });
    build_sign_and_broadcast_tx(
        btc_client,
        challenge_keypair,
        challenge_tx.input,
        graph.kickoff.tx().output[0].value,
        challenge_tx.output,
    )
    .await
}

pub async fn send_watchtower_challenge_tx(
    btc_client: &BTCClient,
    graph: &Bitvm2Graph,
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

pub async fn endorse_graph(goat_client: &GOATClient, graph: &Bitvm2Graph) -> Result<EvmSignature> {
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

pub async fn verify_graph_endorsement(
    goat_client: &GOATClient,
    evm_address: &EvmAddress,
    graph: &Bitvm2Graph,
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

pub async fn get_vk(db: &LocalDB) -> Result<VerifyingKey> {
    if cfg!(all(feature = "tests", feature = "e2e-tests")) {
        return get_test_vk();
    }

    proofs::get_groth16_vk(db, &proofs::get_zkm_version()).await
}

pub fn get_test_groth16_proof() -> Result<(Groth16Proof, PublicInputs, VerifyingKey)> {
    let proof = hex::decode(
        "b6ef2c5aa48a2f599a13bc4d8010e4d0190aeb05ff79e21266aff8dde6353d1756191f0959c787f6dedfc0c47751aed2648775101285b9da2d6c4e912e74891f884bd672f94f4d78528fb10b5410a94b53bcef07f99952ef72b68c72a5c4ff2a3de7c314ffbf17df018a753f070448c2f698706d4c2b99bdb06f928cffe1bea0",
    )?;
    let pis = hex::decode(
        "02000000000000002000000000000000721db33a295a3b29a61c7360486e6d8346288822dc5cab652722e34d4b423d002000000000000000cfdc2f035c3699c6d17563570ea05a3d6d08302487937dd079a6b1671d484c0d",
    )?;
    let proof = goat::proof::deserialize_proof(proof);
    let pis = goat::proof::deserialize_pubin(pis);
    Ok((proof, pis, get_test_vk()?))
}

pub fn get_test_vk() -> Result<VerifyingKey> {
    let zkm_v1_vk_bytes = hex::decode(
        "e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19ffdb10cf9f7e2b08673477187c33a695a397702cf22005900724518b57f92f2ce08f8dfe36ca3eff63b1743d64812936d8cab0d74c063d260e20a9a3339b2a8c0300000000000000d17e1efc51d15eef04bde8dc794edc9e5788eb7539171d3a49d970ab9215b89c9ab6c5ab119ca81927393ef29332a1d15ac5f197b878ea89a1f8f686b747011eaad636dcb52cdfd674d155ddd67d21186fbdd1c0a62ebd74dcd6ddc6784b819e",
    )?;
    Ok(goat::proof::deserialize_vk(zkm_v1_vk_bytes))
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
    let message = GOATMessage::from_typed(actor.clone(), &message_content)?;
    let msg_type = get_goat_message_content_type(&message_content).to_string();
    let message_id = generate_message_id(business_id, msg_type.clone(), sub_type);
    if is_update || storage_processor.find_messages_by_id(&message_id).await?.is_none() {
        storage_processor
            .upsert_message(Message {
                message_id,
                business_id,
                actor: actor.to_string(),
                from_peer,
                msg_type,
                content: serde_json::to_vec(&message)?,
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

/// store new graph, graph_raw_data, and update instance_id
pub async fn get_bitvm2_graph_from_db(
    _local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Bitvm2Graph> {
    Err(anyhow!("graph:{graph_id} not found"))
}

pub async fn publish_graph_to_ipfs(
    _ipfs: &IPFS,
    _graph_id: Uuid,
    _graph: &Bitvm2Graph,
) -> Result<String> {
    todo!("publish_graph_to_ipfs")
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
            reward: 0,
            service_fee_rate: node_info.service_fee_rate,
            available_peg_btc: node_info.available_peg_btc,
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
        match send_to_peer(swarm, GOATMessage::from_typed(actor, &message_content)?) {
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
    if get_proof_server_url().is_some() {
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
            storage_processor.get_graph_raw_data(&graphs[0].graph_id).await?
    {
        let simplified_graph =
            parse_graph_raw_data(graph_raw_data.raw_data, graphs[0].graph_id).await?;

        Ok(Some((
            (graphs[0].kickoff_index + 1) as u64,
            Bitvm2Graph::from_simplified(&simplified_graph)?.next_prekickoff,
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
    instance_params: &Bitvm2InstanceParameters,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
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
) -> Result<Option<Bitvm2InstanceParameters>> {
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

pub async fn store_graph(local_db: &LocalDB, simple_graph: &SimplifiedBitvm2Graph) -> Result<()> {
    let mut tx = local_db.start_transaction().await?;
    let bitvm2_graph: Bitvm2Graph = Bitvm2Graph::from_simplified(simple_graph)?;
    let (graph_id, instance_id, graph_nonce) = (
        simple_graph.parameters.graph_id,
        simple_graph.parameters.instance_parameters.instance_id,
        simple_graph.parameters.graph_nonce,
    );
    let mut status = GraphStatus::OperatorPresigned.to_string();
    if bitvm2_graph.committee_pre_signed() {
        status = GraphStatus::CommitteePresigned.to_string();
    }
    let current_time = current_time_secs();
    let mut graph = Graph {
        graph_id,
        instance_id,
        kickoff_index: graph_nonce as i64,
        from_addr: "".to_string(),
        to_addr: "".to_string(),
        graph_ipfs_base_url: "".to_string(),
        amount: bitvm2_graph.parameters.instance_parameters.pegin_amount.to_sat() as i64,
        challenge_amount: bitvm2_graph.parameters.challenge_amount.to_sat() as i64,
        status,
        sub_status: "".to_string(),
        operator_pubkey: bitvm2_graph.parameters.operator_pubkey.to_string(),
        cur_prekickoff_txid: Some(bitvm2_graph.cur_prekickoff.finalize().compute_txid().into()),
        next_prekickoff: Some(bitvm2_graph.next_prekickoff.finalize().compute_txid().into()),
        force_skip_kickoff_txid: Some(
            bitvm2_graph.force_skip_kickoff.finalize().compute_txid().into(),
        ),
        quick_challenge_txid: Some(bitvm2_graph.quick_challenge.finalize().compute_txid().into()),
        challenge_incomplete_kickoff_txid: Some(
            bitvm2_graph.challenge_incomplete_kickoff.finalize().compute_txid().into(),
        ),
        pegin_txid: Some(bitvm2_graph.pegin.finalize().compute_txid().into()),
        kickoff_txid: Some(bitvm2_graph.kickoff.finalize().compute_txid().into()),
        take1_txid: Some(bitvm2_graph.take1.finalize().compute_txid().into()),
        challenge_txid: None,
        take2_txid: Some(bitvm2_graph.take2.finalize().compute_txid().into()),
        disprove_txid: None,
        watchtower_challenge_init_txid: Some(
            bitvm2_graph.watchtower_challenge_init.finalize().compute_txid().into(),
        ),
        watchtower_challenge_timeout_txids: bitvm2_graph
            .watchtower_challenge_timeout_txns
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        nack_txids: bitvm2_graph
            .nack_txns
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        blockhash_commit_timeout_txid: Some(
            bitvm2_graph.blockhash_commit_timeout.finalize().compute_txid().into(),
        ),
        assert_init_txid: Some(bitvm2_graph.assert_init.finalize().compute_txid().into()),
        assert_commit_timeout_txids: bitvm2_graph
            .assert_commit_timeout_txns
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        init_withdraw_tx_hash: None,
        bridge_out_start_at: 0,
        zkm_version: proofs::get_zkm_version(),
        status_updated_at: current_time,
        proceed_withdraw_height: 0,
        created_at: current_time,
        updated_at: current_time,
    };

    if let Some(node_info) =
        tx.get_node_by_btc_pub_key(&bitvm2_graph.parameters.operator_pubkey.to_string()).await?
    {
        graph.from_addr = node_info.goat_addr.clone();
        graph.to_addr =
            node_p2wsh_address(get_network(), &bitvm2_graph.parameters.operator_pubkey).to_string();
    }

    tx.upsert_graph(&graph).await?;
    if bitvm2_graph.committee_pre_signed() {
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

/// Parse raw graph data JSON string to SimplifiedBitvm2Graph using spawn_blocking
/// to handle large data and potential stack overflow issues
pub async fn parse_graph_raw_data(
    raw_data: String,
    graph_id: Uuid,
) -> Result<SimplifiedBitvm2Graph> {
    let raw_data_len = raw_data.len();
    let raw_data_clone = raw_data.clone();
    let parse_result = tokio::task::spawn_blocking(move || {
        serde_json::from_str::<SimplifiedBitvm2Graph>(&raw_data_clone)
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

/// Serialize SimplifiedBitvm2Graph to JSON string using spawn_blocking
/// to handle large data and potential stack overflow issues
pub async fn serialize_graph_raw_data(
    graph: &SimplifiedBitvm2Graph,
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
) -> Result<Option<SimplifiedBitvm2Graph>> {
    let mut storage_process = local_db.acquire().await?;
    if let Some(graph_raw_data) = storage_process.get_graph_raw_data(&graph_id).await?
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

pub async fn store_committee_endorse_sig_for_pegin(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    endorse_sig: Vec<u8>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
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
                && let Some(sub_status) = sub_status
                && sub_status != ChallengeSubStatus::default()
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
) -> anyhow::Result<Bitvm2InstanceParameters> {
    let network = Network::from_str(&instance.network)?;
    let committee_pubkeys: Vec<PublicKey> = instance
        .committees_answers
        .iter()
        .map(|(_k, v)| PublicKey::from_slice(v).unwrap())
        .collect();

    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    let utxos: Vec<client::Utxo> = serde_json::from_str(&instance.input_utxos)?;
    Ok(Bitvm2InstanceParameters {
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
