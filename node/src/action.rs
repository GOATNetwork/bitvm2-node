use crate::env;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use anyhow::Result;
use bitcoin::PublicKey;
use bitcoin::{Amount, Network, OutPoint, Txid, key::Keypair};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::keys::*;
use bitvm2_lib::types::{
    Bitvm2Graph, Bitvm2Parameters, CustomInputs, Groth16Proof, PublicInputs, VerifyingKey,
};
use bitvm2_lib::verifier::export_challenge_tx;
use bitvm2_lib::{committee::*, operator::*, verifier::*};
use client::client::BitVM2Client;
use goat::transactions::disprove::DisproveTransaction;
use goat::transactions::take_1::Take1Transaction;
use goat::transactions::take_2::Take2Transaction;
use goat::transactions::{assert::utils::COMMIT_TX_NUM, pre_signed::PreSignedTransaction};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use reqwest::Request;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use statics::*;
use std::str::FromStr;
use store::{Graph, GraphStatus};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum GOATMessageContent {
    CreateInstance(CreateInstance),
    CreateGraphPrepare(CreateGraphPrepare),
    CreateGraph(CreateGraph),
    NonceGeneration(NonceGeneration),
    CommitteePresign(CommitteePresign),
    GraphFinalize(GraphFinalize),
    KickoffReady(KickoffReady),
    KickoffSent(KickoffSent),
    Take1Ready(Take1Ready),
    Take1Sent(Take1Sent),
    ChallengeSent(ChallengeSent),
    AssertSent(AssertSent),
    Take2Ready(Take2Ready),
    Take2Sent(Take2Sent),
    DisproveSent(DisproveSent),
}

#[derive(Serialize, Deserialize)]
pub struct CreateInstance {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGraphPrepare {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
    pub committee_member_pubkey: PublicKey,
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
}

#[derive(Serialize, Deserialize)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
    pub agg_nonces: [AggNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
}

#[derive(Serialize, Deserialize)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct KickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub kickoff_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct AssertSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub assert_init_txid: Txid,
    pub assert_commit_txids: [Txid; COMMIT_TX_NUM],
    pub assert_final_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct Take1Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct Take1Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub take1_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct Take2Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct Take2Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub take2_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct DisproveSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub disprove_txid: Txid,
}

impl GOATMessage {
    pub fn from_typed<T: Serialize>(actor: Actor, value: &T) -> Result<Self, serde_json::Error> {
        let content = serde_json::to_vec(value)?;
        Ok(Self { actor, content })
    }

    pub fn to_typed<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.content)
    }

    pub fn default_message_id() -> MessageId {
        MessageId(b"__inner_message_id__".to_vec())
    }
}

pub mod statics {
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use uuid::Uuid;

    // operator node can only process one graph at a time
    pub static OPERATOR_CURRENT_GRAPH: Lazy<Mutex<Option<(Uuid, Uuid)>>> =
        Lazy::new(|| Mutex::new(None));
    pub fn try_start_new_graph(instance_id: Uuid, graph_id: Uuid) -> bool {
        let mut current = OPERATOR_CURRENT_GRAPH.lock().unwrap();
        if current.is_none() {
            *current = Some((instance_id, graph_id));
            true
        } else {
            false
        }
    }
    pub fn finish_current_graph_processing(instance_id: Uuid, graph_id: Uuid) {
        let mut current = OPERATOR_CURRENT_GRAPH.lock().unwrap();
        if *current == Some((instance_id, graph_id)) {
            *current = None;
        }
    }
    pub fn is_processing_graph() -> bool {
        OPERATOR_CURRENT_GRAPH.lock().unwrap().is_some()
    }
    pub fn current_processing_graph() -> Option<(Uuid, Uuid)> {
        *OPERATOR_CURRENT_GRAPH.lock().unwrap()
    }
    pub fn force_stop_current_graph() {
        *OPERATOR_CURRENT_GRAPH.lock().unwrap() = None;
    }
}

#[allow(unused_variables, dead_code)]
pub mod todo_funcs {
    use super::*;
    use crate::env::*;
    use bitcoin::{
        Address, EcdsaSighashType, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoin_script::{Script, script};
    use bitvm::chunk::api::NUM_TAPS;
    use bitvm2_lib::types::WotsPublicKeys;
    use client::chain::chain_adaptor::WithdrawStatus;
    use esplora_client::Utxo;
    use goat::constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK};
    use goat::transactions::base::Input;
    use goat::transactions::signing::populate_p2wsh_witness;
    use goat::utils::num_blocks_per_network;
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter};
    use std::path::Path;

    /// Determines whether the operator should participate in generating a new graph.
    ///
    /// Conditions:
    /// - Participation should be attempted as often as possible.
    /// - Only one graph can be generated at a time; generation must be sequential, not parallel.
    /// - If the remaining funds are less than the required stake-amount, operator should not participate.
    pub async fn should_generate_graph(
        client: &BitVM2Client,
        create_graph_prepare_data: &CreateGraphPrepare,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if is_processing_graph() {
            return Ok(false);
        };
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
        let utxos = client.esplora.get_address_utxo(node_address).await?;
        let utxo_spent_fee = Amount::from_sat(
            (get_fee_rate(client).await? * 2.0 * CHEKSIG_P2WSH_INPUT_VBYTES as f64).ceil() as u64,
        );
        let total_effective_balance: Amount =
            utxos.iter().map(|utxo| utxo.value - utxo_spent_fee).sum();
        Ok(total_effective_balance
            > get_stake_amount(create_graph_prepare_data.pegin_amount.to_sat()))
    }

    /// Checks whether the status of the graph (identified by instance ID and graph ID)
    /// on the Layer 2 contract is currently `Initialized`.
    pub async fn is_withdraw_initialized_on_l2(
        client: &BitVM2Client,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let withdraw_status =
            client.chain_service.adaptor.get_withdraw_data(graph_id).await?.status;
        Ok(withdraw_status == WithdrawStatus::Initialized)
    }

    /// Checks whether the timelock for the specified kickoff transaction has expired,
    /// indicating that the `take1` transaction can now be sent.
    ///
    /// The timelock duration is a fixed constant (goat::constants::CONNECTOR_3_TIMELOCK)
    pub async fn is_take1_timelock_expired(
        client: &BitVM2Client,
        kickoff_txid: Txid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
        let tx_status = client.esplora.get_tx_status(&kickoff_txid).await?;
        match tx_status.block_height {
            Some(tx_height) => {
                let current_height = client.esplora.get_height().await?;
                Ok(current_height > tx_height + lock_blocks)
            }
            _ => Ok(false),
        }
    }

    /// Checks whether the timelock for the specified assert-final transaction has expired,
    /// allowing the `take2` transaction to proceed.
    ///
    /// The timelock duration is a fixed constant (goat::constants::CONNECTOR_4_TIMELOCK)
    pub async fn is_take2_timelock_expired(
        client: &BitVM2Client,
        assert_final_txid: Txid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_4_TIMELOCK);
        let tx_status = client.esplora.get_tx_status(&assert_final_txid).await?;
        match tx_status.block_height {
            Some(tx_height) => {
                let current_height = client.esplora.get_height().await?;
                Ok(current_height > tx_height + lock_blocks)
            }
            _ => Ok(false),
        }
    }

    /// Calculates the required stake amount for the operator.
    ///
    /// Formula:
    /// stake_amount = fixed_min_stake_amount + (pegin_amount * stake_rate)
    pub fn get_stake_amount(pegin_amount: u64) -> Amount {
        Amount::from_sat(MIN_SATKE_AMOUNT + pegin_amount * STAKE_RATE / RATE_MULTIPLIER)
    }

    /// Calculates the required challenge amount, which is based on the stake amount.
    ///
    /// Formula:
    /// challenge_amount = fixed_min_challenge_amount + (pegin_amount * challenge_rate)
    pub fn get_challenge_amount(pegin_amount: u64) -> Amount {
        Amount::from_sat(MIN_CHALLENGE_AMOUNT + pegin_amount * CHALLENGE_RATE / RATE_MULTIPLIER)
    }

    /// Selects suitable UTXOs from the operator’s available funds to construct inputs
    /// for the pre-kickoff transaction.
    ///
    /// Notes:
    /// - UTXOs must be sent to a dedicated P2WSH address, generated at node startup from operator-pubkey
    /// - The same P2WSH address is also used for change output.
    /// - Returns None if operator does not have enough btc
    pub async fn select_operator_inputs(
        client: &BitVM2Client,
        stake_amount: Amount,
    ) -> Result<Option<CustomInputs>, Box<dyn std::error::Error>> {
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
        let fee_rate = get_fee_rate(client).await?;
        match get_proper_utxo_set(
            client,
            PRE_KICKOFF_BASE_VBYTES,
            node_address.clone(),
            stake_amount,
            fee_rate,
        )
        .await?
        {
            Some((inputs, fee_amount, _)) => Ok(Some(CustomInputs {
                inputs,
                input_amount: stake_amount,
                fee_amount,
                change_address: node_address,
            })),
            _ => Ok(None),
        }
    }

    /// Loads partial scripts from a local cache file.
    /// If cache file does not exist, generate partial scripts by vk an cache it
    pub fn get_partial_scripts() -> Result<Vec<Script>, Box<dyn std::error::Error>> {
        let scripts_cache_path = SCRIPT_CACHE_FILE_NAME;
        if Path::new(scripts_cache_path).exists() {
            let file = File::open(scripts_cache_path)?;
            let reader = BufReader::new(file);
            let scripts_bytes: Vec<ScriptBuf> = bincode::deserialize_from(reader).unwrap();
            Ok(scripts_bytes.into_iter().map(|x| script! {}.push_script(x)).collect())
        } else {
            let partial_scripts = generate_partial_scripts(&get_vk()?);
            if let Some(parent) = Path::new(scripts_cache_path).parent() {
                fs::create_dir_all(parent).unwrap();
            };
            let file = File::create(scripts_cache_path).unwrap();
            let scripts_bytes: Vec<ScriptBuf> =
                partial_scripts.iter().map(|scr| scr.clone().compile()).collect();
            let writer = BufWriter::new(file);
            bincode::serialize_into(writer, &scripts_bytes)?;
            Ok(partial_scripts)
        }
    }

    pub async fn get_fee_rate(client: &BitVM2Client) -> Result<f64, Box<dyn std::error::Error>> {
        let res = client.esplora.get_fee_estimates().await?;
        Ok(*res.get(&DEFAULT_CONFIRMATION_TARGET).ok_or(format!(
            "fee for {} confirmation target not found",
            DEFAULT_CONFIRMATION_TARGET
        ))?)
    }

    /// Broadcasts a raw transaction to the Bitcoin network using the mempool API.
    ///
    /// Requirements:
    /// - The mempool API URL must be configured.
    /// - The transaction should already be fully signed.
    pub async fn broadcast_tx(
        client: &BitVM2Client,
        tx: &Transaction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(client.esplora.broadcast(tx).await?)
    }

    /// Signs and broadcasts pre-kickoff transaction.
    ///
    /// All inputs of pre-kickoff transaction should be utxo belonging to node-address
    pub async fn sign_and_broadcast_prekickoff_tx(
        client: &BitVM2Client,
        node_keypair: Keypair,
        prekickoff_tx: Transaction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
        let mut prekickoff_tx = prekickoff_tx;
        for i in 0..prekickoff_tx.input.len() {
            let prev_outpoint = &prekickoff_tx.input[i].previous_output;
            let prev_tx = client
                .esplora
                .get_tx(&prev_outpoint.txid)
                .await?
                .ok_or(format!("previous tx {} not found", prev_outpoint.txid))?;
            let prev_output = &prev_tx.output.get(prev_outpoint.vout as usize).ok_or(format!(
                "previous tx {} does not have vout {}",
                prev_outpoint.txid, prev_outpoint.vout
            ))?;
            if prev_output.script_pubkey != node_address.script_pubkey() {
                return Err(format!(
                    "previous outpoint {}:{} not belong to this node",
                    prev_outpoint.txid, prev_outpoint.vout
                )
                .into());
            };
            node_sign(
                &mut prekickoff_tx,
                i,
                prev_output.value,
                EcdsaSighashType::All,
                &node_keypair,
            )?;
        }
        broadcast_tx(client, &prekickoff_tx).await?;
        Ok(())
    }

    /// Completes and broadcasts a challenge transaction.
    ///
    /// This involves:
    /// - Selecting UTXOs with sufficient amount (may include change),
    /// - Signing the transaction,
    /// - Broadcasting it to the network.
    ///
    /// Notes:
    /// - The challenge node must have pre-funded a P2WSH address during startup.
    pub async fn complete_and_broadcast_challenge_tx(
        client: &BitVM2Client,
        node_keypair: Keypair,
        challenge_tx: Transaction,
        challenge_amount: Amount,
    ) -> Result<Txid, Box<dyn std::error::Error>> {
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
        let fee_rate = get_fee_rate(client).await?;
        let mut challenge_tx = challenge_tx;
        match get_proper_utxo_set(
            client,
            CHALLENGE_BASE_VBYTES,
            node_address.clone(),
            challenge_amount,
            fee_rate,
        )
        .await?
        {
            Some((inputs, _, change_amount)) => {
                for input in &inputs {
                    challenge_tx.input.push(TxIn {
                        previous_output: input.outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::default(),
                    });
                }
                if change_amount > Amount::from_sat(DUST_AMOUNT) {
                    challenge_tx.output.push(TxOut {
                        script_pubkey: node_address.script_pubkey(),
                        value: challenge_amount,
                    });
                };
                for i in 0..inputs.len() {
                    node_sign(
                        &mut challenge_tx,
                        i + 1,
                        inputs[i].amount,
                        EcdsaSighashType::All,
                        &node_keypair,
                    )?;
                }
                broadcast_tx(client, &challenge_tx).await?;
                Ok(challenge_tx.compute_txid())
            }
            _ => Err(format!("insufficient btc, please fund {} first", node_address).into()),
        }
    }

    /// Returns:
    /// - `Ok(None)` if given address does not have enough btc,
    /// - `Ok(Some((utxos, fee_amount, change_amount)))`
    pub async fn get_proper_utxo_set(
        client: &BitVM2Client,
        base_vbytes: u64,
        address: Address,
        target_amount: Amount,
        fee_rate: f64,
    ) -> Result<Option<(Vec<Input>, Amount, Amount)>, Box<dyn std::error::Error>> {
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

        let utxos = client.esplora.get_address_utxo(address).await?;
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

    /// Returns the address to receive disprove reward, which is a P2WSH address
    /// generated by the challenge node at startup.
    pub fn disprove_reward_address() -> Result<Address, Box<dyn std::error::Error>> {
        Ok(node_p2wsh_address(get_network(), &get_node_pubkey()?))
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let node_pubkey = get_node_pubkey()?;
        populate_p2wsh_witness(
            tx,
            input_index,
            sighash_type,
            &node_p2wsh_script(&node_pubkey),
            input_value,
            &vec![node_keypair],
        );
        Ok(())
    }

    /// Determines whether the challenger should challenge a kickoff
    ///
    /// Conditions:
    /// - If kickoff is invalid
    /// - If challenger has enough fund
    /// - Participation should be attempted as often as possible.
    ///
    /// A kickoff transaction is considered invalid if:
    /// - It has already been broadcast on Layer 1,
    /// - But the corresponding graph status on Layer 2 is not `Initialized`.
    pub async fn should_challenge(
        client: &BitVM2Client,
        challenge_amount: Amount,
        instance_id: Uuid,
        graph_id: Uuid,
        graph: &Bitvm2Graph,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // check if kickoff is confirmed on L1
        let kickoff_txid = graph.kickoff.tx().compute_txid();
        if let None = client.esplora.get_tx(&kickoff_txid).await? {
            return Ok(false);
        }

        // check if withdraw is initialized on L2
        let withdraw_status =
            client.chain_service.adaptor.get_withdraw_data(graph_id).await?.status;
        if withdraw_status == WithdrawStatus::Initialized {
            return Ok(false);
        };

        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
        let utxos = client.esplora.get_address_utxo(node_address).await?;
        let utxo_spent_fee = Amount::from_sat(
            (get_fee_rate(client).await? * 2.0 * CHEKSIG_P2WSH_INPUT_VBYTES as f64).ceil() as u64,
        );
        let total_effective_balance: Amount =
            utxos.iter().map(|utxo| utxo.value - utxo_spent_fee).sum();
        Ok(total_effective_balance > challenge_amount)
    }

    /// Validates whether the given kickoff transaction has been confirmed on Layer 1.
    pub async fn tx_on_chain(
        client: &BitVM2Client,
        txid: &Txid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match client.esplora.get_tx(txid).await? {
            Some(_) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Validates whether the given challenge transaction has been confirmed on Layer 1.
    pub async fn validate_challenge(
        client: &BitVM2Client,
        kickoff_txid: &Txid,
        challenge_txid: &Txid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let challenge_tx = match client.esplora.get_tx(challenge_txid).await? {
            Some(tx) => tx,
            _ => return Ok(false),
        };
        let expected_challenge_input_0 = OutPoint { txid: *kickoff_txid, vout: 1 };
        Ok(challenge_tx.input[0].previous_output == expected_challenge_input_0)
    }

    /// Validates whether the given disprove transaction has been confirmed on Layer 1.
    pub async fn validate_disprove(
        client: &BitVM2Client,
        assert_final_txid: &Txid,
        disprove_txid: &Txid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let disprove_tx = match client.esplora.get_tx(disprove_txid).await? {
            Some(tx) => tx,
            _ => return Ok(false),
        };
        let expected_disprove_input_0 = OutPoint { txid: *assert_final_txid, vout: 1 };
        Ok(disprove_tx.input[0].previous_output == expected_disprove_input_0)
    }

    /// Validates the provided assert-commit transactions.
    ///
    /// Steps:
    /// - Extract the Groth16 proof from the witness fields of the provided transactions,
    /// - Verify the validity of the proof.
    ///
    /// Returns:
    /// - `Ok(None)` if the assert is valid,
    /// - `Ok(Some((index, disprove_script)))` if invalid, providing the witness info for later disprove.
    ///
    pub async fn validate_assert(
        client: &BitVM2Client,
        assert_commit_txns: &[Txid; COMMIT_TX_NUM],
        wots_pubkeys: WotsPublicKeys,
    ) -> Result<Option<(usize, Script)>, Box<dyn std::error::Error>> {
        let mut txs = Vec::with_capacity(COMMIT_TX_NUM);
        for txid in assert_commit_txns.iter() {
            let tx = match client.esplora.get_tx(txid).await? {
                Some(v) => v,
                _ => return Ok(None), // nothing to disprove if assert-commit-txns not on chain
            };
            txs.push(tx);
        }
        let assert_commit_txns: [Transaction; COMMIT_TX_NUM] =
            txs.try_into().map_err(|_| "assert-commit-tx num mismatch")?;
        let proof_sigs = extract_proof_sigs_from_assert_commit_txns(assert_commit_txns)?;
        let disprove_scripts = generate_disprove_scripts(&get_partial_scripts()?, &wots_pubkeys);
        let disprove_scripts: [Script; NUM_TAPS] =
            disprove_scripts.try_into().map_err(|_| "disprove script num mismatch")?;
        Ok(verify_proof(&get_vk()?, proof_sigs, &disprove_scripts, &wots_pubkeys))
    }

    pub fn client() -> Result<BitVM2Client, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    /// Retrieves the Groth16 proof, public inputs, and verifying key
    /// for the given graph.
    ///
    /// These are fetched via the ProofNetwork SDK.
    pub fn get_groth16_proof(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<(Groth16Proof, PublicInputs, VerifyingKey), Box<dyn std::error::Error>> {
        Err("TODO".into())
    }
    pub fn get_vk() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }
}

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
pub async fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    actor: Actor,
    peer_id: PeerId,
    id: MessageId,
    message: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        "Got message: {} with id: {} from peer: {:?}",
        String::from_utf8_lossy(message),
        id,
        peer_id
    );
    let default_message_id = GOATMessage::default_message_id();
    if id == default_message_id {
        tracing::debug!("Get the running task, and broadcast the task status or result");
        // TODO
        return Ok(());
    }
    let message: GOATMessage = serde_json::from_slice(message)?;
    println!("Received message: {:?}", message);
    if message.actor != actor && message.actor != Actor::All && actor != Actor::Relayer {
        return Ok(());
    }
    println!("Handle message: {:?}", message);
    let content: GOATMessageContent = message.to_typed()?;
    // TODO: validate message
    let client = todo_funcs::client()?;
    match (content, actor) {
        // pegin
        // CreateInstance sent by bootnode
        (GOATMessageContent::CreateInstance(receive_data), Actor::Committee) => {
            let instance_id = receive_data.instance_id;
            let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
            let keypair = master_key.keypair_for_instance(instance_id);
            let message_content = GOATMessageContent::CreateGraphPrepare(CreateGraphPrepare {
                instance_id,
                network: receive_data.network,
                pegin_amount: receive_data.pegin_amount,
                depositor_evm_address: receive_data.depositor_evm_address,
                user_inputs: receive_data.user_inputs,
                committee_member_pubkey: keypair.public_key().into(),
                committee_members_num: env::get_committee_member_num(),
            });
            store_committee_pubkeys(&client, receive_data.instance_id, keypair.public_key().into())
                .await?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
        (GOATMessageContent::CreateGraphPrepare(receive_data), Actor::Operator) => {
            store_committee_pubkeys(
                &client,
                receive_data.instance_id,
                receive_data.committee_member_pubkey,
            )
            .await?;
            let collected_keys = get_committee_pubkeys(&client, receive_data.instance_id).await?;
            if collected_keys.len() == receive_data.committee_members_num
                && todo_funcs::should_generate_graph(&client, &receive_data).await?
            {
                let graph_id = Uuid::new_v4();
                if try_start_new_graph(receive_data.instance_id, graph_id) {
                    let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(graph_id);
                    let (_, operator_wots_pubkeys) = master_key.wots_keypair_for_graph(graph_id);
                    let committee_agg_pubkey = key_aggregation(&collected_keys);
                    let disprove_scripts = generate_disprove_scripts(
                        &todo_funcs::get_partial_scripts()?,
                        &operator_wots_pubkeys,
                    );
                    let operator_inputs = todo_funcs::select_operator_inputs(
                        &client,
                        todo_funcs::get_stake_amount(receive_data.pegin_amount.to_sat()),
                    )
                    .await?
                    .ok_or("operator doesn't have enough fund")?;
                    let params = Bitvm2Parameters {
                        network: receive_data.network,
                        depositor_evm_address: receive_data.depositor_evm_address,
                        pegin_amount: receive_data.pegin_amount,
                        user_inputs: receive_data.user_inputs,
                        stake_amount: todo_funcs::get_stake_amount(
                            receive_data.pegin_amount.to_sat(),
                        ),
                        challenge_amount: todo_funcs::get_challenge_amount(
                            receive_data.pegin_amount.to_sat(),
                        ),
                        committee_pubkeys: collected_keys,
                        committee_agg_pubkey,
                        operator_pubkey: keypair.public_key().into(),
                        operator_wots_pubkeys,
                        operator_inputs,
                    };
                    let disprove_scripts_bytes =
                        disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                    let mut graph = generate_bitvm_graph(params, disprove_scripts_bytes)?;
                    operator_pre_sign(keypair, &mut graph)?;
                    store_graph(
                        &client,
                        receive_data.instance_id,
                        graph_id,
                        &graph,
                        Some(GraphStatus::OperatorPresigned.to_string()),
                    )
                    .await?;
                    let message_content = GOATMessageContent::CreateGraph(CreateGraph {
                        instance_id: receive_data.instance_id,
                        graph_id,
                        graph,
                    });
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                };
            };
        }
        (GOATMessageContent::CreateGraph(receive_data), Actor::Committee) => {
            store_graph(
                &client,
                receive_data.instance_id,
                receive_data.graph_id,
                &receive_data.graph,
                Some(GraphStatus::OperatorPresigned.to_string()),
            )
            .await?;
            let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
            let nonces =
                master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM] =
                std::array::from_fn(|i| nonces[i].1.clone());
            let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id: receive_data.instance_id,
                graph_id: receive_data.graph_id,
                committee_pubkey: keypair.public_key().into(),
                pub_nonces,
                committee_members_num: receive_data.graph.parameters.committee_pubkeys.len(),
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
        }
        (GOATMessageContent::NonceGeneration(receive_data), Actor::Committee) => {
            store_committee_pub_nonces(
                &client,
                receive_data.instance_id,
                receive_data.graph_id,
                receive_data.committee_pubkey,
                receive_data.pub_nonces,
            )
            .await?;
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let nonces =
                master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let sec_nonces: [SecNonce; COMMITTEE_PRE_SIGN_NUM] =
                std::array::from_fn(|i| nonces[i].0.clone());
            let collected_pub_nonces =
                get_committee_pub_nonces(&client, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if collected_pub_nonces.len() == receive_data.committee_members_num {
                let agg_nonces = nonces_aggregation(collected_pub_nonces);
                let committee_partial_sigs =
                    committee_pre_sign(keypair, sec_nonces, agg_nonces.clone(), &graph)?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    committee_pubkey: receive_data.committee_pubkey,
                    committee_partial_sigs,
                    agg_nonces,
                    committee_members_num: receive_data.committee_members_num,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            };
        }
        (GOATMessageContent::CommitteePresign(receive_data), Actor::Operator) => {
            if Some((receive_data.instance_id, receive_data.graph_id))
                == statics::current_processing_graph()
            {
                store_committee_partial_sigs(
                    &client,
                    receive_data.instance_id,
                    receive_data.graph_id,
                    receive_data.committee_pubkey,
                    receive_data.committee_partial_sigs,
                )
                .await?;
                let collected_partial_sigs = get_committee_partial_sigs(
                    &client,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?;
                if collected_partial_sigs.len() == receive_data.committee_members_num {
                    let mut grouped_partial_sigs: [Vec<PartialSignature>; COMMITTEE_PRE_SIGN_NUM] =
                        Default::default();
                    for partial_sigs in collected_partial_sigs {
                        for (i, sig) in partial_sigs.into_iter().enumerate() {
                            grouped_partial_sigs[i].push(sig);
                        }
                    }
                    let mut graph =
                        get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
                    signature_aggregation_and_push(
                        &grouped_partial_sigs,
                        &receive_data.agg_nonces,
                        &mut graph,
                    )?;
                    store_graph(
                        &client,
                        receive_data.instance_id,
                        receive_data.graph_id,
                        &graph,
                        Some(GraphStatus::CommitteePresigned.to_string()),
                    )
                    .await?;
                    let prekickoff_tx = graph.pre_kickoff.tx().clone();
                    let node_keypair =
                        OperatorMasterKey::new(env::get_bitvm_key()?).master_keypair();
                    todo_funcs::sign_and_broadcast_prekickoff_tx(
                        &client,
                        node_keypair,
                        prekickoff_tx,
                    )
                    .await?;
                    let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        graph,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                    force_stop_current_graph();
                }
            };
        }
        (GOATMessageContent::GraphFinalize(receive_data), _) => {
            // TODO: validate graph
            store_graph(
                &client,
                receive_data.instance_id,
                receive_data.graph_id,
                &receive_data.graph,
                Some(GraphStatus::CommitteePresigned.to_string()),
            )
            .await?;
        }

        // peg-out
        // KickoffReady sent by relayer
        (GOATMessageContent::KickoffReady(receive_data), Actor::Operator) => {
            let mut graph =
                get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && todo_funcs::is_withdraw_initialized_on_l2(
                    &client,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys, operator_wots_pubkeys) =
                    master_key.wots_keypair_for_graph(receive_data.graph_id);
                let mut kickoff_commit_data = [0u8; 32];
                kickoff_commit_data[..16].copy_from_slice(receive_data.instance_id.as_bytes());
                kickoff_commit_data[16..].copy_from_slice(receive_data.graph_id.as_bytes());
                let kickoff_tx = operator_sign_kickoff(
                    keypair,
                    &mut graph,
                    &operator_wots_seckeys,
                    &operator_wots_pubkeys,
                    kickoff_commit_data,
                )?;
                todo_funcs::broadcast_tx(&client, &kickoff_tx).await?;
                // malicious Operator may not broadcast kickoff to the p2p network
                // Relayer will monitor all graphs & broadcast KickoffSent
            }
        }
        // KickoffSent sent by relayer
        (GOATMessageContent::KickoffSent(receive_data), Actor::Challenger) => {
            let mut graph =
                get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::should_challenge(
                &client,
                Amount::from_sat(graph.challenge.min_crowdfunding_amount()),
                receive_data.instance_id,
                receive_data.graph_id,
                &graph,
            )
            .await?
            {
                let (challenge_tx, challenge_amount) = export_challenge_tx(&mut graph)?;
                let node_keypair = ChallengerMasterKey::new(env::get_bitvm_key()?).master_keypair();
                let challenge_txid = todo_funcs::complete_and_broadcast_challenge_tx(
                    &client,
                    node_keypair,
                    challenge_tx,
                    challenge_amount,
                )
                .await?;
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    challenge_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::KickOff.to_string()),
                )
                .await?;
            }
        }
        // Take1Ready sent by relayer
        (GOATMessageContent::Take1Ready(receive_data), Actor::Operator) => {
            let mut graph =
                get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && todo_funcs::is_take1_timelock_expired(&client, graph.take1.tx().compute_txid())
                    .await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let take1_tx = operator_sign_take1(keypair, &mut graph)?;
                let take1_txid = take1_tx.compute_txid();
                todo_funcs::broadcast_tx(&client, &take1_tx).await?;
                let message_content = GOATMessageContent::Take1Sent(Take1Sent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    take1_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Take1.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        // ChallengeSent sent by challenger
        // if challenger
        (GOATMessageContent::ChallengeSent(receive_data), Actor::Operator) => {
            let mut graph =
                get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && todo_funcs::validate_challenge(
                    &client,
                    &graph.kickoff.tx().compute_txid(),
                    &receive_data.challenge_txid,
                )
                .await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys, operator_wots_pubkeys) =
                    master_key.wots_keypair_for_graph(receive_data.graph_id);
                let (proof, pubin, vk) =
                    todo_funcs::get_groth16_proof(receive_data.instance_id, receive_data.graph_id)?;
                let proof_sigs = sign_proof(&vk, proof, pubin, &operator_wots_seckeys);
                let (assert_init_tx, assert_commit_txns, assert_final_tx) =
                    operator_sign_assert(keypair, &mut graph, &operator_wots_pubkeys, proof_sigs)?;
                todo_funcs::broadcast_tx(&client, &assert_init_tx).await?;
                for tx in assert_commit_txns {
                    todo_funcs::broadcast_tx(&client, &tx).await?;
                }
                todo_funcs::broadcast_tx(&client, &assert_final_tx).await?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Assert.to_string()),
                )
                .await?;
                // malicious Operator may not broadcast assert to the p2p network
                // Relayer will monitor all graphs & broadcast AssertSent
            }
        }
        // Take2Ready sent by relayer
        (GOATMessageContent::Take2Ready(receive_data), Actor::Operator) => {
            let mut graph =
                get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && todo_funcs::is_take2_timelock_expired(
                    &client,
                    graph.assert_final.tx().compute_txid(),
                )
                .await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let take2_tx = operator_sign_take2(keypair, &mut graph)?;
                let take2_txid = take2_tx.compute_txid();
                todo_funcs::broadcast_tx(&client, &take2_tx).await?;
                let message_content = GOATMessageContent::Take2Sent(Take2Sent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    take2_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Take2.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        // AssertSent sent by relayer
        (GOATMessageContent::AssertSent(receive_data), Actor::Challenger) => {
            let mut graph =
                get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if let Some(disprove_witness) = todo_funcs::validate_assert(
                &client,
                &receive_data.assert_commit_txids,
                graph.parameters.operator_wots_pubkeys.clone(),
            )
            .await?
            {
                let disprove_scripts = generate_disprove_scripts(
                    &todo_funcs::get_partial_scripts()?,
                    &graph.parameters.operator_wots_pubkeys,
                );
                let disprove_scripts_bytes =
                    disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                let assert_wots_pubkeys = graph.parameters.operator_wots_pubkeys.1.clone();
                let disprove_tx = sign_disprove(
                    &mut graph,
                    disprove_witness,
                    disprove_scripts_bytes,
                    &assert_wots_pubkeys,
                    todo_funcs::disprove_reward_address()?,
                )?;
                let disprove_txid = disprove_tx.compute_txid();
                todo_funcs::broadcast_tx(&client, &disprove_tx).await?;
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    disprove_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Disprove.to_string()),
                )
                .await?;
            }
        }

        // Relayer handles
        (GOATMessageContent::Take1Sent(receive_data), Actor::Relayer) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            let take1_txid = graph.take1.tx().compute_txid();
            if todo_funcs::tx_on_chain(&client, &take1_txid).await? {
                finish_withdraw_happy_path(&client, &receive_data.graph_id, &graph.take1).await?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Take1.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), Actor::Relayer) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::tx_on_chain(&client, &graph.take2.tx().compute_txid()).await? {
                finish_withdraw_unhappy_path(&client, &receive_data.graph_id, &graph.take2).await?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Take2.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::DisproveSent(receive_data), Actor::Relayer) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::validate_disprove(
                &client,
                &graph.assert_final.tx().compute_txid(),
                &receive_data.disprove_txid,
            )
            .await?
            {
                finish_withdraw_disproved(&client, &receive_data.graph_id, &graph.disprove).await?;
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Disprove.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }

        // Other participants update graph status
        (GOATMessageContent::KickoffSent(receive_data), _) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::tx_on_chain(&client, &graph.kickoff.tx().compute_txid()).await? {
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::KickOff.to_string()),
                )
                .await?;
            }
        }
        (GOATMessageContent::ChallengeSent(receive_data), _) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::validate_challenge(
                &client,
                &graph.kickoff.tx().compute_txid(),
                &receive_data.challenge_txid,
            )
            .await?
            {
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Challenge.to_string()),
                )
                .await?;
            }
        }
        (GOATMessageContent::Take1Sent(receive_data), _) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::tx_on_chain(&client, &graph.take1.tx().compute_txid()).await? {
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Take1.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), _) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::tx_on_chain(&client, &graph.take2.tx().compute_txid()).await? {
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Take2.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::DisproveSent(receive_data), _) => {
            let graph = get_graph(&client, receive_data.instance_id, receive_data.graph_id).await?;
            if todo_funcs::validate_disprove(
                &client,
                &graph.assert_final.tx().compute_txid(),
                &receive_data.disprove_txid,
            )
            .await?
            {
                update_graph_status_or_ipfs_base(
                    &client,
                    receive_data.graph_id,
                    None,
                    Some(GraphStatus::Disprove.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }

        _ => {}
    }
    Ok(())
}

pub(crate) fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId, Box<dyn std::error::Error>> {
    let actor = message.actor.to_string();
    let gossipsub_topic = gossipsub::IdentTopic::new(actor);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, &*message.content)?)
}

///  call the rpc service
///     Method::GET/POST/PUT
pub(crate) async fn inner_rpc<S, R>(
    addr: &str,
    method: reqwest::Method,
    uri: &str,
    params: S,
) -> Result<R, Box<dyn std::error::Error>>
where
    S: Serialize,
    R: DeserializeOwned,
{
    let client = reqwest::Client::new();
    let url = reqwest::Url::parse(&format!("{addr}/{uri}"))?;

    let req = Request::new(method, url);
    let req_builder = reqwest::RequestBuilder::from_parts(client, req);
    let resp = req_builder.json(&params).send().await?;
    let txt = resp.text().await?;
    Ok(serde_json::from_str(txt.as_str())?)
}

/// l2 support
pub async fn finish_withdraw_happy_path(
    client: &BitVM2Client,
    graph_id: &Uuid,
    take1: &Take1Transaction,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(client.finish_withdraw_happy_path(graph_id, take1.tx()).await?)
}
pub async fn finish_withdraw_unhappy_path(
    client: &BitVM2Client,
    graph_id: &Uuid,
    take2: &Take2Transaction,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(client.finish_withdraw_unhappy_path(graph_id, take2.tx()).await?)
}

pub async fn finish_withdraw_disproved(
    client: &BitVM2Client,
    graph_id: &Uuid,
    disprove: &DisproveTransaction,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(client.finish_withdraw_disproved(graph_id, disprove.tx()).await?)
}

/// db support
pub async fn store_committee_pub_nonces(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    let nonces_vec: Vec<String> = pub_nonces.iter().map(|v| v.to_string()).collect();
    let nonces_arr: [String; COMMITTEE_PRE_SIGN_NUM] =
        nonces_vec.try_into().map_err(|v: Vec<String>| {
            format!("length wrong: expect {}, real {}", COMMITTEE_PRE_SIGN_NUM, v.len())
        })?;
    Ok(storage_process
        .store_nonces(instance_id, graph_id, &[nonces_arr], committee_pubkey.to_string(), &[])
        .await?)
}
pub async fn get_committee_pub_nonces(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    match storage_process.get_nonces(instance_id, graph_id).await? {
        None => {
            Err(format!("instance id:{}, graph id:{} not found ", instance_id, graph_id).into())
        }
        Some(nonce_collect) => {
            let mut res: Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]> = vec![];
            for nonces_item in nonce_collect.nonces {
                let nonce_vec: Vec<PubNonce> = nonces_item
                    .iter()
                    .map(|v| PubNonce::from_str(v).expect("fail to decode pub nonce"))
                    .collect();
                res.push(nonce_vec.try_into().map_err(|v: Vec<PubNonce>| {
                    format!("length wrong: expect {}, real {}", COMMITTEE_PRE_SIGN_NUM, v.len())
                })?)
            }
            Ok(res)
        }
    }
}

pub async fn store_committee_pubkeys(
    client: &BitVM2Client,
    instance_id: Uuid,
    pubkey: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    Ok(storage_process.store_pubkeys(instance_id, &vec![pubkey.to_string()]).await?)
}
pub async fn get_committee_pubkeys(
    client: &BitVM2Client,
    instance_id: Uuid,
) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    match storage_process.get_pubkeys(instance_id).await? {
        None => Ok(vec![]),
        Some(meta_data) => Ok(meta_data
            .pubkeys
            .iter()
            .map(|v| PublicKey::from_str(v).expect("fail to decode to public key"))
            .collect()),
    }
}

pub async fn store_committee_partial_sigs(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    let signs_vec: Vec<String> = partial_sigs.iter().map(|v| hex::encode(v.serialize())).collect();
    let signs_arr: [String; COMMITTEE_PRE_SIGN_NUM] =
        signs_vec.try_into().map_err(|v: Vec<String>| {
            format!("length wrong: expect {}, real {}", COMMITTEE_PRE_SIGN_NUM, v.len())
        })?;

    Ok(storage_process
        .store_nonces(instance_id, graph_id, &[], committee_pubkey.to_string(), &vec![signs_arr])
        .await?)
}

pub async fn get_committee_partial_sigs(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<[PartialSignature; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    match storage_process.get_nonces(instance_id, graph_id).await? {
        None => {
            Err(format!("instance id:{}, graph id:{} not found ", instance_id, graph_id).into())
        }
        Some(nonce_collect) => {
            let mut res: Vec<[PartialSignature; COMMITTEE_PRE_SIGN_NUM]> = vec![];
            for signs_item in nonce_collect.partial_sigs {
                let signs_vec: Vec<PartialSignature> = signs_item
                    .iter()
                    .map(|v| PartialSignature::from_str(v).expect("fail to decode pub nonce"))
                    .collect();
                res.push(signs_vec.try_into().map_err(|v: Vec<PartialSignature>| {
                    format!("length wrong: expect {}, real {}", COMMITTEE_PRE_SIGN_NUM, v.len())
                })?)
            }
            Ok(res)
        }
    }
}

pub async fn update_graph_status_or_ipfs_base(
    client: &BitVM2Client,
    graph_id: Uuid,
    graph_state: Option<String>,
    ipfs_base_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    Ok(storage_process
        .update_graph_status_or_ipfs_base(graph_id, graph_state, ipfs_base_url)
        .await?)
}
pub async fn store_graph(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &Bitvm2Graph,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    let assert_commit_txids: Vec<String> =
        graph.assert_commit.commit_txns.iter().map(|v| v.tx().compute_txid().to_string()).collect();
    storage_process
        .update_graph(Graph {
            graph_id,
            instance_id,
            graph_ipfs_base_url: "".to_string(), //TODO
            pegin_txid: graph.pegin.tx().compute_txid().to_string(),
            amount: graph.parameters.pegin_amount.to_sat() as i64,
            status: status.unwrap_or_else(|| GraphStatus::OperatorPresigned.to_string()),
            kickoff_txid: Some(graph.kickoff.tx().compute_txid().to_string()),
            challenge_txid: Some(graph.challenge.tx().compute_txid().to_string()),
            take1_txid: Some(graph.take1.tx().compute_txid().to_string()),
            assert_init_txid: Some(graph.assert_init.tx().compute_txid().to_string()),
            assert_commit_txids: Some(format!("{:?}", assert_commit_txids)),
            assert_final_txid: Some(graph.assert_final.tx().compute_txid().to_string()),
            take2_txid_txid: Some(graph.take2.tx().compute_txid().to_string()),
            disprove_txid: Some(graph.disprove.tx().compute_txid().to_string()),
            operator: graph.parameters.operator_pubkey.to_string(),
            raw_data: Some(serde_json::to_string(&graph).expect("to json string")),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn update_graph(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &Bitvm2Graph,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    store_graph(client, instance_id, graph_id, graph, status).await
}

pub async fn get_graph(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Bitvm2Graph, Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    let graph = storage_process.get_graph(&graph_id).await?;
    if graph.instance_id.ne(&instance_id) {
        return Err(format!(
            "grap with graph_id:{} has instance_id:{} not match expec instance:{}",
            graph_id, graph.instance_id, instance_id
        )
        .into());
    }

    if graph.raw_data.is_none() {
        return Err(format!("grap with graph_id:{} raw data is none", graph_id).into());
    }
    let res: Bitvm2Graph = serde_json::from_str(graph.raw_data.unwrap().as_str())?;
    Ok(res)
}
