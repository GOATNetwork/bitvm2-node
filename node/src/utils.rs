use crate::action::CreateGraphPrepare;
use crate::env::*;
use crate::rpc_service::current_time_secs;
use ark_serialize::CanonicalDeserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_script::{Script, script};
use bitvm::chunk::api::NUM_TAPS;
use bitvm2_lib::committee::COMMITTEE_PRE_SIGN_NUM;
use bitvm2_lib::operator::{generate_disprove_scripts, generate_partial_scripts};
use bitvm2_lib::types::{
    Bitvm2Graph, CustomInputs, Groth16Proof, PublicInputs, VerifyingKey, WotsPublicKeys,
};
use bitvm2_lib::verifier::{extract_proof_sigs_from_assert_commit_txns, verify_proof};
use client::chain::chain_adaptor::WithdrawStatus;
use client::client::BitVM2Client;
use esplora_client::Utxo;
use goat::constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK};
use goat::transactions::assert::utils::COMMIT_TX_NUM;
use goat::transactions::base::Input;
use goat::transactions::disprove::DisproveTransaction;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::signing::populate_p2wsh_witness;
use goat::transactions::take_1::Take1Transaction;
use goat::transactions::take_2::Take2Transaction;
use goat::utils::num_blocks_per_network;
use musig2::{PartialSignature, PubNonce};
use statics::*;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::str::FromStr;
use store::{BridgeInStatus, Graph, GraphStatus};
use uuid::Uuid;

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
    #[allow(dead_code)]
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
        utxos
            .iter()
            .map(|utxo| {
                if utxo.value > utxo_spent_fee { utxo.value - utxo_spent_fee } else { Amount::ZERO }
            })
            .sum();
    Ok(total_effective_balance > get_stake_amount(create_graph_prepare_data.pegin_amount.to_sat()))
}

/// Checks whether the status of the graph (identified by instance ID and graph ID)
/// on the Layer 2 contract is currently `Initialized`.
pub async fn is_withdraw_initialized_on_l2(
    client: &BitVM2Client,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let withdraw_status = client.chain_service.adaptor.get_withdraw_data(&graph_id).await?.status;
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
        let scripts_bytes: Vec<ScriptBuf> = bincode::deserialize_from(reader)?;
        Ok(scripts_bytes.into_iter().map(|x| script! {}.push_script(x)).collect())
    } else {
        let partial_scripts = generate_partial_scripts(&get_vk()?);
        if let Some(parent) = Path::new(scripts_cache_path).parent() {
            fs::create_dir_all(parent)?;
        };
        let file = File::create(scripts_cache_path)?;
        let scripts_bytes: Vec<ScriptBuf> =
            partial_scripts.iter().map(|scr| scr.clone().compile()).collect();
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &scripts_bytes)?;
        Ok(partial_scripts)
    }
}

pub async fn get_fee_rate(client: &BitVM2Client) -> Result<f64, Box<dyn std::error::Error>> {
    let res = client.esplora.get_fee_estimates().await?;
    Ok(*res
        .get(&DEFAULT_CONFIRMATION_TARGET)
        .ok_or(format!("fee for {} confirmation target not found", DEFAULT_CONFIRMATION_TARGET))?)
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
        node_sign(&mut prekickoff_tx, i, prev_output.value, EcdsaSighashType::All, &node_keypair)?;
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
    _instance_id: Uuid,
    graph_id: Uuid,
    kickoff_txid: &Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    // check if kickoff is confirmed on L1
    if let None = client.esplora.get_tx(kickoff_txid).await? {
        return Ok(false);
    }

    // check if withdraw is initialized on L2
    let withdraw_status = client.chain_service.adaptor.get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        return Ok(false);
    };

    let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
    let utxos = client.esplora.get_address_utxo(node_address).await?;
    let utxo_spent_fee = Amount::from_sat(
        (get_fee_rate(client).await? * 2.0 * CHEKSIG_P2WSH_INPUT_VBYTES as f64).ceil() as u64,
    );
    let total_effective_balance: Amount =
        utxos
            .iter()
            .map(|utxo| {
                if utxo.value > utxo_spent_fee { utxo.value - utxo_spent_fee } else { Amount::ZERO }
            })
            .sum();
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

/// Retrieves the Groth16 proof, public inputs, and verifying key
/// for the given graph.
///
/// These are fetched via the ProofNetwork SDK.
pub fn get_groth16_proof(
    _instance_id: Uuid,
    _graph_id: Uuid,
) -> Result<(Groth16Proof, PublicInputs, VerifyingKey), Box<dyn std::error::Error>> {
    let mock_proof_bytes: Vec<u8> = [
        162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90,
        122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218, 218,
        151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122, 206, 36,
        122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94, 59, 146, 46,
        252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226, 132, 40, 24, 248,
        232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29, 120, 188, 18, 78, 86, 8,
        121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183, 5, 8, 150, 74, 241, 141, 65,
        150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63, 133, 11, 209, 39, 79, 138, 185, 88,
        20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157, 82, 192, 52, 95, 143, 49, 227, 83, 19, 26,
        108, 63, 232, 213, 169, 64, 221, 159, 214, 220, 246, 174, 35, 43, 143, 80, 168, 142, 29,
        103, 179, 58, 235, 33, 163, 198, 255, 188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18,
        24, 178, 219, 78, 12, 96, 10, 2, 133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74,
        62, 25, 115, 70, 42, 38, 131, 92, 103, 103, 176, 212, 223, 177, 242, 94, 14,
    ]
    .to_vec();
    let mock_scalar = [
        232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129,
        129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
    ]
    .to_vec();
    let proof: ark_groth16::Proof<ark_bn254::Bn254> =
        ark_groth16::Proof::deserialize_uncompressed(&mock_proof_bytes[..])?;
    let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&mock_scalar[..])?;
    Ok((proof, vec![scalar], get_vk()?))
}
pub fn get_vk() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let mock_vk_bytes = [
        115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162, 65,
        107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198, 247, 76,
        241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120, 207, 150, 125,
        108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25, 185, 98, 13, 235,
        118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123, 7, 247, 33, 178, 155,
        121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100, 17, 56, 159, 79, 13, 219,
        221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146, 45, 201, 157, 226, 84, 213,
        135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51, 95, 177, 47, 57, 29, 199, 224,
        98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228, 89, 51, 58, 6, 226, 139, 99, 207,
        22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218, 111, 151, 4, 55, 230, 76, 90, 209, 149,
        113, 248, 245, 50, 231, 137, 51, 157, 40, 29, 184, 198, 201, 108, 199, 89, 67, 136, 239,
        96, 216, 237, 172, 29, 84, 3, 128, 240, 2, 218, 169, 217, 118, 179, 34, 226, 19, 227, 59,
        193, 131, 108, 20, 113, 46, 170, 196, 156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46,
        249, 115, 239, 14, 176, 200, 134, 158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176,
        96, 177, 187, 184, 252, 14, 226, 127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161,
        110, 20, 154, 131, 23, 217, 116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116,
        57, 198, 237, 147, 183, 164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99,
        132, 199, 139, 172, 108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3,
        176, 185, 70, 66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132,
        226, 43, 145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78,
        41, 199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188,
        59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67, 204,
        164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2, 0, 0, 0,
        0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158, 0, 175, 140,
        72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80, 204, 41, 128, 69,
        52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58, 10, 92, 252, 227, 214,
        99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207, 78, 152, 132, 94, 207, 50,
        243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193, 21, 175, 180, 1, 26, 107, 39,
        198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163, 80, 74, 253, 176, 207, 47, 52, 7,
        84, 59, 151, 47, 178, 165, 112, 251, 161,
    ]
    .to_vec();
    Ok(ark_groth16::VerifyingKey::deserialize_uncompressed(&mock_vk_bytes[..])?)
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

pub async fn update_graph_fields(
    client: &BitVM2Client,
    graph_id: Uuid,
    graph_state: Option<String>,
    ipfs_base_url: Option<String>,
    challenge_txid: Option<String>,
    disprove_txid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    Ok(storage_process
        .update_graph_status_or_ipfs_base(
            graph_id,
            graph_state,
            ipfs_base_url,
            challenge_txid,
            disprove_txid,
        )
        .await?)
}
pub async fn store_graph(
    client: &BitVM2Client,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &Bitvm2Graph,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transaction = client.local_db.start_transaction().await?;
    let assert_commit_txids: Vec<String> =
        graph.assert_commit.commit_txns.iter().map(|v| v.tx().compute_txid().to_string()).collect();
    transaction
        .update_graph(Graph {
            graph_id,
            instance_id,
            graph_ipfs_base_url: "".to_string(),
            pegin_txid: graph.pegin.tx().compute_txid().to_string(),
            amount: graph.parameters.pegin_amount.to_sat() as i64,
            status: status.clone().unwrap_or_else(|| GraphStatus::OperatorPresigned.to_string()),
            pre_kickoff_txid: Some(graph.pre_kickoff.tx().compute_txid().to_string()),
            kickoff_txid: Some(graph.kickoff.tx().compute_txid().to_string()),
            challenge_txid: None,
            take1_txid: Some(graph.take1.tx().compute_txid().to_string()),
            assert_init_txid: Some(graph.assert_init.tx().compute_txid().to_string()),
            assert_commit_txids: Some(
                serde_json::to_string(&assert_commit_txids).expect("fail to encode to json"),
            ),
            assert_final_txid: Some(graph.assert_final.tx().compute_txid().to_string()),
            take2_txid: Some(graph.take2.tx().compute_txid().to_string()),
            disprove_txid: None,
            operator: graph.parameters.operator_pubkey.to_string(),
            raw_data: Some(serde_json::to_string(&graph).expect("to json string")),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;

    if let Some(status) = status {
        if status == GraphStatus::CommitteePresigned.to_string() {
            transaction
                .update_instance_status_and_pegin_txid(
                    &instance_id,
                    Some(BridgeInStatus::Presigned.to_string()),
                    Some(graph.pegin.tx().compute_txid().to_string()),
                )
                .await?
        }
    }
    transaction.commit().await?;
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

pub async fn publish_graph_to_ipfs(
    client: &BitVM2Client,
    graph_id: Uuid,
    graph: &Bitvm2Graph,
) -> Result<String, Box<dyn std::error::Error>> {
    fn write_tx(
        base_dir: &str,
        tx_name: IpfsTxName,
        tx: &Transaction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // write tx_hex to base_dir/tx_name
        let tx_hex = serialize_hex(tx);
        let tx_cache_path = format!("{}{}", base_dir, tx_name.as_str());
        let mut file = File::create(&tx_cache_path)?;
        file.write_all(tx_hex.as_bytes())?;
        Ok(())
    }

    let base_dir = format!("{}{}/", IPFS_GRAPH_CACHE_DIR, graph_id);
    fs::create_dir_all(base_dir.clone())?;
    write_tx(&base_dir, IpfsTxName::AssertCommit0, graph.assert_commit.commit_txns[0].tx())?;
    write_tx(&base_dir, IpfsTxName::AssertCommit1, graph.assert_commit.commit_txns[1].tx())?;
    write_tx(&base_dir, IpfsTxName::AssertCommit2, graph.assert_commit.commit_txns[2].tx())?;
    write_tx(&base_dir, IpfsTxName::AssertCommit3, graph.assert_commit.commit_txns[3].tx())?;
    write_tx(&base_dir, IpfsTxName::AssertInit, graph.assert_init.tx())?;
    write_tx(&base_dir, IpfsTxName::AssertFinal, graph.assert_final.tx())?;
    write_tx(&base_dir, IpfsTxName::Challenge, graph.challenge.tx())?;
    write_tx(&base_dir, IpfsTxName::Disprove, graph.disprove.tx())?;
    write_tx(&base_dir, IpfsTxName::Kickoff, graph.kickoff.tx())?;
    write_tx(&base_dir, IpfsTxName::Pegin, graph.pegin.tx())?;
    write_tx(&base_dir, IpfsTxName::Take1, graph.take1.tx())?;
    write_tx(&base_dir, IpfsTxName::Take2, graph.take2.tx())?;
    let cids = client.ipfs.add(&Path::new(&base_dir)).await?;
    let dir_cid = cids
        .iter()
        .find(|f| f.name.is_empty())
        .map(|f| f.hash.clone())
        .ok_or("cid for graph dir not found")?;

    // try to delete the cache files to free up disk, failed deletions do not affect subsequent executions, so there is no need to return an error
    let _ = fs::remove_dir_all(base_dir);
    Ok(dir_cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use client::chain::{chain_adaptor::GoatNetwork, goat_adaptor::GoatInitConfig};
    use reqwest::Url;
    use serial_test::serial;
    use std::fmt;

    async fn test_client() -> BitVM2Client {
        let global_init_config = GoatInitConfig {
            rpc_url: "https://rpc.testnet3.goat.network".parse::<Url>().expect("decode url"),
            gateway_address: "0xeD8AeeD334fA446FA03Aa00B28aFf02FA8aC02df"
                .parse()
                .expect("parse contract address"),
            gateway_creation_block: 0,
            to_block: None,
            private_key: None,
            chain_id: 48816_u32,
        };
        //  let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        BitVM2Client::new(
            tmp_db.path().as_os_str().to_str().unwrap(),
            None,
            Network::Testnet,
            GoatNetwork::Test,
            global_init_config,
            "http://44.229.236.82:5001",
        )
        .await
    }

    fn mock_input() -> CustomInputs {
        let input_amount = Amount::from_sat(10000);
        let fee_amount = Amount::from_sat(2000);
        let mock_input = Input {
            outpoint: OutPoint {
                txid: Txid::from_str(
                    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                )
                .unwrap(),
                vout: 0,
            },
            amount: Amount::from_btc(10000.0).unwrap(),
        };
        let change_address = Address::p2wsh(&ScriptBuf::default(), get_network());
        CustomInputs { inputs: vec![mock_input.clone()], input_amount, fee_amount, change_address }
    }

    #[test]
    fn test_statics() {
        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();
        let other_graph_id = Uuid::new_v4();

        assert!(is_processing_graph() == false);
        assert!(try_start_new_graph(instance_id, graph_id));
        assert!(is_processing_graph() == true);
        assert!(current_processing_graph() == Some((instance_id, graph_id)));

        finish_current_graph_processing(instance_id, other_graph_id);
        assert!(is_processing_graph() == true);

        finish_current_graph_processing(instance_id, graph_id);
        assert!(is_processing_graph() == false);

        try_start_new_graph(instance_id, graph_id);
        assert!(is_processing_graph() == true);
        force_stop_current_graph();
        assert!(is_processing_graph() == false);
    }

    #[tokio::test]
    #[serial(env)]
    async fn test_should_generate_graph() {
        let client = test_client().await;
        let mock_create_graph_prepare_data = CreateGraphPrepare {
            instance_id: Uuid::new_v4(),
            network: get_network(),
            depositor_evm_address: [0xff; 20],
            pegin_amount: Amount::from_sat(100000),
            user_inputs: mock_input(),
            committee_member_pubkey: PublicKey::from_str(
                "028b839569cde368894237913fe4fbd25d75eaf1ed019a39d479e693dac35be19e",
            )
            .unwrap(),
            committee_members_num: 2,
        };

        // rich operator
        unsafe {
            std::env::set_var(ENV_ACTOR, "Operator");
            std::env::set_var(
                ENV_BITVM_SECRET,
                "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac",
            );
        }
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey().unwrap());
        let utxos = client.esplora.get_address_utxo(node_address.clone()).await.unwrap();
        let balance: Amount = utxos.iter().map(|utxo| utxo.value).sum();
        let flag = should_generate_graph(&client, &mock_create_graph_prepare_data).await.unwrap();
        println!(
            "node: {}, balance: {} BTC, should_generate_graph: {}",
            node_address,
            balance.to_btc(),
            flag
        );

        // poor operator
        unsafe {
            std::env::set_var(
                ENV_BITVM_SECRET,
                "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2",
            );
        }
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey().unwrap());
        let utxos = client.esplora.get_address_utxo(node_address.clone()).await.unwrap();
        let balance: Amount = utxos.iter().map(|utxo| utxo.value).sum();
        let flag = should_generate_graph(&client, &mock_create_graph_prepare_data).await.unwrap();
        println!(
            "node: {}, balance: {} BTC, should_generate_graph: {}",
            node_address,
            balance.to_btc(),
            flag
        );
    }

    #[tokio::test]
    #[ignore = "test graph required"]
    async fn test_is_withdraw_initialized_on_l2() {
        let client = test_client().await;
        let unused_instance_id = Uuid::new_v4();
        // TODO: post test graph to L2
        let initialized_graph_id = Uuid::from_slice(&hex::decode("").unwrap()).unwrap();
        let uninitialized_graph_id = Uuid::from_slice(&hex::decode("").unwrap()).unwrap();
        assert_eq!(
            true,
            is_withdraw_initialized_on_l2(&client, unused_instance_id, initialized_graph_id)
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            is_withdraw_initialized_on_l2(&client, unused_instance_id, uninitialized_graph_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_is_take1_timelock_expired() {
        let client = test_client().await;
        let kickoff_txid =
            Txid::from_str("4dd13ca25ef6edb4506394a402db2368d02d9467bc47326d3553310483f2ed04")
                .unwrap();
        assert_eq!(true, is_take1_timelock_expired(&client, kickoff_txid).await.unwrap());
    }

    #[tokio::test]
    async fn test_is_take2_timelock_expired() {
        let client = test_client().await;
        let assert_final_txid =
            Txid::from_str("a2dedfbf376b8c0c183b4dfac7b0765b129a345c870f9fabbdf8c48072697a27")
                .unwrap();
        assert_eq!(true, is_take2_timelock_expired(&client, assert_final_txid).await.unwrap());
    }

    #[tokio::test]
    #[serial(env)]
    async fn test_select_operator_inputs() {
        let client = test_client().await;
        let stake_amount = Amount::from_sat(1600000);
        struct UtxoDisplay(Option<CustomInputs>);

        impl fmt::Display for UtxoDisplay {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match &self.0 {
                    Some(v) => {
                        let items: Vec<String> = v
                            .inputs
                            .iter()
                            .map(|input| {
                                format!(
                                    "{}:{}:{}",
                                    input.outpoint.txid.to_string(),
                                    input.outpoint.vout,
                                    input.amount.to_btc()
                                )
                            })
                            .collect();
                        write!(f, "[ {} ]", items.join(", "))
                    }
                    _ => {
                        write!(f, "insufficient balance")
                    }
                }
            }
        }

        // rich operator
        unsafe {
            std::env::set_var(ENV_ACTOR, "Operator");
            std::env::set_var(
                ENV_BITVM_SECRET,
                "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac",
            );
        }
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey().unwrap());
        let inputs = select_operator_inputs(&client, stake_amount).await.unwrap();
        println!(
            "node: {}, stake_amount: {} BTC, utxos: {}",
            node_address,
            stake_amount,
            UtxoDisplay(inputs)
        );

        // poor operator
        unsafe {
            std::env::set_var(
                ENV_BITVM_SECRET,
                "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2",
            );
        }
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey().unwrap());
        let inputs = select_operator_inputs(&client, stake_amount).await.unwrap();
        println!(
            "node: {}, stake_amount: {} BTC, utxos: {}",
            node_address,
            stake_amount,
            UtxoDisplay(inputs)
        );
    }

    #[tokio::test]
    #[serial(env)]
    async fn test_should_challenge() {
        let client = test_client().await;
        let challenge_amount = Amount::from_sat(1600000);
        let mock_instance_id = Uuid::new_v4();
        let mock_graph_id = Uuid::new_v4();
        let invalid_kickoff_txid =
            Txid::from_str("0c598f63bffe9d7468ce6930bf0fe1ba5c6e125c9c9e38674ee380dd2c6d97f6")
                .unwrap();
        // TODO: add test case: valid kickoff tx

        // rich challenger
        unsafe {
            std::env::set_var(ENV_ACTOR, "Challenger");
            std::env::set_var(
                ENV_BITVM_SECRET,
                "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac",
            );
        }
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey().unwrap());
        let utxos = client.esplora.get_address_utxo(node_address.clone()).await.unwrap();
        let balance: Amount = utxos.iter().map(|utxo| utxo.value).sum();
        let flag = should_challenge(
            &client,
            challenge_amount,
            mock_instance_id,
            mock_graph_id,
            &invalid_kickoff_txid,
        )
        .await
        .unwrap();
        println!(
            "kickoff(invalid): {}, node: {}, balance: {} BTC, should_challenge: {}",
            invalid_kickoff_txid.to_string(),
            node_address,
            balance.to_btc(),
            flag
        );

        // poor challenger
        unsafe {
            std::env::set_var(
                ENV_BITVM_SECRET,
                "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2",
            );
        }
        let node_address = node_p2wsh_address(get_network(), &get_node_pubkey().unwrap());
        let utxos = client.esplora.get_address_utxo(node_address.clone()).await.unwrap();
        let balance: Amount = utxos.iter().map(|utxo| utxo.value).sum();
        let flag = should_challenge(
            &client,
            challenge_amount,
            mock_instance_id,
            mock_graph_id,
            &invalid_kickoff_txid,
        )
        .await
        .unwrap();
        println!(
            "kickoff(invalid): {}, node: {}, balance: {} BTC, should_challenge: {}",
            invalid_kickoff_txid.to_string(),
            node_address,
            balance.to_btc(),
            flag
        );
    }

    #[tokio::test]
    async fn test_validate_challenge() {
        let client = test_client().await;
        let kickoff_txid =
            Txid::from_str("0c598f63bffe9d7468ce6930bf0fe1ba5c6e125c9c9e38674ee380dd2c6d97f6")
                .unwrap();
        let challenge_txid =
            Txid::from_str("d2a2beff7dc0f93fc41505b646c6fa174991b0c4e415a96359607c37ba88e376")
                .unwrap();
        let mismatch_challenge_txid =
            Txid::from_str("c6a033812a1370973f94d956704ed1a68f490141a3c21bce64454d38a2c23794")
                .unwrap();
        let nonexistent_challenge_txid =
            Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")
                .unwrap();

        assert_eq!(
            true,
            validate_challenge(&client, &kickoff_txid, &challenge_txid).await.unwrap()
        );
        assert_eq!(
            false,
            validate_challenge(&client, &kickoff_txid, &mismatch_challenge_txid).await.unwrap()
        );
        assert_eq!(
            false,
            validate_challenge(&client, &kickoff_txid, &nonexistent_challenge_txid).await.unwrap()
        );
    }

    #[tokio::test]
    async fn test_validate_disprove() {
        let client = test_client().await;
        let assert_final_txid =
            Txid::from_str("2da6b0f73cd8835d5b76b62b9bd22314ee61212d348f6a4dbad915253f121012")
                .unwrap();
        let disprove_txid =
            Txid::from_str("5773755d1d0f750830edae5e1afcb37ab106e2dd46e164b09bf6213a0f45b0e1")
                .unwrap();
        let mismatch_disprove_txid =
            Txid::from_str("c6a033812a1370973f94d956704ed1a68f490141a3c21bce64454d38a2c23794")
                .unwrap();

        assert_eq!(
            true,
            validate_disprove(&client, &assert_final_txid, &disprove_txid).await.unwrap()
        );
        assert_eq!(
            false,
            validate_disprove(&client, &assert_final_txid, &mismatch_disprove_txid).await.unwrap()
        );
    }
}
