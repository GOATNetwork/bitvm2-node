use crate::action::{CreateGraphPrepare, GOATMessage, GOATMessageContent, NodeInfo, send_to_peer};
use crate::client::chain::chain_adaptor::WithdrawStatus;
use crate::client::chain::utils::{
    get_graph_ids_by_instance_id, validate_committee, validate_operator, validate_relayer,
};
use crate::client::{BTCClient, GOATClient};
use crate::env::*;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use alloy::providers::ProviderBuilder;
use ark_serialize::CanonicalDeserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, PrivateKey,
    PublicKey, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_script::{Script, script};
use bitvm::chunk::api::NUM_TAPS;
use bitvm::signatures::signing_winternitz::{WinternitzSigningInputs, generate_winternitz_witness};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::committee::COMMITTEE_PRE_SIGN_NUM;
use bitvm2_lib::keys::OperatorMasterKey;
use bitvm2_lib::operator::{generate_disprove_scripts, generate_partial_scripts};
use bitvm2_lib::types::{
    Bitvm2Graph, CustomInputs, Groth16Proof, PublicInputs, VerifyingKey, WotsPublicKeys,
};
use bitvm2_lib::verifier::{extract_proof_sigs_from_assert_commit_txns, verify_proof};
use esplora_client::Utxo;
use goat::commitments::CommitmentMessageId;
use goat::connectors::base::TaprootConnector;
use goat::connectors::connector_6::Connector6;
use goat::constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK};
use goat::transactions::assert::utils::COMMIT_TX_NUM;
use goat::transactions::base::Input;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::signing::{
    generate_taproot_leaf_schnorr_signature, populate_p2wsh_witness, populate_taproot_input_witness,
};
use goat::utils::num_blocks_per_network;
use libp2p::Swarm;
use musig2::{PartialSignature, PubNonce};
use rand::Rng;
use secp256k1::Secp256k1;
use statics::*;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use store::ipfs::IPFS;
use store::localdb::LocalDB;
use store::{BridgeInStatus, Graph, GraphStatus, Node};
use tracing::warn;
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
    client: &BTCClient,
    create_graph_prepare_data: &CreateGraphPrepare,
) -> Result<bool, Box<dyn std::error::Error>> {
    if is_processing_graph() {
        return Ok(false);
    };
    let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
    let utxos = client.esplora.get_address_utxo(node_address.clone()).await?;
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
    let stake_amount = get_stake_amount(create_graph_prepare_data.pegin_amount.to_sat());
    if total_effective_balance < stake_amount {
        tracing::warn!(
            "node address {node_address} ran out of BTC for kickoff, requiring {stake_amount}"
        );
        Ok(false)
    } else {
        Ok(true)
    }
}

pub async fn is_valid_withdraw(
    client: &GOATClient,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let withdraw_status = client.chain_service.adaptor.get_withdraw_data(&graph_id).await?.status;
    Ok([WithdrawStatus::Initialized, WithdrawStatus::Processing].contains(&withdraw_status))
    // TODO: Only WithdrawStatus::Processing should be considered valid,
    // here WithdrawStatus::Initialized is also treated as valid to facilitate test
    // Ok(withdraw_status == WithdrawStatus::Processing)
}

/// Checks whether the status of the graph (identified by instance ID and graph ID)
/// on the Layer 2 contract is currently `Initialized`.
pub async fn is_withdraw_initialized_on_l2(
    client: &GOATClient,
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
    client: &BTCClient,
    kickoff_txid: Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    let tx_status = client.esplora.get_tx_status(&kickoff_txid).await?;
    match tx_status.block_height {
        Some(tx_height) => {
            let current_height = client.esplora.get_height().await?;
            Ok(current_height >= tx_height + lock_blocks)
        }
        _ => Ok(false),
    }
}

/// Checks whether the timelock for the specified assert-final transaction has expired,
/// allowing the `take2` transaction to proceed.
///
/// The timelock duration is a fixed constant (goat::constants::CONNECTOR_4_TIMELOCK)
pub async fn is_take2_timelock_expired(
    client: &BTCClient,
    assert_final_txid: Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_4_TIMELOCK);
    let tx_status = client.esplora.get_tx_status(&assert_final_txid).await?;
    match tx_status.block_height {
        Some(tx_height) => {
            let current_height = client.esplora.get_height().await?;
            Ok(current_height >= tx_height + lock_blocks)
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
    client: &BTCClient,
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

pub async fn get_fee_rate(client: &BTCClient) -> Result<f64, Box<dyn std::error::Error>> {
    match client.network {
        //TODO mempool api /fee-estimates failed, fix it latter
        Network::Testnet | Network::Regtest => Ok(1.0),
        _ => {
            let res = client.esplora.get_fee_estimates().await?;
            Ok(*res.get(&DEFAULT_CONFIRMATION_TARGET).ok_or(format!(
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
pub async fn broadcast_tx(
    client: &BTCClient,
    tx: &Transaction,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(client.esplora.broadcast(tx).await?)
}

/// Signs and broadcasts pre-kickoff transaction.
///
/// All inputs of pre-kickoff transaction should be utxo belonging to node-address
pub async fn sign_and_broadcast_prekickoff_tx(
    client: &BTCClient,
    node_keypair: Keypair,
    prekickoff_tx: Transaction,
) -> Result<(), Box<dyn std::error::Error>> {
    let node_address = node_p2wsh_address(get_network(), &node_keypair.public_key().into());
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

#[allow(dead_code)]
pub async fn recycle_prekickoff_tx(
    client: &BTCClient,
    graph_id: Uuid,
    master_key: OperatorMasterKey,
    prekickoff_txid: Txid,
) -> Result<Option<Txid>, Box<dyn std::error::Error>> {
    let network = get_network();
    let prekickoff_tx = client
        .esplora
        .get_tx(&prekickoff_txid)
        .await?
        .ok_or(format!("pre-kickoff tx {prekickoff_txid} not on chain"))?;
    let fee_rate = get_fee_rate(client).await?;
    let recycle_tx_vbytes = 3105;
    let fee_amount = Amount::from_sat((recycle_tx_vbytes as f64 * fee_rate).ceil() as u64);
    if prekickoff_tx.output[0].value > fee_amount + Amount::from_sat(DUST_AMOUNT) {
        let node_recycle_address =
            node_p2wsh_address(network, &master_key.master_keypair().public_key().into());
        let node_graph_keypair = master_key.keypair_for_graph(graph_id);
        let (operator_taproot_pubkey, _) = node_graph_keypair.x_only_public_key();
        let (operator_wots_seckeys, operator_wots_pubkeys) =
            master_key.wots_keypair_for_graph(graph_id);
        let kickoff_wots_commitment_keys =
            CommitmentMessageId::pubkey_map_for_kickoff(&operator_wots_pubkeys.0);
        let connector_6 =
            Connector6::new(network, &operator_taproot_pubkey, &kickoff_wots_commitment_keys);
        let txin_0 = TxIn {
            previous_output: OutPoint { txid: prekickoff_txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let txout_0 = TxOut {
            value: prekickoff_tx.output[0].value - fee_amount,
            script_pubkey: node_recycle_address.script_pubkey(),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin_0],
            output: vec![txout_0],
        };

        let script = &connector_6.generate_taproot_leaf_script(0);
        let prev_outs = [prekickoff_tx.output[0].clone()];
        let taproot_spend_info = connector_6.generate_taproot_spend_info();
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();

        // get schnorr signature
        let schnorr_signature = generate_taproot_leaf_schnorr_signature(
            &mut tx,
            &prev_outs,
            0,
            TapSighashType::All,
            script,
            &node_graph_keypair,
        );
        unlock_data.push(schnorr_signature.to_vec());

        // get winternitz signature for evm withdraw txid
        let winternitz_signing_inputs = WinternitzSigningInputs {
            message: [0u8; 32].as_ref(),
            signing_key: &operator_wots_seckeys.0[0],
        };
        unlock_data.extend(generate_winternitz_witness(&winternitz_signing_inputs).to_vec());

        populate_taproot_input_witness(&mut tx, 0, &taproot_spend_info, script, unlock_data);

        broadcast_tx(client, &tx).await?;

        Ok(Some(tx.compute_txid()))
    } else {
        Ok(None)
    }
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
    client: &BTCClient,
    node_keypair: Keypair,
    challenge_tx: Transaction,
    // challenge_amount: Amount,
) -> Result<Txid, Box<dyn std::error::Error>> {
    let node_address = node_p2wsh_address(get_network(), &node_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let mut challenge_tx = challenge_tx;
    let challenge_amount = challenge_tx.output[0].value;
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
                    value: change_amount,
                });
            };
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut challenge_tx,
                    i + 1,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_keypair,
                )?;
            }
            broadcast_tx(client, &challenge_tx).await?;
            Ok(challenge_tx.compute_txid())
        }
        _ => Err(format!("insufficient btc, please fund {node_address} first").into()),
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
    println!("get utxos from: {address}");

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
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    challenge_amount: Amount,
    _instance_id: Uuid,
    graph_id: Uuid,
    kickoff_txid: &Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    // check if kickoff is confirmed on L1
    if btc_client.esplora.get_tx(kickoff_txid).await?.is_none() {
        return Ok(false);
    }

    // check if withdraw is initialized on L2
    let withdraw_status =
        goat_client.chain_service.adaptor.get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized
        || withdraw_status == WithdrawStatus::Processing
    {
        return Ok(false);
    };

    let node_address = node_p2wsh_address(get_network(), &get_node_pubkey()?);
    let utxos = btc_client.esplora.get_address_utxo(node_address.clone()).await?;
    let utxo_spent_fee = Amount::from_sat(
        (get_fee_rate(btc_client).await? * 2.0 * CHEKSIG_P2WSH_INPUT_VBYTES as f64).ceil() as u64,
    );
    let total_effective_balance: Amount =
        utxos
            .iter()
            .map(|utxo| {
                if utxo.value > utxo_spent_fee { utxo.value - utxo_spent_fee } else { Amount::ZERO }
            })
            .sum();
    if total_effective_balance < challenge_amount {
        tracing::warn!(
            "graph {graph_id}, kickoff is invalid, but node address {node_address} ran out of BTC for challenge, requiring {challenge_amount}"
        );
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Validates whether the given kickoff transaction has been confirmed on Layer 1.
pub async fn tx_on_chain(
    client: &BTCClient,
    txid: &Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    match client.esplora.get_tx(txid).await? {
        Some(_) => Ok(true),
        _ => Ok(false),
    }
}

pub async fn outpoint_available(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    match client.esplora.get_output_status(txid, vout).await? {
        Some(status) => Ok(!status.spent),
        _ => Ok(false),
    }
}

pub async fn outpoint_spent_txid(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<Txid>, Box<dyn std::error::Error>> {
    match client.esplora.get_output_status(txid, vout).await? {
        Some(status) => Ok(status.txid),
        _ => Ok(None),
    }
}

/// Validates whether the given challenge transaction has been confirmed on Layer 1.
pub async fn validate_challenge(
    btc_client: &BTCClient,
    kickoff_txid: &Txid,
    challenge_txid: &Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let challenge_tx = match btc_client.esplora.get_tx(challenge_txid).await? {
        Some(tx) => tx,
        _ => return Ok(false),
    };
    let expected_challenge_input_0 = OutPoint { txid: *kickoff_txid, vout: 1 };
    Ok(challenge_tx.input[0].previous_output == expected_challenge_input_0)
}

/// Validates whether the given disprove transaction has been confirmed on Layer 1.
pub async fn validate_disprove(
    btc_client: &BTCClient,
    assert_final_txid: &Txid,
    disprove_txid: &Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let disprove_tx = match btc_client.esplora.get_tx(disprove_txid).await? {
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
    btc_client: &BTCClient,
    assert_commit_txns: &[Txid; COMMIT_TX_NUM],
    wots_pubkeys: WotsPublicKeys,
) -> Result<Option<(usize, Script)>, Box<dyn std::error::Error>> {
    let mut txs = Vec::with_capacity(COMMIT_TX_NUM);
    for txid in assert_commit_txns.iter() {
        let tx = match btc_client.esplora.get_tx(txid).await? {
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
pub async fn get_groth16_proof(
    local_db: &LocalDB,
    instance_id: &Uuid,
    graph_id: &Uuid,
) -> Result<(Groth16Proof, PublicInputs, VerifyingKey), Box<dyn std::error::Error>> {
    let (proof, pis) = {
        // query proof from database.
        let mut db_lock = local_db.acquire().await?;
        let (proof, pis) = db_lock.get_proof_with_pis(instance_id, graph_id).await?;
        let proof_bytes = hex::decode(proof)?;
        let pis_bytes = hex::decode(pis)?;
        (proof_bytes, pis_bytes)
    };
    let proof: ark_groth16::Proof<ark_bn254::Bn254> =
        ark_groth16::Proof::deserialize_uncompressed(&proof[..])?;
    let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&pis[..])?;
    Ok((proof, vec![scalar], get_vk()?))
}
pub fn get_vk() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let zkm_v1_vk_bytes = [
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
    Ok(ark_groth16::VerifyingKey::deserialize_uncompressed(&zkm_v1_vk_bytes[..])?)
}

/// l2 support
pub async fn finish_withdraw_happy_path(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph_id: &Uuid,
    tx: &Transaction,
) -> Result<String, Box<dyn std::error::Error>> {
    let tx_hash = goat_client.finish_withdraw_happy_path(btc_client, graph_id, tx).await?;
    tracing::info!("graph_id:{} finish take1, tx_hash: {}", graph_id, tx_hash);
    Ok(tx_hash)
}
pub async fn finish_withdraw_unhappy_path(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph_id: &Uuid,
    tx: &Transaction,
) -> Result<String, Box<dyn std::error::Error>> {
    let tx_hash = goat_client.finish_withdraw_unhappy_path(btc_client, graph_id, tx).await?;
    tracing::info!("graph_id:{} finish take2, tx_hash: {}", graph_id, tx_hash);
    Ok(tx_hash)
}

pub async fn finish_withdraw_disproved(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph_id: &Uuid,
    tx: &Transaction,
) -> Result<String, Box<dyn std::error::Error>> {
    let tx_hash = goat_client.finish_withdraw_disproved(btc_client, graph_id, tx).await?;
    tracing::info!("graph_id:{} finish disprove, tx_hash: {}", graph_id, tx_hash);
    Ok(tx_hash)
}

/// db support
pub async fn store_committee_pub_nonces(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    let nonces_vec: Vec<String> = pub_nonces.iter().map(|v| v.to_string()).collect();
    let nonces_arr: [String; COMMITTEE_PRE_SIGN_NUM] =
        nonces_vec.try_into().map_err(|v: Vec<String>| {
            format!("length wrong: expect {COMMITTEE_PRE_SIGN_NUM}, real {}", v.len())
        })?;
    Ok(storage_process
        .store_nonces(instance_id, graph_id, &[nonces_arr], committee_pubkey.to_string(), &[])
        .await?)
}
pub async fn get_committee_pub_nonces(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    match storage_process.get_nonces(instance_id, graph_id).await? {
        None => Err(format!("instance id:{instance_id}, graph id:{graph_id} not found").into()),
        Some(nonce_collect) => {
            let mut res: Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]> = vec![];
            for nonces_item in nonce_collect.nonces {
                let nonce_vec: Vec<PubNonce> = nonces_item
                    .iter()
                    .map(|v| PubNonce::from_str(v).expect("fail to decode pub nonce"))
                    .collect();
                res.push(nonce_vec.try_into().map_err(|v: Vec<PubNonce>| {
                    format!("length wrong: expect {COMMITTEE_PRE_SIGN_NUM}, real {}", v.len())
                })?)
            }
            Ok(res)
        }
    }
}

pub async fn store_committee_pubkeys(
    local_db: &LocalDB,
    instance_id: Uuid,
    pubkey: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process.store_pubkeys(instance_id, &[pubkey.to_string()]).await?)
}
pub async fn get_committee_pubkeys(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
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
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    let signs_vec: Vec<String> = partial_sigs.iter().map(|v| hex::encode(v.serialize())).collect();
    let signs_arr: [String; COMMITTEE_PRE_SIGN_NUM] =
        signs_vec.try_into().map_err(|v: Vec<String>| {
            format!("length wrong: expect {COMMITTEE_PRE_SIGN_NUM}, real {}", v.len())
        })?;

    Ok(storage_process
        .store_nonces(instance_id, graph_id, &[], committee_pubkey.to_string(), &[signs_arr])
        .await?)
}

pub async fn get_committee_partial_sigs(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<[PartialSignature; COMMITTEE_PRE_SIGN_NUM]>, Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    match storage_process.get_nonces(instance_id, graph_id).await? {
        None => Err(format!("instance id:{instance_id}, graph id:{graph_id} not found ").into()),
        Some(nonce_collect) => {
            let mut res: Vec<[PartialSignature; COMMITTEE_PRE_SIGN_NUM]> = vec![];
            for signs_item in nonce_collect.partial_sigs {
                let signs_vec: Vec<PartialSignature> = signs_item
                    .iter()
                    .map(|v| PartialSignature::from_str(v).expect("fail to decode pub nonce"))
                    .collect();
                res.push(signs_vec.try_into().map_err(|v: Vec<PartialSignature>| {
                    format!("length wrong: expect {COMMITTEE_PRE_SIGN_NUM}, real {}", v.len())
                })?)
            }
            Ok(res)
        }
    }
}

pub async fn update_graph_fields(
    local_db: &LocalDB,
    graph_id: Uuid,
    graph_state: Option<String>,
    ipfs_base_url: Option<String>,
    challenge_txid: Option<String>,
    disprove_txid: Option<String>,
    bridge_out_start_at: Option<i64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process
        .update_graph_fields(
            graph_id,
            graph_state,
            ipfs_base_url,
            challenge_txid,
            disprove_txid,
            bridge_out_start_at,
        )
        .await?)
}
pub async fn store_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &Bitvm2Graph,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transaction = local_db.start_transaction().await?;
    let assert_commit_txids: Vec<String> = graph
        .assert_commit
        .commit_txns
        .iter()
        .map(|v| serialize_hex(&v.tx().compute_txid()))
        .collect();
    let network = transaction.get_instance_network(&instance_id).await?;

    let mut bridge_out_from_addr = "".to_string();
    let mut bridge_out_to_addr = "".to_string();
    if let Ok(node_info) =
        transaction.get_node_by_btc_pub_key(&graph.parameters.operator_pubkey.to_string()).await
    {
        let network = Network::from_str(&network);
        if let Ok(network) = network
            && let Some(node_info) = node_info
        {
            bridge_out_from_addr = node_info.goat_addr;
            bridge_out_to_addr =
                node_p2wsh_address(network, &graph.parameters.operator_pubkey).to_string();
        }
    }
    transaction
        .update_graph(Graph {
            graph_id,
            instance_id,
            graph_ipfs_base_url: "".to_string(),
            pegin_txid: serialize_hex(&graph.pegin.tx().compute_txid()),
            amount: graph.parameters.pegin_amount.to_sat() as i64,
            status: status.clone().unwrap_or_else(|| GraphStatus::OperatorPresigned.to_string()),
            pre_kickoff_txid: Some(serialize_hex(&graph.pre_kickoff.tx().compute_txid())),
            kickoff_txid: Some(serialize_hex(&graph.kickoff.tx().compute_txid())),
            challenge_txid: None,
            take1_txid: Some(serialize_hex(&graph.take1.tx().compute_txid())),
            assert_init_txid: Some(serialize_hex(&graph.assert_init.tx().compute_txid())),
            assert_commit_txids: Some(
                serde_json::to_string(&assert_commit_txids).expect("fail to encode to json"),
            ),
            assert_final_txid: Some(serialize_hex(&graph.assert_final.tx().compute_txid())),
            take2_txid: Some(serialize_hex(&graph.take2.tx().compute_txid())),
            disprove_txid: None,
            operator: graph.parameters.operator_pubkey.to_string(),
            raw_data: Some(serde_json::to_string(&graph).expect("to json string")),
            bridge_out_start_at: 0,
            bridge_out_from_addr,
            bridge_out_to_addr,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;

    if let Some(status) = status
        && status == GraphStatus::CommitteePresigned.to_string()
    {
        let pegin_tx = graph.pegin.tx();
        let sum_input_value =
            graph.pegin.input_amounts.iter().fold(Amount::ZERO, |acc, v| acc + *v);
        let sum_output_value = pegin_tx.output.iter().fold(Amount::ZERO, |acc, v| acc + v.value);
        transaction
            .update_instance_fields(
                &instance_id,
                Some(BridgeInStatus::Presigned.to_string()),
                Some((
                    serialize_hex(&graph.pegin.tx().compute_txid()),
                    (sum_input_value - sum_output_value).to_sat() as i64,
                )),
                None,
            )
            .await?
    }

    transaction.commit().await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn update_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &Bitvm2Graph,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    store_graph(local_db, instance_id, graph_id, graph, status).await
}

pub async fn get_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Bitvm2Graph, Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    let graph_op = storage_process.get_graph(&graph_id).await?;
    if graph_op.is_none() {
        tracing::warn!("graph:{} is not record in db", graph_id);
        return Err(format!("graph:{graph_id} is not record in db").into());
    };
    let graph = graph_op.unwrap();
    if graph.instance_id.ne(&instance_id) {
        return Err(format!(
            "grap with graph_id:{graph_id} has instance_id:{} not match exp instance:{instance_id}",
            graph.instance_id,
        )
        .into());
    }

    if graph.raw_data.is_none() {
        return Err(format!("grap with graph_id:{graph_id} raw data is none").into());
    }
    let res: Bitvm2Graph = serde_json::from_str(graph.raw_data.unwrap().as_str())?;
    Ok(res)
}

pub async fn publish_graph_to_ipfs(
    ipfs: &IPFS,
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
        let tx_cache_path = format!("{base_dir}{}", tx_name.as_str());
        let mut file = File::create(&tx_cache_path)?;
        file.write_all(tx_hex.as_bytes())?;
        Ok(())
    }

    let base_dir = format!("{IPFS_GRAPH_CACHE_DIR}{graph_id}/");
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
    let cids = ipfs.add(Path::new(&base_dir)).await?;
    let dir_cid = cids
        .iter()
        .find(|f| f.name.is_empty())
        .map(|f| f.hash.clone())
        .ok_or("cid for graph dir not found")?;

    // try to delete the cache files to free up disk, failed deletions do not affect subsequent executions, so there is no need to return an error
    let _ = fs::remove_dir_all(base_dir);
    Ok(dir_cid)
}

pub async fn get_my_graph_for_instance(
    goat_client: &GOATClient,
    instance_id: Uuid,
    operator_pubkey: PublicKey,
) -> Result<Option<Uuid>, Box<dyn std::error::Error>> {
    // FIXME: don't use chain_service directly
    let ids_vec = goat_client
        .chain_service
        .adaptor
        .get_instanceids_by_pubkey(&operator_pubkey.to_bytes()[1..33].try_into()?)
        .await?;
    Ok(ids_vec.iter().find(|(a, _)| *a == instance_id).map(|(_, b)| *b))
}

pub async fn get_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<GraphStatus>, Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    let graph_op = storage_process.get_graph(&graph_id).await?;
    if graph_op.is_none() {
        return Ok(None);
    };
    let graph = graph_op.unwrap();
    if graph.instance_id.ne(&instance_id) {
        return Err(format!(
            "grap with graph_id:{graph_id} has instance_id:{} not match exp instance:{instance_id}",
            graph.instance_id,
        )
        .into());
    }
    Ok(Some(
        GraphStatus::from_str(&graph.status)
            .map_err(|_| format!("unknown graph status: {}", graph.status))?,
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
) -> Result<bool, Box<dyn std::error::Error>> {
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
        match btc_client.esplora.get_tx_status(txid).await {
            Ok(status) => {
                if let Some(_height) = status.block_height {
                    // println!("Transaction confirmed in block {}", height);
                    return Ok(true);
                } else {
                    // println!("Transaction unconfirmed, polling again...");
                }
            }
            Err(e) => {
                return Err(format!("Failed to fetch transaction status: {e}").into());
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

    #[test]
    fn test_defer() {
        use super::statics::*;
        use uuid::Uuid;
        fn inner_func(should_success: bool) -> Result<(), Box<dyn std::error::Error>> {
            if should_success { Ok(()) } else { Err("inner functions not success".into()) }
        }
        fn guarded_operation(should_success: bool) -> Result<(), Box<dyn std::error::Error>> {
            defer!(on_err, {
                force_stop_current_graph();
            });
            inner_func(should_success)?;
            dismiss_defer!(on_err);
            Ok(())
        }
        try_start_new_graph(Uuid::new_v4(), Uuid::new_v4());
        assert!(is_processing_graph());
        let _ = guarded_operation(true);
        assert!(is_processing_graph());
        let _ = guarded_operation(false);
        assert!(!is_processing_graph());
    }
}

pub async fn save_node_info(
    local_db: &LocalDB,
    node_info: &NodeInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("save_node_info for {}", node_info.peer_id);
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    let _ = storage_process
        .update_node(Node {
            peer_id: node_info.peer_id.clone(),
            actor: node_info.actor.clone(),
            goat_addr: node_info.goat_addr.clone(),
            btc_pub_key: node_info.btc_pub_key.clone(),
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

pub async fn update_node_timestamp(
    local_db: &LocalDB,
    peer_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("update timestamp for {peer_id}");
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    match storage_process.update_node_timestamp(peer_id, current_time).await {
        Ok(_) => {}
        Err(err) => warn!("{err}"),
    };
    Ok(())
}

pub async fn detect_heart_beat(
    swarm: &mut Swarm<AllBehaviours>,
) -> Result<(), Box<dyn std::error::Error>> {
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

pub async fn validate_actor(
    peer_id: &[u8],
    role: Actor,
) -> Result<bool, Box<dyn std::error::Error>> {
    let rpc_url = get_goat_url_from_env();
    let provider = ProviderBuilder::new().on_http(rpc_url);
    let goat_gateway_contract_address = get_goat_gateway_contract_from_env();
    match role {
        Actor::Committee => {
            Ok(validate_committee(&provider, goat_gateway_contract_address, peer_id).await?)
        }
        Actor::Operator => {
            Ok(validate_operator(&provider, goat_gateway_contract_address, peer_id).await?)
        }
        Actor::Relayer => {
            Ok(validate_relayer(&provider, goat_gateway_contract_address, peer_id).await?)
        }
        _ => Ok(true),
    }
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen_range(0..255)).collect()
}

pub fn get_rand_btc_address(network: Network) -> String {
    let secp = Secp256k1::new();
    Address::p2wpkh(
        &CompressedPublicKey::try_from(PrivateKey::generate(network).public_key(&secp))
            .expect("Could not compress public key"),
        Network::Testnet,
    )
    .to_string()
}

pub async fn obsolete_sibling_graphs(
    local_db: &LocalDB,
    instance_id: Uuid,
    reimbursed_graph_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = get_goat_url_from_env();
    let provider = ProviderBuilder::new().on_http(rpc_url);
    let goat_gateway_contract_address = get_goat_gateway_contract_from_env();
    let all_graphs =
        get_graph_ids_by_instance_id(&provider, goat_gateway_contract_address, instance_id).await?;
    for graph_id in all_graphs {
        if graph_id != reimbursed_graph_id
            && ![None, Some(GraphStatus::Disprove), Some(GraphStatus::Obsoleted)]
                .contains(&get_graph_status(local_db, instance_id, graph_id).await?)
        {
            update_graph_fields(
                local_db,
                graph_id,
                Some(GraphStatus::Obsoleted.to_string()),
                None,
                None,
                None,
                None,
            )
            .await?;
        }
    }
    Ok(())
}
