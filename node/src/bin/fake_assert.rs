use bitcoin::{EcdsaSighashType, Txid};
use bitcoin::{
    Network, PublicKey, TapSighashType, Transaction, TxOut, XOnlyPublicKey,
    consensus::encode::deserialize_hex,
};
use bitvm::chunk::api::type_conversion_utils::{RawWitness, utils_raw_witnesses_from_signatures};
use bitvm::execute_raw_script_with_inputs;
use bitvm2_lib::keys::OperatorMasterKey;
use bitvm2_lib::operator::{corrupt_proof, sign_proof};
use bitvm2_lib::types::{Groth16Proof, VerifyingKey};
use bitvm2_noded::client::BTCClient;
use bitvm2_noded::{
    env::{ENV_ACTOR, ENV_BITVM_SECRET, IpfsTxName},
    utils::{broadcast_tx, tx_on_chain},
};
use clap::Parser;
use goat::connectors::connector_b::ConnectorB;
use goat::proof::{deserialize_proof, deserialize_pubin, deserialize_vk};
use goat::scripts::generate_pay_to_pubkey_script;
use goat::transactions::assert::utils::{
    AllCommitConnectorsE, COMMIT_TX_NUM, MAX_CONNECTORS_E_PER_TX, SingleCommitConnectorsE,
};
use goat::transactions::signing::{populate_p2wsh_witness, populate_taproot_input_witness_default};
use goat::{
    connectors::base::TaprootConnector, contexts::base::generate_keys_from_secret,
    transactions::signing::populate_taproot_input_witness,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use store::ipfs::IPFS;
use uuid::Uuid;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "fake-assert")]
#[command(
    about = "Test disprove",
    long_about = "Send assert, this action should trigger disprove."
)]
struct Args {
    /// graph id
    #[arg(long)]
    graph: String,

    /// operator node bitvm secret key
    #[arg(long)]
    secret: String,

    /// ipfs rpc server url
    #[arg(long, default_value = "http://44.229.236.82:5001")]
    ipfs_url: String,

    /// ipfs cid for bitvm2 txns's dir
    #[arg(long)]
    txns_cid: String,

    /// generate & save wots-sigs for later use  
    #[arg(long)]
    prepare: bool,
}

async fn get_tx_from_ipfs(
    ipfs: &IPFS,
    base_url: &str,
    tx_name: IpfsTxName,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let tx_url = [base_url, "/", tx_name.as_str()].concat();
    let tx_hex = ipfs.cat(&tx_url).await?;
    Ok(deserialize_hex(&tx_hex)?)
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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let ipfs = IPFS::new(&args.ipfs_url);
    let network = Network::Testnet;
    let btc_client = BTCClient::new(None, network);
    unsafe {
        std::env::set_var(ENV_ACTOR, "Operator");
        std::env::set_var(ENV_BITVM_SECRET, &args.secret);
    }
    let (keypair, _) = generate_keys_from_secret(network, &args.secret);
    let (base_url, graph_id, master_key) =
        (args.txns_cid, Uuid::from_str(&args.graph).unwrap(), OperatorMasterKey::new(keypair));

    if args.prepare {
        fake_assert_commits(&ipfs, &base_url, network, graph_id, &master_key).await;
        return;
    }

    let mut assert_init = get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::AssertInit).await.unwrap();
    let operator_pubkey: PublicKey = master_key.keypair_for_graph(graph_id).public_key().into();
    if tx_on_chain(&btc_client, &assert_init.compute_txid()).await.unwrap() {
        println!("assert-init already sent: {}", assert_init.compute_txid());
    } else {
        println!("send assert-init...");
        let kickoff = get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::Kickoff).await.unwrap();
        let connector_b = ConnectorB::new(network, &XOnlyPublicKey::from(operator_pubkey));
        let input_index = 0;
        let prev_outs = vec![TxOut {
            value: kickoff.output[2].value,
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        }];
        let script = connector_b.generate_taproot_leaf_script(0);
        let taproot_spend_info = connector_b.generate_taproot_spend_info();
        populate_taproot_input_witness_default(
            &mut assert_init,
            &prev_outs,
            input_index,
            TapSighashType::All,
            &taproot_spend_info,
            &script,
            &vec![&master_key.keypair_for_graph(graph_id)],
        );
        broadcast_tx(&btc_client, &assert_init).await.unwrap();
        println!("assert-init sent: {}", assert_init.compute_txid());
    }

    let assert_commit0 =
        get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::AssertCommit0).await.unwrap();
    let assert_commit1 =
        get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::AssertCommit1).await.unwrap();
    let assert_commit2 =
        get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::AssertCommit2).await.unwrap();
    let assert_commit3 =
        get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::AssertCommit3).await.unwrap();
    let assert_commits = [assert_commit0, assert_commit1, assert_commit2, assert_commit3];
    if tx_on_chain(&btc_client, &assert_commits[3].compute_txid()).await.unwrap() {
        println!("assert-commit already sent");
    } else {
        println!("processing assert-commit...");
        let assert_commits =
            get_assert_commits(&ipfs, &base_url, network, graph_id, &master_key).await;
        println!("wait assert-init...");
        wait_tx_confirmation(&btc_client, &assert_init.compute_txid(), 5, 1800).await.unwrap();
        for assert_commit_tx in assert_commits.iter() {
            if !tx_on_chain(&btc_client, &assert_commit_tx.compute_txid()).await.unwrap() {
                broadcast_tx(&btc_client, assert_commit_tx).await.unwrap();
                println!("assert-commit sent: {}", assert_commit_tx.compute_txid());
            }
        }
    }

    let mut assert_final =
        get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::AssertFinal).await.unwrap();
    if tx_on_chain(&btc_client, &assert_final.compute_txid()).await.unwrap() {
        println!("assert-final already sent: {}", assert_final.compute_txid());
    } else {
        println!("processing assert-final...");
        for input_index in 1..(COMMIT_TX_NUM + 1) {
            let script = generate_pay_to_pubkey_script(&operator_pubkey);
            let value = assert_commits[input_index - 1].output[0].value;
            populate_p2wsh_witness(
                &mut assert_final,
                input_index,
                EcdsaSighashType::All,
                &script,
                value,
                &vec![&master_key.keypair_for_graph(graph_id)],
            );
        }
        println!("wait assert-commit-3...");
        wait_tx_confirmation(&btc_client, &assert_commits[0].compute_txid(), 5, 1800)
            .await
            .unwrap();
        wait_tx_confirmation(&btc_client, &assert_commits[1].compute_txid(), 5, 1800)
            .await
            .unwrap();
        wait_tx_confirmation(&btc_client, &assert_commits[2].compute_txid(), 5, 1800)
            .await
            .unwrap();
        wait_tx_confirmation(&btc_client, &assert_commits[3].compute_txid(), 5, 1800)
            .await
            .unwrap();
        broadcast_tx(&btc_client, &assert_final).await.unwrap();
        println!("assert-final sent: {}", assert_final.compute_txid());
    }
}

async fn fake_assert_commits(
    ipfs: &IPFS,
    base_url: &str,
    network: Network,
    graph_id: Uuid,
    master_key: &OperatorMasterKey,
) -> [Transaction; COMMIT_TX_NUM] {
    let mut assert_commits = [
        get_tx_from_ipfs(ipfs, base_url, IpfsTxName::AssertCommit0).await.unwrap(),
        get_tx_from_ipfs(ipfs, base_url, IpfsTxName::AssertCommit1).await.unwrap(),
        get_tx_from_ipfs(ipfs, base_url, IpfsTxName::AssertCommit2).await.unwrap(),
        get_tx_from_ipfs(ipfs, base_url, IpfsTxName::AssertCommit3).await.unwrap(),
    ];
    let operator_pubkey: PublicKey = master_key.keypair_for_graph(graph_id).public_key().into();
    println!("processing assert-commit...");
    let (operator_wots_seckeys, operator_wots_pubkeys) =
        master_key.wots_keypair_for_graph(graph_id);
    println!("generate proof-sigs...");
    let (proof, pubin, vk) = get_mock_groth16_proof();
    let mut proof_sigs = sign_proof(&vk, proof, pubin, &operator_wots_seckeys);
    println!("corrupt proof-sigs...");
    corrupt_proof(&mut proof_sigs, &operator_wots_seckeys.1, 8);
    let assert_commit_witness = utils_raw_witnesses_from_signatures(&proof_sigs);
    println!("sign assert-commit...");
    let all_assert_commit_connectors_e =
        AllCommitConnectorsE::new(network, &operator_pubkey, &operator_wots_pubkeys.1);
    fn sign_assert_commit(
        tx: &mut Transaction,
        connectors_e: &SingleCommitConnectorsE,
        witnesses: Vec<RawWitness>,
    ) {
        assert_eq!(witnesses.len(), connectors_e.connectors_num());
        for (input_index, witness) in (0..connectors_e.connectors_num()).zip(witnesses) {
            let taproot_spend_info =
                connectors_e.get_connector_e(input_index).generate_taproot_spend_info();
            let script = &connectors_e.get_connector_e(input_index).generate_taproot_leaf_script(0);

            let res = execute_raw_script_with_inputs(script.clone().to_bytes(), witness.clone());
            assert!(
                res.success,
                "script: {:?}, res: {:?}: stack: {:?}, variable name: {:?}",
                script,
                res,
                res.final_stack,
                connectors_e.get_connector_e(input_index).commitment_public_keys.keys()
            );
            populate_taproot_input_witness(tx, input_index, &taproot_spend_info, script, witness);
        }
    }
    for (i, witness) in
        (0..COMMIT_TX_NUM).zip(assert_commit_witness.chunks(MAX_CONNECTORS_E_PER_TX))
    {
        println!("processing assert-commit-{i}...");
        sign_assert_commit(
            &mut assert_commits[i],
            &all_assert_commit_connectors_e.commit_connectors_e_vec[i],
            witness.to_vec(),
        );
        let tx_data = bitcoin::consensus::serialize(&assert_commits[i]);
        let file_path = assert_commit_cache_file_path(graph_id, i);
        if let Some(parent) = Path::new(&file_path).parent() {
            fs::create_dir_all(parent).unwrap();
            let mut file = File::create(file_path).unwrap();
            file.write_all(&tx_data).unwrap();
        };
    }
    assert_commits
}

#[allow(dead_code)]
fn clear_cache(graph_id: Uuid) {
    for i in 0..4 {
        let file_path = assert_commit_cache_file_path(graph_id, i);
        if Path::new(&file_path).exists() {
            fs::remove_file(file_path).unwrap();
        }
    }
}

fn assert_commit_cache_file_path(graph_id: Uuid, index: usize) -> String {
    format!("cache/tests/{graph_id}/assert-commit-{index}.bin")
}

async fn get_assert_commits(
    ipfs: &IPFS,
    base_url: &str,
    network: Network,
    graph_id: Uuid,
    master_key: &OperatorMasterKey,
) -> [Transaction; COMMIT_TX_NUM] {
    if Path::new(&assert_commit_cache_file_path(graph_id, 3)).exists() {
        let res: [Transaction; COMMIT_TX_NUM] = std::array::from_fn(|i| {
            let file_path = assert_commit_cache_file_path(graph_id, i);
            let tx_data = std::fs::read(file_path).unwrap();
            bitcoin::consensus::deserialize(&tx_data).unwrap()
        });
        res
    } else {
        fake_assert_commits(ipfs, base_url, network, graph_id, master_key).await
    }
}

fn get_mock_groth16_proof() -> (Groth16Proof, Vec<ark_bn254::Fr>, VerifyingKey) {
    // two public-inputs
    let vk_hex = "e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19ffdb10cf9f7e2b08673477187c33a695a397702cf22005900724518b57f92f2ce08f8dfe36ca3eff63b1743d64812936d8cab0d74c063d260e20a9a3339b2a8c0300000000000000d17e1efc51d15eef04bde8dc794edc9e5788eb7539171d3a49d970ab9215b89c9ab6c5ab119ca81927393ef29332a1d15ac5f197b878ea89a1f8f686b747011eaad636dcb52cdfd674d155ddd67d21186fbdd1c0a62ebd74dcd6ddc6784b819e";
    let proof_hex = "b6ef2c5aa48a2f599a13bc4d8010e4d0190aeb05ff79e21266aff8dde6353d1756191f0959c787f6dedfc0c47751aed2648775101285b9da2d6c4e912e74891f884bd672f94f4d78528fb10b5410a94b53bcef07f99952ef72b68c72a5c4ff2a3de7c314ffbf17df018a753f070448c2f698706d4c2b99bdb06f928cffe1bea0";
    let pubin_hex = "02000000000000002000000000000000721db33a295a3b29a61c7360486e6d8346288822dc5cab652722e34d4b423d002000000000000000cfdc2f035c3699c6d17563570ea05a3d6d08302487937dd079a6b1671d484c0d";

    let vk = deserialize_vk(hex::decode(vk_hex).unwrap());
    let proof = deserialize_proof(hex::decode(proof_hex).unwrap());
    let pubin = deserialize_pubin(hex::decode(pubin_hex).unwrap());
    (proof, pubin, vk)
}

#[test]
fn verify_proof() {
    use ark_bn254::Bn254;
    use ark_groth16::{Groth16, r1cs_to_qap::LibsnarkReduction};

    let (proof, pubin, vk) = get_mock_groth16_proof();
    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(&vk.into(), &proof, &pubin).unwrap();
    println!("proof verification result: {ok}")
}
