//! Generate operator proof
use alloy_primitives::U256;
use ark_serialize::CanonicalSerialize;
use bitcoin::{
    Network, ScriptBuf, Transaction, TxOut, Txid,
    hashes::Hash,
    secp256k1::{PublicKey, XOnlyPublicKey},
};
use bitcoin_light_client_circuit::build_spv;
use bitcoin_script::script;
use borsh::BorshDeserialize;
use client::btc_chain::BTCClient;
use commit_chain::{CommitChainCircuitInput, CommitChainPrevProofType};
use header_chain::{
    CircuitBlockHeader, CircuitTransaction, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use hex::FromHex;
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};
use zkm_verifier::{GROTH16_VK_BYTES, convert_ark};

/// A program that aggregates the proofs of the simple program.
const OPERATOR: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

/*
// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(args: &Args) -> EthClientExecutorInput {
    // Setup the provider.
    let rpc_url = Url::parse(&args.execution_layer_rpc).expect("invalid rpc url");

    let provider = RootProvider::<Ethereum>::new_http(rpc_url);

    let rpc_db =
        RpcDb::new(provider.clone(), provider.clone(), args.execution_layer_block_number - 1);

    let genesis = &Genesis::GoatTestnet;
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;

    let host_executor = EthHostExecutor::eth(chain_spec.clone(), custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            args.execution_layer_block_number,
            &rpc_db,
            &provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await
        .expect("failed to execute host");
    client_input
}
*/

pub fn hex_parse(s: &str) -> Result<[u8; 16], String> {
    let mut s = s;
    if s.starts_with("0x") {
        s = &s[2..];
    }
    let b = Vec::from_hex(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "len must be 16".to_string())
}

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    included_watchtowers: String,

    #[clap(long, env, value_parser = hex_parse)]
    graph_id: [u8; 16],

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env)]
    genesis_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, short)]
    state_chain_input_proof: String,

    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    execution_layer_rpc: String,

    #[clap(long, env, short)]
    execution_layer_block_number: u64,

    /// All the watchtower challenges txids
    #[clap(long, env, short)]
    watchtower_challenge_info: String,

    #[clap(long, env, short)]
    watchtower_challenge_init_txid: String,

    #[clap(long, env, default_value = "commit-proof.bin")]
    output: String,

    #[clap(long, env, default_value = "data/header-chain/block_headers.bin")]
    block_headers: String,
    //#[clap(long, env, default_value = "99f6Dc59fB6B5b13578BeBb223e373Cb817Ac8f6")]
    //l2_contract_address: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    //let out = fetch_exection_layer_block(&args).await;
    //println!("output: {:?}", out);

    //let addr = if args.l2_contract_address.starts_with("0x") {
    //    args.l2_contract_address[2..].to_string()
    //} else {
    //    args.l2_contract_address.clone()
    //};
    //let bytes: [u8; 20] = hex::decode(addr).unwrap().try_into().unwrap();
    //let l2_contract_address = Address::from(bytes);
    //let base_slot: [u8; 32] = U256::from(12).to_be_bytes().try_into().unwrap();

    //let input = fetch_exection_layer_block(&args).await;
    //execute_el_block_and_check_withdraw_tx(Some(l2_contract_address), Some(base_slot), Some(args.graph_id), input);

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (proof_pk, proof_vk) = client.setup(OPERATOR);

    // --- header chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.header_chain_input_proof)).unwrap();
    let mut header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    let proof_bytes =
        fs::read(&args.header_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    header_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

    let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
    let bytes = std::fs::read(&format!("{}.vk", args.header_chain_input_proof)).unwrap();
    let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    //assert_eq!(header_chain_output.vk_hash, header_chain_vk.hash_u32());

    // --- commit chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.commit_chain_input_proof)).unwrap();
    let mut commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // Set the previous proof type based on input_proof argument
    let proof_bytes =
        fs::read(&args.commit_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

    //let commit_chain_output: CommitChainCircuitOutput = proof.public_values.read();
    commit_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

    let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };

    let bytes = std::fs::read(&format!("{}.vk", args.commit_chain_input_proof)).unwrap();
    let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    //assert_eq!(commit_chain_output.vk_hash, commit_chain_vk.hash_u32());

    // --- state chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.state_chain_input_proof)).unwrap();
    let mut state_chain_input: StateChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // Set the previous proof type based on input_proof argument
    let proof_bytes =
        fs::read(&args.state_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

    state_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();
    let ZKMProof::Compressed(state_compressed_proof) = proof.proof else { panic!() };
    let bytes = std::fs::read(&format!("{}.vk", args.state_chain_input_proof)).unwrap();
    let state_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    // --- spv --- //
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(&args.latest_sequencer_commit_txid).unwrap();

    let operator_latest_sequencer_commit_txn =
        btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();
    //println!("operator_latest_seqeuncer_commit_txn: {:?}", operator_latest_sequencer_commit_txn);

    let operator_genesis_sequencer_commit_txid =
        Txid::from_str(&args.genesis_sequencer_commit_txid).unwrap();

    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_merkle_proof(&latest_sequencer_commit_txid).await.unwrap().unwrap();
    let block_pos = tx_merkle_proof.block_height;
    println!("block height: {block_pos}");
    let target_block = btc_client.get_block_by_height(block_pos).await.unwrap();

    let bitcoin_block_headers = {
        let headers: Vec<u8> = std::fs::read(&args.block_headers).unwrap();
        headers
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>()
    };
    println!("block headers: {:?}", bitcoin_block_headers.len());
    println!("construct spv");
    let spv = build_spv(
        &operator_latest_sequencer_commit_txn,
        block_pos,
        target_block,
        &bitcoin_block_headers,
    );

    //let eth_client_execution_input: EthClientExecutorInput =
    //    fetch_exection_layer_block(&args).await;
    //println!(
    //    "el block hash: {}",
    //    eth_client_execution_input.current_block.header.hash_slow().to_string()
    //);

    // --- watchtower_challenge_txns --- //
    let bytes = std::fs::read(&args.watchtower_challenge_info).unwrap();
    // watchtower challenge's (txid, public key)
    let watchtower_challenge_txids: Vec<(String, String)> = serde_json::from_slice(&bytes).unwrap();
    let mut watchtower_challenge_txns = Vec::new();
    let mut watchtower_challenge_txn_prev_outs: Vec<TxOut> = Vec::new();
    let mut watchtower_challenge_txn_prev_indices: Vec<usize> = Vec::new();
    let mut watchtower_challenge_txn_pubkeys = Vec::new();
    let mut watchtower_challenge_txn_scripts: Vec<ScriptBuf> = Vec::new();

    let watchtower_challlenge_init_txn: Transaction = btc_client
        .get_tx(&args.watchtower_challenge_init_txid.parse().unwrap())
        .await
        .unwrap()
        .unwrap();

    for (id, pk) in &watchtower_challenge_txids {
        let txid = id.parse().unwrap();
        let txn = btc_client.get_tx(&txid).await.unwrap().unwrap();
        // get prev outs
        // FIXME: update the index
        let index = txn.input[0].previous_output.vout as usize;
        watchtower_challenge_txn_prev_outs
            .push(watchtower_challlenge_init_txn.output[index].clone());
        watchtower_challenge_txn_prev_indices.push(index);

        let public_key = PublicKey::from_str(pk).unwrap();
        watchtower_challenge_txn_pubkeys.push(public_key.clone());
        watchtower_challenge_txns.push(CircuitTransaction(txn));

        // https://github.com/GOATNetwork/BitVM/blob/GA/goat/src/transactions/watchtower_challenge.rs#L45
        // generate_pay_to_pubkey_taproot_script
        let watchtower_challenge_txn_script: ScriptBuf = {
            let public_key: XOnlyPublicKey = public_key.into();
            script! {
                { public_key }
                OP_CHECKSIG
            }
            .compile()
        };
        watchtower_challenge_txn_scripts.push(watchtower_challenge_txn_script);
    }
    // Generate the proofs
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();

        let included_watchtowers: U256 = U256::from_str(&args.included_watchtowers).unwrap();
        stdin.write(&included_watchtowers);

        stdin.write(&args.graph_id);

        stdin.write(&operator_genesis_sequencer_commit_txid.to_byte_array());
        stdin.write(&operator_latest_sequencer_commit_txn);

        stdin.write(&watchtower_challenge_txns);
        stdin.write(&watchtower_challenge_txn_pubkeys);
        stdin.write(&watchtower_challenge_txn_scripts);
        stdin.write(&watchtower_challenge_txn_prev_outs);
        stdin.write(&watchtower_challenge_txn_prev_indices);

        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&state_chain_input);
        stdin.write(&spv);

        if commit_chain_input.prev_proof != CommitChainPrevProofType::GenesisBlock {
            stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        } else {
            println!("Skip writing commit chain proof");
        }

        if header_chain_input.prev_proof != HeaderChainPrevProofType::GenesisBlock {
            stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        } else {
            println!("Skip writing header chain proof");
        }

        if state_chain_input.prev_proof != StateChainPrevProofType::GenesisBlock {
            stdin.write_proof(*state_compressed_proof, state_chain_vk.vk);
        } else {
            println!("Skip writing state chain proof");
        }

        client.prove(&proof_pk, stdin).groth16().run().expect("proving failed")
    });

    //fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    //fs::write(&format!("{}.vk", args.output), bincode::serialize(&proof_vk).unwrap()).unwrap();
    //println!("Generate proof successfully, proof: {:?}", proof);

    let groth16_vk = &GROTH16_VK_BYTES;
    let ark_proof = convert_ark(&proof, proof_vk.bytes32().as_ref(), groth16_vk).unwrap();

    let mut writer = std::fs::File::create(format!("{}.proof.bin", args.output)).unwrap();
    ark_proof.proof.serialize_compressed(&mut writer).unwrap();

    let mut writer = std::fs::File::create(format!("{}.vk.bin", args.output)).unwrap();
    ark_proof.groth16_vk.serialize_compressed(&mut writer).unwrap();

    let mut writer = std::fs::File::create(format!("{}.public_inputs.bin", args.output)).unwrap();
    ark_proof.public_inputs.serialize_compressed(&mut writer).unwrap();

    println!("Generate proof successfully, Ark proof: {:?}", ark_proof);
}
