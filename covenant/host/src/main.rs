extern crate alloc;

use zkm_sdk::{
    include_elf, ProverClient,
};
mod cli;
use cli::HostArgs;

mod bitvm2_node;
use bitvm2_node::BitVM2NodeClient;

const ELF: &[u8] = include_elf!("covenant-guest");

//fn prove_revm() {
//    let mut stdin = ZKMStdin::new();
//    let goat_withdraw_txid: Vec<u8> =
//        hex::decode(std::env::var("GOAT_WITHDRAW_TXID").unwrap_or("32bc8a6c5b3649f92812c461083bab5e8f3fe4516d792bb9a67054ba040b7988".to_string())).unwrap();
//    //assert!(goat_withdraw_txid.len() == 32);
//    stdin.write(&goat_withdraw_txid);
//    // size: 20bytes
//    let withdraw_contract_address: Vec<u8> =
//        hex::decode(std::env::var("WITHDRAW_CONTRACT_ADDRESS").unwrap_or("86a77bdfcaff7435e1f1df06a95304d35b112ba8".to_string()))
//            .unwrap();
//    stdin.write(&withdraw_contract_address);
//    //assert!(withdraw_contract_address.len() == 20);
//
//    let withdraw_map_base_key =
//        hex::decode(std::env::var("WITHDRAW_MAP_BASE_KEY").unwrap_or("32bc8a6c5b3649f92812c461083bab5e8f3fe4516d792bb9a67054ba040b7988".to_string())).unwrap();
//    stdin.write(&withdraw_map_base_key);
//    let withdraw_map_index =
//        hex::decode(std::env::var("WITHDRAW_MAP_INDEX").unwrap_or("32bc8a6c5b3649f92812c461083bab5e8f3fe4516d792bb9a67054ba040b7988".to_string())).unwrap();
//    stdin.write(&withdraw_map_index);
//    let peg_in_txid: Vec<u8> =
//        hex::decode(std::env::var("PEG_IN_TXID").unwrap_or("32bc8a6c5b3649f92812c461083bab5e8f3fe4516d792bb9a67054ba040b7988".to_string())).unwrap();
//    stdin.write(&peg_in_txid);
//
//    let manifest_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
//    let json_path =
//        env::var("JSON_PATH").unwrap_or(format!("{}/../test-vectors/3168249.json", manifest_path));
//    let mut f = File::open(json_path).unwrap();
//    let mut data = vec![];
//    f.read_to_end(&mut data).unwrap();
//
//    let encoded = guest_std::cbor_serialize(&data).unwrap();
//    stdin.write_vec(encoded);
//
//    // Create a `ProverClient` method.
//    let client = ProverClient::new();
//
//    // Execute the program using the `ProverClient.execute` method, without generating a proof.
//    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
//    println!("executed program with {} cycles", report.total_instruction_count());
//
//    // Generate the proof for the given program and input.
//    let (pk, vk) = client.setup(ELF);
//    let proof = client.prove(&pk, stdin).groth16().run().unwrap();
//
//    // Verify proof and public values
//    client.verify(&proof, &vk).expect("verification failed");
//
//    // Test a round trip of proof serialization and deserialization.
//    proof.save("proof-with-pis.bin").expect("saving proof failed");
//    let deserialized_proof =
//        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");
//
//    // Verify the deserialized proof.
//    client.verify(&deserialized_proof, &vk).expect("verification failed");
//
//    // Convert the deserialized proof to an arkworks proof.
//    let ark_proof = convert_ark(&deserialized_proof, &vk.bytes32(), &GROTH16_VK_BYTES).unwrap();
//
//    // Verify the arkworks proof.
//    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
//        &ark_proof.groth16_vk,
//        &ark_proof.proof,
//        &ark_proof.public_inputs,
//    ).unwrap();
//    assert!(ok);
//
//    println!("successfully generated and verified proof for the program!");
//}

use std::sync::Arc;

use clap::Parser;
use host_executor::{
    bins::persist_report_hook::PersistExecutionReport, build_executor,
    create_eth_block_execution_strategy_factory, BlockExecutor, EthExecutorComponents,
};
use provider::create_provider;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("zkm_core_machine=warn".parse().unwrap())
                .add_directive("zkm_core_executor::executor=warn".parse().unwrap())
                .add_directive("zkm_prover=warn".parse().unwrap()),
        )
        .init();

    // Parse the command line arguments.
    let args = HostArgs::parse();
    let block_number = args.block_number;
    let report_path = args.report_path.clone();
    let config = args.as_config().await?;
    let persist_execution_report = PersistExecutionReport::new(
        config.chain.id(),
        report_path,
        args.precompile_tracking,
        args.opcode_tracking,
    );
    // TODO
    // let bitvm2_node_client = BitVM2NodeClient::new();

    let prover_client = Arc::new(ProverClient::new());

    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, config.custom_beneficiary);
    let provider = config.rpc_url.as_ref().map(|url| create_provider(url.clone()));

    let executor = build_executor::<EthExecutorComponents<_>, _>(
        ELF.to_owned(),
        provider,
        block_execution_strategy_factory,
        prover_client,
        persist_execution_report,
        config,
    )
        .await?;

    executor.execute(block_number).await?;

    Ok(())
}