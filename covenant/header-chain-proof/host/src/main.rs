use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
    ZKMVerifyingKey,
};

/// A program that aggregates the proofs of the simple program.
const HEADER_CHAIN: &[u8] = include_elf!("covenant-header-chain-proof");

fn main() {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (header_chain_proof_pk, header_chain_proof_vk) = client.setup(HEADER_CHAIN);

    let block_headers = bitcoin_light_client::HEADERS
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();
    let output = header_chain::BlockHeaderCircuitOutput {
        method_id: [0u32; 8],
        chain_state: {
            let mut chain_state = ChainState::new();
            chain_state.apply_blocks(block_headers.clone());
            chain_state
        }
    };

    let mut start = 0;
    let prev_proof = match prev_receipt.clone() {
            Some(output) => {
                //let output =
                //    BlockHeaderCircuitOutput::try_from_slice(&receipt).unwrap();
                start = output.chain_state.block_height as usize + 1;
                HeaderChainPrevProofType::PrevProof(output)
            }
            None => HeaderChainPrevProofType::GenesisBlock,
        };

    let batch_size = 4;

    let input: HeaderChainCircuitInput = HeaderChainCircuitInput {
        method_id,
        prev_proof,
        block_headers: block_headers[start..start + batch_size].to_vec(),
    };

    // Generate the fibonacci proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        client.prove(&fibonacci_pk, stdin).groth16().run().expect("proving failed")
    });
    println!("Generate proof successfully, proof: {:?}", proof);
}