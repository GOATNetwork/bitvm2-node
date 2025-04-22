use ark_bn254::Bn254;
use ark_serialize::CanonicalDeserialize;
use bitcoin::{
    Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bitvm::chunk::api::NUM_TAPS;
use bitvm::treepp::*;
use bitvm2_lib::{
    committee, operator,
    types::{Bitvm2Parameters, CustomInputs},
    verifier,
};
use goat::transactions::base::Input;
use goat::{contexts::base::generate_n_of_n_public_key, scripts::generate_burn_script_address};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use secp256k1::SECP256K1;
use std::str::FromStr;

#[test]
fn e2e_test() {
    let network = Network::Testnet;
    // key generation
    println!("\ngenerate keypairs");
    const OPERATOR_SECRET: &str =
        "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str =
        "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str =
        "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";

    let verifier_0_keypair = committee::generate_keypair_from_seed(VERIFIER_0_SECRET.to_string());
    let verifier_1_keypair = committee::generate_keypair_from_seed(VERIFIER_1_SECRET.to_string());
    let operator_keypair = committee::generate_keypair_from_seed(OPERATOR_SECRET.to_string());

    let verifier_0_sk = PrivateKey::new(verifier_0_keypair.secret_key(), network);
    let verifier_0_public_key = PublicKey::from_private_key(SECP256K1, &verifier_0_sk);
    let verifier_1_sk = PrivateKey::new(verifier_1_keypair.secret_key(), network);
    let verifier_1_public_key = PublicKey::from_private_key(SECP256K1, &verifier_1_sk);
    let operator_sk = PrivateKey::new(operator_keypair.secret_key(), network);
    let operator_pubkey = PublicKey::from_private_key(SECP256K1, &operator_sk);

    let mut committee_pubkeys: Vec<PublicKey> = Vec::new();
    committee_pubkeys.push(verifier_0_public_key);
    committee_pubkeys.push(verifier_1_public_key);
    let (committee_agg_pubkey, _) = generate_n_of_n_public_key(&committee_pubkeys);

    let (operator_wots_seckeys, operator_wots_pubkeys) =
        operator::generate_wots_keys(OPERATOR_SECRET);

    // mock groth16 proof
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
    let proof: ark_groth16::Proof<Bn254> =
        ark_groth16::Proof::deserialize_uncompressed(&mock_proof_bytes[..]).unwrap();
    let vk: ark_groth16::VerifyingKey<Bn254> =
        ark_groth16::VerifyingKey::deserialize_uncompressed(&mock_vk_bytes[..]).unwrap();
    let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&mock_scalar[..]).unwrap();
    let scalars = vec![scalar];
    let proof_sigs = operator::sign_proof(&vk, proof, scalars, &operator_wots_seckeys);

    // mock graph data
    println!("\ngenerate mock graph");
    let graph_index = 1;
    let pegin_amount = Amount::from_btc(1.0).unwrap();
    let stake_amount = Amount::from_btc(0.2).unwrap();
    let challenge_amount = Amount::from_btc(0.1).unwrap();
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
    let mock_user_change_address = generate_burn_script_address(network);
    let user_inputs = CustomInputs {
        inputs: vec![mock_input.clone()],
        input_amount: pegin_amount,
        fee_amount,
        change_address: mock_user_change_address,
    };
    let mock_operator_change_address = generate_burn_script_address(network);
    let operator_inputs = CustomInputs {
        inputs: vec![mock_input.clone()],
        input_amount: stake_amount,
        fee_amount,
        change_address: mock_operator_change_address,
    };
    let params = Bitvm2Parameters {
        network,
        depositor_evm_address: [0xff; 20],
        pegin_amount,
        stake_amount,
        challenge_amount,
        committee_pubkeys,
        committee_agg_pubkey,
        operator_pubkey,
        operator_wots_pubkeys: operator_wots_pubkeys.clone(),
        user_inputs,
        operator_inputs,
    };

    /*
    let partial_scripts = operator::generate_partial_scripts(&vk);
    let disprove_scripts = operator::generate_disprove_scripts(&partial_scripts, &operator_wots_pubkeys);
     */
    let mock_script = script! {OP_TRUE};
    let mock_script_bytes = mock_script.clone().compile().to_bytes();
    let mock_disprove_scripts_bytes: [Vec<u8>; NUM_TAPS] =
        std::array::from_fn(|_| mock_script_bytes.clone());

    let mut graph =
        operator::generate_bitvm_graph(params, mock_disprove_scripts_bytes.to_vec()).unwrap();

    // opeartor pre-sign
    println!("\nopeartor pre-sign");
    let _ = operator::operator_pre_sign(operator_keypair, &mut graph);

    // committee pre-sign
    println!("\ncommittee pre-sign");
    let verifier_0_nonces = committee::generate_nonce_from_seed(
        VERIFIER_0_SECRET.to_string(),
        graph_index,
        verifier_0_keypair,
    );
    let verifier_1_nonces = committee::generate_nonce_from_seed(
        VERIFIER_1_SECRET.to_string(),
        graph_index,
        verifier_1_keypair,
    );

    let verifier_0_sec_nonces: [SecNonce; committee::COMMITTEE_PRE_SIGN_NUM] =
        std::array::from_fn(|i| verifier_0_nonces[i].0.clone());
    let verifier_0_pub_nonces: [PubNonce; committee::COMMITTEE_PRE_SIGN_NUM] =
        std::array::from_fn(|i| verifier_0_nonces[i].1.clone());

    let verifier_1_sec_nonces: [SecNonce; committee::COMMITTEE_PRE_SIGN_NUM] =
        std::array::from_fn(|i| verifier_1_nonces[i].0.clone());
    let verifier_1_pub_nonces: [PubNonce; committee::COMMITTEE_PRE_SIGN_NUM] =
        std::array::from_fn(|i| verifier_1_nonces[i].1.clone());

    let agg_nonces: [AggNonce; committee::COMMITTEE_PRE_SIGN_NUM] = verifier_0_pub_nonces
        .iter()
        .zip(verifier_1_pub_nonces)
        .map(|(a, b)| committee::nonce_aggregation(&vec![a.clone(), b]))
        .collect::<Vec<AggNonce>>()
        .try_into()
        .unwrap();

    let verifier_0_sigs = committee::committee_pre_sign(
        verifier_0_keypair,
        verifier_0_sec_nonces,
        agg_nonces.clone(),
        &graph,
    )
    .unwrap();

    let verifier_1_sigs = committee::committee_pre_sign(
        verifier_1_keypair,
        verifier_1_sec_nonces,
        agg_nonces.clone(),
        &graph,
    )
    .unwrap();

    let committee_partial_sigs: [Vec<PartialSignature>; committee::COMMITTEE_PRE_SIGN_NUM] =
        verifier_0_sigs
            .iter()
            .zip(verifier_1_sigs)
            .map(|(&a, b)| vec![a, b])
            .collect::<Vec<Vec<PartialSignature>>>()
            .try_into()
            .unwrap();

    let _ =
        committee::signature_aggregation_and_push(&committee_partial_sigs, &agg_nonces, &mut graph);

    // happy_path take
    let withdraw_evm_txid = [0xff; 32];
    let kickoff_tx = operator::operator_sign_kickoff(
        operator_keypair,
        &mut graph,
        &operator_wots_seckeys,
        &operator_wots_pubkeys,
        withdraw_evm_txid,
    )
    .unwrap();
    broadcast_tx(kickoff_tx);

    let take_1_tx = operator::operator_sign_take1(operator_keypair, &mut graph).unwrap();
    broadcast_tx(take_1_tx);

    // unhappy_path take
    let (mut challenge_tx, _) = verifier::export_challenge_tx(&mut graph).unwrap();
    let mock_crowdfund_txin = TxIn {
        previous_output: mock_input.outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };
    let mock_challenger_change_output = TxOut {
        script_pubkey: generate_burn_script_address(network).script_pubkey(),
        value: Amount::from_sat(1000000),
    };
    challenge_tx.input.push(mock_crowdfund_txin);
    challenge_tx.output.push(mock_challenger_change_output);
    broadcast_tx(challenge_tx);

    let (assert_init_tx, assert_commit_txns, assert_final_tx) = operator::operator_sign_assert(
        operator_keypair,
        &mut graph,
        &operator_wots_pubkeys,
        proof_sigs.clone(),
    )
    .unwrap();
    broadcast_tx(assert_init_tx);
    assert_commit_txns.iter().for_each(|tx| broadcast_tx(tx.clone()));
    broadcast_tx(assert_final_tx);

    let take2_tx = operator::operator_sign_take2(operator_keypair, &mut graph).unwrap();
    broadcast_tx(take2_tx);

    // disprove
    /*
    // verify proof published by assert-txns:
    let public_proof_sigs = verifier::extract_proof_sigs_from_assert_commit_txns(assert_commit_txns).unwrap();
    let disprove_witness = verifier::verify_proof(
        &vk,
        public_proof_sigs,
        &mock_disprove_scripts,
        &operator_wots_pubkeys,
    ).unwrap();
    */
    let mock_disprove_witness = (0, mock_script);
    let mock_challenger_reward_address = generate_burn_script_address(network);
    let disprove_tx = verifier::sign_disprove(
        &mut graph,
        mock_disprove_witness,
        mock_disprove_scripts_bytes.to_vec(),
        &operator_wots_pubkeys.1,
        mock_challenger_reward_address,
    )
    .unwrap();
    broadcast_tx(disprove_tx);
}

fn broadcast_tx(_tx: Transaction) {
    // broadcast transaction to bitcoin network
}

/*

Test Transactions on Testnet3:

    happy-path take:
    - Pegin: e413208c6644d51f4f3adf3a5aad425da817ac825e56352e7164de1e2a4d9394
    - Kickoff: 4dd13ca25ef6edb4506394a402db2368d02d9467bc47326d3553310483f2ed04
    - Take1: 23bbba6e80e6e25ebe3f225c253d8f9ff57f4756916d1ded476380776fa03737

    unhappy-path take:
    - Pegin: 36b3d011fa892109a5da6cee240d81c6cb914ca862ebce3530ff3914d6803d16
    - Kickoff: 0c598f63bffe9d7468ce6930bf0fe1ba5c6e125c9c9e38674ee380dd2c6d97f6
    - Challenge: d2a2beff7dc0f93fc41505b646c6fa174991b0c4e415a96359607c37ba88e376
    - Assert-init: 2124278ee4f24dd394dcd1f62e04f18a3b458fdc14f422171dda56c663263195
    - Assert-commit:
        + 1: aff23096043a7372c5e39afde596e0fcc67c8bfe0dbf7810781f0d289f686d87
        + 2: 4385e722f6d22a5f138ae1ef41df686e0e8d888ce8c61be3b8ab6f53f667102e
        + 3: f4ce3e66ce8cc29547c1e52379c7bb8fda25c16b44c1f5544a5dcfd8b9fa2865
        + 4: 8cf248644cdb2290e77c6bfec40ccf9c5eb851b213514544c67ba7aeb80fe717
    - Assert_final: a2dedfbf376b8c0c183b4dfac7b0765b129a345c870f9fabbdf8c48072697a27
    - Take2: 78037fabb18973262711436885b9ea275685b18ce7d0957bd84215be960d792c

    disprove-path:
    - Pegin: e413208c6644d51f4f3adf3a5aad425da817ac825e56352e7164de1e2a4d9394
    - Kickoff: dba931410694e1395cd2c65c1470879eea3cc3a8aa797d7a669734286f4f2825
    - Challenge: c6a033812a1370973f94d956704ed1a68f490141a3c21bce64454d38a2c23794
    - Assert-init: 7cdd1f3384f67877a9844c025fa08b29078208ef1d3f5f4fce07de122d068050
    - Assert-commit:
        + 1: 5b5c7f0b1740d99c683b66a9bdddfeb573ccef088dbd7f0dce76d744a948f9b7
        + 2: 48de8806aa029975d331a4309d2ac707041f88c001ceca492e6df34e25ecf061
        + 3: 58cbfa261c7f94a3e05f5acd39b118817c446d6d3b3fd79007fd8841e37114e9
        + 4: a1a02cb35bcbbbe7d3475d04c557467acfc6b62fd777f9b341179d28b840e234
    - Assert_final: 2da6b0f73cd8835d5b76b62b9bd22314ee61212d348f6a4dbad915253f121012
    - Disprove: 5773755d1d0f750830edae5e1afcb37ab106e2dd46e164b09bf6213a0f45b0e1
*/
