use bitcoin::{consensus::encode::serialize_hex, Amount, Network, OutPoint, PrivateKey, PublicKey, Transaction, Txid};
use bitvm::chunk::api::NUM_TAPS;
use bitvm2_lib::{operator, committee, 
    types::{CustomInputs, Bitvm2Parameters},
};
use bitvm::treepp::*;
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use secp256k1::SECP256K1;
use std::str::FromStr;
use goat::{contexts::base::generate_n_of_n_public_key, scripts::generate_burn_script_address};
use goat::transactions::base::Input;
use goat::transactions::pre_signed::PreSignedTransaction;

pub fn main() {
    let network = Network::Testnet;
    // key generation
    println!("\ngenerate keypairs");
    const OPERATOR_SECRET: &str = "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str = "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str = "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";

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

    let (_, operator_wots_pubkeys) = operator::generate_wots_keys(OPERATOR_SECRET);
    
    // mock graph data
    println!("\ngenerate mock graph");
    let graph_index = 1;
    let pegin_amount = Amount::from_btc(1.0).unwrap();
    let stake_amount = Amount::from_btc(0.2).unwrap();
    let challenge_amount = Amount::from_btc(0.1).unwrap();
    let fee_amount = Amount::from_sat(2000);
    let mock_input = Input {
        outpoint: OutPoint {
            txid: Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap(),
            vout: 0,
        },
        amount: Amount::from_btc(10000.0).unwrap(),
    };
    let user_inputs = CustomInputs {
        inputs: vec![mock_input.clone()],
        input_amount: pegin_amount,
        fee_amount,
        change_address: generate_burn_script_address(network),
    };
    let operator_inputs = CustomInputs {
        inputs: vec![mock_input],
        input_amount: stake_amount,
        fee_amount,
        change_address: generate_burn_script_address(network),
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
    };

    let mock_script = script!{OP_TRUE};
    let mock_script_bytes = mock_script.compile().to_bytes();
    let mock_disprove_scripts_bytes: [Vec<u8>; NUM_TAPS] = std::array::from_fn(|_| mock_script_bytes.clone());

    let mut graph = operator::generate_bitvm_graph(
        user_inputs, 
        operator_inputs, 
        params, 
        &operator_wots_pubkeys, 
        mock_disprove_scripts_bytes.to_vec(),
    ).unwrap();

    // opeartor pre-sign
    println!("\nopeartor pre-sign");
    let _ = operator::operator_pre_sign(operator_keypair, &mut graph);
    
    // committee pre-sign
    println!("\ncommittee pre-sign");
    let verifier_0_nonces = committee::generate_nonce_from_seed(
        VERIFIER_0_SECRET.to_string(), graph_index, verifier_0_keypair);    
    let verifier_1_nonces = committee::generate_nonce_from_seed(
        VERIFIER_1_SECRET.to_string(), graph_index, verifier_1_keypair);

    let verifier_0_sec_nonces: [SecNonce; committee::COMMITTEE_PRE_SIGN_NUM] = std::array::from_fn(|i| verifier_0_nonces[i].0.clone());
    let verifier_0_pub_nonces: [PubNonce; committee::COMMITTEE_PRE_SIGN_NUM] = std::array::from_fn(|i| verifier_0_nonces[i].1.clone());
        
    let verifier_1_sec_nonces: [SecNonce; committee::COMMITTEE_PRE_SIGN_NUM] = std::array::from_fn(|i| verifier_1_nonces[i].0.clone());
    let verifier_1_pub_nonces: [PubNonce; committee::COMMITTEE_PRE_SIGN_NUM] = std::array::from_fn(|i| verifier_1_nonces[i].1.clone());
        
    let agg_nonces: [AggNonce; committee::COMMITTEE_PRE_SIGN_NUM] = verifier_0_pub_nonces.iter().zip(verifier_1_pub_nonces)
        .map(|(a,b)| committee::nonce_aggregation(&vec![a.clone(),b])).collect::<Vec<AggNonce>>().try_into().unwrap();
    
    let verifier_0_sigs = committee::committee_pre_sign(
        verifier_0_keypair, 
        verifier_0_sec_nonces, 
        agg_nonces.clone(), 
        &graph).unwrap();

    let verifier_1_sigs = committee::committee_pre_sign(
        verifier_1_keypair, 
        verifier_1_sec_nonces, 
        agg_nonces.clone(), 
        &graph).unwrap();
    
    let committee_partial_sigs: [Vec<PartialSignature>; committee::COMMITTEE_PRE_SIGN_NUM] = verifier_0_sigs.iter().zip(verifier_1_sigs)
        .map(|(&a,b)| vec![a,b]).collect::<Vec<Vec<PartialSignature>>>().try_into().unwrap();

    let _ = committee::signature_aggregation_and_push(
        &committee_partial_sigs, 
        &agg_nonces, 
        &mut graph
    );

    // write to file 
    fn write_tx_to_file(file: &str, tx: &Transaction) {
        use std::io::Write;
        let tx_hex = serialize_hex(tx);
        let mut file = std::fs::File::create(file).unwrap();
        file.write_all(&tx_hex.into_bytes()).unwrap();
    }

    println!("\nwrite convenant txns to file");
    let file_dir = "graph_txns/";
    let _ = std::fs::create_dir(std::path::Path::new(file_dir));
    println!("write to {file_dir}");

    let pegin_file = format!("{}{}.hex", &file_dir, "pegin");
    write_tx_to_file(&pegin_file, graph.pegin.tx());

    let kickoff_file = format!("{}{}.hex", &file_dir, "kickoff");
    write_tx_to_file(&kickoff_file, graph.kickoff.tx());

    let take1_file = format!("{}{}.hex", &file_dir, "take1");
    write_tx_to_file(&take1_file, graph.take1.tx());

    let take2_file = format!("{}{}.hex", &file_dir, "take2");
    write_tx_to_file(&take2_file, graph.take2.tx());

    let challenge_file = format!("{}{}.hex", &file_dir, "challenge");
    write_tx_to_file(&challenge_file, graph.challenge.tx());

    let assert_init_file = format!("{}{}.hex", &file_dir, "assert-init");
    write_tx_to_file(&assert_init_file, graph.assert_init.tx());

    let assert_commit0_file = format!("{}{}.hex", &file_dir, "assert-commit0");
    write_tx_to_file(&assert_commit0_file, graph.assert_commit.commit_txns[0].tx());

    let assert_commit1_file = format!("{}{}.hex", &file_dir, "assert-commit1");
    write_tx_to_file(&assert_commit1_file, graph.assert_commit.commit_txns[1].tx());

    let assert_commit2_file = format!("{}{}.hex", &file_dir, "assert-commit2");
    write_tx_to_file(&assert_commit2_file, graph.assert_commit.commit_txns[2].tx());

    let assert_commit3_file = format!("{}{}.hex", &file_dir, "assert-commit3");
    write_tx_to_file(&assert_commit3_file, graph.assert_commit.commit_txns[3].tx());

    let assert_final_file = format!("{}{}.hex", &file_dir, "assert-final");
    write_tx_to_file(&assert_final_file, graph.assert_final.tx());

    let disprove_file = format!("{}{}.hex", &file_dir, "disprove");
    write_tx_to_file(&disprove_file, graph.disprove.tx());

    println!("\nDone.");
}