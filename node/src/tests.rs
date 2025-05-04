#[cfg(test)]
pub mod tests {
    use crate::env::{
        DUST_AMOUNT, PEGIN_BASE_VBYTES, PRE_KICKOFF_BASE_VBYTES, get_committee_member_num,
    };
    use crate::utils::{get_proper_utxo_set, node_p2wsh_address, node_p2wsh_script, node_sign};
    use bitcoin::key::Keypair;
    use bitcoin::{CompressedPublicKey, EcdsaSighashType};
    use bitvm2_lib::committee::{COMMITTEE_PRE_SIGN_NUM, committee_pre_sign, nonces_aggregation};
    use client::chain::chain_adaptor::GoatNetwork;
    use client::chain::goat_adaptor::GoatInitConfig;
    use client::client::BitVM2Client;
    use esplora_client::BlockingClient;
    use goat::connectors::base::generate_default_tx_in;
    use goat::transactions::signing::populate_p2wsh_witness;
    use musig2::secp256k1;
    use std::process;
    use uuid::Uuid;

    use ark_bn254::Bn254;
    use ark_serialize::CanonicalDeserialize;
    use bitcoin::{Address, Amount, Network, PrivateKey, PublicKey, Transaction, TxIn, TxOut};
    use bitvm2_lib::{
        committee,
        keys::{ChallengerMasterKey, CommitteeMasterKey, OperatorMasterKey},
        operator,
        types::{Bitvm2Parameters, CustomInputs},
    };
    use goat::contexts::base::generate_n_of_n_public_key;
    use musig2::{PartialSignature, PubNonce, SecNonce};
    use std::str::FromStr;

    const BTCD_RPC_USER: &str = "111111";
    const BTCD_RPC_PASSWORD: &str = "111111";
    const BTCD_WALLET: &str = "alice";
    pub fn create_rpc_client() -> BlockingClient {
        let base_url = "http://127.0.0.1:3002";
        let builder = esplora_client::Builder::new(base_url);
        let client = BlockingClient::from_builder(builder);
        client
    }

    async fn create_bitvm2_client() -> BitVM2Client {
        let global_init_config = GoatInitConfig::from_env_for_test();
        let base_url = "http://127.0.0.1:3002";
        BitVM2Client::new(
            "/tmp/bitvm2-node-0.db",
            Some(base_url),
            Network::Testnet,
            GoatNetwork::Test,
            global_init_config,
            "http://44.229.236.82:5001",
        )
        .await
    }

    pub fn get_regtest_address(client: &BlockingClient) -> (bitcoin::key::PrivateKey, Address) {
        let secp = secp256k1::Secp256k1::new();
        // Create a P2WPKH (bech32) address
        let private_key =
            PrivateKey::from_wif("cSWNzrM1CjFt1VZNBV7qTTr1t2fmZUgaQe2FL4jyFQRgTtrYp8Y5").unwrap();
        // Derive the public key
        let address = Address::p2wpkh(
            &CompressedPublicKey::from_private_key(&secp, &private_key).unwrap(),
            Network::Regtest,
        );
        let default_address = Address::from_str("bcrt1qvnhz5qn4q9vt2sgumajnm8gt53ggvmyyfwd0jg")
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
        assert_eq!(address, default_address);
        let funding_address =
            node_p2wsh_address(Network::Regtest, &PublicKey::from_private_key(&secp, &private_key));
        println!("funding address: {}", funding_address);
        (private_key, funding_address)
    }

    // TODO: derive sender address from depositor sk
    async fn fund_address(
        bitvm2_client: &BitVM2Client,
        target_amount: Amount,
        funding_addr: &Address,
        depositor_private_key: &PrivateKey,
        sender_addr: Address,
        fee_rate: f64,
    ) -> Transaction {
        let inputs = get_proper_utxo_set(
            &bitvm2_client,
            PEGIN_BASE_VBYTES,
            sender_addr.clone(),
            target_amount,
            fee_rate,
        )
        .await
        .unwrap()
        .expect("Insufficient amount");
        let mut total_input_amount = Amount::ZERO;
        let txins: Vec<TxIn> = inputs
            .0
            .iter()
            .map(|input| {
                total_input_amount += input.amount;
                generate_default_tx_in(input)
            })
            .collect();
        let mut txouts = vec![];
        let output_0 = TxOut { value: target_amount, script_pubkey: funding_addr.script_pubkey() };
        txouts.push(output_0);
        let change_amount = inputs.2;
        if change_amount > Amount::from_sat(DUST_AMOUNT) {
            let output_1 =
                TxOut { value: change_amount, script_pubkey: sender_addr.script_pubkey() };
            txouts.push(output_1);
        }
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: txins,
            output: txouts,
        };

        let secp = secp256k1::Secp256k1::new();
        let script = node_p2wsh_script(&depositor_private_key.public_key(&secp));
        let keypair = Keypair::from_secret_key(&secp, &depositor_private_key.inner);
        let tx_inputs = tx.input.clone();
        tx_inputs.iter().enumerate().for_each(|(index, txin)| {
            let amount = inputs.0[index].amount;
            populate_p2wsh_witness(
                &mut tx,
                index,
                EcdsaSighashType::All,
                &script,
                amount,
                &vec![&keypair],
            );
        });
        tx
    }

    fn broadcast_and_wait_for_confirming(
        rpc_client: &BlockingClient,
        tx: &Transaction,
        confimations: u32,
    ) {
        let pre_current_tip = rpc_client.get_height().unwrap();
        let _ = rpc_client.broadcast(tx).unwrap();
        println!("Broadcast tx: {}", tx.compute_txid());
        let mut current_tip = rpc_client.get_height().unwrap();
        while (current_tip - pre_current_tip) < confimations {
            mine_blocks();
            println!("Wait for at least {} block mined", current_tip - pre_current_tip);
            std::thread::sleep(std::time::Duration::from_secs(1));
            current_tip = rpc_client.get_height().unwrap();
        }
    }

    fn mine_blocks() {
        let output = process::Command::new("docker")
            .args([
                "exec",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                &format!("-rpcuser={BTCD_RPC_USER}"),
                &format!("-rpcpassword={BTCD_RPC_PASSWORD}"),
                &format!("--rpcwallet={BTCD_WALLET}"),
                "-generate",
                "1",
            ])
            .output()
            .expect("Failed to execute docker command");

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Success:\n{}", stdout);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Error:\n{}", stderr);
        }
    }

    #[tokio::test]
    async fn e2e_generate_graph() {
        let network = Network::Regtest;
        let rpc_client = create_rpc_client();
        let (depositor_private_key, depositor_addr) = get_regtest_address(&rpc_client);
        let graph_id = Uuid::new_v4();
        // key generation
        let secp = secp256k1::Secp256k1::new();

        let instance_id = Uuid::new_v4();

        let committee_master_keys = (0..get_committee_member_num())
            .into_iter()
            .map(|x| {
                let kp = secp.generate_keypair(&mut rand::thread_rng());
                CommitteeMasterKey::new(Keypair::from_secret_key(&secp, &kp.0))
            })
            .collect::<Vec<CommitteeMasterKey>>();
        let committee_pubkeys: Vec<PublicKey> = committee_master_keys
            .iter()
            .map(|x| x.keypair_for_instance(instance_id).public_key().into())
            .collect();
        let (committee_agg_pubkey, _) = generate_n_of_n_public_key(&committee_pubkeys);

        let challenger_number = 2;
        let verifier_master_key = (0..challenger_number)
            .into_iter()
            .map(|x| {
                let kp = secp.generate_keypair(&mut rand::thread_rng());
                ChallengerMasterKey::new(Keypair::from_secret_key(&secp, &kp.0))
            })
            .collect::<Vec<ChallengerMasterKey>>();

        let kp = secp.generate_keypair(&mut rand::thread_rng());
        let operator_master_key = OperatorMasterKey::new(Keypair::from_secret_key(&secp, &kp.0));
        let (operator_wots_seckeys, operator_wots_pubkeys) =
            operator_master_key.wots_keypair_for_graph(graph_id.clone());
        let operator_p2wsh = node_p2wsh_address(
            network.clone(),
            &operator_master_key.keypair_for_graph(graph_id.clone()).public_key().into(),
        );

        let fee_rate = 1.0f64;
        let bitvm2_client = create_bitvm2_client().await;
        let pegin_amount = Amount::from_btc(0.1).unwrap();
        let stake_amount = Amount::from_btc(0.02).unwrap();
        let challenge_amount = Amount::from_btc(0.01).unwrap();
        // fund the operator
        let extra_fee =
            Amount::from_sat(fee_rate as u64 * (PEGIN_BASE_VBYTES + PRE_KICKOFF_BASE_VBYTES));
        let funding_operator_txn = fund_address(
            &bitvm2_client,
            stake_amount + extra_fee,
            &operator_p2wsh,
            &depositor_private_key,
            depositor_addr.clone(),
            fee_rate,
        )
        .await;

        println!("funding operator {}: {}", operator_p2wsh, funding_operator_txn.compute_txid());
        broadcast_and_wait_for_confirming(&rpc_client, &funding_operator_txn, 1);

        // mock groth16 proof
        let mock_vk_bytes = [
            115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162,
            65, 107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198,
            247, 76, 241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120,
            207, 150, 125, 108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25,
            185, 98, 13, 235, 118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123,
            7, 247, 33, 178, 155, 121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100,
            17, 56, 159, 79, 13, 219, 221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146,
            45, 201, 157, 226, 84, 213, 135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51,
            95, 177, 47, 57, 29, 199, 224, 98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228,
            89, 51, 58, 6, 226, 139, 99, 207, 22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218,
            111, 151, 4, 55, 230, 76, 90, 209, 149, 113, 248, 245, 50, 231, 137, 51, 157, 40, 29,
            184, 198, 201, 108, 199, 89, 67, 136, 239, 96, 216, 237, 172, 29, 84, 3, 128, 240, 2,
            218, 169, 217, 118, 179, 34, 226, 19, 227, 59, 193, 131, 108, 20, 113, 46, 170, 196,
            156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46, 249, 115, 239, 14, 176, 200, 134,
            158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176, 96, 177, 187, 184, 252, 14, 226,
            127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161, 110, 20, 154, 131, 23, 217,
            116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116, 57, 198, 237, 147, 183,
            164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99, 132, 199, 139, 172,
            108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3, 176, 185, 70,
            66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132, 226, 43,
            145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78, 41,
            199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188,
            59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67,
            204, 164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2,
            0, 0, 0, 0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158,
            0, 175, 140, 72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80,
            204, 41, 128, 69, 52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58,
            10, 92, 252, 227, 214, 99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207,
            78, 152, 132, 94, 207, 50, 243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193,
            21, 175, 180, 1, 26, 107, 39, 198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163,
            80, 74, 253, 176, 207, 47, 52, 7, 84, 59, 151, 47, 178, 165, 112, 251, 161,
        ]
        .to_vec();
        let mock_proof_bytes: Vec<u8> = [
            162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90,
            122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218,
            218, 151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122,
            206, 36, 122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94,
            59, 146, 46, 252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226,
            132, 40, 24, 248, 232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29,
            120, 188, 18, 78, 86, 8, 121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183,
            5, 8, 150, 74, 241, 141, 65, 150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63,
            133, 11, 209, 39, 79, 138, 185, 88, 20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157,
            82, 192, 52, 95, 143, 49, 227, 83, 19, 26, 108, 63, 232, 213, 169, 64, 221, 159, 214,
            220, 246, 174, 35, 43, 143, 80, 168, 142, 29, 103, 179, 58, 235, 33, 163, 198, 255,
            188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18, 24, 178, 219, 78, 12, 96, 10, 2,
            133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74, 62, 25, 115, 70, 42, 38, 131,
            92, 103, 103, 176, 212, 223, 177, 242, 94, 14,
        ]
        .to_vec();
        let mock_scalar = [
            232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88,
            129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
        ]
        .to_vec();
        let proof: ark_groth16::Proof<Bn254> =
            ark_groth16::Proof::deserialize_uncompressed(&mock_proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> =
            ark_groth16::VerifyingKey::deserialize_uncompressed(&mock_vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr =
            ark_bn254::Fr::deserialize_uncompressed(&mock_scalar[..]).unwrap();
        let scalars = vec![scalar];
        let proof_sigs = operator::sign_proof(&vk, proof, scalars, &operator_wots_seckeys);

        let depositor_evm_address: [u8; 20] =
            hex::decode("3eAC5F367F19E2E6099e897436DC17456f078609").unwrap().try_into().unwrap();

        let inputs = crate::utils::get_proper_utxo_set(
            &bitvm2_client,
            PEGIN_BASE_VBYTES,
            depositor_addr.clone(),
            pegin_amount,
            fee_rate,
        )
        .await
        .unwrap()
        .expect("Insufficient amount");

        let user_inputs = CustomInputs {
            inputs: inputs.0.clone(),
            input_amount: pegin_amount,
            fee_amount: inputs.1,
            change_address: depositor_addr.clone(),
        };

        let inputs = crate::utils::get_proper_utxo_set(
            &bitvm2_client,
            PRE_KICKOFF_BASE_VBYTES,
            operator_p2wsh,
            stake_amount,
            fee_rate,
        )
        .await
        .unwrap()
        .expect("Insufficient amount");

        let operator_inputs = CustomInputs {
            inputs: inputs.0.clone(),
            input_amount: stake_amount,
            fee_amount: inputs.1,
            change_address: depositor_addr.clone(),
        };

        let operator_keypair = operator_master_key.keypair_for_graph(graph_id.clone());
        let params = Bitvm2Parameters {
            network,
            depositor_evm_address,
            pegin_amount,
            stake_amount,
            challenge_amount,
            committee_pubkeys,
            committee_agg_pubkey,
            operator_pubkey: operator_keypair.public_key().into(),
            operator_wots_pubkeys: operator_wots_pubkeys.clone(),
            user_inputs,
            operator_inputs,
        };

        //let partial_scripts = operator::generate_partial_scripts(&vk);
        let partial_scripts = crate::utils::get_partial_scripts().unwrap();
        let disprove_scripts =
            operator::generate_disprove_scripts(&partial_scripts, &operator_wots_pubkeys);

        let disprove_scripts_bytes = disprove_scripts
            .iter()
            .map(|sc| sc.clone().compile().to_bytes().to_vec())
            .collect::<Vec<Vec<u8>>>();

        let mut graph = operator::generate_bitvm_graph(params, disprove_scripts_bytes).unwrap();

        // opeartor pre-sign
        println!("\nopeartor pre-sign");
        let _ = operator::operator_pre_sign(operator_keypair.clone(), &mut graph);

        // committee pre-sign
        println!("\ncommittee pre-sign");
        let committee_nonce: Vec<[(_, _, _); COMMITTEE_PRE_SIGN_NUM]> = committee_master_keys
            .iter()
            .map(|cmk| cmk.nonces_for_graph(instance_id.clone(), graph_id.clone()))
            .collect();
        let pubnonces: Vec<[PubNonce; COMMITTEE_PRE_SIGN_NUM]> = committee_nonce
            .iter()
            .map(|nonces| std::array::from_fn(|i| nonces[i].1.clone()))
            .collect();
        let secnonces: Vec<[SecNonce; COMMITTEE_PRE_SIGN_NUM]> = committee_nonce
            .iter()
            .map(|nonces| std::array::from_fn(|i| nonces[i].0.clone()))
            .collect();
        let agg_nonces = nonces_aggregation(pubnonces);

        let committee_partial_sigs: Vec<_> = committee_master_keys
            .iter()
            .enumerate()
            .map(|(idx, cmk)| {
                let sec_nonce = &secnonces[idx];
                committee_pre_sign(
                    cmk.keypair_for_instance(instance_id.clone()),
                    sec_nonce.clone(),
                    agg_nonces.clone(),
                    &graph,
                )
                .unwrap()
            })
            .collect();

        // e.g
        // [0, 1]
        // [0, 1]
        // [0, 1]
        // [0, 1]
        // [0, 1]
        //   ==>
        // [0, 0, 0, 0, 0]
        // [1, 1, 1, 1, 1]
        let mut grouped_partial_sigs: [Vec<PartialSignature>; COMMITTEE_PRE_SIGN_NUM] =
            Default::default();
        for partial_sigs in committee_partial_sigs {
            for (i, sig) in partial_sigs.into_iter().enumerate() {
                grouped_partial_sigs[i].push(sig);
            }
        }

        let _ = committee::signature_aggregation_and_push(
            &grouped_partial_sigs,
            &agg_nonces,
            &mut graph,
        )
        .expect("signatures aggregation and push");

        // peg-in
        let amounts = graph.pegin.input_amounts.clone();
        let keypair = Keypair::from_secret_key(&secp, &depositor_private_key.inner);
        (0..graph.pegin.tx().input.len()).into_iter().for_each(|idx| {
            let amount = amounts[idx].clone();
            node_sign(graph.pegin.tx_mut(), idx, amount, EcdsaSighashType::All, &keypair)
                .expect("peg-in signing failed");
        });

        println!("broadcast pegin");
        broadcast_and_wait_for_confirming(&rpc_client, &graph.pegin.tx(), 1);

        // pre-kick-off
        println!("broadcast pre-kickoff");
        let amounts = graph.pre_kickoff.input_amounts.clone();
        let peg_in_tx = (0..graph.pre_kickoff.tx().input.len()).into_iter().for_each(|idx| {
            let amount = amounts[idx].clone();
            node_sign(
                graph.pre_kickoff.tx_mut(),
                idx,
                amount,
                EcdsaSighashType::All,
                &operator_keypair,
            )
            .expect("pre kickoff signing failed");
        });
        broadcast_and_wait_for_confirming(&rpc_client, &graph.pre_kickoff.tx(), 1);

        // kick off
        println!("broadcast kickoff");
        let withdraw_evm_txid = [0xff; 32];
        let kickoff_tx = operator::operator_sign_kickoff(
            operator_keypair,
            &mut graph,
            &operator_wots_seckeys,
            &operator_wots_pubkeys,
            withdraw_evm_txid,
        )
        .unwrap();
        broadcast_and_wait_for_confirming(&rpc_client, &kickoff_tx, 7);

        // take 1
        println!("broadcast take1");
        let take_1_tx = operator::operator_sign_take1(operator_keypair, &mut graph).unwrap();
        broadcast_and_wait_for_confirming(&rpc_client, &take_1_tx, 1);

        //// unhappy_path take
        //let (mut challenge_tx, _) = verifier::export_challenge_tx(&mut graph).unwrap();
        //let mock_crowdfund_txin = TxIn {
        //    previous_output: mock_input.outpoint,
        //    script_sig: ScriptBuf::new(),
        //    sequence: Sequence::MAX,
        //    witness: Witness::default(),
        //};
        //let mock_challenger_change_output = TxOut {
        //    script_pubkey: generate_burn_script_address(network).script_pubkey(),
        //    value: Amount::from_sat(1000000),
        //};
        //challenge_tx.input.push(mock_crowdfund_txin);
        //challenge_tx.output.push(mock_challenger_change_output);
        //broadcast_tx(challenge_tx);

        //let (assert_init_tx, assert_commit_txns, assert_final_tx) = operator::operator_sign_assert(
        //    operator_keypair,
        //    &mut graph,
        //    &operator_wots_pubkeys,
        //    proof_sigs.clone(),
        //)
        //    .unwrap();
        //broadcast_tx(assert_init_tx);
        //assert_commit_txns.iter().for_each(|tx| broadcast_tx(tx.clone()));
        //broadcast_tx(assert_final_tx);

        //let take2_tx = operator::operator_sign_take2(operator_keypair, &mut graph).unwrap();
        //broadcast_tx(take2_tx);

        // // disprove
        // /*
        // // verify proof published by assert-txns:
        //let public_proof_sigs = verifier::extract_proof_sigs_from_assert_commit_txns(assert_commit_txns).unwrap();
        //let disprove_witness = verifier::verify_proof(
        //    &vk,
        //    public_proof_sigs,
        //    &mock_disprove_scripts,
        //    &operator_wots_pubkeys,
        //).unwrap();
        //*/
        //let mock_disprove_witness = (0, mock_script);
        //let mock_challenger_reward_address = generate_burn_script_address(network);
        //let disprove_tx = verifier::sign_disprove(
        //    &mut graph,
        //    mock_disprove_witness,
        //    mock_disprove_scripts_bytes.to_vec(),
        //    &operator_wots_pubkeys.1,
        //    mock_challenger_reward_address,
        //)
        //    .unwrap();
        //broadcast_tx(disprove_tx);
    }
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
