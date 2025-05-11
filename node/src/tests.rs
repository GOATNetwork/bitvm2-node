#![allow(clippy::module_inception)]

#[cfg(test)]
pub mod tests {
    use crate::env::{
        DUST_AMOUNT, PEGIN_BASE_VBYTES, PRE_KICKOFF_BASE_VBYTES, get_committee_member_num,
    };
    use crate::utils::{
        complete_and_broadcast_challenge_tx, get_fee_rate, get_proper_utxo_set, get_vk,
        node_p2wsh_address, node_p2wsh_script, node_sign,
    };
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
    use bitcoin_script::builder::StructuredScript;
    use bitvm::chunk::api::NUM_TAPS;
    use bitvm2_lib::types::{Bitvm2Graph, Groth16WotsSignatures, WotsPublicKeys, WotsSecretKeys};
    use bitvm2_lib::verifier;
    use bitvm2_lib::{
        committee,
        keys::{CommitteeMasterKey, OperatorMasterKey},
        operator,
        types::{Bitvm2Parameters, CustomInputs},
    };
    use goat::contexts::base::generate_n_of_n_public_key;
    use goat::scripts::generate_burn_script_address;
    use musig2::{PartialSignature, PubNonce, SecNonce};
    use std::str::FromStr;

    const BTCD_RPC_USER: &str = "111111";
    const BTCD_RPC_PASSWORD: &str = "111111";
    const BTCD_WALLET: &str = "alice";
    const BTCD_RPC_URL: &str = "http://127.0.0.1:3002";

    //FIXME: The UTs should not use IPFS
    pub fn create_rpc_client() -> BlockingClient {
        let builder = esplora_client::Builder::new(BTCD_RPC_URL);

        BlockingClient::from_builder(builder)
    }

    fn temp_file() -> String {
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        tmp_db.path().as_os_str().to_str().unwrap().to_string()
    }
    async fn create_bitvm2_client(network: Network) -> BitVM2Client {
        let global_init_config = GoatInitConfig::from_env_for_test();
        BitVM2Client::new(
            &temp_file(),
            Some(BTCD_RPC_URL),
            network,
            GoatNetwork::Test,
            global_init_config,
            &crate::env::get_ipfs_url(),
        )
        .await
    }

    pub fn get_regtest_address(network: Network) -> (PrivateKey, Address) {
        let secp = secp256k1::Secp256k1::new();
        // Create a P2WPKH (bech32) address
        let private_key =
            PrivateKey::from_wif("cSWNzrM1CjFt1VZNBV7qTTr1t2fmZUgaQe2FL4jyFQRgTtrYp8Y5").unwrap();
        // Derive the public key
        let address = Address::p2wpkh(
            &CompressedPublicKey::from_private_key(&secp, &private_key).unwrap(),
            network,
        );
        let default_address = Address::from_str("bcrt1qvnhz5qn4q9vt2sgumajnm8gt53ggvmyyfwd0jg")
            .unwrap()
            .require_network(network)
            .unwrap();
        assert_eq!(address, default_address);
        let funding_address =
            node_p2wsh_address(network, &PublicKey::from_private_key(&secp, &private_key));
        println!("funding address: {funding_address}");
        (private_key, funding_address)
    }

    async fn challenger_tx_crowdfund_and_broadcast(
        network: Network,
        bitvm2_client: &BitVM2Client,
        challenge_tx: Transaction,
    ) {
        let (funder_privkey, _) = get_regtest_address(network);
        let _challenge_amount = Amount::from_btc(0.01).unwrap();

        let secp = secp256k1::Secp256k1::new();
        println!("Broadcast challenge tx");
        let txid = complete_and_broadcast_challenge_tx(
            bitvm2_client,
            Keypair::from_secret_key(&secp, &funder_privkey.inner),
            challenge_tx,
            // challenge_amount,
        )
        .await
        .unwrap();
        println!("Mine challenge tx: {txid}");
        mine_blocks()
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
            bitvm2_client,
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
        (0..tx.input.len()).for_each(|index| {
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
        rpc_client.broadcast(tx).unwrap();
        println!("Broadcast tx: {}", tx.compute_txid());
        let mut current_tip = rpc_client.get_height().unwrap();
        while (current_tip - pre_current_tip) < confimations {
            mine_blocks();
            println!(
                "Wait for at least {} block mined",
                confimations - (current_tip - pre_current_tip)
            );
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
            println!("Success:\n{stdout}");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Error:\n{stderr}");
        }
    }

    struct E2eResult {
        graph: Bitvm2Graph,
        operator_keypair: Keypair,
        operator_wots_seckeys: WotsSecretKeys,
        operator_wots_pubkeys: WotsPublicKeys,
        proof_sigs: Groth16WotsSignatures,
        disprove_scripts: Vec<StructuredScript>,
    }
    async fn e2e_setup(
        network: Network,
        rpc_client: &BlockingClient,
        bitvm2_client: &BitVM2Client,
    ) -> E2eResult {
        let fee_rate = get_fee_rate(bitvm2_client).await.unwrap();
        let (depositor_private_key, depositor_addr) = get_regtest_address(network);
        let graph_id = Uuid::new_v4();
        // key generation
        let secp = secp256k1::Secp256k1::new();
        let instance_id = Uuid::new_v4();
        let committee_master_keys = (0..get_committee_member_num())
            .map(|_x| {
                let kp = secp.generate_keypair(&mut rand::thread_rng());
                CommitteeMasterKey::new(Keypair::from_secret_key(&secp, &kp.0))
            })
            .collect::<Vec<CommitteeMasterKey>>();
        let committee_pubkeys: Vec<PublicKey> = committee_master_keys
            .iter()
            .map(|x| x.keypair_for_instance(instance_id).public_key().into())
            .collect();
        let (committee_agg_pubkey, _) = generate_n_of_n_public_key(&committee_pubkeys);

        let kp = secp.generate_keypair(&mut rand::thread_rng());
        let operator_master_key = OperatorMasterKey::new(Keypair::from_secret_key(&secp, &kp.0));
        let (operator_wots_seckeys, operator_wots_pubkeys) =
            operator_master_key.wots_keypair_for_graph(graph_id);
        let operator_p2wsh = node_p2wsh_address(
            network,
            &operator_master_key.keypair_for_graph(graph_id).public_key().into(),
        );

        let pegin_amount = Amount::from_btc(0.1).unwrap();
        let stake_amount = Amount::from_btc(0.02).unwrap();
        let challenge_amount = Amount::from_btc(0.01).unwrap();

        // fund the operator
        let extra_fee =
            Amount::from_sat(fee_rate as u64 * (PEGIN_BASE_VBYTES + PRE_KICKOFF_BASE_VBYTES));
        let funding_operator_txn = fund_address(
            bitvm2_client,
            stake_amount + extra_fee,
            &operator_p2wsh,
            &depositor_private_key,
            depositor_addr.clone(),
            fee_rate,
        )
        .await;

        println!("funding operator {}: {}", operator_p2wsh, funding_operator_txn.compute_txid());
        broadcast_and_wait_for_confirming(rpc_client, &funding_operator_txn, 1);

        let vk = get_vk().unwrap();
        // mock groth16 proof
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
        let scalar: ark_bn254::Fr =
            ark_bn254::Fr::deserialize_uncompressed(&mock_scalar[..]).unwrap();
        let scalars = vec![scalar];
        let proof_sigs = operator::sign_proof(&vk, proof, scalars, &operator_wots_seckeys);

        let depositor_evm_address: [u8; 20] =
            hex::decode("3eAC5F367F19E2E6099e897436DC17456f078609").unwrap().try_into().unwrap();

        let inputs = get_proper_utxo_set(
            bitvm2_client,
            PEGIN_BASE_VBYTES,
            depositor_addr.clone(),
            pegin_amount,
            fee_rate,
        )
        .await
        .unwrap()
        .expect("Insufficient amount for peg-in");

        let user_inputs = CustomInputs {
            inputs: inputs.0.clone(),
            input_amount: pegin_amount,
            fee_amount: inputs.1,
            change_address: depositor_addr.clone(),
        };

        let inputs = get_proper_utxo_set(
            bitvm2_client,
            PRE_KICKOFF_BASE_VBYTES,
            operator_p2wsh,
            stake_amount,
            fee_rate,
        )
        .await
        .unwrap()
        .expect("Insufficient amount for kickoff staking");

        let operator_inputs = CustomInputs {
            inputs: inputs.0.clone(),
            input_amount: stake_amount,
            fee_amount: inputs.1,
            change_address: depositor_addr.clone(),
        };

        let operator_keypair = operator_master_key.keypair_for_graph(graph_id);
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
        let _ = operator::operator_pre_sign(operator_keypair, &mut graph).unwrap();

        // committee pre-sign
        println!("\ncommittee pre-sign");
        let committee_nonce: Vec<[(_, _, _); COMMITTEE_PRE_SIGN_NUM]> = committee_master_keys
            .iter()
            .map(|cmk| cmk.nonces_for_graph(instance_id, graph_id))
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
                    cmk.keypair_for_instance(instance_id),
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
        (0..graph.pegin.tx().input.len()).for_each(|idx| {
            let amount = amounts[idx];
            node_sign(graph.pegin.tx_mut(), idx, amount, EcdsaSighashType::All, &keypair)
                .expect("peg-in signing failed");
        });

        println!("broadcast pegin");
        broadcast_and_wait_for_confirming(rpc_client, graph.pegin.tx(), 1);

        E2eResult {
            graph,
            operator_keypair,
            operator_wots_seckeys,
            operator_wots_pubkeys,
            proof_sigs,
            disprove_scripts,
        }
    }
    /////////////
    #[tokio::test]
    #[ignore = "init depositor error"]
    async fn e2e_take_1() {
        let network = Network::Regtest;
        let rpc_client = create_rpc_client();
        let bitvm2_client = create_bitvm2_client(network).await;

        let E2eResult {
            mut graph,
            operator_keypair,
            operator_wots_seckeys,
            operator_wots_pubkeys,
            ..
        } = e2e_setup(network, &rpc_client, &bitvm2_client).await;
        // pre-kick-off
        println!("broadcast pre-kickoff");
        let amounts = graph.pre_kickoff.input_amounts.clone();
        (0..graph.pre_kickoff.tx().input.len()).for_each(|idx| {
            let amount = amounts[idx];
            node_sign(
                graph.pre_kickoff.tx_mut(),
                idx,
                amount,
                EcdsaSighashType::All,
                &operator_keypair,
            )
            .expect("pre kickoff signing failed");
        });
        broadcast_and_wait_for_confirming(&rpc_client, graph.pre_kickoff.tx(), 1);

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
    }

    #[tokio::test]
    #[ignore = "init depositor error"]
    async fn e2e_take_2() {
        let network = Network::Regtest;
        let rpc_client = create_rpc_client();
        let bitvm2_client = create_bitvm2_client(network).await;

        let E2eResult {
            mut graph,
            operator_keypair,
            operator_wots_seckeys,
            operator_wots_pubkeys,
            proof_sigs,
            ..
        } = e2e_setup(network, &rpc_client, &bitvm2_client).await;

        println!("broadcast pre-kickoff");
        let amounts = graph.pre_kickoff.input_amounts.clone();
        (0..graph.pre_kickoff.tx().input.len()).for_each(|idx| {
            let amount = amounts[idx];
            node_sign(
                graph.pre_kickoff.tx_mut(),
                idx,
                amount,
                EcdsaSighashType::All,
                &operator_keypair,
            )
            .expect("pre kickoff signing failed");
        });
        broadcast_and_wait_for_confirming(&rpc_client, graph.pre_kickoff.tx(), 1);

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

        // unhappy_path take
        let (challenge_tx, _) = verifier::export_challenge_tx(&mut graph).unwrap();

        println!("Broadcast challenge tx");
        challenger_tx_crowdfund_and_broadcast(network, &bitvm2_client, challenge_tx).await;

        let (assert_init_tx, assert_commit_txns, assert_final_tx) = operator::operator_sign_assert(
            operator_keypair,
            &mut graph,
            &operator_wots_pubkeys,
            proof_sigs.clone(),
        )
        .unwrap();
        broadcast_and_wait_for_confirming(&rpc_client, &assert_init_tx, 1);

        assert_commit_txns.iter().for_each(|tx| {
            broadcast_and_wait_for_confirming(&rpc_client, tx, 1);
        });

        broadcast_and_wait_for_confirming(&rpc_client, &assert_final_tx, 1);

        let take2_tx = operator::operator_sign_take2(operator_keypair, &mut graph).unwrap();
        broadcast_and_wait_for_confirming(&rpc_client, &take2_tx, 7);
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_disprove() {
        let network = Network::Regtest;
        let rpc_client = create_rpc_client();
        let bitvm2_client = create_bitvm2_client(network).await;
        let fee_rate = get_fee_rate(&bitvm2_client).await.unwrap();

        let E2eResult {
            mut graph,
            operator_keypair,
            operator_wots_seckeys,
            operator_wots_pubkeys,
            mut proof_sigs,
            disprove_scripts,
            ..
        } = e2e_setup(network, &rpc_client, &bitvm2_client).await;

        println!("broadcast pre-kickoff");
        let amounts = graph.pre_kickoff.input_amounts.clone();
        (0..graph.pre_kickoff.tx().input.len()).for_each(|idx| {
            let amount = amounts[idx];
            node_sign(
                graph.pre_kickoff.tx_mut(),
                idx,
                amount,
                EcdsaSighashType::All,
                &operator_keypair,
            )
            .expect("pre kickoff signing failed");
        });
        broadcast_and_wait_for_confirming(&rpc_client, graph.pre_kickoff.tx(), 1);

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

        // unhappy_path take
        let (challenge_tx, _) = verifier::export_challenge_tx(&mut graph).unwrap();

        println!("Broadcast challenge tx");
        challenger_tx_crowdfund_and_broadcast(network, &bitvm2_client, challenge_tx).await;

        // Iterate all disprove scripts, the 8th is the smallest one in size.
        crate::utils::tests::corrupt(&mut proof_sigs, &operator_wots_seckeys.1, 8);
        let (assert_init_tx, assert_commit_txns, assert_final_tx) = operator::operator_sign_assert(
            operator_keypair,
            &mut graph,
            &operator_wots_pubkeys,
            proof_sigs,
        )
        .unwrap();
        broadcast_and_wait_for_confirming(&rpc_client, &assert_init_tx, 1);

        assert_commit_txns.iter().for_each(|tx| {
            broadcast_and_wait_for_confirming(&rpc_client, tx, 1);
        });

        broadcast_and_wait_for_confirming(&rpc_client, &assert_final_tx, 1);

        // disprove
        // verify proof published by assert-txns:
        let public_proof_sigs =
            verifier::extract_proof_sigs_from_assert_commit_txns(assert_commit_txns).unwrap();
        let disprove_scripts_array: [_; NUM_TAPS] = disprove_scripts.try_into().unwrap();
        let disprove_witness = verifier::verify_proof(
            &get_vk().unwrap(),
            public_proof_sigs,
            &disprove_scripts_array,
            &operator_wots_pubkeys,
        )
        .unwrap();

        // FIXME: avoid clone
        let disprove_scripts_bytes = disprove_scripts_array
            .iter()
            .map(|x| x.clone().compile().into_bytes())
            .collect::<Vec<Vec<u8>>>();

        let mock_challenger_reward_address = generate_burn_script_address(network);
        let disprove_tx = verifier::sign_disprove(
            &mut graph,
            disprove_witness,
            disprove_scripts_bytes.to_vec(),
            &operator_wots_pubkeys.1,
            mock_challenger_reward_address,
            fee_rate,
        )
        .unwrap();
        println!("Broadcast disprove tx");
        broadcast_and_wait_for_confirming(&rpc_client, &disprove_tx, 1);
    }
}
