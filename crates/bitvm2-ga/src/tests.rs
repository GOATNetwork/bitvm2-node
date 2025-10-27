#![allow(dead_code)]

#[cfg(test)]
mod tests {
    use crate::{challenger::*, committee::*, keys::*, operator::*, types::*, watchtower::*};
    use bitcoin::{
        Address, Amount, EcdsaSighashType, Network, OutPoint, PublicKey, ScriptBuf, TapSighashType,
        Transaction, TxIn, TxOut, Txid, XOnlyPublicKey, hashes::Hash, key::Keypair,
    };
    use bitcoincore_rpc::{Auth, Client as BtcdClient, RpcApi};
    use bitvm::{
        chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256},
        treepp::*,
    };
    use core::panic;
    use esplora_client::{AsyncClient as EsploraClient, Builder};
    use goat::{
        connectors::{
            assert_connectors::chunk_assert_commit,
            base::TaprootConnector,
            connector_z::ConnectorZ,
            kickoff_connectors::{ForceSkipConnector, KickoffConnector, PrekickoffConnector},
        },
        constants::CONNECTOR_Z_TIMELOCK,
        contexts::{base::generate_n_of_n_public_key, operator::OperatorContext},
        disprove_scripts::{NUM_GUEST_PUBS_ASSERT, hash160},
        scripts::generate_opreturn_script,
        transactions::{
            base::{BaseTransaction, DUST_AMOUNT, Input},
            pre_signed::{PreSignedTransaction, pre_sign_taproot_input_default},
            prekickoff::PrekickoffTransaction,
            signing::populate_p2wsh_witness,
        },
        utils::num_blocks_per_network,
    };
    use musig2::PubNonce;
    use secp256k1::SECP256K1;
    use sha2::{Digest, Sha256};
    use std::{time::Duration, vec};
    use tokio::time::sleep;
    use uuid::Uuid;

    fn network() -> Network {
        const ENV_KEY: &str = "BITVM_NETWORK";
        match std::env::var(ENV_KEY) {
            Ok(v) => match v.to_lowercase().as_str() {
                "regtest" => Network::Regtest,
                "testnet" => Network::Testnet,
                "signet" => Network::Signet,
                "bitcoin" | "mainnet" => Network::Bitcoin,
                _ => Network::Regtest,
            },
            Err(_) => Network::Regtest,
        }
    }

    fn set_network(n: Network) {
        const ENV_KEY: &str = "BITVM_NETWORK";
        let v = match n {
            Network::Regtest => "regtest",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Bitcoin => "bitcoin",
            _ => "regtest",
        };
        unsafe {
            std::env::set_var(ENV_KEY, v);
        }
    }

    fn fee_rate() -> f64 {
        1.0 // sat/vbyte
    }

    async fn get_esplora_client() -> EsploraClient {
        match network() {
            Network::Regtest => Builder::new("http://127.0.0.1:3002").build_async().unwrap(),
            Network::Testnet => {
                Builder::new("https://mempool.space/testnet/api").build_async().unwrap()
            }
            _ => panic!("Mainnet is not supported in tests"),
        }
    }

    fn get_btcd_client() -> BtcdClient {
        if network() != Network::Regtest {
            panic!("get_btcd_client only supports Regtest");
        }
        BtcdClient::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("111111".to_string(), "111111".to_string()),
        )
        .unwrap()
    }

    fn gen_keypair(secret: &str) -> Keypair {
        if !secret.starts_with("seed:") {
            return Keypair::from_seckey_str_global(secret).unwrap();
        }
        // derive private key from seed
        let hashed = Sha256::digest(secret.as_bytes());
        let sk = secp256k1::SecretKey::from_slice(&hashed).unwrap();
        Keypair::from_secret_key(SECP256K1, &sk)
    }

    fn bank_keypair() -> Keypair {
        gen_keypair("seed:faucet")
    }

    async fn fund_address(
        client: &EsploraClient,
        network: Network,
        address: Address,
        amount: Amount,
    ) -> OutPoint {
        fn estimate_fee(num_inputs: usize, fee_rate: f64) -> Amount {
            let tx_size = (num_inputs * 148 + 2 * 34 + 10) as f64;
            let fee = (tx_size * fee_rate).ceil() as u64;
            Amount::from_sat(fee)
        }
        let mut fund_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut { value: amount, script_pubkey: address.script_pubkey() }],
        };
        let bank_pubkey = bank_keypair().public_key().into();
        let bank_address = node_p2wsh_address(network, &bank_pubkey);
        let utxos = client.get_address_utxo(bank_address.clone()).await.unwrap();
        let mut sorted_utxos = utxos;
        sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));
        let mut selected = Vec::new();
        let mut total_value = Amount::ZERO;

        for utxo in sorted_utxos.into_iter() {
            selected.push(utxo.clone());
            total_value += utxo.value;
            fund_tx.input.push(bitcoin::TxIn {
                previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            });
            if total_value >= amount + estimate_fee(fund_tx.input.len(), fee_rate()) {
                break;
            }
        }

        let change = total_value - amount - estimate_fee(fund_tx.input.len(), fee_rate());
        if change.to_sat() > DUST_AMOUNT {
            fund_tx.output.push(bitcoin::TxOut {
                value: change,
                script_pubkey: bank_address.script_pubkey(),
            });
        }

        let script = node_p2wsh_script(&bank_pubkey);
        (0..fund_tx.input.len()).for_each(|index| {
            let amount = selected[index].value;
            populate_p2wsh_witness(
                &mut fund_tx,
                index,
                EcdsaSighashType::All,
                &script,
                amount,
                &vec![&bank_keypair()],
            );
        });

        client.broadcast(&fund_tx).await.unwrap();
        wait_tx_confirm(client, fund_tx.compute_txid()).await;
        OutPoint { txid: fund_tx.compute_txid(), vout: 0 }
    }

    async fn fund_address_batch(
        client: &EsploraClient,
        network: Network,
        receivers: Vec<(Address, Amount)>,
    ) -> Vec<OutPoint> {
        fn estimate_fee(num_inputs: usize, num_outputs: usize, fee_rate: f64) -> Amount {
            let tx_size = (num_inputs * 148 + (num_outputs + 1) * 34 + 10) as f64;
            let fee = (tx_size * fee_rate).ceil() as u64;
            Amount::from_sat(fee)
        }
        let mut fund_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let output_num = receivers.len();
        let total_output_amount: Amount = receivers.iter().map(|(_, amt)| *amt).sum();
        for (address, amount) in receivers {
            fund_tx
                .output
                .push(bitcoin::TxOut { value: amount, script_pubkey: address.script_pubkey() });
        }
        let bank_pubkey = bank_keypair().public_key().into();
        let bank_address = node_p2wsh_address(network, &bank_pubkey);
        let utxos = client.get_address_utxo(bank_address.clone()).await.unwrap();
        let mut sorted_utxos = utxos;
        sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));
        let mut selected = Vec::new();
        let mut total_value = Amount::ZERO;

        for utxo in sorted_utxos.into_iter() {
            selected.push(utxo.clone());
            total_value += utxo.value;
            fund_tx.input.push(bitcoin::TxIn {
                previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            });
            if total_value
                >= total_output_amount + estimate_fee(fund_tx.input.len(), output_num, fee_rate())
            {
                break;
            }
        }

        let change = total_value
            - total_output_amount
            - estimate_fee(fund_tx.input.len(), output_num, fee_rate());
        if change.to_sat() > DUST_AMOUNT {
            fund_tx.output.push(bitcoin::TxOut {
                value: change,
                script_pubkey: bank_address.script_pubkey(),
            });
        }

        let script = node_p2wsh_script(&bank_pubkey);
        (0..fund_tx.input.len()).for_each(|index| {
            let amount = selected[index].value;
            populate_p2wsh_witness(
                &mut fund_tx,
                index,
                EcdsaSighashType::All,
                &script,
                amount,
                &vec![&bank_keypair()],
            );
        });

        client.broadcast(&fund_tx).await.unwrap();
        wait_tx_confirm(client, fund_tx.compute_txid()).await;
        let fund_txid = fund_tx.compute_txid();
        (0..output_num).map(|i| OutPoint { txid: fund_txid, vout: i as u32 }).collect()
    }

    async fn find_utxo(
        client: &EsploraClient,
        address: Address,
        min_amount: Amount,
    ) -> Option<Input> {
        let utxos = client.get_address_utxo(address).await.unwrap();
        for utxo in utxos {
            if utxo.value >= min_amount {
                return Some(Input {
                    outpoint: OutPoint { txid: utxo.txid, vout: utxo.vout },
                    amount: utxo.value,
                });
            }
        }
        None
    }

    fn user_master_key() -> Keypair {
        gen_keypair("seed:user")
    }

    fn operator_master_key() -> OperatorMasterKey {
        OperatorMasterKey::new(gen_keypair("seed:operator"))
    }

    fn challenger_master_key() -> ChallengerMasterKey {
        ChallengerMasterKey::new(gen_keypair("seed:challenger"))
    }

    fn committee_member_master_key() -> [CommitteeMasterKey; 3] {
        [
            CommitteeMasterKey::new(gen_keypair("seed:committee-1")),
            CommitteeMasterKey::new(gen_keypair("seed:committee-2")),
            CommitteeMasterKey::new(gen_keypair("seed:committee-3")),
        ]
    }

    fn watchtower_master_key() -> [WatchtowerMasterKey; 3] {
        [
            WatchtowerMasterKey::new(gen_keypair("seed:watchtower-1")),
            WatchtowerMasterKey::new(gen_keypair("seed:watchtower-2")),
            WatchtowerMasterKey::new(gen_keypair("seed:watchtower-3")),
        ]
    }

    fn hashlocks() -> ([Vec<u8>; 3], [[u8; 20]; 3]) {
        let preimages = [vec![0x11u8; 20], vec![0x22u8; 20], vec![0x33u8; 20]];
        let mut hashlocks = [[0u8; 20]; 3];
        for (i, preimage) in preimages.iter().enumerate() {
            let hash = hash160(preimage);
            hashlocks[i] = hash;
        }
        (preimages, hashlocks)
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

    fn assert_commit_num() -> usize {
        chunk_assert_commit(NUM_GUEST_PUBS_ASSERT + NUM_PUBS + NUM_U256, NUM_HASH, false).len()
    }

    fn get_test_proof()
    -> ([[u8; 32]; NUM_GUEST_PUBS_ASSERT], Groth16Proof, PublicInputs, VerifyingKey) {
        let proof = hex::decode(
            "b6ef2c5aa48a2f599a13bc4d8010e4d0190aeb05ff79e21266aff8dde6353d1756191f0959c787f6dedfc0c47751aed2648775101285b9da2d6c4e912e74891f884bd672f94f4d78528fb10b5410a94b53bcef07f99952ef72b68c72a5c4ff2a3de7c314ffbf17df018a753f070448c2f698706d4c2b99bdb06f928cffe1bea0",
        ).unwrap();
        let pis = hex::decode(
            "02000000000000002000000000000000721db33a295a3b29a61c7360486e6d8346288822dc5cab652722e34d4b423d002000000000000000cfdc2f035c3699c6d17563570ea05a3d6d08302487937dd079a6b1671d484c0d",
        ).unwrap();
        let vk = hex::decode(
            "e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19ffdb10cf9f7e2b08673477187c33a695a397702cf22005900724518b57f92f2ce08f8dfe36ca3eff63b1743d64812936d8cab0d74c063d260e20a9a3339b2a8c0300000000000000d17e1efc51d15eef04bde8dc794edc9e5788eb7539171d3a49d970ab9215b89c9ab6c5ab119ca81927393ef29332a1d15ac5f197b878ea89a1f8f686b747011eaad636dcb52cdfd674d155ddd67d21186fbdd1c0a62ebd74dcd6ddc6784b819e",
        ).unwrap();
        let proof = goat::proof::deserialize_proof(proof);
        let pis = goat::proof::deserialize_pubin(pis);
        let vk = goat::proof::deserialize_vk(vk);
        let guest_pubs = [[0xddu8; 32]; NUM_GUEST_PUBS_ASSERT];
        (guest_pubs, proof, pis, vk)
    }

    async fn gen_test_graph(
        esplora: &EsploraClient,
        disprove_scripts: Vec<ScriptBuf>,
    ) -> Bitvm2Graph {
        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();
        let pegin_amount = Amount::from_sat(10000);
        let challenge_amount = Amount::from_sat(10000);
        let default_fee_amount = Amount::from_sat(1000);
        let bank_address = node_p2wsh_address(network(), &bank_keypair().public_key().into());
        let user_xonly_pubkey = XOnlyPublicKey::from(user_master_key().public_key());
        let user_address = node_p2wsh_address(network(), &user_master_key().public_key().into());
        let pegin_deposit_input_amount = pegin_amount + default_fee_amount;
        let pegin_deposit_inputs = vec![Input {
            outpoint: fund_address(
                esplora,
                network(),
                user_address.clone(),
                pegin_deposit_input_amount,
            )
            .await,
            amount: pegin_deposit_input_amount,
        }];
        let user_info = UserInfo {
            depositor_evm_address: [0x11u8; 20],
            txn_fees: [default_fee_amount.to_sat(); 3],
            inputs: pegin_deposit_inputs,
            user_xonly_pubkey,
            user_change_address: bank_address.clone(),
            user_refund_address: bank_address.clone(),
        };

        let committee_pubkeys: Vec<PublicKey> = committee_member_master_key()
            .iter()
            .map(|k| k.keypair_for_instance(instance_id).public_key().into())
            .collect();
        let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
        let instance_params = Bitvm2InstanceParameters {
            network: network(),
            instance_id,
            user_info,
            pegin_amount,
            committee_pubkeys,
            committee_agg_pubkey,
        };

        let mut pegin_deposit_tx = instance_params.build_pegin_tx().unwrap().0;
        node_sign(
            pegin_deposit_tx.tx_mut(),
            0,
            pegin_deposit_input_amount,
            EcdsaSighashType::All,
            &user_master_key(),
        )
        .unwrap();
        println!("broadcasting pegin deposit tx {}", pegin_deposit_tx.tx().compute_txid());
        esplora.broadcast(&pegin_deposit_tx.finalize()).await.unwrap();
        wait_tx_confirm(esplora, pegin_deposit_tx.tx().compute_txid()).await;
        println!("pegin deposit tx confirmed");

        let operator_master_key = operator_master_key();
        let operator_keypair = operator_master_key.master_keypair();
        let operator_wots_pubkeys = operator_master_key.wots_keypair_for_graph(graph_id).1;
        let operator_taproot_public_key = XOnlyPublicKey::from(operator_keypair.public_key());
        let prekickoff_connector =
            PrekickoffConnector::new(network(), &operator_taproot_public_key);
        let force_skip_connector = ForceSkipConnector::new(network(), &operator_taproot_public_key);
        let kickoff_connector = KickoffConnector::new(network(), &operator_taproot_public_key);
        let operator_prekickoff_input_amount = Amount::from_sat(50000);
        let cur_prekickoff_connector_input = Input {
            outpoint: fund_address(
                esplora,
                network(),
                prekickoff_connector.generate_taproot_address(),
                operator_prekickoff_input_amount,
            )
            .await,
            amount: operator_prekickoff_input_amount,
        };
        let mut cur_prekickoff_txn = PrekickoffTransaction::new_for_validation(
            &prekickoff_connector,
            &force_skip_connector,
            &kickoff_connector,
            &prekickoff_connector,
            cur_prekickoff_connector_input,
            vec![],
            vec![],
            default_fee_amount.to_sat(),
            3,
            assert_commit_num(),
        )
        .unwrap();
        let base_context = instance_params.get_base_context();
        let operator_context = OperatorContext {
            network: network(),
            operator_keypair,
            operator_public_key: operator_keypair.public_key().into(),
            operator_taproot_public_key,
            n_of_n_public_key: base_context.n_of_n_public_key,
            n_of_n_public_keys: base_context.n_of_n_public_keys,
            n_of_n_taproot_public_key: base_context.n_of_n_taproot_public_key,
        };
        cur_prekickoff_txn.sign_input_0(&operator_context, &prekickoff_connector);
        println!("broadcasting prekickoff tx {}", cur_prekickoff_txn.tx().compute_txid());
        esplora.broadcast(&cur_prekickoff_txn.finalize()).await.unwrap();
        wait_tx_confirm(esplora, cur_prekickoff_txn.tx().compute_txid()).await;
        println!("prekickoff tx confirmed");
        let prekickoff_parameters = PrekickoffParameters {
            cur_prekickoff_txn,
            replenish_fee_inputs: vec![],
            replenish_fee_prev_outs: vec![],
            fee_amount: default_fee_amount.to_sat(),
        };

        let graph_parameters = Bitvm2GraphParameters {
            instance_parameters: instance_params,
            prekickoff_parameters,
            graph_id,
            graph_nonce: 0,
            challenge_amount,
            operator_pubkey: operator_keypair.public_key().into(),
            operator_wots_pubkeys,
            operator_receive_address: bank_address.clone(),
            watchtower_pubkeys: watchtower_master_key()
                .iter()
                .map(|k| k.master_keypair().public_key().into())
                .collect(),
            hashlocks: hashlocks().1.to_vec(),
            guest_constant_value: [0u8; 32], // all zero for test
        };

        generate_bitvm_graph(graph_parameters, disprove_scripts).unwrap()
    }

    fn operator_presign_graph(graph: &mut Bitvm2Graph) {
        operator_pre_sign(operator_master_key().master_keypair(), graph).unwrap();
    }

    fn committee_presign_graph(graph: &mut Bitvm2Graph) {
        let instance_id = graph.parameters.instance_parameters.instance_id;
        let graph_id = graph.parameters.graph_id;
        let watchtower_num = graph.parameters.watchtower_pubkeys.len();
        let assert_commit_num = assert_commit_num();
        let commitee_master_keys = committee_member_master_key();
        let commitee_pub_nonces: Vec<CommitteePubNonces> = commitee_master_keys
            .iter()
            .map(|k| k.nonces_for_graph(instance_id, graph_id, watchtower_num, assert_commit_num).0)
            .collect();
        let agg_nonces = nonces_aggregation(&commitee_pub_nonces).unwrap();
        let committee_partial_sigs = commitee_master_keys
            .iter()
            .map(|k| {
                let s =
                    k.nonces_for_graph(instance_id, graph_id, watchtower_num, assert_commit_num).1;
                committee_pre_sign(
                    k.keypair_for_instance(instance_id),
                    s,
                    agg_nonces.clone(),
                    graph,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let commitee_agg_sigs =
            signature_aggregation(&committee_partial_sigs, &agg_nonces, graph).unwrap();
        push_committee_pre_signatures(graph, &commitee_agg_sigs).unwrap();
    }

    async fn send_pegin_confirm(esplora: &EsploraClient, graph: &Bitvm2Graph) {
        let instance_id = graph.parameters.instance_parameters.instance_id;
        let commitee_master_keys = committee_member_master_key();
        let commitee_pub_nonces: Vec<PubNonce> =
            commitee_master_keys.iter().map(|k| k.nonce_for_instance(instance_id).1).collect();
        let agg_nonce = nonce_aggregation(&commitee_pub_nonces);
        let committee_musig2_sigs = commitee_master_keys
            .iter()
            .map(|k| {
                let (s, _, _) = k.nonce_for_instance(instance_id);
                sign_pegin_confirm(
                    &graph,
                    k.keypair_for_instance(instance_id),
                    s,
                    agg_nonce.clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let tx = agg_and_push_pegin_confirm_sigs(graph, committee_musig2_sigs, &agg_nonce).unwrap();
        println!("broadcasting pegin confirm tx {}", tx.compute_txid());
        esplora.broadcast(&tx).await.unwrap();
        wait_tx_confirm(esplora, tx.compute_txid()).await;
        println!("pegin confirm tx confirmed");
    }

    async fn send_pegin_refund(esplora: &EsploraClient, graph: &Bitvm2Graph) {
        let (pegin_deposit, _, mut pegin_refund) =
            graph.parameters.instance_parameters.build_pegin_tx().unwrap();
        let pegin_deposit_txid = pegin_deposit.tx().compute_txid();
        let pegin_deposit_height = wait_tx_confirm(esplora, pegin_deposit_txid).await;
        let refund_timelock = num_blocks_per_network(network(), CONNECTOR_Z_TIMELOCK);
        println!("waiting for pegin refund timelock");
        wait_timelock(esplora, pegin_deposit_height, refund_timelock).await;
        let committee_taproot_pubkey =
            XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
        let connector_z = ConnectorZ::new(
            network(),
            &committee_taproot_pubkey,
            &graph.parameters.instance_parameters.user_info.user_xonly_pubkey,
        );
        pre_sign_taproot_input_default(
            &mut pegin_refund,
            0,
            TapSighashType::All,
            connector_z.generate_taproot_spend_info(),
            &vec![&user_master_key()],
        );
        println!("broadcasting pegin refund tx {}", pegin_refund.tx().compute_txid());
        esplora.broadcast(&pegin_refund.finalize()).await.unwrap();
        wait_tx_confirm(esplora, pegin_refund.tx().compute_txid()).await;
        println!("pegin refund tx confirmed");
    }

    async fn wait_timelock(esplora: &EsploraClient, start_height: u32, timelock: u32) {
        if network() == Network::Regtest {
            // In regtest, we can just mine blocks to satisfy the timelock
            let current_height = esplora.get_height().await.unwrap();
            let mint_blocks_num = (start_height + timelock + 1).saturating_sub(current_height);
            if mint_blocks_num == 0 {
                return;
            }
            let rpc = get_btcd_client();
            regtest_mint_blocks(&rpc, mint_blocks_num).await;
            sleep(Duration::from_secs(1)).await;
        } else {
            // In testnet, we have to wait for real blocks
            let wait_start = std::time::Instant::now();
            let expected_heigth = start_height + timelock + 1;
            loop {
                let current_height = esplora.get_height().await.unwrap();
                if current_height >= expected_heigth {
                    break;
                }
                sleep(Duration::from_secs(5)).await;
                let elapsed_secs = wait_start.elapsed().as_secs();
                if elapsed_secs % 60 == 0 {
                    println!(
                        "Waited {} mins for timelock, current height {current_height}, expected_height {expected_heigth}",
                        elapsed_secs / 60
                    );
                }
            }
        }
    }

    async fn wait_tx_confirm(esplora: &EsploraClient, txid: Txid) -> u32 {
        if network() == Network::Regtest {
            regtest_mint_blocks(&get_btcd_client(), 1).await;
            sleep(Duration::from_secs(1)).await;
            esplora.get_height().await.unwrap()
        } else {
            let wait_start = std::time::Instant::now();
            loop {
                let tx_status = esplora.get_tx_status(&txid).await.unwrap();
                if let Some(height) = tx_status.block_height {
                    return height;
                }
                sleep(Duration::from_secs(5)).await;
                let elapsed_secs = wait_start.elapsed().as_secs();
                if elapsed_secs % 60 == 0 {
                    println!("Waited {} mins for {txid}", elapsed_secs / 60);
                }
            }
        }
    }

    fn check_tx_sig_witness(
        tx: &Transaction,
        input_index: usize,
        pubkey: &XOnlyPublicKey,
        sighash: bitcoin::TapSighash,
    ) -> bool {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let wit = match tx.input.get(input_index) {
            Some(input) => &input.witness,
            None => return false,
        };

        if wit.is_empty() {
            return false;
        }

        let sig_with_hash = &wit[0];

        if sig_with_hash.len() != 65 {
            return false;
        }

        let sig_bytes = &sig_with_hash[..64];
        let _sighash_flag = sig_with_hash[64];

        let sig = match bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let msg = bitcoin::secp256k1::Message::from(sighash);

        secp.verify_schnorr(&sig, &msg, pubkey).is_ok()
    }

    async fn build_sign_and_broadcast_tx(
        esplora: &EsploraClient,
        node_keypair: Keypair,
        txins: Vec<TxIn>,
        total_input_amount: Amount,
        txouts: Vec<TxOut>,
    ) -> Txid {
        let txouts = if txouts.is_empty() {
            vec![TxOut { value: Amount::ZERO, script_pubkey: generate_opreturn_script(vec![]) }]
        } else {
            txouts
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: txins,
            output: txouts,
        };
        let total_output_amount: Amount = tx.output.iter().map(|o| o.value).sum();
        let fee_amount = Amount::from_sat(
            ((tx.weight().to_vbytes_ceil() + 200) as f64 * fee_rate()).ceil() as u64,
        );
        let node_address = node_p2wsh_address(network(), &node_keypair.public_key().into());
        let shortfall = Amount::from_sat(
            (total_output_amount + fee_amount)
                .to_sat()
                .saturating_sub(total_input_amount.to_sat() + DUST_AMOUNT)
                + DUST_AMOUNT,
        );
        let payer_outpoint =
            fund_address(esplora, network(), node_address.clone(), shortfall).await;
        wait_tx_confirm(esplora, payer_outpoint.txid).await;
        tx.input.push(bitcoin::TxIn {
            previous_output: payer_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        let payer_input_index = tx.input.len() - 1;
        node_sign(&mut tx, payer_input_index, shortfall, EcdsaSighashType::All, &node_keypair)
            .unwrap();
        esplora.broadcast(&tx).await.unwrap();
        tx.compute_txid()
    }

    async fn merge_bank_utxo(esplora: &EsploraClient) {
        // get_address_utxo may fail if there are too many UTXOs (e.g. 500), so we merge them before its too late
        println!("merging bank UTXOs");
        let bank_address = node_p2wsh_address(network(), &bank_keypair().public_key().into());
        let utxos = esplora.get_address_utxo(bank_address.clone()).await.unwrap();
        if utxos.len() < 300 {
            println!("bank UTXOs are not too many {}, no need to merge", utxos.len());
            return;
        }
        let mut selected_utxos = vec![];
        let current_height = esplora.get_height().await.unwrap();
        // coinbase outputs need 100 blocks to mature, so we leave them untouched
        for utxo in utxos.into_iter() {
            let tx_info = esplora.get_tx_info(&utxo.txid).await.unwrap().unwrap();
            if tx_info.vin[0].txid == Txid::from_slice(&[0u8; 32]).unwrap()
                && tx_info.vin[0].vout == u32::MAX
            {
                // coinbase output
                if let Some(height) = tx_info.status.block_height {
                    if current_height.saturating_sub(height) < 100 {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            selected_utxos.push(utxo.clone());
        }
        if selected_utxos.len() < 2 {
            println!("not enough mature UTXOs to merge");
            return;
        }
        let txins: Vec<TxIn> = selected_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint { txid: u.txid, vout: u.vout },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            })
            .collect();
        let total_input_amount: Amount = selected_utxos.iter().map(|u| u.value).sum();
        let txout = TxOut {
            value: total_input_amount - Amount::from_sat(100000),
            script_pubkey: bank_address.script_pubkey(),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: txins,
            output: vec![txout],
        };
        for i in 0..tx.input.len() {
            node_sign(&mut tx, i, selected_utxos[i].value, EcdsaSighashType::All, &bank_keypair())
                .unwrap();
        }
        esplora.broadcast(&tx).await.unwrap();
        wait_tx_confirm(esplora, tx.compute_txid()).await;
        println!("bank UTXOs merged");
    }

    async fn regtest_mint_blocks(btcd: &BtcdClient, num: u32) {
        if network() != Network::Regtest {
            panic!("can only mint blocks in regtest");
        }
        let bank_address = node_p2wsh_address(network(), &bank_keypair().public_key().into());
        btcd.generate_to_address(num.into(), &bank_address).unwrap();
    }

    #[tokio::test]
    async fn test_take1() {
        set_network(Network::Regtest);
        let esplora = get_esplora_client().await;
        let disprove_scripts = vec![script! {OP_TRUE}.compile()]; // No disprove, use empty vector to simplify

        merge_bank_utxo(&esplora).await;
        let mut graph = gen_test_graph(&esplora, disprove_scripts).await;
        operator_presign_graph(&mut graph);
        committee_presign_graph(&mut graph);
        send_pegin_confirm(&esplora, &graph).await;

        // kickoff
        let operator_keypair = operator_master_key().master_keypair();
        let kickoff = operator_sign_kickoff(operator_keypair, &mut graph).unwrap();
        println!("broadcasting kickoff tx {}", kickoff.compute_txid());
        esplora.broadcast(&kickoff).await.unwrap();
        let kickoff_height = wait_tx_confirm(&esplora, kickoff.compute_txid()).await;
        println!("kickoff tx confirmed");

        // take1
        println!("waiting for take1 timelock");
        wait_timelock(&esplora, kickoff_height, take1_timelock(network())).await;
        let take1 = operator_sign_take1(operator_keypair, &mut graph).unwrap();
        println!("broadcasting take1 tx {}", take1.compute_txid());
        esplora.broadcast(&take1).await.unwrap();
        wait_tx_confirm(&esplora, take1.compute_txid()).await;
        println!("take1 tx confirmed");
    }

    #[tokio::test]
    async fn test_take2() {
        set_network(Network::Regtest);
        let esplora = get_esplora_client().await;
        let disprove_scripts = vec![script! {OP_TRUE}.compile()]; // No disprove, use empty vector to simplify

        let bank_address = node_p2wsh_address(network(), &bank_keypair().public_key().into());
        let default_fee_amount = Amount::from_sat(1000);

        merge_bank_utxo(&esplora).await;
        let mut graph = gen_test_graph(&esplora, disprove_scripts).await;
        operator_presign_graph(&mut graph);
        committee_presign_graph(&mut graph);
        send_pegin_confirm(&esplora, &graph).await;

        // kickoff
        let operator_keypair = operator_master_key().master_keypair();
        let kickoff = operator_sign_kickoff(operator_keypair, &mut graph).unwrap();
        println!("broadcasting kickoff tx {}", kickoff.compute_txid());
        esplora.broadcast(&kickoff).await.unwrap();
        wait_tx_confirm(&esplora, kickoff.compute_txid()).await;
        println!("kickoff tx confirmed");

        // challenge
        let (mut challenge_tx, _) = export_challenge_tx(&graph).unwrap();
        let challenge_keypair = challenger_master_key().master_keypair();
        challenge_tx.output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(vec![0xffu8; 20]),
        });
        println!("broadcasting challenge tx {}", challenge_tx.compute_txid());
        build_sign_and_broadcast_tx(
            &esplora,
            challenge_keypair,
            challenge_tx.input,
            kickoff.output[0].value,
            challenge_tx.output,
        )
        .await;
        println!("challenge tx confirmed");

        // watchtower challenge init
        let watchtower_challenge_init =
            operator_sign_watchtower_challenge_init(operator_keypair, &mut graph).unwrap();
        let watchtower_challenge_init_txid = watchtower_challenge_init.compute_txid();
        println!("broadcasting watchtower challenge init tx {}", watchtower_challenge_init_txid);
        esplora.broadcast(&watchtower_challenge_init).await.unwrap();
        let watchtower_challenge_init_height =
            wait_tx_confirm(&esplora, watchtower_challenge_init_txid).await;
        println!("watchtower challenge init tx confirmed");

        // watchtower[0] challenge
        let watchtower_0_keypair = watchtower_master_key()[0].master_keypair();
        let watchtower_challenge_payer_amount = Amount::from_sat(3000);
        let watchtower_0_challenge_payer_input = Input {
            outpoint: fund_address(
                &esplora,
                network(),
                node_p2wsh_address(network(), &watchtower_0_keypair.public_key().into()),
                watchtower_challenge_payer_amount,
            )
            .await,
            amount: watchtower_challenge_payer_amount,
        };

        const PROOF: &[u8] =
            include_bytes!("../../bitcoin-light-client-circuit/samples/output.bin.proof.bin");
        const PUBLIC_INPUTS: &[u8] = include_bytes!(
            "../../bitcoin-light-client-circuit/samples/output.bin.public_inputs.bin"
        );
        const VK_HASH: &str =
            include_str!("../../bitcoin-light-client-circuit/samples/output.bin.vk_hash.bin");

        let graph_id = graph.parameters.graph_id.to_bytes_le();
        let total_work = 100;
        let block_height = 100;
        let comm = bitcoin_light_client_circuit::build_watchtower_commitment(
            &graph_id,
            &PROOF.try_into().unwrap(),
            &PUBLIC_INPUTS.try_into().unwrap(),
            VK_HASH,
            total_work,
            block_height,
        );

        let mut watchtower_0_challenge = build_watchtower_challenge_tx(
            &graph,
            &watchtower_0_keypair,
            0,
            &comm,
            vec![watchtower_0_challenge_payer_input],
            &bank_address,
            default_fee_amount,
        )
        .unwrap();
        node_sign(
            &mut watchtower_0_challenge,
            1,
            watchtower_challenge_payer_amount,
            EcdsaSighashType::All,
            &watchtower_0_keypair,
        )
        .unwrap();
        println!(
            "broadcasting watchtower 0 challenge tx {}",
            watchtower_0_challenge.compute_txid()
        );
        esplora.broadcast(&watchtower_0_challenge).await.unwrap();
        wait_tx_confirm(&esplora, watchtower_0_challenge.compute_txid()).await;
        println!("watchtower 0 challenge tx confirmed");

        // operator ack
        let (ack_txin, ack_txin_amount) =
            operator_sign_ack(operator_keypair, &mut graph, 0, &hashlocks().0[0]).unwrap();
        println!("broadcasting ack tx");
        let ack_txid = build_sign_and_broadcast_tx(
            &esplora,
            operator_keypair,
            vec![ack_txin],
            ack_txin_amount,
            vec![],
        )
        .await;
        wait_tx_confirm(&esplora, ack_txid).await;
        println!("ack tx {} confirmed", ack_txid);

        // watchtower challenge timeout
        println!("waiting for watchtower challenge timeout");
        wait_timelock(
            &esplora,
            watchtower_challenge_init_height,
            watchtower_challenge_timeout_timelock(network()),
        )
        .await;
        let watchtower_challenge_timeout_tx =
            operator_sign_watchtower_challenge_timeout(operator_keypair, &mut graph, 1).unwrap();
        println!(
            "broadcasting watchtower challenge timeout tx {}",
            watchtower_challenge_timeout_tx.compute_txid()
        );
        esplora.broadcast(&watchtower_challenge_timeout_tx).await.unwrap();
        wait_tx_confirm(&esplora, watchtower_challenge_timeout_tx.compute_txid()).await;
        println!("watchtower challenge timeout tx confirmed");

        // operator_commit_blockhash
        let wots_secret_keys =
            operator_master_key().wots_keypair_for_graph(graph.parameters.graph_id).0;
        let blockhash_wots_secret_key = &wots_secret_keys[0];
        let (operator_commit_blockhash_txin, operator_commit_blockhash_txin_amount) =
            operator_sign_blockhash_commit(
                operator_keypair,
                &mut graph,
                &[0xeeu8; 32],
                blockhash_wots_secret_key,
            )
            .unwrap();
        println!("broadcasting operator commit blockhash tx");
        let operator_commit_blockhash_txid = build_sign_and_broadcast_tx(
            &esplora,
            operator_keypair,
            vec![operator_commit_blockhash_txin],
            operator_commit_blockhash_txin_amount,
            vec![],
        )
        .await;
        wait_tx_confirm(&esplora, operator_commit_blockhash_txid).await;
        println!("operator commit blockhash tx {} confirmed", operator_commit_blockhash_txid);

        // assert-init
        let assert_init_tx = operator_sign_assert_init(operator_keypair, &mut graph).unwrap();
        let assert_init_txid = assert_init_tx.compute_txid();
        println!("broadcasting assert-init tx {}", assert_init_txid);
        esplora.broadcast(&assert_init_tx).await.unwrap();
        let assert_init_height = wait_tx_confirm(&esplora, assert_init_txid).await;
        println!("assert-init tx confirmed");

        // assert-commit
        let (guest_inputs, proof, groth16_pubin, vk) = get_test_proof();
        let assert_commit_txins = operator_sign_assert_commit(
            operator_keypair,
            &mut graph,
            &wots_secret_keys,
            guest_inputs,
            proof,
            groth16_pubin,
            &vk,
        )
        .unwrap();
        println!("broadcasting assert-commit tx");
        let mut index = 0;
        for (txin, amount) in assert_commit_txins {
            let assert_commit_txid =
                build_sign_and_broadcast_tx(&esplora, operator_keypair, vec![txin], amount, vec![])
                    .await;
            wait_tx_confirm(&esplora, assert_commit_txid).await;
            println!("assert-commit tx-{index} {} confirmed", assert_commit_txid);
            index += 1;
        }

        // take2
        println!("waiting for take2 timelock");
        wait_timelock(&esplora, watchtower_challenge_init_height, take2_timelocks(network()).0)
            .await;
        wait_timelock(&esplora, assert_init_height, take2_timelocks(network()).1).await;
        let take2 = operator_sign_take2(operator_keypair, &mut graph).unwrap();
        println!("broadcasting take2 tx {}", take2.compute_txid());
        esplora.broadcast(&take2).await.unwrap();
        wait_tx_confirm(&esplora, take2.compute_txid()).await;
        println!("take2 tx confirmed");
    }

    #[tokio::test]
    async fn test_nack() {
        set_network(Network::Regtest);
        let esplora = get_esplora_client().await;
        let disprove_scripts = vec![script! {OP_TRUE}.compile()]; // No disprove, use empty vector to simplify

        merge_bank_utxo(&esplora).await;
        let mut graph = gen_test_graph(&esplora, disprove_scripts).await;
        operator_presign_graph(&mut graph);
        committee_presign_graph(&mut graph);
        send_pegin_refund(&esplora, &graph).await;

        // kickoff
        let operator_keypair = operator_master_key().master_keypair();
        let kickoff = operator_sign_kickoff(operator_keypair, &mut graph).unwrap();
        println!("broadcasting kickoff tx {}", kickoff.compute_txid());
        esplora.broadcast(&kickoff).await.unwrap();
        wait_tx_confirm(&esplora, kickoff.compute_txid()).await;
        println!("kickoff tx confirmed");

        // challenge
        let (mut challenge_tx, _) = export_challenge_tx(&graph).unwrap();
        let challenge_keypair = challenger_master_key().master_keypair();
        challenge_tx.output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(vec![0xffu8; 20]),
        });
        println!("broadcasting challenge tx {}", challenge_tx.compute_txid());
        build_sign_and_broadcast_tx(
            &esplora,
            challenge_keypair,
            challenge_tx.input,
            kickoff.output[0].value,
            challenge_tx.output,
        )
        .await;
        println!("challenge tx confirmed");

        // watchtower challenge init
        let watchtower_challenge_init =
            operator_sign_watchtower_challenge_init(operator_keypair, &mut graph).unwrap();
        let watchtower_challenge_init_txid = watchtower_challenge_init.compute_txid();
        println!("broadcasting watchtower challenge init tx {}", watchtower_challenge_init_txid);
        esplora.broadcast(&watchtower_challenge_init).await.unwrap();
        let watchtower_challenge_init_height =
            wait_tx_confirm(&esplora, watchtower_challenge_init_txid).await;
        println!("watchtower challenge init tx confirmed");

        // nack
        println!("waiting for nack timelock");
        wait_timelock(&esplora, watchtower_challenge_init_height, nack_timelock(network())).await;
        let nack_tx = graph.nack_txns[0].finalize();
        println!("broadcasting nack tx {}", nack_tx.compute_txid());
        esplora.broadcast(&nack_tx).await.unwrap();
        wait_tx_confirm(&esplora, nack_tx.compute_txid()).await;
        println!("nack tx confirmed");
    }

    #[tokio::test]
    async fn test_commit_timeout() {
        set_network(Network::Regtest);
        let esplora = get_esplora_client().await;
        let disprove_scripts = vec![script! {OP_TRUE}.compile()]; // No disprove, use empty vector to simplify

        merge_bank_utxo(&esplora).await;
        let mut graph = gen_test_graph(&esplora, disprove_scripts).await;
        operator_presign_graph(&mut graph);
        committee_presign_graph(&mut graph);
        send_pegin_refund(&esplora, &graph).await;

        // kickoff
        let operator_keypair = operator_master_key().master_keypair();
        let kickoff = operator_sign_kickoff(operator_keypair, &mut graph).unwrap();
        println!("broadcasting kickoff tx {}", kickoff.compute_txid());
        esplora.broadcast(&kickoff).await.unwrap();
        wait_tx_confirm(&esplora, kickoff.compute_txid()).await;
        println!("kickoff tx confirmed");

        // challenge
        let (mut challenge_tx, _) = export_challenge_tx(&graph).unwrap();
        let challenge_keypair = challenger_master_key().master_keypair();
        challenge_tx.output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(vec![0xffu8; 20]),
        });
        println!("broadcasting challenge tx {}", challenge_tx.compute_txid());
        build_sign_and_broadcast_tx(
            &esplora,
            challenge_keypair,
            challenge_tx.input,
            kickoff.output[0].value,
            challenge_tx.output,
        )
        .await;
        println!("challenge tx confirmed");

        // watchtower challenge init
        let watchtower_challenge_init =
            operator_sign_watchtower_challenge_init(operator_keypair, &mut graph).unwrap();
        let watchtower_challenge_init_txid = watchtower_challenge_init.compute_txid();
        println!("broadcasting watchtower challenge init tx {}", watchtower_challenge_init_txid);
        esplora.broadcast(&watchtower_challenge_init).await.unwrap();
        let watchtower_challenge_init_height =
            wait_tx_confirm(&esplora, watchtower_challenge_init_txid).await;
        println!("watchtower challenge init tx confirmed");

        // assert-init
        let assert_init_tx = operator_sign_assert_init(operator_keypair, &mut graph).unwrap();
        let assert_init_txid = assert_init_tx.compute_txid();
        println!("broadcasting assert-init tx {}", assert_init_txid);
        esplora.broadcast(&assert_init_tx).await.unwrap();
        let assert_init_height = wait_tx_confirm(&esplora, assert_init_txid).await;
        println!("assert-init tx confirmed");

        // assert-commit timeout
        // normally, only one of assert-commit or blockhash-commit timeout will be triggered
        println!("waiting for assert-commit timeout");
        wait_timelock(&esplora, assert_init_height, assert_commit_timeout_timelock(network()))
            .await;
        let assert_commit_timeout_tx = graph.assert_commit_timeout_txns[0].finalize();
        println!(
            "broadcasting assert-commit timeout tx {}",
            assert_commit_timeout_tx.compute_txid()
        );
        esplora.broadcast(&assert_commit_timeout_tx).await.unwrap();
        wait_tx_confirm(&esplora, assert_commit_timeout_tx.compute_txid()).await;
        println!("assert-commit timeout tx confirmed");

        // blockhash-commit timeout
        println!("waiting for blockhash-commit timeout");
        wait_timelock(
            &esplora,
            watchtower_challenge_init_height,
            commit_blockhash_timeout_timelock(network()),
        )
        .await;
        let blockhash_commit_timeout_tx = graph.blockhash_commit_timeout.finalize();
        println!(
            "broadcasting blockhash-commit timeout tx {}",
            blockhash_commit_timeout_tx.compute_txid()
        );
        esplora.broadcast(&blockhash_commit_timeout_tx).await.unwrap();
        wait_tx_confirm(&esplora, blockhash_commit_timeout_tx.compute_txid()).await;
        println!("blockhash-commit timeout tx confirmed");
    }

    #[ignore = "debug"]
    #[tokio::test]
    async fn test_broadcast_cpfp_package() {
        use client::btc_chain::BTCClient;
        use goat::scripts::*;

        let network = Network::Testnet;
        set_network(network);
        let esplora = get_esplora_client().await;
        let client = BTCClient::new(network, None);
        let test_keypair = gen_keypair("seed:test");
        let test_address = node_p2wsh_address(network, &test_keypair.public_key().into());
        let default_input_amount = Amount::from_sat(2000);
        let receivers = std::iter::repeat((test_address.clone(), default_input_amount))
            .take(3)
            .collect::<Vec<_>>();
        let utxos = fund_address_batch(&esplora, network, receivers).await;
        let [utxo0, utxo1, utxo2]: [OutPoint; 3] = utxos.try_into().unwrap();
        let mut txn0 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: utxo0,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![
                TxOut { value: Amount::ZERO, script_pubkey: test_address.script_pubkey() },
                p2a_output(),
            ],
        };
        node_sign(
            &mut txn0,
            0,
            default_input_amount,
            bitcoin::EcdsaSighashType::All,
            &test_keypair,
        )
        .unwrap();
        let output0_amount =
            default_input_amount - Amount::from_sat(txn0.weight().to_vbytes_ceil()) - p2a_amount();
        txn0.output[0].value = output0_amount;
        txn0.input[0].witness.clear();
        node_sign(
            &mut txn0,
            0,
            default_input_amount,
            bitcoin::EcdsaSighashType::All,
            &test_keypair,
        )
        .unwrap();
        let txn0_txid = txn0.compute_txid();

        let mut cpfp_txn0 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: txn0_txid, vout: 1 },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::default(),
                },
                TxIn {
                    previous_output: utxo1,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::default(),
                },
            ],
            output: vec![p2a_output()],
        };
        node_sign(
            &mut cpfp_txn0,
            1,
            default_input_amount,
            bitcoin::EcdsaSighashType::All,
            &test_keypair,
        )
        .unwrap();

        let mut txn1 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: txn0_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![
                TxOut { value: Amount::ZERO, script_pubkey: test_address.script_pubkey() },
                p2a_output(),
            ],
        };
        let input0_amount = txn0.output[0].value;
        node_sign(&mut txn1, 0, input0_amount, bitcoin::EcdsaSighashType::All, &test_keypair)
            .unwrap();
        let output0_amount =
            input0_amount - Amount::from_sat(txn1.weight().to_vbytes_ceil()) - p2a_amount();
        txn1.output[0].value = output0_amount;
        txn1.input[0].witness.clear();
        node_sign(&mut txn1, 0, input0_amount, bitcoin::EcdsaSighashType::All, &test_keypair)
            .unwrap();
        let txn1_txid = txn1.compute_txid();

        let mut cpfp_txn1 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: txn1_txid, vout: 1 },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::default(),
                },
                TxIn {
                    previous_output: utxo2,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::default(),
                },
            ],
            output: vec![p2a_output()],
        };
        node_sign(
            &mut cpfp_txn1,
            1,
            default_input_amount,
            bitcoin::EcdsaSighashType::All,
            &test_keypair,
        )
        .unwrap();

        let tx_package_1 = vec![txn0, cpfp_txn0];
        let tx_package_2 = vec![txn1, cpfp_txn1];
        println!(
            "txids in the package: \ntxn0 {}, \ncpfp_txn0 {}, \ntxn1 {}, \ncpfp_txn1 {}",
            tx_package_1[0].compute_txid(),
            tx_package_1[1].compute_txid(),
            tx_package_2[0].compute_txid(),
            tx_package_2[1].compute_txid()
        );
        client.broadcast_package(&tx_package_1).await.unwrap();
        client.broadcast_package(&tx_package_2).await.unwrap();

        // this will fail because cpfp_txn0 and cpfp_txn1 not parent & child, only 1c1p is allowed in a package
        // let tx_package_1 = vec![txn0, txn1];
        // let tx_package_2 = vec![cpfp_txn0, cpfp_txn1];
        // println!("txids in the package: \ntxn0 {}, \ncpfp_txn0 {}, \ntxn1 {}, \ncpfp_txn1 {}",
        //     tx_package_1[0].compute_txid(),
        //     tx_package_2[0].compute_txid(),
        //     tx_package_1[1].compute_txid(),
        //     tx_package_2[1].compute_txid());
        // client.broadcast_package(&tx_package_1).await.unwrap();
        // client.broadcast_package(&tx_package_2).await.unwrap();

        // // this will fail because both cpfp_txn0 and txn1 depends on txn0, only 1c1p is allowed in a package
        // let tx_package = vec![txn0, cpfp_txn0, txn1, cpfp_txn1];
        // client.broadcast_package(&tx_package).await.unwrap();
    }

    #[tokio::test]
    async fn test_unlimited_opreturn() {
        let network = Network::Testnet;
        set_network(network);
        let esplora = get_esplora_client().await;
        let bank_address = node_p2wsh_address(network, &bank_keypair().public_key().into());
        let utxos = esplora.get_address_utxo(bank_address.clone()).await.unwrap();
        let utxo = if utxos.is_empty() {
            panic!("No UTXOs found for bank address");
        } else {
            utxos[0].clone()
        };
        let msg = b"test OP_RETURN with more than 80 bytes.\n\"A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending.We propose a solution to the double-spending problem using a peer-to-peer network.The network timestamps transactions by hashing them into an ongoing chain of hash-based proof-of-work, forming a record that cannot be changed without redoing the proof-of-work. The longest chain not only serves as proof of the sequence of events witnessed, but proof that it came from the largest pool of CPU power. As long as a majority of CPU power is controlled by nodes that are not cooperating to attack the network, they'll generate the longest chain and outpace attackers. The network itself requires minimal structure. Messages are broadcast on a best effort basis, and nodes can leave and rejoin the network at will, accepting the longest proof-of-work chain as proof of what happened while they were gone.\"";
        // let msg = b"short OP_RETURN message";
        let opreturn_script = script! {
            OP_RETURN
            {msg.to_vec()}
        }
        .compile();
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![
                TxOut { value: Amount::ZERO, script_pubkey: opreturn_script },
                TxOut { value: Amount::ZERO, script_pubkey: bank_address.script_pubkey() },
            ],
        };
        let tx_size = tx.weight().to_vbytes_ceil() + 200;
        if utxo.value < Amount::from_sat(tx_size) {
            panic!("cannot find utxo with enough value for the test");
        }
        let change_amount = utxo.value - Amount::from_sat(tx_size); // 1 sat/vbyte fee
        if change_amount > Amount::from_sat(330) {
            tx.output[1].value = change_amount;
        } else {
            tx.output.pop(); // remove change output if it's too small
        }
        node_sign(&mut tx, 0, utxo.value, EcdsaSighashType::All, &bank_keypair()).unwrap();
        esplora.broadcast(&tx).await.unwrap();
        println!(
            "Broadcasted transaction with {} bytes OP_RETURN: {}",
            msg.len(),
            tx.compute_txid()
        );
    }
}
