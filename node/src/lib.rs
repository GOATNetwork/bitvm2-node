pub mod action;
pub mod env;
pub mod metrics_service;
pub mod middleware;
pub mod p2p_msg_handler;

pub mod rpc_service;
mod scheduled_tasks;
pub mod utils;
pub use scheduled_tasks::{run_maintenance_tasks, run_watch_event_task};
mod error;

mod vk;

mod dbg {
    #![allow(unused)]
    use std::str::FromStr;

    use bitcoin::{Address, Amount, Network, Witness};
    use bitvm2_lib::actors::Actor;
    use bitvm2_lib::committee::*;
    use bitvm2_lib::operator::*;
    use bitvm2_lib::types::*;
    use bitvm2_lib::keys::*;
    use goat::connectors::connector_e::ConnectorE;
    use goat::connectors::kickoff_connectors::*;
    use goat::contexts::base::generate_n_of_n_public_key;
    use goat::scripts::p2a_script;
    use goat::transactions::base::Input;
    use goat::transactions::prekickoff::PrekickoffTransaction;
    use goat::disprove_scripts::hash160;
    use serde::Deserialize;
    use serde::Serialize;
    use uuid::Uuid;
    use crate::utils::*;
    use crate::action::*;
    use secp256k1::{rand, Secp256k1, SecretKey, Keypair};
    use zkm_sdk::ZKM_CIRCUIT_VERSION;

    fn dbg_network() -> Network {
        Network::Testnet4
    }
    fn dbg_keypair() -> Keypair {
        let secp = Secp256k1::new();
        Keypair::new(&secp, &mut rand::thread_rng())
    }
    fn dbg_input() -> Input {
        Input {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str("b2b18acfdd358369d9a1e8370cfd9eb4ee123507a0321ad608de500cc54740d8").unwrap(),
                vout: 0,
            },
            amount: Amount::from_sat(500000000),
        }
    }
    fn dbg_address() -> Address {
        node_p2wsh_address(dbg_network(), &dbg_keypair().public_key().into())
    }
    fn build_dbg_instance_parameters() -> Bitvm2InstanceParameters {
        let user_info = UserInfo {
            depositor_evm_address: [1u8; 20],
            txn_fees: [1000u64; 3],
            inputs: vec![dbg_input()],
            user_xonly_pubkey: dbg_keypair().public_key().x_only_public_key().0,
            user_change_address: dbg_address(),
            user_refund_address: dbg_address(),
        };
        let committee_pubkeys = vec![
            dbg_keypair().public_key().into(),
            dbg_keypair().public_key().into(),
        ];
        let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
        Bitvm2InstanceParameters {
            network: dbg_network(),
            instance_id: Uuid::new_v4(),
            user_info,
            pegin_amount: Amount::from_sat(1000000),
            committee_pubkeys,
            committee_agg_pubkey,
        }
    }
    fn build_dbg_prekickoff_parameters() -> PrekickoffParameters {
        let xonly_pubkey = dbg_keypair().public_key().x_only_public_key().0;
        let force_skip_connector = ForceSkipConnector::new(dbg_network(), &xonly_pubkey);
        let kickoff_connector = KickoffConnector::new(dbg_network(), &xonly_pubkey);
        let prekickoff_connector = PrekickoffConnector::new(dbg_network(), &xonly_pubkey);
        let cur_prekickoff_txn = PrekickoffTransaction::new_for_validation(
            &prekickoff_connector,
            &force_skip_connector,
            &kickoff_connector,
            &prekickoff_connector,
            dbg_input(),
            vec![],
            vec![],
            1000,
            2,
            50,
        )
        .unwrap();
        PrekickoffParameters {
            cur_prekickoff_txn,
            replenish_fee_inputs: vec![],
            replenish_fee_prev_outs: vec![],
            fee_amount: 1000,
        }
    }
    fn build_dbg_graph_parameters() -> Bitvm2GraphParameters {
        let graph_id = Uuid::new_v4();
        let instance_parameters = build_dbg_instance_parameters();
        let prekickoff_parameters = build_dbg_prekickoff_parameters();
        let operator_master_key = OperatorMasterKey::new(dbg_keypair());
        let operator_master_keypair = operator_master_key.master_keypair();
        let operator_pubkey = operator_master_keypair.public_key().into();
        let operator_wots_pubkeys = operator_master_key.wots_keypair_for_graph(graph_id).1;
        let watchtower_pubkeys = vec![
            dbg_keypair().public_key().x_only_public_key().0,
            dbg_keypair().public_key().x_only_public_key().0,
        ];
        let mut hashlocks = vec![];
        for index in 0..watchtower_pubkeys.len() {
            let preimage = b"preimage".to_vec();
            let hashlock = hash160(&preimage);
            hashlocks.push(hashlock);
        }
        let instance_id = instance_parameters.instance_id;
        Bitvm2GraphParameters {
            instance_parameters,
            prekickoff_parameters,
            graph_id,
            graph_nonce: 1,
            challenge_amount: todo_funcs::challenge_amount(),
            operator_pubkey,
            operator_wots_pubkeys,
            operator_receive_address: dbg_address(),
            watchtower_pubkeys,
            hashlocks,
            guest_constant_value: [3u8; 32],
            zkm_version: ZKM_CIRCUIT_VERSION.to_string(),
        }
    }
    fn build_dbg_simplified_graph() -> SimplifiedBitvm2Graph {
        let disprove_scripts = vec![p2a_script()];
        let graph = generate_bitvm_graph(build_dbg_graph_parameters(), disprove_scripts).unwrap();
        graph.to_simplified().unwrap()
    }

    #[test]
    fn dbg_serde() {
        let graph: SimplifiedBitvm2Graph = build_dbg_simplified_graph();
        // let graph_ser = serde_json::to_vec(&graph).unwrap();
        // let _graph_de: SimplifiedBitvm2Graph = serde_json::from_slice(&graph_ser).unwrap();
        // let graph_ser = serde_cbor::to_vec(&graph).unwrap();
        // let _graph_de: SimplifiedBitvm2Graph = serde_cbor::from_slice(&graph_ser).unwrap();
        // let dbg_path = "/home/ubuntu/bitvm2-noded-test/operator_0/bitvm2-node.db";
        // let instance_id = uuid::Uuid::parse_str("c41d4b7c967f4e4d975853723571bd7f").unwrap();
        // let graph_id = uuid::Uuid::parse_str("c35914b88d7f4670a75aa7d91b855439").unwrap();
        // let local_db = store::create_local_db(dbg_path).await;
        // let graph = get_graph(&local_db, instance_id, graph_id).await.unwrap().unwrap();
        let message_content = GOATMessageContent::CreateGraph(CreateGraph {
            instance_id: graph.parameters.instance_parameters.instance_id,
            graph_id: graph.parameters.graph_id,
            graph_nonce: graph.parameters.graph_nonce,
            graph,
        });
        let msg = GOATMessage::new(Actor::All, message_content);
        let msg_se = msg.serialize_message().unwrap();
        let _msg_de = GOATMessage::deserialize_message(&msg_se).unwrap();
    }
}
