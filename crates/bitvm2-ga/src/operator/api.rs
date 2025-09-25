use std::vec;

use crate::types::{
    Bitvm2Graph, Bitvm2GraphParameters, Groth16Proof, OperatorWotsPublicKeys,
    OperatorWotsSecretKeys, OperatorWotsSignatures, PublicInputs, VerifyingKey,
};
use anyhow::{Result, bail};
use bitcoin::{Address, Amount, Network, PublicKey, ScriptBuf, Transaction, TxIn};
use bitcoin::{OutPoint, Witness, XOnlyPublicKey, key::Keypair};
use bitvm::chunk::api::{
    NUM_HASH, NUM_PUBS, NUM_U256, PublicKeys as Groth16WotsPublicKeys,
    api_generate_full_tapscripts, api_generate_partial_script, generate_assertions,
};
use bitvm::signatures::{HASH_LEN, WinternitzSecret, Wots, Wots16, Wots32};
use goat::connectors::assert_connectors::generate_chunked_assert_commit_connectors;
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_a::ConnectorA;
use goat::connectors::connector_b::ConnectorB;
use goat::connectors::connector_c::ConnectorC;
use goat::connectors::connector_d::ConnectorD;
use goat::connectors::connector_e::ConnectorE;
use goat::connectors::connector_f::ConnectorF;
use goat::connectors::connector_g::ConnectorG;
use goat::connectors::kickoff_connectors::{
    ForceSkipConnector, GuardianConnector, KickoffConnector, PrekickoffConnector,
};
use goat::connectors::watchtower_connectors::{
    AckConnector, WatchctowerConnectors, WatchtowerChallengeConnector,
};
use goat::constants::{
    CONNECTOR_A_TIMELOCK, CONNECTOR_D_TIMELOCK, CONNECTOR_F_TIMELOCK, WATCHTOWER_CHALLENGE_TIMELOCK,
};
use goat::disprove_scripts::{
    ChallengeHashType, NUM_GUEST, NUM_GUEST_PUBS_ASSERT, NUM_GUEST_PUBS_EXTRA, hash160,
    verify_guest_pubin,
};
use goat::transactions::assert::{
    AssertCommitTimeoutTransaction, AssertInitTransaction, operator_commit_proof,
};
use goat::transactions::base::{DUST_AMOUNT, Input};
use goat::transactions::challenge::ChallengeTransaction;
use goat::transactions::kickoff::KickoffTransaction;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::{
    ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction, PrekickoffTransaction,
    QuickChallengeTransaction, operator_skip_kickoff,
};
use goat::transactions::take1::Take1Transaction;
use goat::transactions::take2::Take2Transaction;
use goat::transactions::watchtower_challenge::{
    BlockhashCommitTimeoutTransaction, NackTransaction, WatchtowerChallengeInitTransaction,
    WatchtowerChallengeTimeoutTransaction, operator_ack, operator_commit_blockhash,
};
use goat::utils::num_blocks_per_network;
use sha2::{Digest, Sha256};

pub fn generate_wots_keys(seed: &str) -> (OperatorWotsSecretKeys, OperatorWotsPublicKeys) {
    let secrets = wots_seed_to_secrets(seed);
    let pubkeys = wots_secrets_to_pubkeys(&secrets);
    (secrets, pubkeys)
}

pub fn operator_presig_num() -> usize {
    6
}

#[allow(deprecated)]
pub fn wots_secrets_to_pubkeys(secrets: &OperatorWotsSecretKeys) -> OperatorWotsPublicKeys {
    let mut index = 0;

    let mut guest_extra = vec![];
    for _ in 0..NUM_GUEST_PUBS_EXTRA {
        guest_extra.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }

    let mut guest_assert = vec![];
    for _ in 0..NUM_GUEST_PUBS_ASSERT {
        guest_assert.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }

    let mut pubins = vec![];
    for _ in 0..NUM_PUBS {
        pubins.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }
    let mut fq_arr = vec![];
    for _ in 0..NUM_U256 {
        fq_arr.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }
    let mut h_arr = vec![];
    for _ in 0..NUM_HASH {
        h_arr.push(Wots16::generate_public_key(&secrets[index]));
        index += 1;
    }

    let g16_wotspubkey: Groth16WotsPublicKeys =
        (pubins.try_into().unwrap(), fq_arr.try_into().unwrap(), h_arr.try_into().unwrap());
    (guest_extra.try_into().unwrap(), guest_assert.try_into().unwrap(), Box::new(g16_wotspubkey))
}

#[allow(deprecated)]
pub fn wots_seed_to_secrets(seed: &str) -> OperatorWotsSecretKeys {
    fn sha256(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
    fn sha256_with_id(input: &str, idx: usize) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        sha256(&format!("{:x}{:04x}", hasher.finalize(), idx))
    }

    let seed_hash = sha256(seed);
    let wot32_seckeys = (0..NUM_GUEST + NUM_PUBS + NUM_U256)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 1);
            let sec_i = sha256_with_id(&sec_i, idx);
            let sec_str = format!("{sec_i}{:04x}{:04x}", 1, idx);
            Wots32::secret_from_str(&sec_str)
        })
        .collect::<Vec<WinternitzSecret>>();
    let wot16_seckeys = (0..NUM_HASH)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 2);
            let sec_i = sha256_with_id(&sec_i, idx);
            let sec_str = format!("{sec_i}{:04x}{:04x}", 0, idx);
            Wots16::secret_from_str(&sec_str)
        })
        .collect::<Vec<WinternitzSecret>>();

    Box::new([wot32_seckeys, wot16_seckeys].concat().try_into().unwrap())
}

pub fn generate_partial_scripts(ark_vkey: &VerifyingKey) -> Vec<ScriptBuf> {
    api_generate_partial_script(ark_vkey)
}

pub fn generate_disprove_scripts(
    partial_scripts: &[ScriptBuf],
    wots_pubkeys: OperatorWotsPublicKeys,
    guest_constant_value: &[u8; 32],
    watchtower_hashlocks: &Vec<ChallengeHashType>,
) -> (Vec<ScriptBuf>, Vec<ScriptBuf>) {
    let (guest_pubkeys_0, guest_pubkeys_1, proof_pubkeys) = wots_pubkeys;
    let mut guest_pubin_wots_pubkeys = guest_pubkeys_0.to_vec();
    guest_pubin_wots_pubkeys.extend(guest_pubkeys_1);
    let guest_pubin_wots_pubkeys = guest_pubin_wots_pubkeys.try_into().unwrap();
    let guest_pubin_scripts = verify_guest_pubin(
        &guest_pubin_wots_pubkeys,
        &proof_pubkeys.0,
        guest_constant_value,
        watchtower_hashlocks,
    );
    let guest_pubin_scripts = guest_pubin_scripts.into_iter().map(|s| s.compile()).collect();
    let proof_scripts = api_generate_full_tapscripts(*proof_pubkeys, partial_scripts);
    (guest_pubin_scripts, proof_scripts)
}

#[allow(deprecated)]
pub fn corrupt_proof(
    sigs: &mut OperatorWotsSignatures,
    wots_sec: &OperatorWotsSecretKeys,
    index: usize,
) {
    let mut scramble: [u8; 32] = [1u8; 32];
    scramble[16] = 37;
    let mut scramble2: [u8; HASH_LEN] = [1u8; HASH_LEN];
    scramble2[HASH_LEN / 2] = 37;
    println!("corrupted assertion at index {index}");
    if index < NUM_PUBS {
        let i = index;
        let assn = scramble;
        let sig = Wots32::sign(&wots_sec[index], &assn);
        sigs.1.0[i] = sig;
    } else if index < NUM_PUBS + NUM_U256 {
        let i = index - NUM_PUBS;
        let assn = scramble;
        let sig = Wots32::sign(&wots_sec[index], &assn);
        sigs.1.1[i] = sig;
    } else if index < NUM_PUBS + NUM_U256 + NUM_HASH {
        let i = index - NUM_PUBS - NUM_U256;
        let assn = scramble2;
        let sig = Wots16::sign(&wots_sec[index], &assn);
        sigs.1.2[i] = sig;
    }
}

pub fn generate_bitvm_graph(
    params: Bitvm2GraphParameters,
    disprove_scripts: Vec<ScriptBuf>,
) -> Result<Bitvm2Graph> {
    let network = params.instance_parameters.network;
    let operator_pubkey = params.operator_pubkey;
    let operator_taproot_public_key = XOnlyPublicKey::from(operator_pubkey);
    let (connector_e, _) =
        ConnectorE::new_with_scripts(network, &operator_taproot_public_key, disprove_scripts);
    generate_bitvm_graph_inner(params, connector_e)
}

pub(crate) fn generate_bitvm_graph_inner(
    params: Bitvm2GraphParameters,
    connector_e: ConnectorE,
) -> Result<Bitvm2Graph> {
    // TODO: check parameters?
    let network = params.instance_parameters.network;
    let operator_pubkey = params.operator_pubkey;
    let operator_taproot_public_key = XOnlyPublicKey::from(operator_pubkey);
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(params.instance_parameters.committee_agg_pubkey);
    let watchtower_num = params.watchtower_pubkeys.len();
    let assert_wots_pubkeys =
        (params.operator_wots_pubkeys.1.clone(), *params.operator_wots_pubkeys.2);
    let assert_commit_connectors = generate_chunked_assert_commit_connectors(
        network,
        &n_of_n_taproot_public_key,
        assert_wots_pubkeys,
    );
    let assert_commit_num = assert_commit_connectors.len();

    // pegin
    let (_, pegin, _) = params.instance_parameters.build_pegin_tx()?;
    let pegin_txid = pegin.tx().compute_txid();
    let connector_0_input = Input {
        outpoint: OutPoint { txid: pegin_txid, vout: 0 },
        amount: pegin.tx().output[0].value,
    };

    // prekickoff
    let cur_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    let next_kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let cur_prekickoff = params.prekickoff_parameters.cur_prekickoff_txn.clone();
    let cur_prekickoff_txid = cur_prekickoff.tx().compute_txid();
    let cur_prekickoff_connector_input = Input {
        outpoint: OutPoint { txid: cur_prekickoff_txid, vout: 2 },
        amount: cur_prekickoff.tx().output[2].value,
    };
    let next_prekickoff = PrekickoffTransaction::new_for_validation(
        &cur_prekickoff_connector,
        &next_force_skip_connector,
        &next_kickoff_connector,
        &next_prekickoff_connector,
        cur_prekickoff_connector_input,
        params.prekickoff_parameters.replenish_fee_inputs.clone(),
        params.prekickoff_parameters.replenish_fee_prev_outs.clone(),
        params.prekickoff_parameters.fee_amount,
        watchtower_num,
        assert_commit_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {}", e))?;
    let next_prekickoff_txid = next_prekickoff.tx().compute_txid();
    let next_force_skip_connector_input = Input {
        outpoint: OutPoint { txid: next_prekickoff_txid, vout: 0 },
        amount: cur_prekickoff.tx().output[0].value,
    };
    let next_prekickoff_connector_input = Input {
        outpoint: OutPoint { txid: next_prekickoff_txid, vout: 2 },
        amount: cur_prekickoff.tx().output[2].value,
    };

    // kickoff
    let kickoff_connector_input = Input {
        outpoint: OutPoint { txid: cur_prekickoff_txid, vout: 1 },
        amount: cur_prekickoff.tx().output[1].value,
    };
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let connector_a =
        ConnectorA::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_b = ConnectorB::new(network, &operator_taproot_public_key);
    let connector_c = ConnectorC::new(network, &operator_taproot_public_key);
    let guardian_connector = GuardianConnector::new(network, &operator_taproot_public_key);
    let kickoff = KickoffTransaction::new_for_validation(
        &kickoff_connector,
        &connector_a,
        &connector_b,
        &connector_c,
        &connector_e,
        &guardian_connector,
        &kickoff_connector_input,
        watchtower_num,
        assert_commit_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create kickoff txn: {}", e))?;
    let kickoff_txid = kickoff.tx().compute_txid();
    let connector_a_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 0 },
        amount: kickoff.tx().output[0].value,
    };
    let connector_b_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 1 },
        amount: kickoff.tx().output[1].value,
    };
    let connector_c_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 2 },
        amount: kickoff.tx().output[2].value,
    };
    let connector_e_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 3 },
        amount: kickoff.tx().output[3].value,
    };
    let guardian_connector_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 4 },
        amount: kickoff.tx().output[4].value,
    };

    // prekickoff challenge
    let force_skip_kickoff = ForceSkipKickoffTransaction::new_for_validation(
        &kickoff_connector,
        &next_force_skip_connector,
        kickoff_connector_input,
        next_force_skip_connector_input.clone(),
    );
    let quick_challenge = QuickChallengeTransaction::new_for_validation(
        &guardian_connector,
        &next_force_skip_connector,
        guardian_connector_input.clone(),
        next_force_skip_connector_input,
    );
    let challenge_incomplete_kickoff = ChallengeIncompleteKickoffTransaction::new_for_validation(
        &guardian_connector,
        &next_prekickoff_connector,
        guardian_connector_input.clone(),
        next_prekickoff_connector_input,
    );

    // take-1
    let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
    let take1 = Take1Transaction::new_for_validation(
        &connector_0,
        &connector_a,
        &connector_b,
        &connector_c,
        &guardian_connector,
        connector_0_input.clone(),
        connector_a_input.clone(),
        connector_b_input.clone(),
        connector_c_input.clone(),
        guardian_connector_input.clone(),
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-1 txn: {}", e))?;

    // challenge
    let challenge = ChallengeTransaction::new_for_validation(
        &connector_a,
        connector_a_input,
        params.challenge_amount,
        &params.operator_receive_address,
    );

    // watchtower-challenge-init
    let connector_g = ConnectorG::new(
        network,
        &n_of_n_taproot_public_key,
        &operator_taproot_public_key,
        &params.operator_wots_pubkeys.0[0],
    );
    let connector_f =
        ConnectorF::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let watchtower_connectors_array = (0..watchtower_num)
        .map(|i| {
            (
                WatchtowerChallengeConnector::new(
                    network,
                    &operator_taproot_public_key,
                    &XOnlyPublicKey::from(params.watchtower_pubkeys[i]),
                ),
                AckConnector::new(network, &n_of_n_taproot_public_key, &params.hashlocks[i]),
            )
        })
        .collect::<Vec<WatchctowerConnectors>>();
    let watchtower_challenge_init = WatchtowerChallengeInitTransaction::new_for_validation(
        &connector_b,
        &connector_g,
        &connector_f,
        &watchtower_connectors_array,
        connector_b_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create watchtower-challenge-init txn: {}", e))?;
    let watchtower_challenge_init_txid = watchtower_challenge_init.tx().compute_txid();
    let connector_g_vout = watchtower_num * 2;
    let connector_g_input = Input {
        outpoint: OutPoint { txid: watchtower_challenge_init_txid, vout: connector_g_vout as u32 },
        amount: watchtower_challenge_init.tx().output[connector_g_vout].value,
    };
    let connector_f_vout = connector_g_vout + 1;
    let connector_f_input = Input {
        outpoint: OutPoint { txid: watchtower_challenge_init_txid, vout: connector_f_vout as u32 },
        amount: watchtower_challenge_init.tx().output[connector_f_vout].value,
    };

    // watchtower-challenge-timeout & nack
    let mut watchtower_challenge_timeout_txns = vec![];
    let mut nack_txns = vec![];
    for (i, watchtower_connectors) in watchtower_connectors_array.iter().enumerate() {
        let watchtower_challenge_connector_input_vout: usize = i * 2;
        let watchtower_challenge_connector_input = Input {
            outpoint: OutPoint {
                txid: watchtower_challenge_init_txid,
                vout: watchtower_challenge_connector_input_vout as u32,
            },
            amount: watchtower_challenge_init.tx().output
                [watchtower_challenge_connector_input_vout]
                .value,
        };
        let ack_connector_input_vout: usize = i * 2 + 1;
        let ack_connector_input = Input {
            outpoint: OutPoint {
                txid: watchtower_challenge_init_txid,
                vout: ack_connector_input_vout as u32,
            },
            amount: watchtower_challenge_init.tx().output[ack_connector_input_vout].value,
        };
        let watchtower_challenge_timeout_tx =
            WatchtowerChallengeTimeoutTransaction::new_for_validation(
                watchtower_connectors,
                watchtower_challenge_connector_input,
                ack_connector_input.clone(),
            );
        let nack_tx = NackTransaction::new_for_validation(
            watchtower_connectors,
            &connector_f,
            ack_connector_input,
            connector_f_input.clone(),
        );
        watchtower_challenge_timeout_txns.push(watchtower_challenge_timeout_tx);
        nack_txns.push(nack_tx);
    }

    // operator-commit-blockhash-timeout
    let blockhash_commit_timeout = BlockhashCommitTimeoutTransaction::new_for_validation(
        &connector_g,
        &connector_f,
        connector_g_input.clone(),
        connector_f_input.clone(),
    );

    // assert-init
    let connector_d =
        ConnectorD::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let assert_init = AssertInitTransaction::new_for_validation(
        &connector_c,
        &connector_d,
        &assert_commit_connectors,
        &connector_c_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create assert-init txn: {}", e))?;
    let assert_init_txid = assert_init.tx().compute_txid();
    let connector_d_vout: usize = assert_commit_connectors.len();
    let connector_d_input = Input {
        outpoint: OutPoint { txid: assert_init_txid, vout: connector_d_vout as u32 },
        amount: assert_init.tx().output[connector_d_vout].value,
    };

    // assert-commit-timeout
    let mut assert_commit_timeout_txns = vec![];
    for (i, assert_commit_connector) in assert_commit_connectors.iter().enumerate() {
        let assert_commit_timeout_input_0_vout: usize = i;
        let assert_commit_timeout_input_0 = Input {
            outpoint: OutPoint {
                txid: assert_init_txid,
                vout: assert_commit_timeout_input_0_vout as u32,
            },
            amount: assert_init.tx().output[assert_commit_timeout_input_0_vout].value,
        };
        let assert_commit_timeout_tx = AssertCommitTimeoutTransaction::new_for_validation(
            assert_commit_connector,
            &connector_d,
            &assert_commit_timeout_input_0,
            &connector_d_input,
        );
        assert_commit_timeout_txns.push(assert_commit_timeout_tx);
    }

    // take-2
    let take2 = Take2Transaction::new_for_validation(
        &connector_0,
        &connector_d,
        &connector_e,
        &connector_f,
        &guardian_connector,
        connector_0_input,
        connector_d_input,
        connector_e_input,
        connector_f_input,
        guardian_connector_input,
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-2 txn: {}", e))?;

    Ok(Bitvm2Graph {
        operator_pre_signed: false,
        committee_pre_signed: false,
        parameters: params,

        cur_prekickoff,
        next_prekickoff,
        force_skip_kickoff,
        quick_challenge,
        challenge_incomplete_kickoff,

        pegin,
        kickoff,
        take1,
        challenge,
        take2,

        watchtower_challenge_init,
        watchtower_challenge_timeout_txns,
        nack_txns,
        blockhash_commit_timeout,

        assert_init,
        assert_commit_timeout_txns,

        connector_e,
    })
}

pub fn operator_pre_sign(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Vec<Witness>> {
    let keypair_pubkey = PublicKey::from(operator_keypair.public_key());
    if keypair_pubkey != graph.parameters.operator_pubkey {
        bail!("operator keypair does not match graph operator pubkey".to_string())
    };

    let mut wits = vec![];
    let context = graph.parameters.get_operator_context(operator_keypair)?;
    let network = context.network;
    let operator_taproot_public_key = context.operator_taproot_public_key;

    // presign force_skip_kickoff
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    graph.force_skip_kickoff.pre_sign_and_push(
        &context,
        &kickoff_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.force_skip_kickoff.tx().input[0].witness.clone());
    wits.push(graph.force_skip_kickoff.tx().input[1].witness.clone());

    // presign quick_challenge
    let guardian_connector = GuardianConnector::new(network, &operator_taproot_public_key);
    graph.quick_challenge.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.quick_challenge.tx().input[0].witness.clone());
    wits.push(graph.quick_challenge.tx().input[1].witness.clone());

    // presign challenge_incomplete_kickoff
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    graph.challenge_incomplete_kickoff.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_prekickoff_connector,
    );
    wits.push(graph.challenge_incomplete_kickoff.tx().input[0].witness.clone());
    wits.push(graph.challenge_incomplete_kickoff.tx().input[1].witness.clone());

    graph.operator_pre_signed = true;
    Ok(wits)
}

pub fn push_operator_pre_signature(
    graph: &mut Bitvm2Graph,
    signed_witness: &Vec<Witness>,
) -> Result<()> {
    if graph.operator_pre_signed {
        bail!("already pre-signed by operator".to_string())
    };
    if signed_witness.len() != operator_presig_num() {
        bail!("invalid number of pre-signatures".to_string())
    };

    graph.force_skip_kickoff.tx_mut().input[0].witness = signed_witness[0].clone();
    graph.force_skip_kickoff.tx_mut().input[1].witness = signed_witness[1].clone();
    graph.quick_challenge.tx_mut().input[0].witness = signed_witness[2].clone();
    graph.quick_challenge.tx_mut().input[1].witness = signed_witness[3].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[0].witness = signed_witness[4].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[1].witness = signed_witness[5].clone();

    graph.operator_pre_signed = true;
    Ok(())
}

/// remember to sign replensish inputs (if any) after this
pub fn operator_sign_prekickoff_input_0(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let cur_prekickoff_connector = PrekickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.next_prekickoff.sign_input_0(&operator_context, &cur_prekickoff_connector);
    Ok(graph.next_prekickoff.tx().clone())
}

pub fn operator_sign_skip_kickoff(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    operator_receive_address: Address,
    fee_rate: f64,
) -> Result<Option<Transaction>> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = KickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    let kickoff_connector_input = Input {
        outpoint: OutPoint { txid: graph.cur_prekickoff.tx().compute_txid(), vout: 1 },
        amount: graph.cur_prekickoff.tx().output[1].value,
    };
    // create a sample tx to estimate fee
    let sample_tx = operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input.clone(),
        Amount::ZERO,
        operator_receive_address.clone(),
    )
    .map_err(|e| anyhow::anyhow!("failed to create sample skip-kickoff txn: {}", e))?;

    let fee_amount =
        Amount::from_sat((sample_tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if fee_amount + Amount::from_sat(DUST_AMOUNT) >= kickoff_connector_input.amount {
        // if fee_amount > input_amount - dust_amount, skip-kickoff tx is meaningless
        return Ok(None);
    }
    match operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input,
        fee_amount,
        operator_receive_address,
    ) {
        Ok(tx) => Ok(Some(tx)),
        Err(e) => bail!("failed to create skip-kickoff txn: {}", e),
    }
}

pub fn operator_sign_kickoff(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = KickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.kickoff.sign_input_0(&operator_context, &kickoff_connector);
    Ok(graph.kickoff.tx().clone())
}

pub fn operator_sign_take1(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_a = ConnectorA::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b =
        ConnectorB::new(operator_context.network, &operator_context.operator_taproot_public_key);
    let connector_c =
        ConnectorC::new(operator_context.network, &operator_context.operator_taproot_public_key);
    let guardian_connector = GuardianConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.take1.sign_input_1(&operator_context, &connector_a);
    graph.take1.sign_input_2(&operator_context, &connector_b);
    graph.take1.sign_input_3(&operator_context, &connector_c);
    graph.take1.sign_input_4(&operator_context, &guardian_connector);
    Ok(graph.take1.tx().clone())
}

pub fn operator_sign_take2(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_d = ConnectorD::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_f = ConnectorF::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let guardian_connector = GuardianConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.take2.sign_input_1(&operator_context, &connector_d);
    graph.take2.sign_input_2(&operator_context, &graph.connector_e);
    graph.take2.sign_input_3(&operator_context, &connector_f);
    graph.take2.sign_input_4(&operator_context, &guardian_connector);
    Ok(graph.take2.tx().clone())
}

pub fn operator_sign_watchtower_challenge_init(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_b =
        ConnectorB::new(operator_context.network, &operator_context.operator_taproot_public_key);
    graph.watchtower_challenge_init.sign_input_0(&operator_context, &connector_b);
    Ok(graph.watchtower_challenge_init.tx().clone())
}

pub fn operator_sign_watchtower_challenge_timeout(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    watchtower_index: usize,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("invalid watchtower index {watchtower_index}".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let watchtower_challenge_connector = WatchtowerChallengeConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &XOnlyPublicKey::from(graph.parameters.watchtower_pubkeys[watchtower_index]),
    );
    let ack_connector = AckConnector::new(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &graph.parameters.hashlocks[watchtower_index],
    );
    let watchtower_connectors = (watchtower_challenge_connector, ack_connector);
    graph.watchtower_challenge_timeout_txns[watchtower_index]
        .sign_input_0(&operator_context, &watchtower_connectors);
    Ok(graph.watchtower_challenge_timeout_txns[watchtower_index].tx().clone())
}

pub fn operator_sign_ack(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    watchtower_index: usize,
    preimage: &Vec<u8>,
) -> Result<(TxIn, Amount)> {
    if hash160(preimage) != graph.parameters.hashlocks[watchtower_index] {
        bail!("invalid preimage for watchtower index {watchtower_index}".to_string())
    };
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("invalid watchtower index {watchtower_index}".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let watchtower_challenge_connector = WatchtowerChallengeConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &XOnlyPublicKey::from(graph.parameters.watchtower_pubkeys[watchtower_index]),
    );
    let ack_connector = AckConnector::new(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &graph.parameters.hashlocks[watchtower_index],
    );
    let watchtower_connectors = (watchtower_challenge_connector, ack_connector);
    let ack_vout = watchtower_index * 2 + 1;
    let ack_input = Input {
        outpoint: OutPoint {
            txid: graph.watchtower_challenge_init.tx().compute_txid(),
            vout: ack_vout as u32,
        },
        amount: graph.watchtower_challenge_init.tx().output[ack_vout].value,
    };
    match operator_ack(&watchtower_connectors, preimage, ack_input.clone()) {
        Ok(txin) => Ok((txin, ack_input.amount)),
        Err(e) => bail!("failed to sign ack for watchtower index {watchtower_index}: {}", e),
    }
}

pub fn operator_sign_blockhash_commit(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    latest_blockhash: &[u8; 32],
    wots_secret_key: &WinternitzSecret,
) -> Result<(TxIn, Amount)> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let blockhash_wots_pubkey = graph.parameters.operator_wots_pubkeys.0[0];
    if Wots32::generate_public_key(wots_secret_key) != blockhash_wots_pubkey {
        bail!("provided WOTS secret key does not match expected public key".to_string())
    };
    let connector_g = ConnectorG::new(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &operator_context.operator_taproot_public_key,
        &blockhash_wots_pubkey,
    );
    let connector_g_vout = graph.watchtower_challenge_init.tx().output.len() - 3;
    let connector_g_input = Input {
        outpoint: OutPoint {
            txid: graph.watchtower_challenge_init.tx().compute_txid(),
            vout: connector_g_vout as u32,
        },
        amount: graph.watchtower_challenge_init.tx().output[connector_g_vout].value,
    };
    match operator_commit_blockhash(
        &connector_g,
        latest_blockhash,
        wots_secret_key,
        connector_g_input.clone(),
    ) {
        Ok(txin) => Ok((txin, connector_g_input.amount)),
        Err(e) => bail!("failed to sign blockhash commit: {}", e),
    }
}

pub fn operator_sign_assert_init(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_c =
        ConnectorC::new(operator_context.network, &operator_context.operator_taproot_public_key);
    graph.assert_init.sign_input_0(&operator_context, &connector_c);
    Ok(graph.assert_init.tx().clone())
}

pub fn operator_sign_assert_commit(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    wots_secret_keys: &OperatorWotsSecretKeys,
    guest_inputs: [[u8; 32]; NUM_GUEST_PUBS_ASSERT],
    proof: Groth16Proof,
    groth16_pubin: PublicInputs,
    vk: &VerifyingKey,
) -> Result<Vec<(TxIn, Amount)>> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    if !is_valid_wots_secrets(wots_secret_keys, &graph.parameters.operator_wots_pubkeys) {
        bail!("provided WOTS secret keys do not match expected public keys".to_string())
    };
    let assert_wots_pubkeys = (
        graph.parameters.operator_wots_pubkeys.1.clone(),
        *graph.parameters.operator_wots_pubkeys.2,
    );
    let assert_commit_connectors = generate_chunked_assert_commit_connectors(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        assert_wots_pubkeys,
    );
    let mut assert_commit_inputs = vec![];
    for i in 0..assert_commit_connectors.len() {
        let vout = i;
        let input = Input {
            outpoint: OutPoint { txid: graph.assert_init.tx().compute_txid(), vout: vout as u32 },
            amount: graph.assert_init.tx().output[vout].value,
        };
        assert_commit_inputs.push(input);
    }
    let assert_assertions = (
        guest_inputs,
        generate_assertions(proof, groth16_pubin, vk)
            .map_err(|e| anyhow::anyhow!("failed to generate assertions: {}", e))?,
    );
    match operator_commit_proof(
        &assert_commit_connectors,
        &wots_secret_keys[1..].to_vec(),
        &assert_commit_inputs,
        &assert_assertions,
    ) {
        Ok(txins) => Ok(txins
            .into_iter()
            .enumerate()
            .map(|(i, txin)| (txin, assert_commit_inputs[i].amount))
            .collect::<Vec<(TxIn, Amount)>>()),
        Err(e) => bail!("failed to sign assert commit: {}", e),
    }
}

pub fn is_valid_wots_secrets(
    wots_seckeys: &OperatorWotsSecretKeys,
    expected_pubkeys: &OperatorWotsPublicKeys,
) -> bool {
    // let generated_pubkeys = wots_secrets_to_pubkeys(wots_seckeys);
    // &generated_pubkeys == expected_pubkeys

    // Compare each generated WOTS public key against the expected public keys
    // without allocating large temporaries. This keeps stack usage small.
    let (guest_extra_expected, guest_assert_expected, proof_pubkeys_box) = expected_pubkeys;
    let proof_pubkeys = proof_pubkeys_box.as_ref();

    let mut idx: usize = 0;

    // guest_extra (Wots32)
    for expected in guest_extra_expected.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // guest_assert (Wots32)
    for expected in guest_assert_expected.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // proof pubins (Wots32)
    for expected in proof_pubkeys.0.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // proof fq_arr (Wots32)
    for expected in proof_pubkeys.1.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // proof h_arr (Wots16)
    for expected in proof_pubkeys.2.iter() {
        let generated = Wots16::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    true
}

pub fn take1_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, CONNECTOR_A_TIMELOCK)
}

/// take2 has two timelocks, relative to (watchtower_challenge_init, assert_init)
pub fn take2_timelocks(network: Network) -> (u32, u32) {
    (
        num_blocks_per_network(network, CONNECTOR_D_TIMELOCK),
        num_blocks_per_network(network, CONNECTOR_F_TIMELOCK),
    )
}

pub fn watchtower_challenge_timeout_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, WATCHTOWER_CHALLENGE_TIMELOCK)
}
