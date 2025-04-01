use bitcoin::{Amount, XOnlyPublicKey, OutPoint};
use bitvm::treepp::*;
use bitvm::chunk::api::{
    api_generate_partial_script, api_generate_full_tapscripts,
    generate_signatures_lit,
    NUM_PUBS, NUM_HASH, NUM_U256
};
use bitvm::signatures::{
    wots_api::{wots256, wots_hash},
    signing_winternitz::{
        WinternitzPublicKey, WinternitzSecret, LOG_D,
    },
    winternitz::Parameters, 
};
use goat::commitments::{NUM_KICKOFF, KICKOFF_MSG_SIZE, CommitmentMessageId};
use sha2::{Sha256, Digest};
use crate::types::{
    Bitvm2Graph, CustomInputs, Groth16Proof, Groth16WotsPublicKeys, Groth16WotsSignatures, Bitvm2Parameters, PublicInputs, VerifyingKey, WotsPublicKeys, WotsSecretKeys, Error
};
use goat::transactions::{
    base::Input,
    pre_signed::PreSignedTransaction,
    peg_in::peg_in::PegInTransaction,
    peg_out_confirm::PreKickoffTransaction,
    kick_off::KickOffTransaction,
    take_1::Take1Transaction,
    challenge::ChallengeTransaction,
    assert::assert_initial::AssertInitialTransaction,
    assert::assert_commit::AssertCommitTransactionSet,
    assert::assert_final::AssertFinalTransaction,
    assert::utils::{AllCommitConnectorsE, AssertCommitConnectorsF, convert_to_connector_c_commits_public_key, COMMIT_TX_NUM},
    take_2::Take2Transaction,
    disprove::DisproveTransaction,
};
use goat::connectors::{
    connector_0::Connector0,
    connector_3::Connector3,
    connector_4::Connector4,
    connector_5::Connector5,
    connector_6::Connector6,
    connector_a::ConnectorA,
    connector_b::ConnectorB,
    connector_c::ConnectorC,
    connector_d::ConnectorD,
};

pub fn generate_wots_keys(seed: &str) -> (WotsSecretKeys, WotsPublicKeys) {
    let secrets = wots_seed_to_secrets(seed);
    let pubkeys = wots_secrets_to_pubkeys(&secrets);
    (secrets, pubkeys)
}

pub fn wots_secrets_to_pubkeys(secrets: &WotsSecretKeys) -> WotsPublicKeys {
    let mut pubins = vec![];
    for i in 0..NUM_PUBS {
        pubins.push(wots256::generate_public_key(&secrets.1[i]));
    }
    let mut fq_arr = vec![];
    for i in 0..NUM_U256 {
        let p256 = wots256::generate_public_key(&secrets.1[i+NUM_PUBS]);
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..NUM_HASH {
        let p160 = wots_hash::generate_public_key(&secrets.1[i+NUM_PUBS+NUM_U256]);
        h_arr.push(p160);
    }
    let g16_wotspubkey: Groth16WotsPublicKeys = (
        pubins.try_into().unwrap(),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );

    let mut kickoff_wotspubkey = vec![];
    for i in 0..NUM_KICKOFF {
        kickoff_wotspubkey.push(WinternitzPublicKey::from(&secrets.0[i]));
    }

    (
        kickoff_wotspubkey.try_into().unwrap_or_else(|_e| panic!("kickoff bitcom key number not match")), 
        g16_wotspubkey,
    )
}

pub fn wots_seed_to_secrets(seed: &str) -> WotsSecretKeys {
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
    let g16_wotsseckey = (0..NUM_PUBS+NUM_U256+NUM_HASH)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 1);
            let sec_i = sha256_with_id(&sec_i, idx);
            format!("{sec_i}{:04x}{:04x}", 1, idx)
        })
        .collect::<Vec<String>>()
        .try_into().unwrap();
    
    let kickoff_wotsseckey = (0..NUM_KICKOFF)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 0);
            let sec_i = sha256_with_id(&sec_i, idx);
            let sec_str = format!("{sec_i}{:04x}{:04x}", 0, idx);
            let parameters = Parameters::new_by_bit_length(KICKOFF_MSG_SIZE[idx] as u32 * 8, LOG_D);
            WinternitzSecret::from_string(&sec_str, &parameters)
        })
        .collect::<Vec<WinternitzSecret>>()
        .try_into().unwrap_or_else(|_e| panic!("kickoff bitcom key number not match"));
    (kickoff_wotsseckey, g16_wotsseckey)
}

pub fn generate_partial_scripts(ark_vkey: &VerifyingKey) -> Vec<Script> {
    api_generate_partial_script(ark_vkey)
}

pub fn generate_disprove_scripts(partial_scripts: &Vec<Script>, wots_pubkeys: &WotsPublicKeys) -> Vec<Script> {
    api_generate_full_tapscripts(wots_pubkeys.1, partial_scripts)
} 

pub fn sign_proof(ark_vkey: &VerifyingKey, ark_proof: Groth16Proof, ark_pubin: PublicInputs, wots_sec: &WotsSecretKeys) -> Groth16WotsSignatures {
    generate_signatures_lit(ark_proof, ark_pubin, &ark_vkey, wots_sec.1.to_vec()).unwrap()
}

pub fn generate_bitvm_graph(
    user_inputs: CustomInputs,
    operator_inputs: CustomInputs,
    params: Bitvm2Parameters,
    disprove_scripts_bytes: Vec<Vec<u8>>,
) -> Result<Bitvm2Graph, Error> {
    fn inputs_check(inputs: &CustomInputs) -> Option<Error> {
        let inputs_amount_sum: Amount = inputs.inputs.iter()
            .map(|input| input.amount)
            .sum();
        if inputs_amount_sum < inputs.fee_amount + inputs.input_amount {
            Some("insufficient inputs amount".to_string())
        } else {
            None
        }
    }

    // check inputs amount
    if let Some(err) = inputs_check(&user_inputs) {
        return Err(format!("user's inputs did not pass the check: {}", err))
    }
    if params.pegin_amount != user_inputs.input_amount {
        return Err("user_inputs_amount and pegin_amount mismatch".to_string())
    };
    if let Some(err) = inputs_check(&operator_inputs) {
        return Err(format!("operator's inputs did not pass the check: {}", err))
    }
    if params.stake_amount != operator_inputs.input_amount {
        return Err("operator_inputs_amount and stake_amount mismatch ".to_string())
    };

    // Pegin
    let network = params.network;
    let federation_taproot_pubkey = params.federation_taproot_pubkey;
    let connector_0 = Connector0::new(
        network,
        &federation_taproot_pubkey,
    );
    let pegin = PegInTransaction::new_for_validation(
        &connector_0, 
        user_inputs.inputs, 
        user_inputs.input_amount, 
        user_inputs.fee_amount, 
        user_inputs.change_address, 
        params.depositor_evm_address.to_vec(),
    );
    let pegin_txid = pegin.tx().compute_txid();

    // Pre-Kickoff
    let operator_pubkey = params.operator_pubkey;
    let operator_taproot_pubkey = XOnlyPublicKey::from(operator_pubkey);
    let kickoff_wots_commitment_keys = CommitmentMessageId::pubkey_map_for_kickoff(&params.operator_wots_pubkeys.0);
    let connector_6 = Connector6::new(
        network, 
        &operator_taproot_pubkey, 
        &kickoff_wots_commitment_keys,
    );
    let pre_kickoff = PreKickoffTransaction::new_unsigned(
        &connector_6, 
        operator_inputs.inputs,
        operator_inputs.input_amount,
        operator_inputs.fee_amount,
        operator_inputs.change_address,
    );
    let pre_kickoff_txid = pre_kickoff.tx().compute_txid();


    // Kickoff
    let connector_3 = Connector3::new(
        network,
        &operator_pubkey,
    );
    let connector_a = ConnectorA::new(
        network,
        &operator_taproot_pubkey,
        &federation_taproot_pubkey,
    );
    let connector_b = ConnectorB::new(
        network,
        &operator_taproot_pubkey,
    );
    let kickoff_input_0_vout: usize = 0;
    let kickoff_input_0 = Input {
        outpoint: OutPoint {
            txid: pre_kickoff_txid,
            vout: kickoff_input_0_vout as u32,
        },
        amount: pre_kickoff.tx().output[kickoff_input_0_vout].value,
    };
    let kickoff = KickOffTransaction::new_for_validation(
        &connector_3,
        &connector_6,
        &connector_a,
        &connector_b,
        kickoff_input_0,
    );
    let kickoff_txid = kickoff.tx().compute_txid();

    // take-1
    let take1_input_0_vout: usize = 0;
    let take1_input_0 = Input {
        outpoint: OutPoint {
            txid: pegin_txid,
            vout: take1_input_0_vout as u32,
        },
        amount: pegin.tx().output[take1_input_0_vout].value,
    };
    let take1_input_1_vout: usize = 1;
    let take1_input_1 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: take1_input_1_vout as u32,
        },
        amount: kickoff.tx().output[take1_input_1_vout].value,
    };
    let take1_input_2_vout: usize = 0;
    let take1_input_2 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: take1_input_2_vout as u32,
        },
        amount: kickoff.tx().output[take1_input_2_vout].value,
    };
    let take1 = Take1Transaction::new_for_validation(
        network,
        &operator_pubkey,
        &connector_0,
        &connector_3,
        &connector_a,
        take1_input_0,
        take1_input_1,
        take1_input_2,
    );

    // challenge
    let challenge_input_0_vout: usize = 1;
    let challenge_input_0 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: challenge_input_0_vout as u32,
        },
        amount: kickoff.tx().output[challenge_input_0_vout].value,
    };
    let challenge = ChallengeTransaction::new_for_validation(
        network, 
        &operator_pubkey, 
        &connector_a, 
        challenge_input_0, 
        params.challenge_amount,
    );

    // assert-initial
    let assert_wots_pubkeys = &params.operator_wots_pubkeys.1;
    let connector_d = ConnectorD::new(
        network,
        &federation_taproot_pubkey,
    );
    let all_assert_commit_connectors_e = AllCommitConnectorsE::new(
        network,
        &operator_pubkey,
        &assert_wots_pubkeys,
    );
    let assert_init_input_0_vout: usize = 2;
    let assert_init_input_0 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: assert_init_input_0_vout as u32,
        },
        amount: kickoff.tx().output[assert_init_input_0_vout].value,
    };
    let assert_init = AssertInitialTransaction::new_for_validation(
        &connector_b, 
        &connector_d, 
        &all_assert_commit_connectors_e, 
        assert_init_input_0,
    );
    let assert_init_txid = assert_init.tx().compute_txid();

    // assert-commit 
    let connectors_f = AssertCommitConnectorsF::new(
        network,
        &operator_pubkey,
    );
    let vout_base: usize = 1;
    let assert_commit_inputs = (0..all_assert_commit_connectors_e.connectors_num())
        .map(|idx| Input {
            outpoint: OutPoint {
                txid: assert_init_txid,
                vout: (idx + vout_base) as u32,
            },
            amount: assert_init.tx().output[idx + vout_base].value,
        })
        .collect();
    let assert_commit = AssertCommitTransactionSet::new(
        &all_assert_commit_connectors_e, 
        &connectors_f, 
        assert_commit_inputs,
    );

    // assert-final
    let assert_wots_commitment_keys = convert_to_connector_c_commits_public_key(assert_wots_pubkeys);
    let connector_4 = Connector4::new(
        network,
        &operator_pubkey,
    );
    let connector_5 = Connector5::new(
        network,
        &federation_taproot_pubkey,
    );
    let connector_c = ConnectorC::new_from_scripts(
        network,
        &operator_taproot_pubkey,
        assert_wots_commitment_keys,
        disprove_scripts_bytes,
    );
    let assert_final_input_0_vout: usize = 0;
    let assert_final_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_init_txid,
            vout: assert_final_input_0_vout as u32,
        },
        amount: assert_init.tx().output[assert_final_input_0_vout].value,
    };
    let assert_final_input_f_vout: usize = 0;
    let assert_final_inputs_f: [Input; COMMIT_TX_NUM] = (0..COMMIT_TX_NUM)
        .map(|i| {
            Input {
                outpoint: OutPoint {
                    txid: assert_commit.commit_txns[i].tx().compute_txid(),
                    vout: assert_final_input_f_vout as u32,
                },
                amount: assert_commit.commit_txns[i].tx().output[assert_final_input_f_vout].value,
            }
        }).collect::<Vec<Input>>().try_into().unwrap_or_else(|_e| panic!("impossible"));
    let assert_final = AssertFinalTransaction::new_for_validation(
        &connector_4, 
        &connector_5, 
        &connector_c, 
        &connector_d, 
        &connectors_f, 
        assert_final_input_0, 
        assert_final_inputs_f,
    );
    let assert_final_txid = assert_final.tx().compute_txid();

    // take-2
    let take2_input_0_vout: usize = 0;
    let take2_input_0 = Input {
        outpoint: OutPoint {
            txid: pegin_txid,
            vout: take2_input_0_vout as u32,
        },
        amount: pegin.tx().output[take2_input_0_vout].value,
    };
    let take2_input_1_vout: usize = 0;
    let take2_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: take2_input_1_vout as u32,
        },
        amount: assert_final.tx().output[take2_input_1_vout].value,
    };
    let take2_input_2_vout: usize = 1;
    let take2_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: take2_input_2_vout as u32,
        },
        amount: assert_final.tx().output[take2_input_2_vout].value,
    };
    let take2_input_3_vout: usize = 2;
    let take2_input_3 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: take2_input_3_vout as u32,
        },
        amount: assert_final.tx().output[take2_input_3_vout].value,
    };
    let take2 = Take2Transaction::new_for_validation(
        network, 
        &operator_pubkey, 
        &connector_0, 
        &connector_4, 
        &connector_5, 
        &connector_c, 
        take2_input_0, 
        take2_input_1, 
        take2_input_2, 
        take2_input_3,
    );

    // disprove
    let disprove_input_0_vout: usize = 1;
    let disprove_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: disprove_input_0_vout as u32,
        },
        amount: assert_final.tx().output[disprove_input_0_vout].value,
    };
    let disprove_input_1_vout: usize = 2;
    let disprove_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: disprove_input_1_vout as u32,
        },
        amount: assert_final.tx().output[disprove_input_1_vout].value,
    };
    let disprove = DisproveTransaction::new_for_validation(
        network, 
        &connector_5, 
        &connector_c, 
        disprove_input_0, 
        disprove_input_1,
    );

    Ok(Bitvm2Graph {
        operator_pre_signed: false,
        federation_pre_signed: false,
        parameters: params,
        pegin,
        pre_kickoff,
        kickoff,
        take1,
        challenge,
        assert_init,
        assert_commit,
        assert_final,
        take2,
        disprove,
    })
}

