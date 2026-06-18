use rayon::prelude::*;
use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use anyhow::{Result, bail};
use ark_bn254::{Bn254, Fq, Fr};
use ark_bn254::g1::G1Affine;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use garbled_snark_verifier::bag::S;
use goat::assert_scripts::{
    INPUT_WIRE_NUM, OperatorAssertPublicKey, OperatorAssertSecretKey, WireHash, label_hash,
};
use goat::wots::{Wots, Wots96};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soldering_host::BabeBundle;
pub use soldering_host::BabeBundleBuilder;
use verifiable_circuit_babe::babe::{ProverSetupState, WeKnownPi1SetupCt, babe_verifier_presign, GC_INPUT_WIRES, interleave_dummy_positions, build_challenge_assert_witness_raw, deinterleave_dummy_positions};
pub use verifiable_circuit_babe::cac::{CACSetupPackage, FinalizedInstanceData};
use verifiable_circuit_babe::cac::cac_finalize_indices;
use verifiable_circuit_babe::dre::N;
use verifiable_circuit_babe::gc::{SparseAdaptorTable, SGC_PART1_CONSTANT_SIZE};
use verifiable_circuit_babe::instance::CACInstance;
use verifiable_circuit_babe::instance::commit::{CACInstanceCommit as RealCACInstanceCommit, CACInstanceCommit};
use verifiable_circuit_babe::prover::BABEProver;
use verifiable_circuit_babe::soldering::{SolderedLabelsData, SolderingData as RealSolderingData, SolderingProof as RealSolderingProof};
use verifiable_circuit_babe::transactions::{ChallengeAssertWitnessRaw, TxAssertWitness};
use verifiable_circuit_babe::utils::pi1_xd_to_wots96_msg;
use verifiable_circuit_babe::verifier::{BABEVerifier, InstanceLightSecrets};
use crate::types::BitvmGcCircuitData;

/// Number of Wots96 digit signatures expected by the GOAT GC-V2 connector.
pub const WOTS_SIG_COUNT: usize = Wots96::TOTAL_DIGIT_LEN as usize;
pub const BABE_N_CC: usize = 181;
// TODO: use verifiable_circuit_babe::babe::M_CC instead
pub const BABE_M_CC: usize = 7;

pub type OpenedInstanceSeeds = Vec<(usize, u64)>;
pub type FinalizedInstances = Vec<FinalizedInstanceData>;
pub type SetupAndSolderingData = (OpenedInstanceSeeds, FinalizedInstances, SolderingData);

// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct CACSetupPackage {
//     pub commits: Vec<CACInstanceCommit>,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct CACInstanceCommit {
//     pub epk: Vec<[[u8; 20]; 2]>,
//     pub wots_padding_epk: [[[u8; 20]; 2]; 4],
//     pub constant_commits: [[[u8; 32]; 2]; 2],
//     pub h_msg: [u8; 20],
//     pub h_ct_setup: [u8; 32],
//     pub com_adaptor: [u8; 32],
//     pub com_gc: [u8; 32],
// }

// #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct FinalizedInstanceData {
//     pub index: usize,
//     pub final_msg_hash: [u8; 20],
//     // todo: we maybe dont need this, it's in the CACInstanceCommit::epk
//     pub wire_hashes: Vec<WireHash>,
//     // todo: we already has this in the package before.
//     pub gc_commitment: [u8; 32],
//     // todo: we already has this in the package before.
//     pub adaptor_commitment: [u8; 32],
//     // todo: we already has this in the package before.
//     pub ct_setup_commitment: [u8; 32],
//     pub real_data: Option<RealFinalizedPayload>,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct RealFinalizedPayload {
//     pub gc_ciphertexts: Vec<Option<[u8; 16]>>,
//     pub adaptor_table: SerializableSparseAdaptorTable,
//     pub ct_setup: SerializableSetupCt,
//     pub constant_labels: [[u8; 16]; 2],
//     pub wots_padding_zero_labels: [[u8; 16]; 4],
// }

// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct CompactFinalizedInstanceData { // Replaced by FinalizedInstanceData
//     pub index: usize,
//     pub real_data: RealFinalizedPayload,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactSolderingData {
    pub finalized_indices: Vec<usize>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactSolderingProofPayload {
    pub opened: OpenedInstanceSeeds,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: CompactSolderingData,
}

// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct SerializableSetupCt {  replaced by WeKnownPi1SetupCt
//     pub ct2_r_delta_g2: Vec<u8>,
//     pub ct3_masked_msg: Vec<u8>,
// }

// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct SerializableSparseAdaptorTable { replaced by SparseAdaptorTable
//     pub entries: Vec<SerializableSparseAdaptorEntry>,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct SerializableSparseAdaptorEntry { replaced by SparseAdaptorEntry
//     pub x: SerializableSparseAdaptorRow,
//     pub y: SerializableSparseAdaptorRow,
//     pub z: SerializableSparseAdaptorRow,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct SerializableSparseAdaptorRow { replaced by SparseAdaptorRow
//     pub cts: Vec<[u8; 32]>,
//     pub offset: Vec<u8>,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolderingData {
    pub finalized_indices: Vec<usize>,
    pub soldered_output: SolderedLabelsData,
    pub proof: Vec<u8>,
}

// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
// pub struct SolderedLabelsData {
//     pub base_commitment: Vec<([u8; 32], [u8; 32])>,
//     pub deltas: Vec<Vec<([u8; 16], [u8; 16])>>,
//     pub commitments: Vec<Vec<([u8; 32], [u8; 32])>>,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierPrivateState {
    pub instance_seeds: Vec<u64>,
    pub statement_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierState {
    pub package: CACSetupPackage,
    pub finalized_indices: Vec<usize>,
    pub verifier_pubkey: bitcoin::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeProverState {
    pub package: CACSetupPackage,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: SolderingData,
    pub h_msgs: Vec<[u8; 20]>,
}

// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct BabeAssertWitness { // replace by TxAssertWitness
//     // pub pi1: Vec<u8>,
//     // #[serde(default)]
//     // pub pubin_commitment: [u8; 32],
//     pub wots_sig: Vec<[u8; 21]>,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeChallengeAssertWitness {
    pub verifier_index: usize,
    pub witness: ChallengeAssertWitnessRaw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeWronglyChallengedWitness {
    pub verifier_index: usize,
    // just need to contain one valid msg
    pub final_msg: Vec<u8>,
}


/// Builds deterministic placeholder setup commitments for tests and wiring.
pub fn sample_cac_instance_commit(seed: u8) -> CACInstanceCommit {
    let epk = (0..GC_INPUT_WIRES)
        .map(|wire| [hash20(&[seed, wire as u8, 0]), hash20(&[seed, wire as u8, 1])])
        .collect();

    let constant_commit_sgc: Vec<_> = (0..SGC_PART1_CONSTANT_SIZE)
        .map(|_| {
            [
                hash32(&[seed, 0xf0, 0]),
                hash32(&[seed, 0xf0, 1]),
            ]
        })
        .collect();

    CACInstanceCommit {
        epk,
        constant_commits_fgc: [
            [hash32(&[seed, 0xf0, 0]), hash32(&[seed, 0xf0, 1])],
            [hash32(&[seed, 0xf1, 0]), hash32(&[seed, 0xf1, 1])],
        ],
        constant_commits_sgc: constant_commit_sgc,
        b_blind_commit: hash32(&[seed, 0xa0]),
        h_msg: hash20(&[seed, 0xa1]),
        h_ct_setup: hash32(&[seed, 0xa2]),
        com_adaptor: [hash32(&[seed, 0xa3]), hash32(&[seed, 0xa4])],
        com_gc: [hash32(&[seed, 0xa5]), hash32(&[seed, 0xa6]), hash32(&[seed, 0xa7])],
    }
}

pub fn sample_finalized_instance_data(index: usize) -> FinalizedInstanceData {
    let seed = index as u8;
    let adaptor_tables = [
        SparseAdaptorTable {
            entries: vec![]
        },
        SparseAdaptorTable {
            entries: vec![]
        }
    ];
    let ct_setup = WeKnownPi1SetupCt {
        ct2_r_delta_g2: vec![],
        ct3_masked_msg: vec![],
    };

    FinalizedInstanceData {
        index,
        ciphertext_sets: [vec![], vec![], vec![]],
        adaptor_tables,
        ct_setup,
        constant_labels_0: [S([0; 16]), S([0; 16])],
        constant_labels_1: vec![],
        b: G1Affine::identity(),
    }
}


// impl CompactFinalizedInstanceData {
//     pub fn try_from_finalized(finalized: &FinalizedInstanceData) -> Result<Self> {
//         let real_data = finalized.real_data.clone().ok_or_else(|| {
//             anyhow::anyhow!("finalized index {} lacks real BABE payload", finalized.index)
//         })?;
//         Ok(Self { index: finalized.index, real_data })
//     }
// }

impl SolderingData {
    /// Builds deterministic placeholder soldering data for the selected finalized indices.
    pub fn sample(finalized_indices: Vec<usize>) -> Self {
        Self { finalized_indices, soldered_output: SolderedLabelsData::default(), proof: vec![] }
    }
}

/// Builds a deterministic placeholder CAC setup package with `n_cc` instances.
pub fn build_setup_package(n_cc: usize) -> Result<CACSetupPackage> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    Ok(CACSetupPackage {
        commits: (0..n_cc).map(|index| sample_cac_instance_commit(index as u8)).collect(),
    })
}

/// Builds a real random BABE/CAC setup package bound to the supplied Groth16 statement.
pub fn build_real_setup_package(
    n_cc: usize,
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
) -> Result<(CACSetupPackage, BabeVerifierPrivateState)> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    ensure_real_gc_assets_configured()?;
    let verifier = catch_unwind(AssertUnwindSafe(|| BABEVerifier::new(n_cc, vk, static_inputs)))
        .map_err(|_| anyhow::anyhow!("real BABE verifier setup panicked while loading GC assets"))?
        .map_err(anyhow::Error::msg)?;
    let package = verifier.commit();
    let private_state = BabeVerifierPrivateState {
        instance_seeds: verifier.get_seeds(),
        statement_digest: statement_digest(vk, static_inputs)?,
    };

    Ok((package, private_state))
}

/// Reconstructs the real Verifier instances and creates CAC opening/soldering output data.
pub fn open_real_setup_and_solder(
    soldering_builder: &BabeBundleBuilder,
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
) -> Result<SetupAndSolderingData> {
    ensure_real_gc_assets_configured()?;
    if private_state.statement_digest != statement_digest(vk, static_inputs)? {
        bail!("BABE setup statement does not match persisted verifier state");
    }
    validate_finalized_indices(package, finalized_indices)?;
    let verifier = restore_real_verifier(private_state, package, vk, static_inputs)?;
    if verifier.commit() != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    let bundle = soldering_builder
        .babe_verifier_open_and_solder(&verifier, finalized_indices)
        .map_err(anyhow::Error::msg)?;
    Ok((
        bundle.opened,
        bundle.finalized,
        from_real_soldering(&bundle.soldering)?,
    ))
}

/// Verifies real CAC openings, commitments, and the native Ziren soldering proof.
pub fn verify_real_setup(
    soldering_builder: &BabeBundleBuilder,
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    vk: &Groth16VerifyingKey<Bn254>,
    static_public_inputs: Fr,
) -> Result<()> {
    let bundle = BabeBundle {
        opened: opened.to_vec(),
        finalized: finalized.to_vec(),
        soldering: to_real_soldering(soldering)?,
    };
    soldering_builder
        .babe_prover_verify_setup(&package, &bundle, vk, static_public_inputs)
        .map_err(anyhow::Error::msg)
}

/// Removes setup-derived public fields from the Verifier-to-Operator soldering proof payload.
pub fn compact_soldering_proof_payload(
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<CompactSolderingProofPayload> {
    Ok(CompactSolderingProofPayload {
        opened: opened.to_vec(),
        finalized: finalized.to_vec(),
            // .iter()
            // .map(CompactFinalizedInstanceData::try_from_finalized)
            // .collect::<Result<Vec<_>>>()?,
        soldering: CompactSolderingData {
            finalized_indices: soldering.finalized_indices.clone(),
            proof: soldering.proof.clone(),
        },
    })
}

/// Reconstructs the full BABE setup data using the locally trusted setup package.
pub fn expand_compact_soldering_proof_payload(
    package: &CACSetupPackage,
    payload: CompactSolderingProofPayload,
) -> Result<SetupAndSolderingData> {
    let finalized = payload.finalized.clone();
    Ok((payload.opened, finalized, expand_compact_soldering_data(payload.soldering)?))
}

/// Derives finalized circuit indices using the real BABE/CAC Fiat-Shamir selection.
pub fn derive_finalized_indices(package: &CACSetupPackage, m_cc: usize) -> Result<Vec<usize>> {
    let n_cc = package.commits.len();
    if m_cc == 0 || m_cc > n_cc {
        bail!("invalid m_cc {m_cc} for n_cc {n_cc}");
    }
    Ok(cac_finalize_indices(n_cc, m_cc))
}

/// Opens non-finalized placeholder instances and returns finalized data plus soldering data.
pub fn open_and_solder(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<SetupAndSolderingData> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    let opened = (0..package.commits.len())
        .filter(|index| !finalized_set.contains(index))
        .map(|index| (index, deterministic_seed(index)))
        .collect::<Vec<_>>();
    let finalized =
        finalized_indices.iter().map(|index| sample_finalized_instance_data(*index)).collect();
    let soldering = SolderingData::sample(finalized_indices.to_vec());
    Ok((opened, finalized, soldering))
}

/// Validates placeholder opened, finalized, and soldering data consistency.
pub fn verify_setup(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<()> {
    let n_cc = package.commits.len();
    let finalized_set = finalized.iter().map(|data| data.index).collect::<HashSet<_>>();
    if finalized_set.len() != finalized.len() {
        bail!("duplicate finalized data");
    }
    for (index, seed) in opened {
        if *index >= n_cc {
            bail!("opened index {index} out of range");
        }
        if finalized_set.contains(index) {
            bail!("index {index} cannot be both opened and finalized");
        }
        if *seed != deterministic_seed(*index) {
            bail!("opened seed mismatch for index {index}");
        }
    }
    if soldering.finalized_indices != finalized.iter().map(|data| data.index).collect::<Vec<_>>() {
        bail!("soldering finalized indices mismatch");
    }
    for data in finalized {
        if data.index >= n_cc {
            bail!("finalized index {} out of range", data.index);
        }
        // if data.wire_hashes.len() != INPUT_WIRE_NUM {
        //     bail!("finalized index {} has invalid wire hash count", data.index);
        // }
    }
    Ok(())
}

/// Extracts one graph slot owned by `verifier_pubkey` from finalized setup data.
pub fn extract_gc_circuit_data(
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    verifier_pubkey: bitcoin::PublicKey,
    epk: &[[[u8; 20]; 2]],
    h_msgs: &[[u8; 20]],
) -> Result<BitvmGcCircuitData> {
    if finalized.len() != BABE_M_CC {
        bail!("each verifier must contribute exactly {BABE_M_CC} finalized BABE instances");
    }
    if soldering.finalized_indices != finalized.iter().map(|data| data.index).collect::<Vec<_>>() {
        bail!("soldering finalized indices mismatch");
    }
    let data = &finalized[0];
    let wire_hashes: [WireHash; INPUT_WIRE_NUM] = epk
        .iter()
        .map(|labels| WireHash {
            false_label_hash: labels[0],
            true_label_hash: labels[1],
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|wire_hashes: Vec<WireHash>| {
            anyhow::anyhow!(
            "BABE input label count {} is incompatible with GOAT verifier connector wire count {INPUT_WIRE_NUM}",
            wire_hashes.len()
        )
        })?;
    Ok(BitvmGcCircuitData {
        verifier_pubkey,
        final_msg_hashlocks: h_msgs.to_vec(),
        wire_hashes,
    })
}

/// Builds the native BABE assertion witness from the validated wrapper Groth16 proof.
pub fn build_assert_witness(
    proof: &ark_groth16::Proof<Bn254>,
    assert_secret_key: &OperatorAssertSecretKey,
    dynamic_input: ark_bn254::Fr,
) -> Result<TxAssertWitness> {
    let msg = pi1_xd_to_wots96_msg(&proof.a, dynamic_input);
    let wots_sig = Wots96::sign(assert_secret_key, &msg);
    Ok(TxAssertWitness { wots_sig: wots_sig.to_vec() })
}

// pub fn build_assert_witness_with_pubin_commitment(
//     proof: &ark_groth16::Proof<Bn254>,
//     pubin_commitment: &[u8; 32],
//     assert_secret_key: &OperatorAssertSecretKey,
// ) -> Result<BabeAssertWitness> {
//     if assert_secret_key.is_empty() {
//         bail!("operator WOTS secret key must not be empty");
//     }
//     let pi1 = proof.a;
//     let mut pi1_bytes = Vec::new();
//     pi1.serialize_compressed(&mut pi1_bytes).expect("serialize pi1");
//     let msg = pi1_to_wots96_msg(&pi1, pubin_commitment);
//     let wots_sig = Wots96::sign(assert_secret_key, &msg);
//     Ok(BabeAssertWitness {
//         pi1: pi1_bytes,
//         pubin_commitment: *pubin_commitment,
//         wots_sig: wots_sig.to_vec(),
//     })
// }

pub fn assert_wots_message(assert_witness: &TxAssertWitness) -> Result<[u8; 96]> {
    // let pi1 = ark_bn254::G1Affine::deserialize_compressed(assert_witness.pi1.as_slice())
    //     .map_err(|error| anyhow::anyhow!("invalid BABE pi1 in assert witness: {error}"))?;
    // Ok(pi1_to_wots96_msg(&pi1, &assert_witness.pubin_commitment))
    let recover = assert_witness.recover_pi1_xd_without_verify();
    if recover.is_none() {
        return Err(anyhow::anyhow!("Cannot recover pi1 and xd"))
    }
    let (pi1, x_d) = recover.unwrap();
    Ok(pi1_xd_to_wots96_msg(&pi1, x_d))
}

/// Builds a placeholder verifier challenge witness from an assert witness.
pub fn build_challenge_assert_witness(
    verifier_state: &BabeVerifierState,
    assert_witness: &TxAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if verifier_state.finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    let bytes = assert_wots_message(assert_witness)?;
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness: ChallengeAssertWitnessRaw {
            input_labels: (0usize..INPUT_WIRE_NUM)
                .map(|index| hash16_with_index(&bytes, index))
                .collect(),
            wots_sig: assert_witness.wots_sig.clone(),
        }
    })
}

/// Verifies a native operator assertion and reveals the real base-instance labels.
#[allow(clippy::too_many_arguments)]
pub fn build_real_challenge_assert_witness(
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
    operator_wots_pubkey: &OperatorAssertPublicKey,
    assert_witness: &TxAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    let verifier = restore_real_verifier(private_state, package, vk, static_inputs)?;
    if verifier.commit() != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }

    let recover = assert_witness.recover_pi1_xd_without_verify();
    if recover.is_none() {
        return Err(anyhow::anyhow!("Cannot recover pi1 and xd"))
    }
    let (pi1, x_d) = recover.unwrap();
    let expected_message = pi1_xd_to_wots96_msg(&pi1, x_d);
    let wots_sig = to_real_wots_sig(&assert_witness.wots_sig)?;
    let signed_message = Wots96::signature_to_message(&wots_sig);
    if signed_message != expected_message {
        bail!("operator BABE assertion WOTS signature message does not match pi1/pubin");
    }
    let base_idx = finalized_indices[0];

    let witness = build_challenge_assert_witness_raw(
        &verifier,
        assert_witness,
        operator_wots_pubkey,
        base_idx,
    );
    if witness.is_none() {
        bail!("cannot generate challenge assert witness");
    }
    let witness = witness.unwrap();

    if witness.input_labels.len() != INPUT_WIRE_NUM {
        bail!("real BABE challenge labels have {}; expected {INPUT_WIRE_NUM}", witness.input_labels.len());
    }
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness,
    })
}

/// Builds a wrongly-challenged witness from a valid recovered finalized-message preimage.
pub fn build_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    final_msg: Vec<u8>,
) -> Result<BabeWronglyChallengedWitness> {
    build_wrongly_challenged_witness_from_preimages(
        &prover_state.h_msgs,
        challenge_witness,
        final_msg,
    )
}

/// Evaluates the native BABE garbled circuit and returns a finalized hashlock preimages.
pub fn recover_real_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    proof: &ark_groth16::Proof<Bn254>,
    vk: Groth16VerifyingKey<Bn254>,
    dyn_pubin: ark_bn254::Fr,
) -> Result<BabeWronglyChallengedWitness> {
    let real_state = ProverSetupState {
        wots_sk_p: vec![],
        finalized: prover_state
            .finalized.clone(),
            // .iter()
            // .map(to_real_finalized)
            // .collect::<Result<Vec<_>>>()?,
        soldering: to_real_soldering(&prover_state.soldering)?,
        h_msgs: prover_state.h_msgs.clone(),
        presigs_v: babe_verifier_presign(),
    };
    let mut prover = BABEProver::new(vk, proof.clone(), dyn_pubin);
    recover_a_valid_finalized_messages(prover_state, challenge_witness, &mut prover, &real_state)
}

/// Builds a wrongly-challenged witness after validating all finalized preimages.
pub fn build_wrongly_challenged_witness_from_preimages(
    h_msgs: &[[u8; 20]],
    challenge_witness: &BabeChallengeAssertWitness,
    final_msg: Vec<u8>,
) -> Result<BabeWronglyChallengedWitness> {
    if h_msgs.len() != BABE_M_CC {
        bail!("wrongly challenged setup must contain exactly {BABE_M_CC} finalized hashlocks");
    }

    if !h_msgs.contains(&label_hash(&final_msg)) {
        bail!("message is not a valid preimage");
    }

    Ok(BabeWronglyChallengedWitness {
        verifier_index: challenge_witness.verifier_index,
        final_msg,
    })
}

fn ensure_real_gc_assets_configured() -> Result<()> {
    for name in [
        "FGC_GATES_PATH", "FGC_OUT_INDICES_PATH", "SGC_GATES_PATH", "SGC_OUT_INDICES_PATH",
        "FGC_COMPACT_GATES_PATH", "FGC_COMPACT_OUT_INDICES_PATH", "SGC_COMPACT_GATES_PATH", "SGC_COMPACT_OUT_INDICES_PATH"
    ] {
        let path = PathBuf::from(
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is required for real CAC setup"))?,
        );
        if !path.is_file() {
            bail!("{name} does not point to a readable file: {}", path.display());
        }
    }
    Ok(())
}

fn statement_digest(vk: &Groth16VerifyingKey<Bn254>, static_inputs: Fr) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)?;
    static_inputs.serialize_compressed(&mut bytes)?;
    Ok(hash32(&bytes))
}

fn restore_real_verifier(
    state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
) -> Result<BABEVerifier> {
    let verifier = BABEVerifier::from_state(
        &state.instance_seeds, package, vk, static_inputs
    );
    if verifier.is_none() {
        Err(anyhow::anyhow!("Cannot restore real verifier"))
    } else {
        Ok(verifier.unwrap())
    }
}

fn validate_finalized_indices(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<()> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.is_empty() {
        bail!("at least one finalized index is required");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    Ok(())
}

// fn from_real_package(package: &RealCACSetupPackage) -> CACSetupPackage {
//     CACSetupPackage { commits: package.commits.iter().map(from_real_commit).collect() }
// }
//
// fn from_real_commit(commit: &RealCACInstanceCommit) -> CACInstanceCommit {
//     CACInstanceCommit {
//         epk: commit.epk.clone(),
//         wots_padding_epk: padding_wire_hashes(),
//         constant_commits: commit.constant_commits,
//         h_msg: commit.h_msg,
//         h_ct_setup: commit.h_ct_setup,
//         com_adaptor: commit.com_adaptor,
//         com_gc: commit.com_gc,
//     }
// }

// fn to_real_package(package: &CACSetupPackage) -> RealCACSetupPackage {
//     RealCACSetupPackage {
//         commits: package
//             .commits
//             .iter()
//             .map(|commit| RealCACInstanceCommit {
//                 epk: commit.epk.clone(),
//                 constant_commits: commit.constant_commits,
//                 h_msg: commit.h_msg,
//                 h_ct_setup: commit.h_ct_setup,
//                 com_adaptor: commit.com_adaptor,
//                 com_gc: commit.com_gc,
//             })
//             .collect(),
//     }
// }

// fn from_real_finalized(
//     finalized: &RealFinalizedInstanceData,
//     package: &CACSetupPackage,
// ) -> Result<FinalizedInstanceData> {
//     let real_data = RealFinalizedPayload {
//         gc_ciphertexts: finalized
//             .gc_ciphertexts
//             .iter()
//             .map(|ciphertext| ciphertext.map(|label| label.0))
//             .collect(),
//         adaptor_table: from_real_adaptor_table(&finalized.adaptor_table),
//         ct_setup: SerializableSetupCt {
//             ct2_r_delta_g2: finalized.ct_setup.ct2_r_delta_g2.clone(),
//             ct3_masked_msg: finalized.ct_setup.ct3_masked_msg.clone(),
//         },
//         constant_labels: [finalized.constant_labels[0].0, finalized.constant_labels[1].0],
//         wots_padding_zero_labels: [[0u8; 16]; 4],
//     };
//     expand_compact_finalized_instance(
//         package,
//         CompactFinalizedInstanceData { index: finalized.index, real_data },
//     )
// }

// fn expand_compact_finalized_instance(
//     package: &CACSetupPackage,
//     finalized: FinalizedInstanceData,
// ) -> Result<FinalizedInstanceData> {
//     let commit = package
//         .commits
//         .get(finalized.index)
//         .ok_or_else(|| anyhow::anyhow!("finalized index {} out of range", finalized.index))?;
//     if commit.epk.len() != LAMPORT_N {
//         bail!(
//             "finalized index {} has {} BABE input commitments; expected {LAMPORT_N}",
//             finalized.index,
//             commit.epk.len()
//         );
//     }
//     let mut wire_hashes = Vec::with_capacity(INPUT_WIRE_NUM);
//     wire_hashes.extend(commit.epk[..254].iter().map(to_wire_hash));
//     wire_hashes.extend(commit.wots_padding_epk[..2].iter().map(to_wire_hash));
//     wire_hashes.extend(commit.epk[254..].iter().map(to_wire_hash));
//     wire_hashes.extend(commit.wots_padding_epk[2..].iter().map(to_wire_hash));
//     wire_hashes.extend(pubin_wire_hashes(commit));
//     Ok(FinalizedInstanceData {
//         index: finalized.index,
//         final_msg_hash: commit.h_msg,
//         wire_hashes,
//         gc_commitment: commit.com_gc,
//         adaptor_commitment: commit.com_adaptor,
//         ct_setup_commitment: commit.h_ct_setup,
//         real_data: Some(finalized.real_data),
//     })
// }

// fn to_real_finalized(finalized: &FinalizedInstanceData) -> Result<RealFinalizedInstanceData> {
//     let payload = finalized.real_data.as_ref().ok_or_else(|| {
//         anyhow::anyhow!("finalized index {} lacks real BABE payload", finalized.index)
//     })?;
//     Ok(RealFinalizedInstanceData {
//         index: finalized.index,
//         gc_ciphertexts: payload.gc_ciphertexts.iter().map(|value| value.map(S)).collect(),
//         adaptor_table: to_real_adaptor_table(&payload.adaptor_table)?,
//         ct_setup: RealSetupCt {
//             ct2_r_delta_g2: payload.ct_setup.ct2_r_delta_g2.clone(),
//             ct3_masked_msg: payload.ct_setup.ct3_masked_msg.clone(),
//         },
//         constant_labels: [S(payload.constant_labels[0]), S(payload.constant_labels[1])],
//     })
// }

// fn from_real_adaptor_table(table: &RealSparseAdaptorTable) -> SerializableSparseAdaptorTable {
//     SerializableSparseAdaptorTable {
//         entries: table
//             .entries
//             .iter()
//             .map(|entry| SerializableSparseAdaptorEntry {
//                 x: from_real_adaptor_row(&entry.x),
//                 y: from_real_adaptor_row(&entry.y),
//                 z: from_real_adaptor_row(&entry.z),
//             })
//             .collect(),
//     }
// }
//
// fn from_real_adaptor_row(row: &RealSparseAdaptorRow) -> SerializableSparseAdaptorRow {
//     let mut offset = Vec::new();
//     row.offset.serialize_compressed(&mut offset).expect("serialize adaptor offset");
//     SerializableSparseAdaptorRow { cts: row.cts.clone(), offset }
// }

// fn to_real_adaptor_table(table: &SerializableSparseAdaptorTable) -> Result<RealSparseAdaptorTable> {
//     Ok(RealSparseAdaptorTable {
//         entries: table
//             .entries
//             .iter()
//             .map(|entry| {
//                 Ok(RealSparseAdaptorEntry {
//                     x: to_real_adaptor_row(&entry.x)?,
//                     y: to_real_adaptor_row(&entry.y)?,
//                     z: to_real_adaptor_row(&entry.z)?,
//                 })
//             })
//             .collect::<Result<Vec<_>>>()?,
//     })
// }

// fn to_real_adaptor_row(row: &SerializableSparseAdaptorRow) -> Result<RealSparseAdaptorRow> {
//     Ok(RealSparseAdaptorRow {
//         cts: row.cts.clone(),
//         offset: Fq::deserialize_compressed(row.offset.as_slice())?,
//     })
// }

fn from_real_soldering(soldering: &RealSolderingData) -> Result<SolderingData> {
    let output = soldering.soldering_proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: bincode::serialize(&soldering.soldering_proof.proof)?,
    })
}

fn expand_compact_soldering_data(soldering: CompactSolderingData) -> Result<SolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    let proof = RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? };
    let output = proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices,
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: soldering.proof,
    })
}

fn to_real_soldering(soldering: &SolderingData) -> Result<RealSolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    Ok(RealSolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldering_proof: RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? },
    })
}

fn recover_a_valid_finalized_messages(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    prover: &mut BABEProver,
    real_state: &ProverSetupState,
) -> Result<BabeWronglyChallengedWitness> {
    if real_state.finalized.len() != prover_state.h_msgs.len() {
        bail!("BABE prover state finalized data and hash count differ");
    }
    if real_state.finalized.is_empty() {
        bail!("BABE prover state has no finalized instances");
    }

    let base_input_labels: Vec<S> = challenge_witness.witness.input_labels.iter().map(|&b| S(b)).collect();
    // Strip the 6 dummy labels before passing to the GC (which has GC_INPUT_WIRES real wires).
    let (pi1_x_labels, pi1_y_labels, x_d_labels) = deinterleave_dummy_positions(&base_input_labels);
    let pi1_labels: Vec<S> = pi1_x_labels.into_iter().chain(pi1_y_labels).collect();
    let soldered_output = &prover_state.soldering.soldered_output;
    let real_soldering = to_real_soldering(&prover_state.soldering)?;

    let soldered_output = &prover_state.soldering.soldered_output;
    if soldered_output.base_commitment.len() != base_input_labels.len() {
        bail!(
            "soldering base commitment count {} does not match BABE input label count {}",
            soldered_output.base_commitment.len(),
            base_input_labels.len()
        );
    }

    let found = prover.check_compute_msg(
        &prover_state.finalized,
        &pi1_labels,
        &x_d_labels,
        &real_soldering,
        &prover_state.h_msgs,
    );


    if !found {
        bail!("Cannot find any valid msg");
    }

    Ok(BabeWronglyChallengedWitness {
        verifier_index: challenge_witness.verifier_index,
        final_msg: prover.valid_msg.unwrap().to_vec(),
    })
}

// fn pi1_labels_from_challenge(input_labels: &[[u8; 16]]) -> Result<Vec<S>> {
//     if input_labels.len() == LAMPORT_N {
//         return Ok(input_labels.iter().copied().map(S).collect());
//     }
//     if input_labels.len() != INPUT_WIRE_NUM {
//         bail!(
//             "challenge witness has {} input labels; expected {LAMPORT_N} or {INPUT_WIRE_NUM}",
//             input_labels.len()
//         );
//     }
//     Ok(input_labels[..254].iter().chain(&input_labels[256..510]).copied().map(S).collect())
// }

// fn soldered_input_labels(
//     base_input_labels: &[S],
//     soldered_output: &SolderedLabelsData,
//     finalized_position: usize,
// ) -> Result<Vec<S>> {
//     if finalized_position == 0 {
//         return Ok(base_input_labels.to_vec());
//     }
//     let deltas = soldered_output.deltas.get(finalized_position - 1).ok_or_else(|| {
//         anyhow::anyhow!("missing soldering deltas for finalized position {finalized_position}")
//     })?;
//     if deltas.len() != base_input_labels.len() {
//         bail!(
//             "soldering delta count {} does not match BABE input label count {}",
//             deltas.len(),
//             base_input_labels.len()
//         );
//     }
//
//     Ok(base_input_labels
//         .iter()
//         .enumerate()
//         .map(|(wire, &base_label)| {
//             let (delta_false, delta_true) = deltas[wire];
//             if hash32(&base_label.0) == soldered_output.base_commitment[wire].0 {
//                 base_label ^ S(delta_false)
//             } else {
//                 base_label ^ S(delta_true)
//             }
//         })
//         .collect())
// }

// fn recover_finalized_message(
//     prover: &BABEProver,
//     proof: &ark_groth16::Proof<Bn254>,
//     finalized: &RealFinalizedInstanceData,
//     input_labels: &[S],
//     expected_hash: [u8; 20],
//     finalized_position: usize,
// ) -> Result<Vec<u8>> {
//     let mut full_labels = Vec::with_capacity(2 + input_labels.len());
//     full_labels.push(finalized.constant_labels[0]);
//     full_labels.push(finalized.constant_labels[1]);
//     full_labels.extend_from_slice(input_labels);
//
//     let (mut circuit, gc_output_indices) = verifiable_circuit_babe::gc::read_fresh_circuit();
//     let ct_prove = prover.compute_ct_prove(
//         &mut circuit,
//         &gc_output_indices,
//         &full_labels,
//         &finalized.gc_ciphertexts,
//         &finalized.adaptor_table,
//     );
//     let msg = BABEProver::compute_msg(proof, &ct_prove, &finalized.ct_setup)
//         .map_err(anyhow::Error::msg)?;
//     let final_msg = msg.to_vec();
//     if label_hash(&final_msg) != expected_hash {
//         bail!(
//             "recovered message at finalized position {finalized_position} does not match hashlock"
//         );
//     }
//     Ok(final_msg)
// }

fn to_real_wots_sig(wots_sig: &[[u8; 21]]) -> Result<<Wots96 as Wots>::Signature> {
    wots_sig.try_into().map_err(|_| {
        anyhow::anyhow!(
            "WOTS signature has {} digit signatures; expected {WOTS_SIG_COUNT}",
            wots_sig.len()
        )
    })
}

// fn padding_wire_hashes() -> [[[u8; 20]; 2]; 4] {
//     let false_hash = label_hash(&vec![0u8; 16]);
//     let true_hash = label_hash(&vec![1u8; 16]);
//     [[false_hash, true_hash]; 4]
// }

fn deterministic_seed(index: usize) -> u64 {
    u64::from_le_bytes(hash32(&(index as u64).to_le_bytes())[0..8].try_into().expect("8 bytes"))
}

// fn to_wire_hash(pair: &[[u8; 20]; 2]) -> WireHash {
//     WireHash { false_label_hash: pair[0], true_label_hash: pair[1] }
// }

// fn pi1_to_wots96_msg(pi1: &ark_bn254::G1Affine, pubin_commitment: &[u8; 32]) -> [u8; 96] {
//     let mut msg = [0u8; 96];
//     let mut tmp = Vec::new();
//
//     pi1.x.serialize_uncompressed(&mut tmp).expect("serialize pi1.x");
//     msg[..32].copy_from_slice(&tmp);
//
//     tmp.clear();
//     pi1.y.serialize_uncompressed(&mut tmp).expect("serialize pi1.y");
//     msg[32..64].copy_from_slice(&tmp);
//
//     msg[64..96].copy_from_slice(pubin_commitment);
//     msg
// }

// fn pubin_wire_hashes(commit: &CACInstanceCommit) -> Vec<WireHash> {
//     (0..256)
//         .map(|index| WireHash {
//             false_label_hash: label_hash(&pubin_label(commit, index, false).to_vec()),
//             true_label_hash: label_hash(&pubin_label(commit, index, true).to_vec()),
//         })
//         .collect()
// }
//
// fn pubin_input_labels(commit: &CACInstanceCommit, pubin_commitment: &[u8; 32]) -> Vec<[u8; 16]> {
//     (0..256)
//         .map(|index| {
//             let byte = pubin_commitment[index / 8];
//             let bit = ((byte >> (index % 8)) & 1) == 1;
//             pubin_label(commit, index, bit)
//         })
//         .collect()
// }

// fn pubin_label(commit: &CACInstanceCommit, index: usize, bit: bool) -> [u8; 16] {
//     let mut bytes = Vec::with_capacity(32 * 4 + std::mem::size_of::<u64>() + 1);
//     bytes.extend_from_slice(&commit.h_ct_setup);
//     bytes.extend_from_slice(&commit.com_adaptor);
//     bytes.extend_from_slice(&commit.com_gc);
//     bytes.extend_from_slice(&commit.h_msg);
//     bytes.extend_from_slice(&(index as u64).to_le_bytes());
//     bytes.push(u8::from(bit));
//     hash16(&bytes)
// }

fn hash20(data: &[u8]) -> [u8; 20] {
    let hash = hash32(data);
    hash[0..20].try_into().expect("20 bytes")
}

fn hash16(data: &[u8]) -> [u8; 16] {
    let hash = hash32(data);
    hash[0..16].try_into().expect("16 bytes")
}

fn hash16_with_index(data: &[u8], index: usize) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(data.len() + std::mem::size_of::<u64>());
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&(index as u64).to_le_bytes());
    hash16(&bytes)
}

fn hash32(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
