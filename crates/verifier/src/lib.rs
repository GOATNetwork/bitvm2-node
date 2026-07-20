use sha2::{Digest, Sha256};
use zkm_verifier::{Groth16Verifier, IMM_GROTH16_VK_BYTES, decode_zkm_vkey_hash};

pub type ProgramId = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramType {
    Header = 1,
    State = 2,
    Commit = 3,
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn program_id_with_part_vk(zkm_vk_hash: &str, part_stark_vk: &[u8]) -> Result<ProgramId, String> {
    let vk_hash = decode_zkm_vkey_hash(zkm_vk_hash).map_err(|e| format!("{e:?}"))?;
    let part_vk_hash: [u8; 32] = Sha256::digest(part_stark_vk).into();
    Ok(tagged_hash(b"bitvm2/program-id/v1", &[&vk_hash, &part_vk_hash]))
}

pub fn program_id(zkm_vk_hash: &[u8], zkm_version: &str) -> Result<ProgramId, String> {
    let zkm_vk_hash = String::from_utf8(zkm_vk_hash.to_vec()).map_err(|e| e.to_string())?;
    program_id_with_part_vk(&zkm_vk_hash, Groth16Verifier::get_part_stark_vk(zkm_version))
}

pub fn initial_history(program_type: ProgramType) -> [u8; 32] {
    tagged_hash(b"bitvm2/vk-history-seed/v1", &[&[program_type as u8]])
}

pub fn legacy_history(
    program_type: ProgramType,
    previous_program_id: ProgramId,
    previous_public_values: &[u8],
) -> [u8; 32] {
    let public_values_hash: [u8; 32] = Sha256::digest(previous_public_values).into();
    tagged_hash(
        b"bitvm2/vk-history-migration/v1",
        &[&[program_type as u8], &previous_program_id, &public_values_hash],
    )
}

pub fn next_history(
    program_type: ProgramType,
    previous_history: [u8; 32],
    previous_program_id: ProgramId,
    current_program_id: ProgramId,
) -> [u8; 32] {
    if previous_program_id == current_program_id {
        previous_history
    } else {
        tagged_hash(
            b"bitvm2/vk-history-step/v1",
            &[&[program_type as u8], &previous_history, &previous_program_id],
        )
    }
}

pub fn finalize_history(
    program_type: ProgramType,
    history: [u8; 32],
    current_program_id: ProgramId,
) -> [u8; 32] {
    tagged_hash(
        b"bitvm2/vk-history-final/v1",
        &[&[program_type as u8], &history, &current_program_id],
    )
}

pub fn program_history_root(
    header_history: [u8; 32],
    state_history: [u8; 32],
    commit_history: [u8; 32],
) -> [u8; 32] {
    tagged_hash(b"bitvm2/program-history/v1", &[&header_history, &state_history, &commit_history])
}

pub fn verify_groth16_proof(
    proof: &[u8],
    zkm_public_values: &[u8],
    zkm_vk_hash: &[u8],
    zkm_version: &str,
) -> Result<ProgramId, String> {
    let groth16_vk = *IMM_GROTH16_VK_BYTES;
    let zkm_vk_hash = String::from_utf8(zkm_vk_hash.to_vec()).map_err(|e| e.to_string())?;
    let part_stark_vk = Groth16Verifier::get_part_stark_vk(zkm_version);

    Groth16Verifier::verify_by_imm_groth16_vk(
        proof,
        zkm_public_values,
        &zkm_vk_hash,
        groth16_vk,
        part_stark_vk,
    )
    .map_err(|err| format!("Verify Groth16 proof, err: {err:?}"))?;

    program_id_with_part_vk(&zkm_vk_hash, part_stark_vk)
}
