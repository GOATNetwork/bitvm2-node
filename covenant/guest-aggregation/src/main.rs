#![no_main]
zkm_zkvm::entrypoint!(main);

use revm_primitives::B256;
use sha2::{Digest, Sha256};

use crate::io::ZKMPublicValues;

mod io;

pub fn main() {
    let vkey_pre = zkm_zkvm::io::read::<[u32; 8]>();
    let public_values_pre = zkm_zkvm::io::read::<Vec<u8>>();
    let states_pre: (B256, B256) = {
        let mut public_value = ZKMPublicValues::from(&public_values_pre);
        // (prev_state_root, cur_state_root)
        (public_value.read::<B256>(), public_value.read::<B256>())
    };

    let vkey_cur = zkm_zkvm::io::read::<[u32; 8]>();
    let public_values_cur = zkm_zkvm::io::read::<Vec<u8>>();
    let states_cur: (B256, B256) = {
        let mut public_value = ZKMPublicValues::from(&public_values_cur);
        // (prev_state_root, cur_state_root)
        (public_value.read::<B256>(), public_value.read::<B256>())
    };

    assert_eq!(states_pre.1, states_cur.0);

    // Verify the proofs.
    zkm_zkvm::lib::verify::verify_zkm_proof(&vkey_pre, &Sha256::digest(&public_values_pre).into());
    zkm_zkvm::lib::verify::verify_zkm_proof(&vkey_cur, &Sha256::digest(&public_values_cur).into());

    zkm_zkvm::io::commit(&states_pre.0); // prev state root
    zkm_zkvm::io::commit(&states_cur.1); // cur state root
}
