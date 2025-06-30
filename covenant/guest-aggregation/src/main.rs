#![no_main]
zkm_zkvm::entrypoint!(main);

use revm_primitives::B256;
use sha2::{Digest, Sha256};

use crate::io::ZKMPublicValues;

mod io;

pub fn main() {
    // Read the verification keys.
    let vkeys = zkm_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = zkm_zkvm::io::read::<Vec<Vec<u8>>>();

    assert!(vkeys.len() > 1);
    assert_eq!(vkeys.len(), public_values.len());

    let states: Vec<(B256, B256)> = public_values.iter().map(|public_value_bytes| {
        let mut public_value = ZKMPublicValues::from(public_value_bytes);
        // (prev_state_root, cur_state_root)
        (public_value.read::<B256>(), public_value.read::<B256>())
    }).collect();

    // Verify the proofs.
    for i in 0..vkeys.len() {
        if i > 0 {
            assert_eq!(states[i-1].1, states[i].0);
        }

        let public_values_digest = Sha256::digest(&public_values[i]);
        zkm_zkvm::lib::verify::verify_zkm_proof(&vkeys[i], &public_values_digest.into());
    }

    zkm_zkvm::io::commit(&states.first().unwrap().0); // prev state root
    zkm_zkvm::io::commit(&states.last().unwrap().1); // cur state root
}
