#![no_main]
zkm_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    // Read block numbers.
    let block_numbers = zkm_zkvm::io::read::<Vec<u64>>();

    // Read the verification keys.
    let vkeys = zkm_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = zkm_zkvm::io::read::<Vec<Vec<u8>>>();

    assert_eq!(vkeys.len(), block_numbers.len());
    assert_eq!(vkeys.len(), public_values.len());

    // Verify the proofs.
    for i in 0..vkeys.len() {
        if i < vkeys.len() - 1 {
            assert_eq!(block_numbers[i] + 1, block_numbers[i + 1]);
        }

        let vkey = &vkeys[i];
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        zkm_zkvm::lib::verify::verify_zkm_proof(vkey, &public_values_digest.into());
    }

    zkm_zkvm::io::commit(&block_numbers);
}
