#![no_main]
zkm_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    // Read block number.
    let block_number = zkm_zkvm::io::read::<u64>();

    // Read the verification key.
    let vkey = zkm_zkvm::io::read::<[u32; 8]>();

    // Read the public values.
    let public_values = zkm_zkvm::io::read::<Vec<u8>>();

    // Verify the proofs.
    let public_values_digest = Sha256::digest(&public_values);
    zkm_zkvm::lib::verify::verify_zkm_proof(&vkey, &public_values_digest.into());

    zkm_zkvm::io::commit(&block_number);
}
