#![no_main]
zkm_zkvm::entrypoint!(main);

use guest_executor::verify_block_hash;
use std::sync::Arc;

pub fn main() {
    // Read the input.
    let input = zkm_zkvm::io::read_vec();

    let block_hash = verify_block_hash(&input);

    // Commit the block hash.
    zkm_zkvm::io::commit(&block_hash);
}