#![no_main]
zkm_zkvm::entrypoint!(main);

use guest_executor::verify_block;

pub fn main() {
    // Read the input.
    let input = zkm_zkvm::io::read_vec();

    let (_, cur_state_root, prev_state_root) = verify_block(&input);

    zkm_zkvm::io::commit(&prev_state_root);
    zkm_zkvm::io::commit(&cur_state_root);
}
