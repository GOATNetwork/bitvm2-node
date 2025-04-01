mod musig2;

pub use musig2::*;

use libp2p::identity;

pub fn generate_local_key() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}
