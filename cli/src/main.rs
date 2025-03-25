use clap::{Parser, Args};
use libp2p::PeerId;

#[derive(Debug, Parser)]
enum CliArgument {
    GetPeers {
        #[clap(long)]
        peer_id: Option<PeerId>,
    },
    PutPkRecord {},
}

fn main() {
    let cli = CliArgument::parse();
}