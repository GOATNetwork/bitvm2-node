# GOAT Bitvm2 Node

GOAT Network's BitVM2 bridge implementation. See [GOAT BitVM2 Whitepaper](https://www.goat.network/bitvm2-whitepaper) for more details.

## Layout

- `node/`: Main node implementation, including P2P, RPC, and scheduled tasks
- `circuits/`: Circuits and proof generation logic
- `proof-builder-rpc/`: RPC server for offloading proof generation to a separate process
- `crates/`: Shared Rust crates for common types and utilities
- `deployment`: Deployment scripts and documentation


## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.