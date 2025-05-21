# BitVM2 Node

## Run Node

1. Install bitvm2-noded

```aiignore
cargo install --bin bitvm2-noded --git https://github.com/GOATNetwork/bitvm2-node
```

2. Run a bootnode.
```bash
./target/debug/bitvm2-noded key peer

# setup the PEER_KEY, BITVM_NODE_PUBKEY, BITVM_SECRET in .env

./target/debug/bitvm2-noded 
```

Run another node with a bootnode.
```bash
./target/debug/bitvm2-noded key peer

# setup the PEER_KEY, BITVM_NODE_PUBKEY, BITVM_SECRET in .env

./target/debug/bitvm2-noded --bootnodes $BOOTNODE -d
```

if you launch multiple node in a single server, use different `rpc_addr` and `db_path`, for example,

```
./target/debug/bitvm2-noded --bootnodes $BOOTNODE -d --rpc-addr localhost:8081 --db-path /tmp/bitvm2-node-2.db
```

## Env

check out the [.env.template](../.env.template) for details

For example:

```bash
ACTOR=Operator RUST_LOG=debug ./target/debug/bitvm2-noded --bootnodes 12D3KooWKqq1xos6tEAm8tzmMchzSdJzmaf4qaXf5fFmgQuTLA76 -d --rpc-addr localhost:8081 --db-path /tmp/bitvm2-node.db2
```

## Debug

We can send message to the P2P network via the local node's Stdin. The message is formated as `Actor:Message`, for example, If we send a message to Operator,

```bash
Challenger: {"key": "123"}
```
