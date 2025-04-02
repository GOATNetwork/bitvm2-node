# Node

Run a bootnode.
```bash
./target/debug/bitvm2-noded key gen
./target/debug/bitvm2-noded -d
```

Run another node with a bootnode.
```bash
./target/debug/bitvm2-noded key gen
./target/debug/bitvm2-noded --bootnodes $BOOTNODE -d
```

if you launch multiple node in a single server, use different `rpc_addr` and `db_path`, for example,

```
./target/debug/bitvm2-noded --bootnodes $BOOTNODE -d --rpc-addr localhost:8081 --db-path /tmp/bitvm2-node-2.db
```

## Env

`ROLE`: CHALLENGER, COMMITTEE, OPERATOR
`PEER_ID`: local peer id
`KEY`: local identity private key

