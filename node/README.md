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
