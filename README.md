# GOAT Bitvm2 Node

GOAT Network's BitVM2 bridge implementation. See [GOAT BitVM2 Whitepaper](https://www.goat.network/bitvm2-whitepaper) for more details.

## Layout

- `node/`: Main node implementation, including P2P, RPC, and scheduled tasks
- `circuits/`: Circuits and proof generation logic
- `proof-builder-rpc/`: RPC server for offloading proof generation to a separate process
- `crates/`: Shared Rust crates for common types and utilities
- `deployment`: Deployment scripts and documentation


## Formal verification (TLA+)

`node/tla/` contains TLA+ specs that formally verify the graph/instance status
state machines and the peg-out timelock configuration against real races and
boundary conditions found in the Rust implementation - each `.cfg` file notes
in a comment whether it's expected to pass (the fix) or fail with a
counterexample (the bug it demonstrates).

**Setup** (once): install a JRE (11+) and download the official TLA+ tools jar:

```bash
sudo apt-get install -y openjdk-21-jre-headless   # or any JRE 11+
mkdir -p ~/.local/share/tlaplus
curl -sL -o ~/.local/share/tlaplus/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
```

**Run a spec**:

```bash
cd node/tla
java -jar ~/.local/share/tlaplus/tla2tools.jar -config <Spec>.cfg <Spec>.tla
```

| Spec | Config | Expected |
|---|---|---|
| `GraphLifecycle.tla` | `GraphLifecycleCoreOnly.cfg` | pass - chain-scan state machine alone is sound |
| `GraphLifecycle.tla` | `GraphLifecycle.cfg` | **fails** - unguarded race between the Bitcoin-chain-scan and GoatChain-event writers of `Graph.status` |
| `GraphLifecycle.tla` | `GraphLifecycleFixed.cfg` | pass - with the atomic guard fix applied |
| `GraphLifecycleFineGrained.tla` | `GraphLifecycleFineGrained.cfg` | **fails** - exposes the read/write gap in a naive (non-atomic) guard implementation |
| `GraphLifecycleFineGrainedFixed.tla` | `GraphLifecycleFineGrainedFixed.cfg` | pass - single-statement atomic CAS closes the gap |
| `InstancePresigned.tla` | `InstancePresignedBug.cfg` | **fails** - `Instance.status` can regress past `Presigned` |
| `InstancePresigned.tla` | `InstancePresignedFixed.cfg` | pass - with the guard fix applied |
| `Take2DisproveRace.tla` | `Take2DisproveRace.cfg` | pass - Take2 vs. Disprove UTXO race has strict margin on all networks (also how the testnet4 timelock boundary bug in `crates/bitvm-gc/src/timelocks.rs` was found) |

Additional standalone tools available in the jar if needed: SANY (parser/type-checker)
via `java -cp tla2tools.jar tla2sany.SANY <Spec>.tla`, and the PlusCal translator
(used to generate `GraphLifecycleFineGrained*.tla`'s TLA+ body from its PlusCal
algorithm block) via `java -cp tla2tools.jar pcal.trans <Spec>.tla`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.