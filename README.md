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
boundary conditions found in the Rust implementation. This is an **audit
pass**: the specs prove several real bugs exist in the *current* code, and
prove a correct fix design for each - but the fixes themselves have **not
been applied to the Rust code yet**. That's tracked as follow-up work; see
each spec's header comment and `node/README.md`'s "Known gap" sections for
exactly what's still open.

Concretely: for each bug found, there is a **pair** of configs - one modeling
the actual current code (still buggy - **expected to fail**, and that failure
is a real, live issue, not a historical artifact) and one modeling the
verified fix design (**expected to pass**, proving the design is sound and
ready to implement, not that it's already shipped).

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

| Spec | Config | Models | Result |
|---|---|---|---|
| `GraphLifecycle.tla` | `GraphLifecycleCoreOnly.cfg` | current code (baseline) | pass - chain-scan state machine alone is sound |
| `GraphLifecycle.tla` | `GraphLifecycle.cfg` | **current code** | **fails - live bug**: unguarded race between the Bitcoin-chain-scan and GoatChain-event writers of `Graph.status` |
| `GraphLifecycle.tla` | `GraphLifecycleFixed.cfg` | proposed fix (verified, not applied) | pass - atomic guard design closes the race |
| `GraphLifecycleFineGrained.tla` | `GraphLifecycleFineGrained.cfg` | current code | **fails - live bug**: the read/write gap a naive (non-atomic) guard would still have |
| `GraphLifecycleFineGrainedFixed.tla` | `GraphLifecycleFineGrainedFixed.cfg` | proposed fix (verified, not applied) | pass - single-statement atomic CAS design closes the gap |
| `InstancePresigned.tla` | `InstancePresignedBug.cfg` | **current code** | **fails - live bug**: `Instance.status` can regress past `Presigned` |
| `InstancePresigned.tla` | `InstancePresignedFixed.cfg` | proposed fix (verified, not applied) | pass - guard design closes the regression |
| `Take2DisproveRace.tla` | `Take2DisproveRace.cfg` | proposed fix (verified, not applied) | pass - Take2 vs. Disprove UTXO race has strict margin on all networks *with the proposed `crates/bitvm-gc/src/timelocks.rs` values*; current shipped `connector_d` for testnet4 (34) does **not** have this margin - that boundary case is how this spec found the bug in the first place |
| `MultiActorRace.tla` | `MultiActorRace.cfg` | proposed fix (verified, not applied) | pass - the 1-of-N watchtower/verifier security property holds under the same proposed timelock values, checked against 2 independent actors per role rather than 1 |
| `InstanceBridgeOutRace.tla` | `InstanceBridgeOutRace.cfg` | **current code** | **fails - live bug**: `InstanceBridgeOutStatus` can be resurrected to `Initialize` after reaching `Claim`/`Timeout`/`Refund` by a stale RPC upsert or maintenance-task write |
| `InstanceBridgeOutRace.tla` | `InstanceBridgeOutRaceFixed.cfg` | proposed fix (verified, not applied) | pass - atomic guard design (write only if not already terminal) closes the resurrection |
| `MessageStateRace.tla` | `MessageStateRace.cfg` | **current code** | **fails - live bug**: `MessageState::Cancelled` can be resurrected to `Pending` by `upsert_message`'s unconditional `ON CONFLICT DO UPDATE`, re-dispatching a message whose graph already closed |
| `MessageStateRace.tla` | `MessageStateRaceFixed.cfg` | proposed fix (verified, not applied) | pass - guarding the resurrect-to-Pending write against terminal status closes the race |

Additional standalone tools available in the jar if needed: SANY (parser/type-checker)
via `java -cp tla2tools.jar tla2sany.SANY <Spec>.tla`, and the PlusCal translator
(used to generate `GraphLifecycleFineGrained*.tla`'s TLA+ body from its PlusCal
algorithm block) via `java -cp tla2tools.jar pcal.trans <Spec>.tla`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.