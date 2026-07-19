---- MODULE Take1ChallengeRace ----
(***************************************************************************)
(* Formal model of a new bottleneck connector found while extending the    *)
(* transaction-graph audit beyond ConnectorD (see Take2DisproveRace.tla    *)
(* and audit/TLAPlus-*.md's "Cross-check"/connector-sweep follow-up).      *)
(*                                                                         *)
(* Ground truth, read directly from the external goat crate                *)
(* (checkout e369b2a, goat/src/connectors/connector_a.rs,                  *)
(* goat/src/transactions/{kickoff,take1,challenge}.rs):                    *)
(*   - KickoffTransaction creates ConnectorA's output (kickoff.rs:67-71,   *)
(*     output_0 = connector_a.generate_taproot_address()) - this is the    *)
(*     single shared clock root for both leaves below.                    *)
(*   - ConnectorA leaf 0: operator key + CSV(connector_a) (connector_a.rs: *)
(*     37-46) - spent by Take1Transaction (take1.rs:73-74, input_1_leaf=0),*)
(*     the operator's uncontested fast-exit path.                          *)
(*   - ConnectorA leaf 1: n-of-n committee key, NO CSV at all               *)
(*     (connector_a.rs:48-54) - spent by ChallengeTransaction               *)
(*     (challenge.rs:56-57, input_0_leaf=1) using SinglePlusAnyoneCanPay    *)
(*     (challenge.rs:93), so any third-party challenger can add their own   *)
(*     fee input and force this tx through the instant it's noticed.       *)
(* Same ConnectorA output, different leaves - ordinary UTXO semantics mean  *)
(* whichever of Take1/Challenge confirms first wins it permanently. Unlike  *)
(* ConnectorD (Take2 vs Disprove), this is a single-clock race: Challenge   *)
(* is spendable immediately once Kickoff confirms, so the entire margin a   *)
(* challenger has to detect fraud and get Challenge confirmed IS            *)
(* connector_a's own CSV value, in blocks, from Kickoff's confirmation.     *)
(*                                                                         *)
(* crates/bitvm-gc/src/timelocks.rs's validate_timelock_config (69-101)    *)
(* checks connector_a is merely nonzero (73-81) but - unlike every other   *)
(* named timelock field - never puts it in any ensure_lt/ensure_lte        *)
(* comparison (91-99). There is no enforcement anywhere in the codebase    *)
(* that connector_a leaves a challenger enough real-world reaction time,   *)
(* on ANY network, not just the boundary case this module happens to find. *)
(* MinReactionBlocks is the same ~1-hour-of-reaction-time policy floor     *)
(* Take2DisproveRace.tla already established and validated for the         *)
(* analogous ConnectorD/ProverConnector race - reused here, not re-derived,*)
(* since it's the same real-world assumption (off-chain fraud detection +  *)
(* tx construction + broadcast + confirmation lag) applied to a different  *)
(* connector.                                                              *)
(***************************************************************************)
EXTENDS Integers

Networks == {"Bitcoin", "Testnet4", "Signet", "Regtest"}

\* Real shipped values, crates/bitvm-gc/src/timelocks.rs (current code -
\* NO validation of this field's margin exists anywhere).
ConnectorA == [Bitcoin |-> 144, Testnet4 |-> 16, Signet |-> 6, Regtest |-> 1]

\* Proposed fix design (not applied to code): add an
\* ensure_gt("connector_a", config.connector_a, "min_reaction_blocks", ...)
\* check to validate_timelock_config, mirroring Finding 4's floor. Bumping
\* just the one network that actually needs it (Regtest 1 -> 2) is enough
\* to satisfy that check with the current values elsewhere already clear.
ConnectorAFixed == [Bitcoin |-> 144, Testnet4 |-> 16, Signet |-> 6, Regtest |-> 2]

\* Take2DisproveRace.tla's policy floor, reused verbatim (same real-world
\* reaction-time assumption, different connector).
MinReactionBlocks == [Bitcoin |-> 6, Testnet4 |-> 12, Signet |-> 1, Regtest |-> 1]

VARIABLE net
vars == <<net>>

Init == net \in Networks
Next == FALSE  \* no transitions - exhaustive check over Init, same idiom as Take2DisproveRace.tla
Spec == Init /\ [][Next]_vars

\* The property connector_a's margin exists to guarantee but nothing in
\* the code currently checks: a challenger has strictly more than the
\* assumed real-world reaction-time floor, from Kickoff's confirmation, to
\* detect fraud and get a Challenge transaction confirmed before the
\* operator's Take1 CSV (rooted at that same confirmation) elapses.
ChallengeHasSufficientReactionMargin == ConnectorA[net] > MinReactionBlocks[net]
ChallengeHasSufficientReactionMarginFixed == ConnectorAFixed[net] > MinReactionBlocks[net]

====
