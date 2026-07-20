---- MODULE ShippedTimelocks ----
(***************************************************************************)
(* Real per-network timelock values, transcribed from                      *)
(* crates/bitvm-gc/src/timelocks.rs, shared by every margin-arithmetic     *)
(* spec in this directory (Take2DisproveRace.tla, MultiActorRace.tla,      *)
(* Take1ChallengeRace.tla) - single source of truth instead of each spec   *)
(* re-transcribing its own copy.                                          *)
(*                                                                         *)
(* ConnectorD here is the PROPOSED FIX value (35 on testnet4), not the raw *)
(* currently-shipped value (34, the exact boundary Take2DisproveRace.tla's *)
(* bug-discovery run found) - every spec that EXTENDS this module models   *)
(* the fix design, consistent with each of their own README-documented     *)
(* "proposed fix (verified, not applied)" status. connector_a is NOT here  *)
(* - Take1ChallengeRace.tla defines its own ConnectorA/ConnectorAFixed     *)
(* locally, since that value pair is the actual subject under test in that *)
(* spec, not a settled "known good" constant.                              *)
(***************************************************************************)

Networks == {"Bitcoin", "Testnet4", "Signet", "Regtest"}

ProverConnector     == [Bitcoin |-> 144, Testnet4 |-> 22, Signet |-> 6, Regtest |-> 1]
ConnectorD          == [Bitcoin |-> 432, Testnet4 |-> 35, Signet |-> 18, Regtest |-> 3]  \* post-fix
WatchtowerChallenge == [Bitcoin |-> 144, Testnet4 |-> 34, Signet |-> 6, Regtest |-> 1]
OperatorAck         == [Bitcoin |-> 288, Testnet4 |-> 46, Signet |-> 12, Regtest |-> 2]
OperatorCommit      == [Bitcoin |-> 432, Testnet4 |-> 58, Signet |-> 18, Regtest |-> 3]
ConnectorF          == [Bitcoin |-> 576, Testnet4 |-> 70, Signet |-> 24, Regtest |-> 4]

\* Policy floor, not itself a timelocks.rs field: the assumed real-world
\* reaction-time bound (~1 hour) used across every margin-race spec.
MinReactionBlocks == [Bitcoin |-> 6, Testnet4 |-> 12, Signet |-> 1, Regtest |-> 1]

====
