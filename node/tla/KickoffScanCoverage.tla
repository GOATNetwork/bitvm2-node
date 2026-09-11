---- MODULE KickoffScanCoverage ----
(************************************************************************** *)
(* Model of GOATNetwork/bitvm-node issue #431:                              *)
(*   "detect_kickoff watches only the lowest-nonce graph per operator, so   *)
(*    a kickoff on a later graph is never Challenged (unauthorized Take1)". *)
(*                                                                          *)
(* THE ORIGINAL BUG (gc-v2 @ f2f0285e): detect_kickoff sourced its graphs   *)
(* from fetch_on_turn_graph_by_status, which keeps ONE row per              *)
(* operator_pubkey - the lowest kickoff_index still at OperatorDataPushed   *)
(* (SQL: ORDER BY operator_pubkey, kickoff_index; Rust keeps the first per  *)
(* operator). An operator with two posted graphs leaves nonce 0 idle and    *)
(* kicks nonce >= 1; the kicked graph is never in the watched set, so no    *)
(* KickoffSent / Challenge is ever created for it, and after the ConnectorA *)
(* CSV the operator Take1s with pegBTC never burned. Distinct from #429     *)
(* (there the message exists but the verifier skips it on SPV lag).         *)
(*                                                                          *)
(* THE FIX (commit 2bce25d, "Fix graph maintenance logic" #451, on current  *)
(* dev): detect_kickoff now runs scan_kickoff_chain from each root, which   *)
(* walks confirmed_prekickoff_successor forward - following each graph's    *)
(* on-chain-confirmed next_prekickoff to the successor (validated           *)
(* kickoff_index == prev+1) - so the idle lowest-nonce decoy no longer      *)
(* hides a kicked successor. This closes the filed 2-graph attack.          *)
(*                                                                          *)
(* THE RESIDUAL (of #451): the walk is capped at                            *)
(* MAX_PREKICKOFF_SUCCESSORS_PER_SCAN = 32 (graph_maintenance_tasks.rs).    *)
(* With a single fixed root per operator, a chain of > 32 idle decoys with  *)
(* the kicked graph beyond depth 32 is not reached WITHIN ONE TICK. In the  *)
(* real node the window does slide across ticks - each PreKickoffSent the   *)
(* walk enqueues moves its graph to PreKickoff (already an entry) and       *)
(* force-skips the one before it - but only if verifiers keep handling      *)
(* those messages; single-tick coverage depended on that liveness.          *)
(*                                                                          *)
(* STATUS: FIXED - detect_kickoff now takes EVERY OperatorDataPushed /      *)
(* PreKickoff graph as a scan entry (fetch_all_graphs_by_status) and        *)
(* checks each entry's own kickoff directly. The chain walk (still capped   *)
(* at 32) only propagates PreKickoffSent; coverage no longer depends on     *)
(* walk depth, the root, or message handling. Modeled by ScanAllPending.    *)
(*                                                                          *)
(* This spec is a COVERAGE abstraction (same static-Init idiom as           *)
(* Take2DisproveRace.tla): the operator kicks graph `kicked`, keeping the   *)
(* root idle; detect_kickoff covers exactly the confirmed chain reachable   *)
(* from some scan entry within ScanDepth. Property: the kicked graph is     *)
(* covered (hence Challenged). With ScanAllPending = FALSE the only entry   *)
(* is the root: ScanDepth=0 models the original no-walk selection;          *)
(* ScanDepth>=NumGraphs-1 models #451 with an adequate depth budget;        *)
(* 0<ScanDepth<NumGraphs-1 models the depth-limit residual. With            *)
(* ScanAllPending = TRUE every graph is an entry and coverage holds for     *)
(* any ScanDepth, including 0.                                              *)
(************************************************************************** *)
EXTENDS Naturals

CONSTANTS
    NumGraphs,     \* graphs this operator has posted (all OperatorDataPushed, nonce 0..NumGraphs-1)
    ScanDepth,     \* how many confirmed prekickoff successors a walk follows from its entry
                   \*   0                    = no chain walk
                   \*   >= NumGraphs-1        = adequate budget for this chain (real MAX = 32)
                   \*   0 < d < NumGraphs-1   = depth-limit residual
    ScanAllPending \* FALSE = only the lowest-nonce root is a scan entry (original / #451)
                   \* TRUE  = every pending graph is a scan entry (current code)

ASSUME ScanAllPending \in BOOLEAN

Graphs == 0 .. (NumGraphs - 1)

\* The operator keeps the lowest-nonce graph idle as the decoy. Under the
\* original / #451 selection (fetch_first_graph_per_operator_by_status) it is
\* the single root detect_kickoff selects per operator; because it is never
\* kicked it never leaves OperatorDataPushed within the modeled tick.
Root == 0

\* Graphs from which detect_kickoff starts a walk this tick.
Entries == IF ScanAllPending THEN Graphs ELSE {Root}

VARIABLE kicked          \* the graph whose kickoff the operator broadcasts (no L2 initWithdraw)
vars == <<kicked>>

TypeOK == kicked \in Graphs

\* To broadcast graph `kicked`'s kickoff the operator must have confirmed the
\* prekickoff chain Root..kicked on Bitcoin (each successor's prekickoff spends
\* the prior next_prekickoff). scan_kickoff_chain therefore CAN follow that
\* confirmed chain from any entry - but only up to ScanDepth successors deep.
\* A graph g is covered (its kickoff observed -> KickoffSent -> Challenge) iff
\* some walk reaches it: it lies on the confirmed chain (g <= kicked) and is
\* within the depth budget of some entry at or below it. With the root as the
\* only entry this is g <= ScanDepth; with every graph an entry, g itself is
\* an entry at distance 0.
WalkedSet == { g \in Graphs :
                 g <= kicked /\ \E e \in Entries : e <= g /\ g - e <= ScanDepth }

Init == kicked \in Graphs
Next == UNCHANGED vars   \* exhaustive over the Init choice of `kicked`
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* Safety: every unauthorized kickoff is covered by detect_kickoff (so a
\* Challenge can fire before the operator's uncontested Take1).
\* Root-only entries: kicked \in WalkedSet  <=>  kicked <= ScanDepth.
\* All-pending entries: always true (kicked is its own entry).
KickoffAlwaysCovered == kicked \in WalkedSet

====
