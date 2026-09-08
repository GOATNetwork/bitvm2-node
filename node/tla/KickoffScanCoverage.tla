---- MODULE KickoffScanCoverage ----
(***************************************************************************)
(* Model of GOATNetwork/bitvm-node issue #431:                             *)
(*   "detect_kickoff watches only the lowest-nonce graph per operator, so  *)
(*    a kickoff on a later graph is never Challenged (unauthorized Take1)". *)
(*                                                                         *)
(* THE ORIGINAL BUG (gc-v2 @ f2f0285e): detect_kickoff sourced its graphs  *)
(* from fetch_on_turn_graph_by_status, which keeps ONE row per             *)
(* operator_pubkey - the lowest kickoff_index still at OperatorDataPushed   *)
(* (SQL: ORDER BY operator_pubkey, kickoff_index; Rust keeps the first per  *)
(* operator). An operator with two posted graphs leaves nonce 0 idle and    *)
(* kicks nonce >= 1; the kicked graph is never in the watched set, so no    *)
(* KickoffSent / Challenge is ever created for it, and after the ConnectorA *)
(* CSV the operator Take1s with pegBTC never burned. Distinct from #429     *)
(* (there the message exists but the verifier skips it on SPV lag).         *)
(*                                                                         *)
(* THE FIX (commit 2bce25d, "Fix graph maintenance logic" #451, on current  *)
(* dev): detect_kickoff now runs scan_kickoff_chain from each root, which   *)
(* walks confirmed_prekickoff_successor forward - following each graph's    *)
(* on-chain-confirmed next_prekickoff to the successor (validated           *)
(* kickoff_index == prev+1) - so the idle lowest-nonce decoy no longer      *)
(* hides a kicked successor. This closes the filed 2-graph attack.          *)
(*                                                                         *)
(* THE RESIDUAL: the walk is capped at MAX_PREKICKOFF_SUCCESSORS_PER_SCAN   *)
(* = 32 (graph_maintenance_tasks.rs). The perpetually-idle root (never      *)
(* kicked, so never advancing out of OperatorDataPushed) means the scan     *)
(* window never slides; a chain of > 32 idle decoys with the kicked graph   *)
(* beyond depth 32 is never reached on any tick. Expensive (33+ confirmed   *)
(* on-chain prekickoffs, capital-locked) but structurally open.             *)
(*                                                                         *)
(* This spec is a COVERAGE abstraction (same static-Init idiom as           *)
(* Take2DisproveRace.tla): the operator kicks graph `kicked`, keeping the   *)
(* root idle; detect_kickoff covers exactly the confirmed chain reachable   *)
(* from the root within ScanDepth. Property: the kicked graph is covered    *)
(* (hence Challenged). ScanDepth=0 models the original no-walk selection;   *)
(* ScanDepth>=NumGraphs-1 models the fix with an adequate depth budget;     *)
(* 0<ScanDepth<NumGraphs-1 models the depth-limit residual.                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    NumGraphs,   \* graphs this operator has posted (all OperatorDataPushed, nonce 0..NumGraphs-1)
    ScanDepth    \* how many confirmed prekickoff successors detect_kickoff walks from the root
                 \*   0                    = original bug (watch the root only, no chain walk)
                 \*   >= NumGraphs-1        = shipped fix with adequate budget (real MAX = 32)
                 \*   0 < d < NumGraphs-1   = depth-limit residual

Graphs == 0 .. (NumGraphs - 1)

\* The operator keeps the lowest-nonce graph idle as the decoy; it is the
\* single root detect_kickoff selects per operator (fetch_first_graph_per_
\* operator_by_status). Because it is never kicked it never leaves
\* OperatorDataPushed, so the scan window never advances past it.
Root == 0

VARIABLE kicked          \* the graph whose kickoff the operator broadcasts (no L2 initWithdraw)
vars == <<kicked>>

TypeOK == kicked \in Graphs

\* To broadcast graph `kicked`'s kickoff the operator must have confirmed the
\* prekickoff chain Root..kicked on Bitcoin (each successor's prekickoff spends
\* the prior next_prekickoff). scan_kickoff_chain therefore CAN follow that
\* confirmed chain from Root - but only up to ScanDepth successors deep. A
\* graph g is covered (its kickoff observed -> KickoffSent -> Challenge) iff
\* the walk reaches it: it lies on the confirmed chain (g <= kicked) and within
\* the depth budget (g <= ScanDepth).
WalkedSet == { g \in Graphs : g <= kicked /\ g <= ScanDepth }

Init == kicked \in Graphs
Next == UNCHANGED vars   \* exhaustive over the Init choice of `kicked`
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* Safety: every unauthorized kickoff is covered by detect_kickoff (so a
\* Challenge can fire before the operator's uncontested Take1).
\* kicked \in WalkedSet  <=>  kicked <= ScanDepth.
KickoffAlwaysCovered == kicked \in WalkedSet

====
