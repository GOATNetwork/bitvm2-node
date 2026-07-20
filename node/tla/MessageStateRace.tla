---- MODULE MessageStateRace ----
(***************************************************************************)
(* Formal model of a race found while auditing every remaining stateful    *)
(* enum after GraphStatus/InstanceBridgeInStatus (see audit/TLAPlus-*.md). *)
(*                                                                         *)
(* `MessageState` (crates/store/src/schema.rs:431-437: Pending, Processed, *)
(* Failed, Expired, Cancelled) tracks P2P message delivery/processing      *)
(* status. Unlike the GraphStatus/InstanceBridgeOutStatus findings, the    *)
(* "cancel" writer here IS correctly guarded - `update_messages_state_by_  *)
(* business_id` (crates/store/src/localdb.rs) does a real CAS: `UPDATE ... *)
(* WHERE business_id=? AND state='Pending'`, called from                   *)
(* node/src/scheduled_tasks/event_watch_task.rs's handle_withdraw_paths_/  *)
(* disproved_events when a graph reaches a closed on-chain status          *)
(* (OperatorTake1/OperatorTake2/Disprove) - bulk-cancelling any still-     *)
(* Pending message for that graph as moot.                                 *)
(*                                                                         *)
(* The bug is on the OTHER side: `upsert_message` (node/src/utils.rs,      *)
(* called by push_local_unhandled_messages - the generic "defer/retry      *)
(* this p2p message" primitive used ~30 times across node/src/handle.rs)   *)
(* with `is_update=true` unconditionally sets state back to Pending via    *)
(* `INSERT ... ON CONFLICT(message_id) DO UPDATE SET state=excluded.state` *)
(* - no WHERE clause is possible on an upsert, so a message the system     *)
(* just administratively marked Cancelled (because its graph is already    *)
(* finalized) can be silently resurrected to Pending and re-dispatched     *)
(* the next time a handler in the swarm-message task calls a retry/defer   *)
(* on it, unrelated to the cancellation.                                   *)
(***************************************************************************)
Statuses == {"Pending", "Cancelled"}

\* Cancelled is an administrative "this message is moot, stop touching it"
\* marker tied to its graph reaching a closed status - it must stay final.
TerminalStatuses == {"Cancelled"}

VARIABLE status
vars == <<status>>

TypeOK == status \in Statuses

Init == status = "Pending"

--------------------------------------------------------------------------
\* event_watch_task.rs's handle_withdraw_paths_events / handle_withdraw_
\* disproved_events, via update_messages_state_by_business_id - a genuine
\* CAS, correctly guarded in the real code.
BulkCancelOnGraphClose ==
    /\ status = "Pending"
    /\ status' = "Cancelled"

\* push_local_unhandled_messages -> utils::upsert_message(is_update=true)
\* -> store upsert_message's `ON CONFLICT DO UPDATE SET state=excluded.state`
\* - confirmed NO guard of any kind. Fires from ~30 call sites in
\* node/src/handle.rs whenever a message handler needs to defer/retry,
\* with no awareness of whether the message was since cancelled.
ResurrectPendingUnconditional == status' = "Pending"

Next ==
    \/ BulkCancelOnGraphClose
    \/ ResurrectPendingUnconditional

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Next)

\* Proposed fix design (not applied to code): guard the resurrect-to-Pending
\* write the same way - only apply it if the message isn't already in a
\* terminal status, folded into the UPDATE/upsert's WHERE clause.
NextFixed ==
    \/ BulkCancelOnGraphClose
    \/ (status \notin TerminalStatuses /\ ResurrectPendingUnconditional)

SpecFixed == Init /\ [][NextFixed]_vars
FairSpecFixed == SpecFixed /\ WF_vars(NextFixed)

--------------------------------------------------------------------------
\* Safety property: once a message is administratively Cancelled, it must
\* never be resurrected and re-dispatched.
TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_status

====
