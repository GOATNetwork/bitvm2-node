# Node

## Build

```bash
BITCOIN_NETWORK=regtest cargo build -r
```

## Graph State Machines

Based on `crates/store/src/schema.rs::GraphStatus` and `node/src/scheduled_tasks/graph_maintenance_tasks.rs`.

### Main Graph Status Transitions

```mermaid
---
title: Graph Lifecycle - GraphStatus Transitions
---
stateDiagram-v2
    [*] --> OperatorPresigned: Create graph
    
    OperatorPresigned --> CommitteePresigned: Committee presigns
    CommitteePresigned --> OperatorDataPushed: Operator pushes L2 data
    OperatorDataPushed --> PreKickoff: PreKickoff tx confirmed
    
    PreKickoff --> OperatorKickOff: Kickoff tx broadcast
    PreKickoff --> Skipped: Guardian/ForceSkip triggered
    
    OperatorKickOff --> Challenge: WatchtowerChallengeInit confirmed
    OperatorKickOff --> OperatorTake1: Timeout (Take1 path)
    
    Challenge --> Disprove: Challenge detected or timeout
    Challenge --> OperatorTake1: All resolved normally
    
    Disprove --> OperatorTake2: Disprove verified
    
    OperatorTake1 --> [*]
    OperatorTake2 --> [*]
    Skipped --> [*]
    Obsoleted --> [*]
    
    note right of Challenge
        Involves three sub-processes:
        - WatchtowerChallengeStatus
        - CommitBlockHashStatus
        - AssertCommitStatus
    end note
```

### Challenge Phase: WatchtowerChallengeStatus

From `src/scheduled_tasks/graph_maintenance_tasks.rs::WatchtowerChallengeStatus`:

```mermaid
---
title: WatchtowerChallengeStatus - Challenge Phase Tracking
---
stateDiagram-v2
    [*] --> None
    
    None --> OperatorInit: WatchtowerChallengeInitTx confirmed
    
    OperatorInit --> WatchtowerChallenge: Watchtowers may challenge
    OperatorInit --> WatchtowerChallengeTimeout: No watchtower challenges
    
    WatchtowerChallenge --> WatchtowerChallengeNormalFinished: All watchtowers ACK
    WatchtowerChallenge --> WatchtowerChallengeDisproveFinished: Any NACK/timeout
    WatchtowerChallenge --> OperatorACKTimeout: Operator ACK timeout
    
    WatchtowerChallengeTimeout --> WatchtowerChallengeDisproveFinished
    OperatorACKTimeout --> WatchtowerChallengeDisproveFinished
    
    WatchtowerChallengeNormalFinished --> [*]
    WatchtowerChallengeDisproveFinished --> [*]
    
    note right of OperatorInit
        Each watchtower index has item status:
        - OperatorInit → Challenge → OperatorACK/NACK
        - OperatorInit → ChallengeTimeout
    end note
```

### Challenge Phase: CommitBlockHashStatus

From `src/scheduled_tasks/graph_maintenance_tasks.rs::CommitBlockHashStatus`:

```mermaid
---
title: CommitBlockHashStatus - Operator Commitment Tracking
---
stateDiagram-v2
    [*] --> None
    
    None --> WatchtowerChallengeProcessed: Monitor challenges start
    
    WatchtowerChallengeProcessed --> OperatorCommit: Operator commits blockhash
    WatchtowerChallengeProcessed --> OperatorCommitTimeout: Timelock expires
    
    OperatorCommit --> [*]
    OperatorCommitTimeout --> [*]
    
    note right of WatchtowerChallengeProcessed
        Waits for WatchtowerChallengeStatus
        to complete before proceeding
    end note
```

### Challenge Phase: AssertCommitStatus

From `src/scheduled_tasks/graph_maintenance_tasks.rs::AssertCommitStatus`:

```mermaid
---
title: AssertCommitStatus - Assert Phase Tracking
---
stateDiagram-v2
    [*] --> None
    
    None --> OperatorInit: AssertInitTx confirmed
    
    OperatorInit --> OperatorCommit: Operator commits assertion
    OperatorInit --> OperatorCommitTimeout: Timelock expires
    
    OperatorCommit --> [*]
    OperatorCommitTimeout --> [*]
```

### Per-Watchtower Item Status

From `src/scheduled_tasks/graph_maintenance_tasks.rs::WatchtowerChallengeItemStatus`:

```mermaid
---
title: WatchtowerChallengeItemStatus - Individual Watchtower Tracking
---
stateDiagram-v2
    [*] --> OperatorInit
    
    OperatorInit --> Challenge: Watchtower sends challenge
    OperatorInit --> ChallengeTimeout: Timelock expires without challenge
    
    Challenge --> OperatorACK: Operator accepts challenge claim
    Challenge --> OperatorNACK: Operator rejects challenge claim
    Challenge --> ChallengeTimeout: Operator response timelock expires
    
    OperatorACK --> [*]
    OperatorNACK --> [*]
    ChallengeTimeout --> [*]
    
    note right of Challenge
        Per-watchtower ACK/NACK determines
        disprove necessity
    end note
```

## Core Data Structures

### ChallengeSubStatus

From `src/scheduled_tasks/graph_maintenance_tasks.rs`:

```rust
pub struct ChallengeSubStatus {
    pub watchtower_challenge_status: WatchtowerChallengeStatus,
    pub commit_blockhash_status: CommitBlockHashStatus,
    pub assert_commit_status: AssertCommitStatus,
    pub disprove_type: Option<DisproveTxType>,
    pub disprove_index: i32,
}
```

### WTInitTxVoutMonitorData

From `src/scheduled_tasks/graph_maintenance_tasks.rs`:

```rust
pub struct WTInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, WatchtowerChallengeItemStatus>,
    pub require_disproved_indexes: Vec<usize>,
    pub commit_blockhash_status: CommitBlockHashStatus,
    pub is_challenge_timeout_sent: bool,
}
```

Tracks per-watchtower status during challenge phase. If any item transitions to `Challenge`, `ChallengeTimeout`, or `OperatorNACK`, it's added to `require_disproved_indexes`.

## Key Implementation Files

- `src/action.rs` - Message dispatch via `recv_and_dispatch()`
- `src/scheduled_tasks/graph_maintenance_tasks.rs` - Main challenge monitoring logic:
  - `process_watchtower_challenge_monitoring()` - Track challenges
  - `process_commit_blockhash_monitoring()` - Track blockhash commitment
  - `process_assert_commit_monitoring()` - Track assert phase
- `src/utils.rs` - Graph refresh: `refresh_graph()` updates status based on Bitcoin state
- `crates/store/src/schema.rs` - `GraphStatus` and related enums
