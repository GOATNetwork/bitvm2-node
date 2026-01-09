# Node

## Build

```bash
BITCOIN_NETWORK=regtest cargo build -r
```

## Graph State Machines

Based on `crates/store/src/schema.rs::GraphStatus` and `node/src/scheduled_tasks/graph_maintenance_tasks.rs`.

### Main Graph Status Transitions

From `crates/store/src/schema.rs::GraphStatus`:

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
    OperatorKickOff --> OperatorTake1: Timeout without challenge
    
    Challenge --> Disprove: Challenge or timeout detected
    Challenge --> OperatorTake1: All resolved normally
    
    Disprove --> OperatorTake2: Disprove verified
    
    OperatorTake1 --> [*]
    OperatorTake2 --> [*]
    Skipped --> [*]
    Obsoleted --> [*]
    
    note right of Challenge
        Tracked by ChallengeSubStatus:
        - watchtower_challenge_status
        - commit_blockhash_status
        - assert_commit_status
    end note
    
    note right of OperatorPresigned
        Frontend-only states for UI:
        - Created, Presigned, L2Recorded
        - OperatorKickOffing, Challenging
        - Disproving
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
    [*] --> None
    
    None --> OperatorInit: WatchtowerChallengeInitTx confirmed
    
    OperatorInit --> Challenge: Watchtower sends challenge tx
    OperatorInit --> ChallengeTimeout: Timelock expires without challenge
    
    Challenge --> OperatorACK: Operator accepts challenge claim
    Challenge --> OperatorNACK: Operator rejects challenge claim
    Challenge --> ChallengeTimeout: Operator response timelock expires
    
    OperatorACK --> [*]
    OperatorNACK --> [*]
    ChallengeTimeout --> [*]
    
    note right of OperatorInit
        Watchtower index state is tracked in
        WTInitTxVoutMonitorData.data_map
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

// Helper methods:
pub fn is_watchtower_challenge_normal_finished(&self) -> bool
pub fn is_disproved(&self) -> bool
pub fn is_normal_finished(&self) -> bool
pub fn is_assert_commit_normal_finished(&self) -> bool
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

- `data_map`: Tracks status for each watchtower index
- `require_disproved_indexes`: Indices requiring disprove (populated when item status changes to ChallengeTimeout or OperatorNACK)
- `commit_blockhash_status`: Synchronized with WatchtowerChallengeStatus
- `is_challenge_timeout_sent`: Flag for timeout message tracking

### Status Enums

```rust
pub enum WatchtowerChallengeStatus {
    None,
    OperatorInit,
    WatchtowerChallenge,
    WatchtowerChallengeTimeout,
    OperatorACKTimeout,
    WatchtowerChallengeNormalFinished,
    WatchtowerChallengeDisproveFinished,
}

pub enum CommitBlockHashStatus {
    None,
    WatchtowerChallengeProcessed,
    OperatorCommit,
    OperatorCommitTimeout,
}

pub enum AssertCommitStatus {
    None,
    OperatorInit,
    OperatorCommit,
    OperatorCommitTimeout,
}

pub enum WatchtowerChallengeItemStatus {
    None,
    OperatorInit,
    Challenge,
    ChallengeTimeout,
    OperatorACK,
    OperatorNACK,
}
```

## Key Implementation Files

### Main Files

- `src/action.rs` - Message handling
  - `recv_and_dispatch()` - Routes incoming messages by type
  - Handles WatchtowerChallengeSent, OperatorAckTimeout, etc.

- `src/scheduled_tasks/graph_maintenance_tasks.rs` - Challenge phase monitoring
  - `process_watchtower_challenge_monitoring()` - Tracks watchtower challenges per index
  - `process_commit_blockhash_monitoring()` - Monitors operator blockhash commitment
  - `process_assert_commit_monitoring()` - Tracks assertion phase
  - `detect_take1()` - Checks happy path withdrawal conditions
  - `detect_take2()` - Checks disprove path withdrawal conditions

- `src/utils.rs` - Graph state updates
  - `refresh_graph()` - Scans Bitcoin and updates graph status
  - `get_watchtower_commitment()` - Fetches watchtower proofs
  - `get_operator_proof()` - Fetches operator proofs

### Data Definitions

- `crates/store/src/schema.rs` - Core enums
  - `GraphStatus` - Main graph states
  - Related `DisproveTxType`, `ProofState` enums
