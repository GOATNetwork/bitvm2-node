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
    OperatorPresigned --> Obsoleted: PreKickoff on-chain but data not posted
    
    CommitteePresigned --> OperatorDataPushed: Operator pushes L2 data
    CommitteePresigned --> Obsoleted: PreKickoff on-chain but data not posted
    
    OperatorDataPushed --> PreKickoff: PreKickoff tx confirmed on Bitcoin
    OperatorDataPushed --> Obsoleted: Pegin not withdrawable & no withdraw request
    
    PreKickoff --> OperatorKickOff: Kickoff tx broadcast
    PreKickoff --> Skipped: Guardian/ForceSkip triggered
    
    OperatorKickOff --> OperatorTake1: Timeout without challenge
    OperatorKickOff --> Challenge: WatchtowerChallengeInit confirmed
    
    Challenge --> Disprove: Disprove needed<br/>(challenge/timeout detected)
    Challenge --> OperatorTake2: Normal completion<br/>(all challenges passed)
    
    OperatorTake1 --> [*]
    OperatorTake2 --> [*]
    Skipped --> [*]
    Obsoleted --> [*]
    Disprove --> [*]
    
    note right of Challenge
        Sub-phases tracked by ChallengeSubStatus:
        1. Watchtower Challenge Phase
           - Watchers may challenge
           - Operator ACK/NACK responses
        2. CommitBlockHash Phase
           - Operator commits blockhash
        3. Assert Commit Phase
           - Operator commits assertions
    end note
    
    note right of Disprove
        Triggered when any challenge
        or timeout detected during
        Challenge phase sub-phases
    end note
    
    note right of Obsoleted
        Reimbursement by other operators
        or graph data not posted in time
    end note
    
    note right of OperatorPresigned
        Frontend-only states for UI:
        - Created, Presigned, L2Recorded
        - OperatorKickOffing, Challenging
        - Disproving
    end note
```

### Challenge to OperatorTake2 Flow

The path from Challenge → OperatorTake2 requires successful completion of three sub-phases:

```mermaid
---
title: Challenge Phase Flow to OperatorTake2
---
stateDiagram-v2
    [*] --> Challenge
    
    Challenge --> WTPhase: Enter Watchtower Challenge Phase
    Challenge --> Disprove: Challenge/Timeout<br/>detected
    
    WTPhase --> WTInit: WatchtowerChallengeInitTx<br/>confirmed
    WTInit --> WTChallenge: Watchtowers may challenge
    WTInit --> WTTimeout: No watchtower<br/>challenges
    
    WTChallenge --> WTAllACK: All watchtowers ACK
    WTChallenge --> Disprove: Any NACK or timeout
    
    WTTimeout --> Disprove: Timeout expired
    
    WTAllACK --> BlockHashPhase: Proceed to BlockHash Phase
    
    BlockHashPhase --> BlockHashWait: Wait for<br/>WatchtowerChallenge<br/>completion
    BlockHashWait --> BlockHashCommit: Operator commits<br/>blockhash
    BlockHashWait --> Disprove: Commit timeout
    
    BlockHashCommit --> AssertPhase: Proceed to Assert Phase
    
    AssertPhase --> AssertInit: AssertInitTx confirmed
    AssertInit --> AssertCommit: Operator commits<br/>assertions
    AssertInit --> Disprove: Assert timeout
    
    AssertCommit --> CheckComplete: All phases complete?
    
    CheckComplete --> OperatorTake2: Yes - All conditions met<br/>✓ WatchtowerChallengeNormalFinished<br/>✓ BlockHash committed<br/>✓ Assertions committed
    CheckComplete --> Disprove: No - Missing conditions
    
    OperatorTake2 --> [*]
    Disprove --> [*]
    
    note right of Challenge
        Initial state when
        WatchtowerChallengeInit
        confirmed on Bitcoin
    end note
    
    note right of WTPhase
        Monitor each watchtower
        for challenges or timeout
    end note
    
    note right of BlockHashPhase
        Only proceeds after
        WatchtowerChallengeStatus
        reaches normal finish
    end note
    
    note right of AssertPhase
        Operator must commit
        all assertions within
        timelock window
    end note
```

**Transition Conditions to OperatorTake2:**
- `watchtower_challenge_status == WatchtowerChallengeNormalFinished`
- `commit_blockhash_status == OperatorCommit`
- `assert_commit_status == OperatorCommit`
- `disprove_type == None` (no errors detected)

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
- `require_disproved_indexes`: Indices requiring disprove (populated for items in OperatorInit or Challenge status)
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
