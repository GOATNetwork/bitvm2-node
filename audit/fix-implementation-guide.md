# Fix Implementation Guide

**Companion to `audit/TLAPlus-20260630.md`.** This is a write-up only — no code in this repository has been changed to apply these suggestions. Each section below gives the exact current code, the exact suggested change, and why it closes the gap the corresponding TLA+ spec proved. Someone applying these should re-run the relevant `.cfg`/`.tla` pair after each change (see root `README.md`'s "Formal verification (TLA+)" section) and move that finding's bug config from `.github/workflows/ci.yml`'s must-fail list to its `*Fixed.cfg` in the must-pass list.

All snippets below are the *actual current code on this branch* (`audit/round-1`, base `gc-v2`) as of this writing — not paraphrased.

---

## Findings 1, 1b, and 2 — one shared fix, one shared function

`Graph.status` (Findings 1/1b) and the `InstanceBridgeInStatus::Presigned` side-effect write (Finding 2) both go through the *same* function, `node/src/utils.rs`'s `update_graph_status` (currently lines 5185–5227):

```rust
pub async fn update_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    new_status: GraphStatus,
    sub_status: Option<ChallengeSubStatus>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    match storage_processor.find_graph(&graph_id).await? {
        Some(graph) => {
            if graph.status == new_status.to_string()
                && let Some(ref sub_status) = sub_status
                && *sub_status == ChallengeSubStatus::default()
            {
                warn!("... so not update");
                return Ok(());
            }
        }
        None => {
            warn!("graph: {graph_id} is not update, so not update");
            return Ok(());
        }
    }

    if new_status == GraphStatus::CommitteePresigned {
        storage_processor
            .update_instance(
                &InstanceUpdate::new_with_instance_id(instance_id)
                    .with_status(InstanceBridgeInStatus::Presigned.to_string()),
            )
            .await?;
    }

    let mut graph_update = GraphUpdate::new(graph_id).with_status(new_status.to_string());
    if let Some(sub_status) = sub_status {
        graph_update = graph_update.with_sub_status(serde_json::to_string(&sub_status)?);
    }

    storage_processor.update_graph(&graph_update).await?;
    Ok(())
}
```

This function is called from both real writers this audit modeled — `scan_graph_chain_state` (`ChainScan` in `GraphLifecycle.tla`) and the GoatChain event handlers in `event_watch_task.rs` (`GoatRace`) — with no coordination between callers. It has exactly the TOCTOU shape `GraphLifecycleFineGrained.tla` demonstrates: `find_graph` (the read) and `update_graph` (the write) are two separate `.await` points, so another caller's full read-decide-write can land in between.

### Step 1 — add a status guard to the SQL layer

`GraphUpdate` and `InstanceUpdate` (`crates/store/src/localdb.rs:207` and `:501`) build their SQL via `QueryBuilder` (`crates/store/src/utils.rs`), which **already has exactly the right primitive**: `and_where_in(field, values, not_in)` (`utils.rs:77-92`) appends `WHERE field IN (?,?,...)` (or `AND ... IN` if a `WHERE` is already present) and binds every value as a `QueryParam::Text` in order — no new SQL-building code needed, just wire it up. Add a new optional field to both structs:

```rust
// GraphUpdate (localdb.rs:501)
pub struct GraphUpdate {
    pub graph_id: Uuid,
    pub status: Option<String>,
    // ... existing fields ...
    pub only_if_status_in: Option<Vec<String>>,   // NEW
}

impl GraphUpdate {
    pub fn with_only_if_status_in(mut self, statuses: Vec<String>) -> Self {
        self.only_if_status_in = Some(statuses);
        self
    }
    // in get_query_builder(), alongside the existing `and_where("hex(...)=?", ...)` call:
    if let Some(ref statuses) = self.only_if_status_in {
        query_builder.and_where_in("status", statuses, false);
    }
}
```

Do the identical thing for `InstanceUpdate` (`localdb.rs:207`). One ordering note: `and_where`/`and_where_in` both switch on whether the SQL already contains the literal string `"WHERE"` to decide `WHERE` vs `AND` — so whichever guard call runs first (the existing `hex(graph_id)=?`/`hex(instance_id)=?` clause, or this new `only_if_status_in` one) determines which keyword the *other* one gets. Either order produces correct SQL (`WHERE a=? AND status IN (...)` vs `WHERE status IN (...) AND a=?`), just keep both calls in `get_query_builder` so the combined `WHERE ... AND ...` always includes both conditions.

Also change `update_graph`'s return type from `()` to `bool` (mirroring `update_instance`'s existing `Ok(result.rows_affected() > 0)` pattern at `localdb.rs:1036`), so callers can tell whether the guarded write actually happened:

```rust
pub async fn update_graph(&mut self, params: &GraphUpdate) -> anyhow::Result<bool> {
    let query_builder = params.get_query_builder("graph");
    let update_sql = query_builder.get_sql();
    let query = sqlx::query(&update_sql);
    let query = query_builder.query(query);
    let result = query.execute(self.conn()).await?;
    Ok(result.rows_affected() > 0)
}
```

### Step 2 — apply the two guard clauses `GraphLifecycle.tla`'s `GuardOK` proves are both necessary

The first draft of this fix that only refused writes *off* a closed/terminal status was found by TLC to still fail `EventuallyTerminal` — `OperatorDataPushed` could still be re-written after the graph progressed past it, combined with `Obsoleted`'s resurrection edges, cycling forever. `GraphLifecycle.tla`'s `GuardOK` (and the deduplicated `GraphTopology.tla` module's `TerminalStatuses`) encodes both clauses that turned out to be necessary:

```rust
pub async fn update_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    new_status: GraphStatus,
    sub_status: Option<ChallengeSubStatus>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;

    // Guard 1: never write OFF a terminal status. GraphStatus doesn't derive
    // EnumIter, so this is hardcoded directly from GraphTopology.tla's
    // AllStatuses \ TerminalStatuses rather than computed from
    // GraphStatus::is_closed() (which exists, schema.rs:326, but there's no
    // enumerable "all variants" to filter with it without adding a new
    // derive) - keeps the guard's allow-list textually traceable to the
    // already-verified TLA+ set instead of introducing a second, easy-to-
    // drift copy of the same status list.
    let mut allowed_from: Vec<String> = vec![
        GraphStatus::OperatorPresigned.to_string(),
        GraphStatus::CommitteePresigned.to_string(),
        GraphStatus::OperatorDataPushed.to_string(),
        GraphStatus::PreKickoff.to_string(),
        GraphStatus::OperatorKickOff.to_string(),
        GraphStatus::Challenge.to_string(),
        GraphStatus::Obsoleted.to_string(),
    ];

    // Guard 2: OperatorDataPushed specifically may only be (re)written while
    // the graph hasn't progressed past it - a correctly functioning node
    // never needs to "re-push" data after kickoff has already happened.
    if new_status == GraphStatus::OperatorDataPushed {
        allowed_from = vec![
            GraphStatus::OperatorPresigned.to_string(),
            GraphStatus::CommitteePresigned.to_string(),
            GraphStatus::OperatorDataPushed.to_string(),
        ];
    }

    if new_status == GraphStatus::CommitteePresigned {
        storage_processor
            .update_instance(
                &InstanceUpdate::new_with_instance_id(instance_id)
                    .with_status(InstanceBridgeInStatus::Presigned.to_string())
                    // Finding 2's fix, same pattern: only regress-proof write
                    // Presigned while the instance hasn't already advanced.
                    .with_only_if_status_in(vec![
                        InstanceBridgeInStatus::UserIniting.to_string(), // "Early" in InstancePresigned.tla
                        InstanceBridgeInStatus::Presigned.to_string(),
                    ]),
            )
            .await?;
    }

    let graph_update = GraphUpdate::new(graph_id)
        .with_status(new_status.to_string())
        .with_only_if_status_in(allowed_from);
    let graph_update = match sub_status {
        Some(sub_status) => graph_update.with_sub_status(serde_json::to_string(&sub_status)?),
        None => graph_update,
    };

    storage_processor.update_graph(&graph_update).await?;
    // Note: the old no-op-if-status-already-equal short-circuit (the
    // `find_graph` read at the top of the original function) is gone -
    // it's now subsumed by the WHERE clause. A no-op write (0 rows
    // affected because the guard rejected it) is expected and NOT an
    // error; do not `bail!` on `!update_graph(...)`.
    Ok(())
}
```

The critical property, proven by `GraphLifecycleFineGrainedFixed.tla` (132 reachable states, all properties hold): the guard-check and the write must be **one atomic SQL statement** (`UPDATE ... WHERE status IN (...)`), not a `SELECT` followed by an `UPDATE` — even with identical guard logic, splitting them back into two steps re-opens the exact gap `GraphLifecycleFineGrained.tla`'s bug config demonstrates. The `find_graph`-then-`update_graph` shape in the *original* function above is precisely that anti-pattern; Step 1/2 replace it with a single guarded statement instead of removing the read and leaving the write unguarded.

**Exact WHERE clause shape**, matching `Take2DisproveRace.tla`... no — matching `GraphLifecycleFixed.cfg`'s guard: `UPDATE graph SET status = ?, ... WHERE graph_id = ? AND status IN (<allowed_from>)`.

**Files touched**: `crates/store/src/schema.rs` (if `only_if_status_in`/`with_only_if_status_in` belongs on a builder defined there instead of `localdb.rs` — check which file actually owns `GraphUpdate`/`InstanceUpdate` before implementing, this guide found them in `localdb.rs`), `crates/store/src/localdb.rs`, `node/src/utils.rs`. No `.sqlx` query-cache regeneration needed here since these use the runtime `QueryBuilder`, not the `sqlx::query!` macro — but confirm by running `cargo sqlx prepare --check` (or just `cargo check`) after the change.

---

## Finding 6 — `InstanceBridgeOutStatus`, three call sites, same guard mechanism

Reuses the `InstanceUpdate::with_only_if_status_in` from above. Three sites need it, and one of them needs a bigger structural change first because it currently doesn't use the guardable code path at all.

### 6a. `bridge_out_init_tag` (`node/src/rpc_service/handler/bitvm2_handler.rs:308-368`)

Current (relevant excerpt):
```rust
if let Some(mut instance) = find_instances_by_escrow_hash(&mut storage_process, &escrow_hash).await? {
    if instance.status == InstanceBridgeOutStatus::Initialize.to_string() {
        instance.to_addr = payload.to_addr.clone();
        instance.network = get_network().to_string();
        storage_process.upsert_instance(&instance).await?;   // <-- full-row INSERT OR REPLACE
    }
    return ok_response(BridgeOutInitTagResponse {});
}
```

The `if instance.status == Initialize` check reads a **stale, already-fetched** `instance` — it's checking the in-memory copy from the `find_instances_by_escrow_hash` call a few lines up, not the row's live value at write time. And `upsert_instance` (`localdb.rs:806-813`) is a literal `INSERT OR REPLACE INTO instance (...)` full-row statement — there is no `WHERE` clause possible on that statement shape at all, so even a live re-check couldn't be folded into it.

**Fix**: stop using `upsert_instance` for this update. Switch to a targeted, guarded `update_instance`:
```rust
if let Some(instance) = find_instances_by_escrow_hash(&mut storage_process, &escrow_hash).await? {
    storage_process.update_instance(
        &InstanceUpdate::new_with_instance_id(instance.instance_id)
            .with_to_addr(payload.to_addr.clone())
            .with_only_if_status_in(vec![InstanceBridgeOutStatus::Initialize.to_string()]),
    ).await?;
    // network field: only set on genuine first-insert (the `let mut instance = Instance { ... }`
    // branch further down already sets it at construction time) - drop the
    // redundant re-set of `network` on the existing-row path entirely, it
    // never needs to change post-creation.
    return ok_response(BridgeOutInitTagResponse {});
}
```

### 6b. GoatChain L2-event watcher (`node/src/scheduled_tasks/event_watch_task.rs:634-669`, SwapClaimEvent/SwapRefundEvent handlers)

Current (relevant excerpt):
```rust
if let Some(mut instance) = instance {
    instance.bridge_out_amount = escrow_data.amount.to_string();
    // ... several more field sets ...
    instance.status_updated_at = create_time;
    storage_processor.upsert_instance(&instance).await?;   // <-- full-row again
    ...
}
```

Same shape, same fix direction: switch the update path for an *existing* instance from `upsert_instance` to a targeted `update_instance` with `.with_only_if_status_in(vec![InstanceBridgeOutStatus::Initialize.to_string()])`. This is a bigger lift than 6a: `InstanceUpdate`'s current field list (`localdb.rs:207-219`) is `instance_id, escrow_hash, from_addr, to_addr, btc_txid, status, pegin_confirm_txid, post_pegin_txhash, btc_height, committees_answers, bridge_out_lock_time` — **none** of `bridge_out_amount`, `goat_tx_hash`, `goat_tx_height`, `user_change_addr`, `user_refund_addr` exist on it yet, so all five need adding as new `Option<T>` fields plus `with_*` builder methods (following the exact pattern `with_btc_txid`/`with_to_addr` already use at `localdb.rs:255-270`) and corresponding `set_field(...)` calls in `get_query_builder`. `upsert_instance` should be reserved for the genuine new-instance-creation branch a few lines above this one (the `else` branch that builds a fresh `Instance { .. }`), which is a real insert, not a status-bearing update.

### 6c. `instance_bridge_out_monitor` (`node/src/scheduled_tasks/instance_maintenance_tasks.rs:482-517`)

This one already uses the guardable path — it just doesn't set the guard:
```rust
if lock_time < current_time && lock_time > 0 {
    instance_update = instance_update.with_status(InstanceBridgeOutStatus::Timeout.to_string());
}
if instance_update.has_updates() {
    storage_processor.update_instance(&instance_update).await?;
}
```
Fix is a one-line addition:
```rust
if lock_time < current_time && lock_time > 0 {
    instance_update = instance_update
        .with_status(InstanceBridgeOutStatus::Timeout.to_string())
        .with_only_if_status_in(vec![InstanceBridgeOutStatus::Initialize.to_string()]);
}
```
(The batch read (`find_one_instance_page(...).with_status(Initialize)`) already scopes the *candidates* to `Initialize` — this addition re-checks that at write time too, closing the staleness window between batch-read and per-row write that `InstanceBridgeOutRace.tla`'s 3-state counterexample demonstrates.)

---

## Finding 7 — `MessageState`, `upsert_message`

Current (`crates/store/src/localdb.rs:1973-2003`, using the `sqlx::query!` compile-time-checked macro):
```rust
pub async fn upsert_message(&mut self, msg: Message) -> anyhow::Result<bool> {
    let current_time = get_current_timestamp_secs();
    let res = sqlx::query!(
        r#"INSERT INTO message (message_id, business_id, from_peer, actor, msg_type, content, state, message_version, lock_time_until, weight, updated_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(message_id) DO UPDATE SET business_id = excluded.business_id,
                                                from_peer = excluded.from_peer,
                                                actor = excluded.actor,
                                                msg_type = excluded.msg_type,
                                                content = excluded.content,
                                                state = excluded.state,
                                                message_version = message.message_version + 1,
                                                lock_time_until = excluded.lock_time_until,
                                                weight = excluded.weight,
                                                updated_at = excluded.updated_at"#,
        msg.message_id, msg.business_id, msg.from_peer, msg.actor, msg.msg_type,
        msg.content, msg.state, msg.message_version, msg.lock_time_until, msg.weight,
        current_time, current_time
    )
    .execute(self.conn())
    .await?;
```

SQLite's `ON CONFLICT ... DO UPDATE` supports an optional `WHERE` clause on the `DO UPDATE` itself (distinct from a `WHERE` on the whole statement) — this is exactly the tool for this bug, since it's an upsert, not a plain `UPDATE`:

```rust
r#"INSERT INTO message (message_id, business_id, from_peer, actor, msg_type, content, state, message_version, lock_time_until, weight, updated_at, created_at)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
 ON CONFLICT(message_id) DO UPDATE SET business_id = excluded.business_id,
                                        from_peer = excluded.from_peer,
                                        actor = excluded.actor,
                                        msg_type = excluded.msg_type,
                                        content = excluded.content,
                                        state = excluded.state,
                                        message_version = message.message_version + 1,
                                        lock_time_until = excluded.lock_time_until,
                                        weight = excluded.weight,
                                        updated_at = excluded.updated_at
 WHERE message.state != 'Cancelled'"#,
```

This directly implements `MessageStateRace.tla`'s `NextFixed`: `status \notin TerminalStatuses /\ ResurrectPendingUnconditional`. One thing to verify before landing this: whether any *legitimate* code path needs to resurrect a `Cancelled` message (e.g. re-litigating a graph that somehow un-closes — per this audit's own Finding-6-adjacent territory, `GraphStatus` terminal statuses are supposed to be absorbing once Finding 1/1b's fix lands, so this shouldn't happen, but confirm no call site relies on the current resurrection behavior intentionally before landing the `WHERE`). Since `upsert_message` uses `sqlx::query!` (compile-time schema-checked), changing the SQL text requires the local `DATABASE_URL` dev database to be present and running `cargo sqlx prepare` to regenerate the corresponding file under `crates/store/.sqlx/` — a plain `cargo build`/`cargo check` will fail on a stale cache otherwise.

---

## Findings 4 and 9 — `validate_timelock_config`, same function, both self-contained

Current (`crates/bitvm-gc/src/timelocks.rs:69-101`):
```rust
pub fn validate_timelock_config(network: Network, config: &TimelockConfig) -> Result<()> {
    for (name, value) in [
        ("connector_z", config.connector_z),
        ("connector_a", config.connector_a),
        ("prover_connector", config.prover_connector),
        ("connector_d", config.connector_d),
        ("watchtower_challenge", config.watchtower_challenge),
        ("operator_ack", config.operator_ack),
        ("operator_commit", config.operator_commit),
        ("connector_f", config.connector_f),
    ] {
        if value == 0 {
            bail!("timelock_config.{name} must be greater than 0");
        }
    }
    let default_connector_z = default_timelock_config(network).connector_z;
    if config.connector_z != default_connector_z {
        bail!("timelock_config.connector_z must remain {} because connector-z is fixed before graph construction", default_connector_z);
    }

    ensure_lte("prover_connector", config.prover_connector, "connector_d", config.connector_d)?;
    ensure_lt("watchtower_challenge", config.watchtower_challenge, "operator_ack", config.operator_ack)?;
    ensure_lt("operator_ack", config.operator_ack, "operator_commit", config.operator_commit)?;
    ensure_lt("operator_commit", config.operator_commit, "connector_f", config.connector_f)?;
    Ok(())
}
```

**Finding 9's fix** (`connector_a` has no check at all): add a network-aware reaction-time floor and check `connector_a` against it. `Take1ChallengeRace.tla`'s `MinReactionBlocks` (now in `ShippedTimelocks.tla`) is the concrete floor to encode:
```rust
fn min_reaction_blocks(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 6,
        Network::Testnet | Network::Testnet4 => 12,
        Network::Signet => 1,
        Network::Regtest => 1,
    }
}

fn ensure_gt(left_name: &str, left: u32, right_name: &str, right: u32) -> Result<()> {
    if left <= right {
        bail!("timelock_config.{left_name} must be > {right_name} ({right})");
    }
    Ok(())
}
```
then, in `validate_timelock_config`:
```rust
ensure_gt("connector_a", config.connector_a, "min_reaction_blocks", min_reaction_blocks(network))?;
```

**Finding 4's fix** (`prover_connector <= connector_d` accepts equality, and neither has an absolute floor): change the existing `ensure_lte` call to a strict `ensure_gt`-style check with margin, and add the same floor to `connector_d`'s side of the comparison:
```rust
// was: ensure_lte("prover_connector", config.prover_connector, "connector_d", config.connector_d)?;
let margin = min_reaction_blocks(network);
if config.prover_connector + margin >= config.connector_d {
    bail!(
        "timelock_config.prover_connector ({}) + min_reaction_blocks ({}) must be strictly less than connector_d ({}) - equal or greater means Disprove and Take2 can land on the same block",
        config.prover_connector, margin, config.connector_d
    );
}
```
Note `min_reaction_blocks` should probably be exempted for `Signet`/`Regtest` per the audit report's Finding 4 fix-design text ("exempting the pure test networks Signet/Regtest") if a genuinely-zero-margin test network configuration is otherwise desired for local dev — this guide leaves that policy call to whoever implements it, since it's a product decision, not something TLC verified either way.

**Config value bumps needed to make these checks pass with the current shipped values**:
- `NODE_TESTNET_TIMELOCK_CONFIG.connector_d`: 34 → 35 (Finding 4, confirmed by `Take2DisproveRace.tla`)
- `NODE_REGTEST_TIMELOCK_CONFIG.connector_a`: 1 → 2 (Finding 9, confirmed by `Take1ChallengeRaceFixed.cfg`)

Both are in `crates/bitvm-gc/src/timelocks.rs`'s `NODE_*_TIMELOCK_CONFIG` constants (currently lines ~10-44).

---

## After implementing: closing the loop

For each finding above, once the code change lands:
1. Re-run the corresponding `*Fixed.cfg` (should already pass — that's what "verified fix design" means) and the corresponding bug `.cfg` (should now also pass, if the fix is implemented correctly, since it now models fixed-not-buggy code — or, more precisely, the bug `.cfg` no longer describes shipped reality once the fix lands, so it should be deleted/retired from the must-fail list rather than expected to keep failing).
2. Move that finding's entry from `.github/workflows/ci.yml`'s "Fail while documented bugs remain unfixed" heredoc list to the "Run baseline + proposed-fix specs (must pass)" list (if not already there).
3. Update `audit/TLAPlus-20260630.md`'s finding text and the root `README.md` spec table to say "fix applied" instead of "proposed fix (verified, not applied)".
4. Once all 6 CI-tracked findings (1/1b/2/6/7/9) are fixed, `tla-plus`'s bug-list step will have nothing left to iterate and will pass on its own - no further CI change needed at that point.
