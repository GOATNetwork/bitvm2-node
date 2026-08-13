Initiate operator pegout (Gateway.initWithdraw) via the `pegout` binary.

The pegout binary calls the operator node's REST API, so an **Operator node** must be running and reachable.

## Prerequisites — Running an Operator Node

Before using this command, ensure an Operator role node (`ACTOR=Operator`) is running.

Use the `/run-operator-node` skill to start one, or see `deployment/README.md` (section **Operator**) for full details.

## Instructions

1. Ask the user for the following parameters (skip any already provided as arguments: $ARGUMENTS):
   - **subcommand**: Which mode to use?
     - `once` - Single pegout for one graph
     - `batch` - Repeat until balance insufficient or target reached
   - **rpc_url**: Node API base URL. Default: `http://localhost:8080`
   - For `once`:
     - **graph_id**: Optional UUID of the graph to pegout (auto-selects if omitted)
     - **dry_run**: Whether to skip the actual Gateway.initWithdraw call. Default: false
   - For `batch`:
     - **max_total_amount_sats**: Required. Stop after total pegout amount reaches this target (sats)
     - **max_count**: Optional limit on number of pegouts. Default: 0 (unlimited)
     - **dry_run**: Whether to skip the actual calls. Default: false
     - **poll_interval_secs**: Poll interval between pegouts. Default: 300
     - **max_wait_secs**: Max wait for a graph to be ready. Default: 36000

2. **Check that `BITVM_SECRET` is set** in the current shell environment. The binary uses this key to sign the request — it must match the secret configured on the target node.
   ```bash
   echo "BITVM_SECRET is ${BITVM_SECRET:+set}"
   ```
   If it is not set, ask the user to export it before continuing.

3. Confirm that the Operator node is running and reachable at the given `rpc_url`. If the user hasn't started a node yet, walk them through the `/run-operator-node` skill.

3. **Verify the node has synced eligible graphs.** The operator node syncs graph data via P2P. Check by calling:
   ```bash
   curl -s <rpc_url>/v1/graphs/ready-to-kickoff?btc_pub_key=<OPERATOR_BTC_PUBKEY> | jq .
   ```
   If `"graph"` is null, the node may not have synced yet or there are no eligible graphs.

4. Check if the `pegout` binary exists at `./bin/pegout`. If not, run:
   ```bash
   .claude/commands/install-bitvm.sh install
   ```

5. Run the command using the pre-built binary:

```bash
./bin/pegout [--rpc-url <URL>] <subcommand> [options]
```

### Example commands

Single pegout (auto-select graph):
```bash
./bin/pegout --rpc-url http://127.0.0.1:8902 once
```

Single pegout (specific graph, dry run):
```bash
./bin/pegout --rpc-url http://127.0.0.1:8902 once --graph-id <UUID> --dry-run
```

Batch pegout:
```bash
./bin/pegout --rpc-url http://127.0.0.1:8902 batch --max-total-amount-sats 10000000 --max-count 5
```

> The binary calls `POST /v1/graphs/pegout` on the node API.
