Initiate Bridge Out via the `bridge-out` binary (payInvoice quote -> swap initialize -> init-tag).

## Instructions

1. Ask the user for the following parameters (skip any already provided as arguments: $ARGUMENTS):
   - **rpc_url**: Node API base URL. Default: `http://localhost:8080`
   - **from_addr**: Source GOAT address (used by `init-tag`)
   - **to_addr**: Destination BTC address (used by `init-tag`)
   - **pay_invoice_url**: Quote endpoint. Default: `https://152-32-185-32.nodes.atomiq.exchange:8443/tobtc/payInvoice?chain=GOAT`
   - **amount**: Amount in pegBTC (human-readable). Example: `0.0015`
   - **exact_in**: Whether quote is exact-in (`true`/`false`). Default: `true`
   - **confirmation_target**: Bitcoin confirmation target. Default: `3`
   - **confirmations**: Required confirmations. Default: `2`
   - **token**: Token address
   - **offerer**: Offerer GOAT address
   - **additional_params_json**: Optional JSON object merged into payInvoice body
   - **contract_address**: Optional (fallback to `GOAT_SWAP_CONTRACT_ADDRESS`)
   - **max_wait_secs**: Max wait for tx receipt. Default: `60`

2. Ensure required environment and runtime prerequisites are ready:
   - `GOAT_PRIVATE_KEY` must be set (unless user passes `--goat-private-key`)
   - `GOAT_CHAIN_URL` and chain config must be valid for on-chain calls
   - `GOAT_SWAP_CONTRACT_ADDRESS` should be set if `--contract-address` is omitted
   - Optional but recommended: use `node/.env` to manage the above variables consistently

3. Check if the `bridge-out` binary exists at `./bin/bridge-out`. If not, run the install script to download it:
   ```bash
   .claude/commands/install-bitvm.sh install
   ```
   To upgrade to the latest version:
   ```bash
   .claude/commands/install-bitvm.sh upgrade
   ```
   The script auto-detects the platform (x86_64-linux / aarch64-macos), downloads from GitHub Releases,
   verifies the sha256 checksum, and installs all binaries to `./bin/`.

4. Run swap initialize (this step calls payInvoice first, then sends token approve if needed, then swap `initialize` tx):
   ```bash
   ./bin/bridge-out --rpc-url <rpc_url> swap-initialize \
     --pay-invoice-url <pay_invoice_url> \
     --btc-address <to_addr> \
     --amount <amount> \
     --exact-in <exact_in> \
     --confirmation-target <confirmation_target> \
     --confirmations <confirmations> \
     --token <token> \
     --offerer <offerer> \
     --max-wait-secs <max_wait_secs>
   ```
   - If needed, append:
   ```bash
   --additional-params-json '<json_object>'
   --contract-address <contract_address>
   --goat-private-key <goat_private_key>
   ```

5. Parse output from step 4:
   - `swap initialize submitted: <tx_hash>`
   - `escrow_hash (from Initialize log): <escrow_hash>`
   Save `<escrow_hash>` for the next step.

6. Submit bridge-out init-tag to node API:
   ```bash
   ./bin/bridge-out --rpc-url <rpc_url> init-tag \
     --from-addr <from_addr> \
     --to-addr <to_addr> \
     --escrow-hash <escrow_hash> \
     --contract-address <contract_address>
   ```
   - Alternative: derive escrow hash from tx logs directly:
   ```bash
   ./bin/bridge-out --rpc-url <rpc_url> init-tag \
     --from-addr <from_addr> \
     --to-addr <to_addr> \
     --swap-init-tx-hash <tx_hash> \
     --contract-address <contract_address>
   ```

7. Optional verification (if instance id is known):
   ```bash
   ./bin/bridge-out --rpc-url <rpc_url> escrow-data --instance-id <instance_id>
   ```
