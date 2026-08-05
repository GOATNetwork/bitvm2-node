Upgrade or install bitvm-node binaries via `install-bitvm.sh`.

## Instructions

1. Check the currently installed version:
   ```bash
   .claude/commands/install-bitvm.sh version
   ```

2. If $ARGUMENTS contains a target version (e.g. `v0.3.2`), use that version. Otherwise, upgrade to the latest release.

3. Run the upgrade:
   ```bash
   .claude/commands/install-bitvm.sh upgrade $ARGUMENTS
   ```

4. If the script is missing or not executable, inform the user that `.claude/commands/install-bitvm.sh` is required and offer to check if it exists.

5. Report the result to the user: what version was installed before, what version is installed now, and list the installed binaries.
