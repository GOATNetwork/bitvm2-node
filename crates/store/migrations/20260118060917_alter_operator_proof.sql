-- Add migration script here
ALTER TABLE `operator_proof`
    DROP COLUMN `blockhash_commit_txid`;

ALTER TABLE `operator_proof`
    ADD COLUMN `operator_committed_blockhash` TEXT NOT NULL DEFAULT 'dac7516877b069dac6d2b0430e8b23812392665ecbb0c36c78c8acd12ddc929e';