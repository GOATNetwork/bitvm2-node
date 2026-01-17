-- Add migration script here
ALTER TABLE `operator_proof`
    ADD COLUMN `blockhash_commit_txid` TEXT NOT NULL DEFAULT 'dac7516877b069dac6d2b0430e8b23812392665ecbb0c36c78c8acd12ddc929e';