-- Add migration script here
DROP TABLE IF EXISTS `watchtower_proof`;
CREATE TABLE watchtower_proof
(
    `id`                           INTEGER PRIMARY KEY AUTOINCREMENT,
    `latest_sequencer_commit_txid` TEXT   NOT NULL,
    `header_chain_proof_file_path` TEXT   NOT NULL,
    `commit_chain_proof_file_path` TEXT   NOT NULL,
    `proof_file_path`              TEXT   NOT NULL,
    `status`                       TEXT   NOT NULLCHECK (status IN ('queued', 'executed', 'proved', 'failed')),
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0,
);