-- Add migration script here
DROP TABLE IF EXISTS `watchtower_proof`;
CREATE TABLE watchtower_proof
(
    `graph_id`                     TEXT   NOT NULL,
    `instance_id`                  TEXT   NOT NULL,
    `latest_sequencer_commit_txid` TEXT   NOT NULL,
    `header_chain_proof_file_path` TEXT   NOT NULL,
    `commit_chain_proof_file_path` TEXT   NOT NULL,
    `proof`                        TEXT,
    `groth16_vk`                   TEXT,
    `public_inputs`                TEXT,
    `status`                       TEXT   NOT NULL CHECK (status IN ('pending', 'ready', 'proved', 'failed')),
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                  TEXT   NOT NULL,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);