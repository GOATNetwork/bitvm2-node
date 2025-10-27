-- Add migration script here
DROP TABLE IF EXISTS `operator_proof`;
CREATE TABLE operator_proof
(
    `graph_id`                       TEXT   NOT NULL,
    `instance_id`                    TEXT   NOT NULL,
    `included_watchtowers`           TEXT   NOT NULL,
    `latest_sequencer_commit_txid`   TEXT   NOT NULL,
    `header_chain_proof_file_path`   TEXT   NOT NULL,
    `commit_chain_proof_file_path`   TEXT   NOT NULL,
    `consensus_layer_block_number`   BIGINT NOT NULL,
    `execution_layer_block_number`   BIGINT NOT NULL,
    `watchtower_challenge_info`      TEXT   NOT NULL,
    `watchtower_challenge_init_txid` TEXT   NOT NULL,
    `block_headers_file_path`        TEXT   NOT NULL,
    `proof`                          TEXT,
    `groth16_vk`                     TEXT,
    `public_inputs`                  TEXT,
    `status`                         TEXT   NOT NULL CHECK (status IN ('pending', 'ready', 'proved', 'failed')),
    `proving_time`                   BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                    TEXT   NOT NULL,
    `created_at`                     BIGINT NOT NULL DEFAULT 0,
    `updated_at`                     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);
