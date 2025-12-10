-- Add migration script here
DROP TABLE IF EXISTS `operator_proof`;
CREATE TABLE operator_proof
(
    `graph_id`                       TEXT   NOT NULL,
    `instance_id`                    TEXT   NOT NULL,
    `genesis_sequencer_commit_txid`  TEXT   NOT NULL,
    `latest_sequencer_commit_txid`   BIGINT NOT NULL DEFAULT 0,
    `header_chain_proof_id`          BIGINT NOT NULL DEFAULT 0,
    `commit_chain_proof_id`          BIGINT NOT NULL,
    `state_chain_proof_id`           BIGINT NOT NULL,
    `execution_layer_block_number`   BIGINT NOT NULL,
    `watchtower_challenge_txids`     TEXT   NOT NULL,
    `watchtower_public_keys`         TEXT   NOT NULL,
    `watchtower_challenge_init_txid` TEXT   NOT NULL,
    `data_location`                  TEXT   NOT NULL CHECK (status IN ('File', 'DB', 'S3')),
    `proof`                          TEXT,
    `groth16_vk_hash`                TEXT,
    `public_inputs`                  TEXT,
    `status`                         TEXT   NOT NULL CHECK (status IN ('Pending', 'Proved', 'Failed')),
    `proving_time`                   BIGINT NOT NULL DEFAULT 0,
    `proving_cycles`                 BIGINT NOT NULL DEFAULT 0,
    `proof_size`                     BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                    TEXT   NOT NULL,
    `created_at`                     BIGINT NOT NULL DEFAULT 0,
    `updated_at`                     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);

