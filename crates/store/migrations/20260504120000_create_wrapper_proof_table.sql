CREATE TABLE IF NOT EXISTS wrapper_proof
(
    `id`                              INTEGER PRIMARY KEY,
    `operator_proof_id`               BIGINT NOT NULL,
    `instance_id`                     TEXT   NOT NULL,
    `graph_id`                        TEXT   NOT NULL,
    `execution_layer_block_number`    BIGINT NOT NULL DEFAULT 0,
    `operator_path_to_proof`          TEXT   NOT NULL DEFAULT '',
    `path_to_proof`                   TEXT,
    `public_value_hex`                TEXT,
    `operator_vk_hash`                TEXT   NOT NULL DEFAULT '',
    `genesis_sequencer_commit_txid`   TEXT   NOT NULL DEFAULT '',
    `operator_public_value_hex`       TEXT,
    `proof_size`                      BIGINT NOT NULL DEFAULT 0,
    `cycles`                          BIGINT NOT NULL DEFAULT 0,
    `proof_state`                     BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `total_time_to_proof`             BIGINT NOT NULL DEFAULT 0,
    `proving_time`                    BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                     TEXT   NOT NULL DEFAULT '',
    `extra`                           TEXT,
    `created_at`                      BIGINT NOT NULL DEFAULT 0,
    `updated_at`                      BIGINT NOT NULL DEFAULT 0,
    UNIQUE (`operator_proof_id`)
);

CREATE INDEX IF NOT EXISTS idx_wrapper_proof_instance_graph
    ON wrapper_proof (`instance_id`, `graph_id`);

CREATE INDEX IF NOT EXISTS idx_wrapper_proof_state
    ON wrapper_proof (`proof_state`);
