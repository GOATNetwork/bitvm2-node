-- Add migration script here
DROP TABLE IF EXISTS `watchtower_proof`;
CREATE TABLE watchtower_proof
(
    `id`                  INTEGER PRIMARY KEY,
    `instance_id`         TEXT   NOT NULL,
    `graph_id`            TEXT   NOT NULL,
    `public_key`          TEXT   NOT NULL,
    `challenge_txid`      TEXT   NOT NULL,
    `challenge_init_txid` TEXT   NOT NULL,
    `execution_layer_block_number` BIGINT NOT NULL DEFAULT 0,
    `path_to_proof`       TEXT,
    `proof_size`          BIGINT NOT NULL DEFAULT 0,
    `public_value_hex`   TEXT,
    `cycles`              BIGINT NOT NULL DEFAULT 0,
    `proof_state`         BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `proving_time`        BIGINT NOT NULL DEFAULT 0,
    `zkm_version`         TEXT   NOT NULL DEFAULT '',
    `extra`               TEXT,
    `created_at`          BIGINT NOT NULL DEFAULT 0,
    `updated_at`          BIGINT NOT NULL DEFAULT 0
);