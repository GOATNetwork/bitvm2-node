-- Add migration script here
DROP TABLE IF EXISTS `operator_proof`;
CREATE TABLE operator_proof
(
    `id`                           INTEGER PRIMARY KEY,
    `instance_id`                  TEXT   NOT NULL,
    `graph_id`                     TEXT   NOT NULL,
    `execution_layer_block_number` BIGINT NOT NULL DEFAULT 0,
    `path_to_proof`                TEXT,
    `cycles`                       BIGINT NOT NULL DEFAULT 0,
    `proof_state`                  BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                  TEXT   NOT NULL DEFAULT '',
    `extra`                        TEXT,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0
);