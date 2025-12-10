-- Add migration script here
-- Add migration script here
DROP TABLE IF EXISTS `header_chain_proof`;
CREATE TABLE header_chain_proof
(
    `id`             INTEGER PRIMARY KEY AUTOINCREMENT,
    `data_location`  TEXT   NOT NULL CHECK (status IN ('File', 'DB', 'S3')),
    `batch_size`     BIGINT NOT NULL DEFAULT 6,
    `start`          BIGINT NOT NULL DEFAULT 0,
    `proof`          TEXT   NOT NULL,
    `vk_hash`        TEXT   NOT NULL,
    `public_inputs`  TEXT   NOT NULL,
    `status`         TEXT   NOT NULL CHECK (status IN ('Pending',  'Proved', 'Failed')),
    `proving_cycles` BIGINT NOT NULL DEFAULT 0,
    `proof_size`     BIGINT NOT NULL DEFAULT 0,
    `proving_time`   BIGINT NOT NULL DEFAULT 0,
    `zkm_version`    TEXT   NOT NULL,
    `created_at`     BIGINT NOT NULL DEFAULT 0,
    `updated_at`     BIGINT NOT NULL DEFAULT 0
);
